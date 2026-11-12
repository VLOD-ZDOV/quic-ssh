//! The `qshd` daemon.

// Switching users, the helpers that run as them and what needs Unix
// sockets or utmp: Unix only. On Windows qshd serves the user it runs as.
mod agent;
mod auth;
mod exec;
mod files;
#[cfg(unix)]
pub mod helpers;
#[cfg(unix)]
mod login_record;
#[cfg(unix)]
pub mod keys_command;
#[cfg(all(feature = "pam", target_os = "linux"))]
#[allow(unsafe_code)]
pub mod pam;
mod penalty;
mod persist;
pub mod transfer;
mod sftp;
#[cfg(unix)]
mod x11;
/// X11 forwarding needs Unix sockets: never set up on Windows.
#[cfg(windows)]
mod x11 {
    pub struct Display {
        pub display: String,
        pub auth_display: String,
        pub proto: String,
        pub cookie: String,
    }
    #[derive(Default)]
    pub struct X11(());
    impl X11 {
        pub fn display(&self) -> Option<Display> {
            None
        }
    }
}
pub mod revoked;
#[cfg(unix)]
mod users;
#[cfg(windows)]
#[path = "users_windows.rs"]
mod users;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

use crate::config::{GatewayPorts, PermitRootLogin, ServerConfig};
use crate::keys::{Identity, PublicKey};
use crate::authkeys::Grant;
use crate::proto::{read_msg, read_msg_capped, valid_user_name, write_msg, Hello, PtySpec, Reply, Request, MIN_VERSION, VERSION};
use crate::transport::{Conn, Listener, RecvHalf, SendHalf};
use penalty::Outcome;
pub use users::INTERNAL_SFTP;

/// `qshd internal-sftp`: on Unix through [`helpers::run_internal`].
#[cfg(windows)]
pub fn run_sftp(args: &[String]) -> Result<()> {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let home = crate::keys::home_dir()?;
    sftp::serve(sftp::Options::parse(args, &user, &home.to_string_lossy())?)
}
use users::User;

/// Time a connected client has to open its first stream and say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
/// The greeting (version + user name + optional resume token) is tiny; cap it
/// well below `MAX_MSG` so a pre-login peer cannot flood the log with a huge name.
const HELLO_MAX: usize = 4096;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const NO_PAIRING: &str = "no active pairing code for this user (run `qshd pair` on the server; codes expire)";
/// "No pairing code" always takes this long, so that the time a check for an
/// existing user takes does not tell which users exist.
const NO_PAIRING_DELAY: Duration = Duration::from_millis(500);

async fn refuse_pairing(send: &mut SendHalf, since: tokio::time::Instant) -> Result<()> {
    tokio::time::sleep_until(since + NO_PAIRING_DELAY).await;
    write_msg(send, &Reply::Err(NO_PAIRING.into())).await
}
/// How long a finished connection waits for the client to close it.
const LINGER: Duration = Duration::from_secs(5);

struct State {
    /// The current settings; replaced when qshd reloads its config (SIGHUP).
    cfg: std::sync::RwLock<Arc<ServerConfig>>,
    host_key: PublicKey,
    penalties: penalty::Penalties,
    totp_used: auth::UsedCodes,
    sessions: Arc<persist::Sessions>,
    /// The port qshd listens on (UDP and TCP share it).
    port: u16,
}

impl State {
    fn cfg(&self) -> Arc<ServerConfig> {
        self.cfg.read().unwrap().clone()
    }
}

/// Reads the config again (for SIGHUP).
pub type Reload = Box<dyn Fn() -> Result<ServerConfig> + Send + Sync>;

/// Settings that only take effect when qshd starts.
#[cfg(unix)]
fn restart_needed(old: &ServerConfig, new: &ServerConfig) -> Vec<&'static str> {
    let mut changed = Vec::new();
    for (name, differs) in [
        ("listen", old.listen != new.listen),
        ("tcp", old.tcp != new.tcp),
        ("host_key", old.host_key != new.host_key),
        ("host_certificate", old.host_certificate != new.host_certificate),
        ("max_connections", old.max_connections != new.max_connections),
        ("max_startups", old.max_startups != new.max_startups),
        ("max_startups_per_ip", old.max_startups_per_ip != new.max_startups_per_ip),
        ("session_timeout", old.session_timeout != new.session_timeout),
        ("client_alive_interval", old.client_alive_interval != new.client_alive_interval),
        ("client_alive_count_max", old.client_alive_count_max != new.client_alive_count_max),
        ("per_source_penalties", old.per_source_penalties != new.per_source_penalties),
        ("per_source_penalty_exempt_list", old.per_source_penalty_exempt_list != new.per_source_penalty_exempt_list),
        ("session_scope", old.session_scope != new.session_scope),
        ("require_post_quantum", old.require_post_quantum != new.require_post_quantum),
    ] {
        if differs {
            changed.push(name);
        }
    }
    changed
}

/// Reloads the config on SIGHUP, like sshd. New logins use the new
/// settings; running sessions keep theirs.
#[cfg(unix)]
fn reload_on_hangup(state: Arc<State>, reload: Reload) {
    use tokio::signal::unix::{signal, SignalKind};
    let Ok(mut hangups) = signal(SignalKind::hangup()) else { return };
    tokio::spawn(async move {
        while hangups.recv().await.is_some() {
            match tokio::task::block_in_place(&reload) {
                Ok(new) => {
                    let old = state.cfg();
                    let ignored = restart_needed(&old, &new);
                    if !ignored.is_empty() {
                        warn!("config reloaded; changes to {} take effect after a restart", ignored.join(", "));
                    } else {
                        info!("config reloaded");
                    }
                    // The host key is not at hand here: host_certificate needs a restart anyway.
                    for problem in config_problems(&new, None) {
                        warn!("{problem}");
                    }
                    for line in new.match_overrides() {
                        info!("{line}");
                    }
                    crate::transport::set_server_buffer(new.connection_buffer_mb);
                    *state.cfg.write().unwrap() = Arc::new(new);
                }
                Err(e) => warn!("config not reloaded, keeping the old one: {e:#}"),
            }
        }
    });
}

/// Counts connections that have not authenticated yet, in total and per IP,
/// so a flood of half-open connections cannot lock out real users (the
/// MaxStartups idea; compare pre-auth DoS issues like CVE-2025-26466).
struct Startups {
    total: usize,
    per_ip: usize,
    counts: std::sync::Mutex<(usize, HashMap<IpAddr, usize>)>,
}

/// A slot in [`Startups`], released on drop.
struct Startup {
    owner: Arc<Startups>,
    ip: IpAddr,
}

impl Startups {
    fn new(total: usize, per_ip: usize) -> Arc<Startups> {
        Arc::new(Startups { total, per_ip, counts: Default::default() })
    }

    /// What an address counts as: itself, or its /64 for IPv6 (one host
    /// usually has the whole /64).
    fn key(ip: IpAddr) -> IpAddr {
        match ip.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !(u128::MAX >> 64)).into()),
            v4 => v4,
        }
    }

    /// Half the slots in use, in total or for `ip`: time to make QUIC
    /// clients prove their address first (a Retry), so that spoofed ones
    /// cannot hold the slots.
    fn busy(&self, ip: IpAddr) -> bool {
        let c = self.counts.lock().unwrap();
        let n = c.1.get(&Self::key(ip)).copied().unwrap_or(0);
        2 * c.0 >= self.total || 2 * n >= self.per_ip
    }

    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<Startup> {
        let ip = Self::key(ip);
        let mut c = self.counts.lock().unwrap();
        let n = c.1.get(&ip).copied().unwrap_or(0);
        if c.0 >= self.total || n >= self.per_ip {
            return None;
        }
        c.0 += 1;
        c.1.insert(ip, n + 1);
        Some(Startup { owner: self.clone(), ip })
    }
}

impl Drop for Startup {
    fn drop(&mut self) {
        let mut c = self.owner.counts.lock().unwrap();
        c.0 -= 1;
        if let Some(n) = c.1.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                c.1.remove(&self.ip);
            }
        }
    }
}

/// Looks up the user who logs in as `name`, and their groups if `groups`.
/// Blocking (NSS may ask LDAP or SSSD).
fn resolve_user(name: &str, groups: bool) -> Result<(User, Vec<String>)> {
    if !valid_user_name(name) {
        bail!("invalid user name");
    }
    let u = User::lookup(name)?;
    // Policies match the name as given: it must be the account's own
    // (a case-insensitive directory finds "ALICE" for "alice").
    if u.name != name {
        bail!("the account's name is {:?}", u.name);
    }
    let names = if groups { u.group_names() } else { Vec::new() };
    Ok((u, names))
}

/// Why this (existing) user may not log in: allow/deny lists, root login.
fn refused(cfg: &ServerConfig, who: &crate::config::Login, user: &User) -> Option<String> {
    if user.uid == 0 && cfg.permit_root_login == PermitRootLogin::No {
        return Some("root login is not permitted (permit_root_login)".into());
    }
    // Like sshd: an account whose shell is missing is not one to log in to.
    #[cfg(unix)]
    let runnable = |m: &std::fs::Metadata| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let runnable = |_: &std::fs::Metadata| true;
    if !std::fs::metadata(&user.shell).is_ok_and(|m| m.is_file() && runnable(&m)) {
        return Some(format!("shell {} does not exist or is not executable", user.shell.display()));
    }
    cfg.login_refused(who)
}

/// The settings for a login of `name` from `addr`, and why it would be
/// refused, found as a real login finds them: for `qshd -T -C`.
pub fn check_login(global: &ServerConfig, name: &str, addr: IpAddr) -> (ServerConfig, Option<String>) {
    let (user, groups, error) = match resolve_user(name, global.needs_groups()) {
        Ok((u, g)) => (Some(u), g, None),
        Err(e) => (None, Vec::new(), Some(format!("{e:#}"))),
    };
    let who = crate::config::Login { user: name, groups: &groups, addr: addr.to_canonical() };
    let cfg = global.for_login(&who);
    let verdict = match user {
        Some(u) => refused(&cfg, &who, &u),
        None => error,
    };
    (cfg, verdict)
}

/// Largest banner sent (like sshd, which reads the whole file, but bounded).
const MAX_BANNER: u64 = 64 * 1024;

/// The `banner` file's text, if one is set and readable.
fn banner(cfg: &ServerConfig) -> Option<String> {
    use std::io::Read;
    let path = cfg.banner.as_ref()?;
    let mut text = Vec::new();
    match std::fs::File::open(path).and_then(|f| f.take(MAX_BANNER).read_to_end(&mut text)) {
        Ok(_) => Some(String::from_utf8_lossy(&text).into_owned()).filter(|t| !t.is_empty()),
        Err(e) => {
            warn!("banner {}: {e}", path.display());
            None
        }
    }
}

/// The host certificate from `host_certificate`, if it is valid for the host key.
fn host_certificate(cfg: &ServerConfig, host: &Identity) -> Option<Vec<u8>> {
    let path = cfg.host_certificate.as_ref()?;
    match load_host_certificate(path, host) {
        Ok(cert) => {
            info!("host certificate {:?} for {:?}", cert.key_id(), cert.valid_principals());
            cert.to_bytes().ok()
        }
        Err(e) => {
            warn!("host certificate {}: {e:#}; not used", path.display());
            None
        }
    }
}

/// The host certificate, if clients could accept it: one they would refuse
/// is worse than none, as they would turn away from a host they know.
fn load_host_certificate(path: &std::path::Path, host: &Identity) -> Result<ssh_key::Certificate> {
    use ssh_key::certificate::CertType;
    let text = std::fs::read_to_string(path).context("cannot read")?;
    let cert = ssh_key::Certificate::from_openssh(text.trim()).context("cannot parse")?;
    let own = ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(host.public().0));
    if cert.cert_type() != CertType::Host || cert.public_key() != &own {
        anyhow::bail!("not a host certificate for this host key");
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let ca = cert.signature_key().fingerprint(ssh_key::HashAlg::Sha256);
    if cert.validate_at(now, [&ca]).is_err() {
        anyhow::bail!("expired, not valid yet, or its signature does not verify");
    }
    Ok(cert)
}

/// What is set but cannot work here, for `qshd -t` and the log at startup
/// and after a reload.
pub fn config_problems(cfg: &ServerConfig, host: Option<&Identity>) -> Vec<String> {
    let mut problems = cfg.warnings();
    if let (Some(path), Some(host)) = (&cfg.host_certificate, host) {
        if let Err(e) = load_host_certificate(path, host) {
            problems.push(format!("host_certificate {}: {e:#}; it will not be used", path.display()));
        }
    }
    #[cfg(unix)]
    if !nix::unistd::geteuid().is_root() && (cfg.chroot_directory.is_some() || cfg.matches.iter().any(|m| m.chroot_directory.is_some())) {
        problems.push("chroot_directory needs qshd to run as root: sessions it applies to will fail".into());
    }
    let passwords = cfg.password_authentication || cfg.matches.iter().any(|m| m.password_authentication == Some(true));
    #[cfg(unix)]
    let shadow = cfg!(target_os = "linux") && nix::unistd::geteuid().is_root();
    #[cfg(not(unix))]
    let shadow = false;
    if passwords && !shadow && !cfg.use_pam {
        problems.push("password_authentication needs qshd to run as root on Linux (to read /etc/shadow); no password will match".into());
    }
    problems
}

/// Binds the configured address on UDP and TCP. If the default dual-stack
/// address is unavailable (IPv6 disabled), falls back to IPv4.
pub async fn bind(cfg: &ServerConfig, host: &Identity) -> Result<Listener> {
    crate::transport::set_server_buffer(cfg.connection_buffer_mb);
    let tls = crate::tls::server_config(host, host_certificate(cfg, host), cfg.require_post_quantum)?;
    let alive = (cfg.client_alive_interval > 0)
        .then(|| crate::transport::Alive { interval: Duration::from_secs(cfg.client_alive_interval), count: cfg.client_alive_count_max });
    match Listener::bind(cfg.listen, tls.clone(), cfg.tcp, alive).await {
        Err(e) if cfg.listen.ip() == Ipv6Addr::UNSPECIFIED => {
            debug!("dual-stack bind failed ({e:#}), using IPv4 only");
            Listener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), cfg.listen.port()), tls, cfg.tcp, alive).await
        }
        other => other,
    }
}

pub async fn serve(listener: Listener, cfg: ServerConfig, host: &Identity, reload: Option<Reload>) -> Result<()> {
    // Remember where qshd is while the path is still valid (see users::exe_path).
    let _ = users::exe_path();
    #[cfg(not(unix))]
    let _ = &reload;
    let scope = cfg.session_scope;
    tokio::task::spawn_blocking(move || users::set_session_scope(scope)).await?;
    let limit = Arc::new(Semaphore::new(cfg.max_connections));
    let startups = Startups::new(cfg.max_startups, cfg.max_startups_per_ip);
    let sessions = Arc::new(persist::Sessions::new(Duration::from_secs(cfg.session_timeout)));
    let penalties = penalty::Penalties::new(crate::config::Penalties {
        exempt: cfg.per_source_penalty_exempt_list.clone(),
        ..cfg.per_source_penalties.clone()
    });
    let state = Arc::new(State {
        cfg: std::sync::RwLock::new(Arc::new(cfg)),
        host_key: host.public(),
        penalties,
        totp_used: Default::default(),
        sessions,
        port: listener.local_addr()?.port(),
    });
    #[cfg(unix)]
    if let Some(reload) = reload {
        reload_on_hangup(state.clone(), reload);
    }
    loop {
        let incoming = match listener.accept().await {
            Ok(i) => i,
            // Out of descriptors (EMFILE) and the like: wait a little and go
            // on, as sshd does; the server must not end over one connection.
            Err(e) if e.is::<std::io::Error>() => {
                warn!("cannot accept a connection: {e:#}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(e) => return Err(e),
        };
        let addr = incoming.remote_addr();
        // A QUIC Initial's source address proves nothing: under load, the
        // client must show it gets packets there first (stateless Retry).
        let validated = incoming.validated();
        if !validated && startups.busy(addr.ip()) {
            debug!("{addr}: asking for a QUIC retry");
            incoming.retry();
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            warn!("connection limit reached, dropping {addr}");
            incoming.reject();
            continue;
        };
        if let Some(left) = state.penalties.refused(addr.ip()) {
            debug!("dropping {addr}: penalty for {}s more", left.as_secs());
            incoming.reject();
            continue;
        }
        let Some(startup) = startups.try_acquire(addr.ip()) else {
            debug!("too many unauthenticated connections, dropping {addr}");
            incoming.reject();
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            match incoming.handshake().await {
                Ok(conn) => {
                    let conn = Arc::new(conn);
                    let mut outcome = Outcome::NoAuth;
                    if let Err(e) = handle_conn(&conn, state.clone(), startup, &mut outcome).await {
                        debug!("{addr}: {e:#}");
                    }
                    if state.penalties.record(addr.ip(), outcome) {
                        warn!("{addr}: too many failed logins; dropping its connections for a while (per_source_penalties)");
                    }
                    // Dropping a QUIC connection discards unsent data, so let the
                    // client read the final reply (e.g. "access denied") and hang up first.
                    let _ = tokio::time::timeout(LINGER, conn.closed()).await;
                }
                Err(e) => {
                    debug!("{addr}: handshake failed: {e:#}");
                    // Not for an address that may be someone else's (a spoofed QUIC Initial).
                    if validated {
                        state.penalties.record(addr.ip(), Outcome::NoAuth);
                    }
                }
            }
            drop(permit);
        });
    }
}

/// Serves one connection; `outcome` tells how its login went (for penalties).
async fn handle_conn(conn: &Arc<Conn>, state: Arc<State>, startup: Startup, outcome: &mut Outcome) -> Result<()> {
    let started = tokio::time::Instant::now();
    let addr = conn.remote_addr();
    let key = conn.peer_key();
    let (mut send, mut recv, hello) = tokio::time::timeout(HELLO_TIMEOUT, async {
        let (send, mut recv) = conn.accept_bi().await.context("closed before hello")?;
        // A small cap before login: the greeting is version + user name (<=64)
        // + optional resume token, never large. This keeps an anonymous peer
        // from sending a huge name that the rejection path would then log.
        let hello: Hello = read_msg_capped(&mut recv, HELLO_MAX).await?;
        anyhow::Ok((send, recv, hello))
    })
    .await
    .context("no hello in time")??;

    let (name, pairing, version, resume) = match hello {
        Hello::Login { version, user } | Hello::Pair { version, user } | Hello::Resume { version, user, .. } if version < MIN_VERSION => {
            write_msg(&mut send, &Reply::Err(format!("unsupported protocol version {version}"))).await?;
            bail!("client {user:?} uses protocol version {version}");
        }
        Hello::Login { user, version } => (user, false, version, None),
        Hello::Pair { user, version } => (user, true, version, None),
        Hello::Resume { user, version, token } => (user, false, version, Some(token)),
    };
    // User lookups (NSS: maybe LDAP or SSSD) and reading the key files can
    // block: never on a worker thread, which may be the one driving the network.
    let global = state.cfg();
    let (n, groups) = (name.clone(), global.needs_groups());
    let looked_up = tokio::task::spawn_blocking(move || resolve_user(&n, groups)).await?;
    let (user, groups) = match looked_up {
        Ok((u, g)) => (Some(u), g),
        Err(e) => {
            warn!("{addr}: rejected user {name:?}: {e:#}");
            (None, Vec::new())
        }
    };
    // This login's settings ([[match]] blocks applied).
    let who = crate::config::Login { user: &name, groups: &groups, addr: addr.ip().to_canonical() };
    let cfg = Arc::new(global.for_login(&who));
    // A user the config keeps out goes through the same steps as an
    // unknown one, so the answer does not tell which users exist.
    let user = match user {
        Some(u) => match refused(&cfg, &who, &u) {
            Some(reason) => {
                warn!("{addr}: user {name:?} not allowed: {reason}");
                None
            }
            None => Some(u),
        },
        None => None,
    };
    if version >= 6 && !pairing && resume.is_none() {
        if let Some(text) = banner(&cfg) {
            write_msg(&mut send, &Reply::Banner(text)).await?;
        }
    }
    // For the whole login, like sshd's LoginGraceTime (not for each step).
    let grace = match cfg.login_grace_time {
        0 => Duration::MAX,
        s => Duration::from_secs(s),
    };
    let left = || grace.saturating_sub(started.elapsed());
    if resume.is_some() && !cfg!(feature = "persist") {
        *outcome = Outcome::AuthFailed;
        return write_msg(&mut send, &Reply::Err("this qshd was built without persist (no sessions to resume)".into())).await;
    }
    if pairing && !cfg!(feature = "pair") {
        *outcome = Outcome::AuthFailed;
        return write_msg(&mut send, &Reply::Err("this qshd was built without pairing; add the key to authorized_keys".into())).await;
    }
    if pairing {
        // A paired key would go to a file this server does not read.
        let user = user.filter(|_| cfg.use_qsh_authorized_keys);
        match user {
            // A pairing that does not add a key counts as a failed login,
            // for unknown users too (penalties must not tell them apart).
            Some(user) => {
                *outcome = match tokio::time::timeout(left(), pair(conn, &state, &user, send, recv)).await {
                    Ok(Ok(true)) => Outcome::LoggedIn,
                    Ok(Ok(false)) => Outcome::AuthFailed,
                    Ok(Err(e)) => {
                        *outcome = Outcome::AuthFailed;
                        return Err(e);
                    }
                    Err(_) => {
                        *outcome = Outcome::GraceExceeded;
                        bail!("pairing took too long");
                    }
                };
                return Ok(());
            }
            // Same answer, after the same time, as for an existing user
            // without a code, so names cannot be probed.
            None => {
                *outcome = Outcome::AuthFailed;
                return refuse_pairing(&mut send, tokio::time::Instant::now()).await;
            }
        }
    }

    // An unknown user goes through the same steps with no keys, so names cannot be probed.
    let (entries, cas, revoked, principals, runner) = {
        let (cfg, user) = (cfg.clone(), user.clone());
        tokio::task::spawn_blocking(move || {
            let entries = user.as_ref().map(|u| auth::authorized_entries(&cfg, u)).unwrap_or_default();
            let principals = match &user {
                Some(u) => auth::authorized_principals(&cfg, u),
                None => cfg.authorized_principals_file.as_ref().map(|_| Vec::new()),
            };
            // KeysCommand looks its user up (NSS) too.
            #[cfg(unix)]
            let runner = user.as_ref().and_then(|u| keys_command::KeysCommand::runner(&cfg, u));
            #[cfg(not(unix))]
            let runner = ();
            (entries, auth::trusted_cas(&cfg), revoked::Revocation::load(cfg.revoked_keys.as_deref()), principals, runner)
        })
        .await?
    };
    #[cfg(unix)]
    let command = user.as_ref().zip(runner).and_then(|(u, runner)| keys_command::KeysCommand::new(&cfg, u, runner));
    #[cfg(unix)]
    let mimic = if command.is_none() { keys_command::Mimic::new(&cfg) } else { None };
    #[cfg(not(unix))]
    let () = runner;
    let checker = auth::Checker {
        entries: &entries,
        cas: &cas,
        revoked: &revoked,
        #[cfg(unix)]
        command: command.as_ref(),
        #[cfg(unix)]
        mimic: mimic.as_ref(),
        login: crate::authkeys::Login { user: &name, ip: addr.ip().to_canonical(), now: auth::now(), principals: principals.as_deref() },
        exporter: conn.exporter(),
    };
    let mut granted = checker.check(&auth::tls_key(key)).await.ok().map(|g| (g, format!("ED25519 {}", key.fingerprint())));
    if granted.is_none() && version >= 4 {
        // A refused signature is a failed login even if the client hangs up
        // afterwards (as on the password path). The refused TLS key is not:
        // clients send a throwaway one on purpose.
        let mut failed = false;
        let attempt = auth::key_auth(&mut send, &mut recv, &checker, cfg.max_auth_tries, &mut failed);
        let result = tokio::time::timeout(left(), attempt).await;
        if failed {
            *outcome = Outcome::AuthFailed;
        }
        granted = match result {
            Ok(result) => result?,
            Err(_) => {
                *outcome = Outcome::GraceExceeded;
                bail!("login took too long");
            }
        };
    }
    // Whether PAM's account check has been done (`use_pam`).
    let mut account_checked = false;
    // Passwords, if allowed, when no key worked (never for root unless
    // permit_root_login = "yes"). Unknown users are asked too.
    if granted.is_none() && version >= 6 && cfg.password_authentication {
        // Guessing passwords counts as a failed login even if the client hangs up midway.
        *outcome = Outcome::AuthFailed;
        let root_ok = user.as_ref().is_none_or(|u| u.uid != 0) || cfg.permit_root_login == PermitRootLogin::Yes;
        let candidate = user.as_ref().filter(|_| root_ok);
        #[cfg(all(feature = "pam", target_os = "linux"))]
        let attempt = async {
            if cfg.use_pam {
                auth::pam_password_auth(&mut send, &mut recv, candidate, &cfg, &checker.login).await
            } else {
                auth::password_auth(&mut send, &mut recv, candidate, cfg.permit_empty_passwords, &checker.login).await
            }
        };
        #[cfg(not(all(feature = "pam", target_os = "linux")))]
        let attempt = auth::password_auth(&mut send, &mut recv, candidate, cfg.permit_empty_passwords, &checker.login);
        match tokio::time::timeout(left(), attempt).await {
            Ok(Ok(true)) => {
                granted = Some((crate::authkeys::Grant::default(), "password".to_string()));
                // pam_password_auth checked the account already.
                account_checked = cfg.use_pam;
            }
            Ok(Ok(false)) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                *outcome = Outcome::GraceExceeded;
                bail!("login took too long");
            }
        }
    }
    // Root with forced-commands-only: only keys with a forced command of
    // their own (as in sshd, the server's force_command does not count: it
    // is not a statement about which keys may log in as root).
    let granted = granted.filter(|(grant, _)| {
        let forced = grant.restrictions.command.is_some();
        let ok = user.as_ref().is_none_or(|u| u.uid != 0) || cfg.permit_root_login != PermitRootLogin::ForcedCommandsOnly || forced;
        if !ok {
            warn!("{addr}: root login refused: the key has no forced command (permit_root_login = forced-commands-only)");
        }
        ok
    });
    let (Some(user), Some((mut grant, how))) = (user, granted) else {
        *outcome = Outcome::AuthFailed;
        warn!("{addr}: no authorized key for {name:?} (TLS key {})", key.fingerprint());
        write_msg(&mut send, &Reply::Err("access denied".into())).await?;
        return Ok(());
    };
    // PAM's account check (pam_access, pam_nologin, expiry) for every login.
    #[cfg(all(feature = "pam", target_os = "linux"))]
    if cfg.use_pam && !account_checked {
        let (service, account, rhost) = (cfg.pam_service.clone(), user.name.clone(), addr.ip().to_canonical().to_string());
        match tokio::task::spawn_blocking(move || pam::account(&service, &account, &rhost)).await? {
            pam::Account::Ok => {}
            // As sshd: a password marked for a change (`passwd -e`) must be
            // changed first; qsh cannot change it, so it is refused.
            pam::Account::PasswordExpired => {
                *outcome = Outcome::AuthFailed;
                warn!("{addr}: {name}: the password has expired and must be changed (login with {how} refused)");
                write_msg(&mut send, &Reply::Err("your password has expired: change it first (passwd, as root or over ssh)".into())).await?;
                return Ok(());
            }
            pam::Account::Refused(reason) => {
                *outcome = Outcome::AuthFailed;
                warn!("{addr}: {name}: refused by PAM's account check: {reason}");
                write_msg(&mut send, &Reply::Err("access denied".into())).await?;
                return Ok(());
            }
        }
    }
    #[cfg(not(all(feature = "pam", target_os = "linux")))]
    let _ = account_checked;
    // Without PAM (and its pam_nologin), as sshd's do_nologin: /etc/nologin
    // keeps everyone but root out, and its text says why.
    if !cfg.use_pam && user.switches() && user.uid != 0 {
        if let Some(text) = tokio::task::spawn_blocking(|| nologin(std::path::Path::new("/etc/nologin"))).await? {
            *outcome = Outcome::AuthFailed;
            warn!("{addr}: {name}: refused because /etc/nologin exists");
            write_msg(&mut send, &Reply::Err(text)).await?;
            return Ok(());
        }
    }
    // Resuming a session that this user started after a full login: the
    // session token stands in for the second factor. Such a connection may
    // resume that one session and carry on its forwards, nothing else (see
    // StreamCtx::resume_only and `goes_on`).
    if let Some(token) = &resume {
        if !state.sessions.owns(token, user.uid) {
            write_msg(&mut send, &Reply::Err(persist::GONE.into())).await?;
            return Ok(());
        }
    }
    // Likewise for one-time codes.
    *outcome = Outcome::AuthFailed;
    let second = async {
        if resume.is_some() {
            return Ok(Ok(false));
        }
        auth::second_factor(&mut send, &mut recv, &user, cfg.totp, version, &state.totp_used).await
    };
    let code_given = match tokio::time::timeout(left(), second).await {
        Err(_) => {
            *outcome = Outcome::GraceExceeded;
            bail!("login took too long");
        }
        Ok(Err(e)) => return Err(e),
        Ok(Ok(Err(msg))) => {
            warn!("{addr}: {name}: second factor failed");
            *outcome = Outcome::AuthFailed;
            write_msg(&mut send, &Reply::Err(msg)).await?;
            return Ok(());
        }
        Ok(Ok(Ok(code))) => code,
    };
    let mut user = user;
    user.chroot = match cfg.chroot_for(&user.name, user.uid, &user.home) {
        // Nothing confines a session on Windows: refused, not ignored.
        #[cfg(windows)]
        Ok(Some(_)) => {
            warn!("{addr}: {name}: chroot_directory is not supported on Windows");
            write_msg(&mut send, &Reply::Err("access denied".into())).await?;
            return Ok(());
        }
        Ok(c) => c,
        Err(e) => {
            warn!("{addr}: {name}: {e:#}");
            write_msg(&mut send, &Reply::Err("access denied".into())).await?;
            return Ok(());
        }
    };
    info!("{addr}: {name} logged in with {how} over {}", conn.transport_name());
    *outcome = Outcome::LoggedIn;
    conn.logged_in(version);
    let welcome = if version >= 4 { Reply::Welcome { version: VERSION } } else { Reply::Ok };
    write_msg(&mut send, &welcome).await?;
    drop(startup);

    // Server-wide limits go into the grant, so they are part of what a
    // resumed session must match too.
    if let Some(c) = &cfg.force_command {
        grant.restrictions.command = Some(c.clone());
    }
    if !cfg.permit_tty {
        grant.restrictions.no_pty = true;
    }
    let user = Arc::new(user);
    let grant = Arc::new(grant);
    let sessions_limit = Arc::new(Semaphore::new(cfg.max_sessions));
    // A shared connection outlives the code it was opened with only so long.
    let code_expires = (code_given && cfg.totp_valid_for > 0).then(|| tokio::time::Instant::now() + Duration::from_secs(cfg.totp_valid_for));
    let agent = Arc::new(agent::AgentSocket::default());
    let x11 = Arc::new(x11::X11::default());
    // Lets running sessions notice a dead connection even after the client
    // finished sending on their stream.
    let (closed_tx, closed_rx) = watch::channel(false);
    while let Some((send, recv)) = conn.accept_bi().await {
        let (user, state, closed, conn, grant, agent, x11, resume, cfg, sessions_limit) = (
            user.clone(),
            state.clone(),
            closed_rx.clone(),
            conn.clone(),
            grant.clone(),
            agent.clone(),
            x11.clone(),
            resume.clone(),
            cfg.clone(),
            sessions_limit.clone(),
        );
        tokio::spawn(async move {
            let ctx = StreamCtx {
                conn: &conn,
                user: &user,
                grant: &grant,
                state: &state,
                cfg: &cfg,
                sessions: &sessions_limit,
                agent: &agent,
                x11: &x11,
                resume_only: resume.as_deref(),
                code_expires,
            };
            if let Err(e) = handle_stream(send, recv, ctx, closed).await {
                debug!("{addr}: stream error: {e:#}");
            }
        });
    }
    let _ = closed_tx.send(true);
    info!("{addr}: {name} disconnected");
    Ok(())
}

/// `SSH_CLIENT` and `SSH_CONNECTION` as sshd sets them: programs (shell
/// prompts among them) use these to tell a remote login.
fn ssh_connection(conn: &Conn, cfg: &ServerConfig, server_port: u16) -> [(String, String); 2] {
    let remote = conn.remote_addr();
    let (ip, port) = (remote.ip().to_canonical(), remote.port());
    let local = conn.local_ip().map(|l| l.to_canonical()).unwrap_or(cfg.listen.ip());
    [
        ("SSH_CLIENT".into(), format!("{ip} {port} {server_port}")),
        ("SSH_CONNECTION".into(), format!("{ip} {port} {local} {server_port}")),
    ]
}

/// Runs a transfer until it ends or the connection closes; dropping it
/// kills its helper.
async fn until_closed(mut closed: watch::Receiver<bool>, transfer: impl std::future::Future<Output = Result<()>>) -> Result<()> {
    tokio::select! {
        res = transfer => res,
        _ = closed.wait_for(|c| *c) => Ok(()),
    }
}

/// What a stream of a logged-in connection works with.
struct StreamCtx<'a> {
    conn: &'a Arc<Conn>,
    user: &'a User,
    grant: &'a Grant,
    state: &'a State,
    /// This login's settings.
    cfg: &'a ServerConfig,
    /// Session slots of this connection (max_sessions).
    sessions: &'a Arc<Semaphore>,
    agent: &'a agent::AgentSocket,
    x11: &'a x11::X11,
    /// Logged in with `Hello::Resume` (no second factor): only this session may be resumed.
    resume_only: Option<&'a [u8]>,
    /// `totp_valid_for`: when the one-time code of this connection runs out.
    code_expires: Option<tokio::time::Instant>,
}

async fn handle_stream(mut send: SendHalf, mut recv: RecvHalf, ctx: StreamCtx<'_>, closed: watch::Receiver<bool>) -> Result<()> {
    let StreamCtx { conn, user, grant, state, cfg, sessions, agent, x11, resume_only, code_expires } = ctx;
    let request = match read_msg(&mut recv).await {
        Ok(r) => r,
        // A request type from a newer client: say so instead of dropping the stream.
        Err(e) if e.is::<crate::proto::Malformed>() => {
            return write_msg(&mut send, &Reply::Err("request not supported by this qshd (update it)".into())).await;
        }
        Err(e) => return Err(e),
    };
    // What this qshd was built without is refused before anything else
    // looks at the request: its code is never reached.
    if let Some(feature) = left_out(&request) {
        return write_msg(&mut send, &Reply::Err(format!("this qshd was built without {feature}"))).await;
    }
    // Pings (ServerAlive) and the forwards of what is already running: a
    // port stays usable as long as the connection, and across a reconnect.
    // The session they belong to may have them anyway, and what the login
    // may do still limits them below.
    let goes_on = matches!(
        request,
        Request::Ping
            | Request::DirectTcp { .. }
            | Request::DirectStreamLocal { .. }
            | Request::RemoteForward { .. }
            | Request::RemoteForwardStreamLocal { .. }
            | Request::AgentForward
    );
    // Once the code has run out, nothing else new: not a session, a copy, a
    // socket or a resumed session, any of which a shared connection could
    // otherwise go on opening without a code. `MayStart` is refused too:
    // that is how a client learns it.
    if !goes_on && code_expires.is_some_and(|t| tokio::time::Instant::now() >= t) {
        return write_msg(&mut send, &Reply::Err("the one-time code of this connection has expired (totp_valid_for): connect again".into())).await;
    }
    if let Some(allowed) = resume_only {
        if !goes_on && !matches!(&request, Request::Resume { token, .. } if token == allowed) {
            return write_msg(&mut send, &Reply::Err("this connection may only resume its session".into())).await;
        }
    }
    // Compression only wraps file transfers.
    let (request, compressed) = match request {
        Request::Compressed(transfer) => (Request::from(transfer), true),
        other => (other, false),
    };
    let limits = &grant.restrictions;
    // Sessions hold one of the connection's slots while they run; so do
    // file transfers (each a helper process, like sftp in sshd) and speed tests.
    let _slot = if matches!(
        request,
        Request::Exec { .. }
            | Request::Persistent { .. }
            | Request::Resume { .. }
            | Request::Subsystem { .. }
            | Request::Tunnel { .. }
            | Request::Upload { .. }
            | Request::Download { .. }
            | Request::UploadTree { .. }
            | Request::DownloadTree { .. }
            | Request::UploadResume { .. }
            | Request::DownloadFrom { .. }
            | Request::SpeedDown { .. }
            | Request::SpeedUp { .. }
    ) {
        match sessions.clone().try_acquire_owned() {
            Ok(slot) => Some(slot),
            Err(_) => {
                let msg = format!("too many sessions on this connection (max_sessions = {})", cfg.max_sessions);
                return write_msg(&mut send, &Reply::Err(msg)).await;
            }
        }
    } else {
        None
    };
    let user_rc = cfg.permit_user_rc && !limits.no_user_rc;
    let display = x11.display();
    // A forced command (`command=`, a certificate's force-command) replaces
    // whatever the client asked to run, which is passed on like sshd does.
    // `subsystem`: `command` is the server's (a subsystem's), not the client's.
    let session = |command: Option<String>, client_env: Vec<(String, String)>, pty: Option<PtySpec>, subsystem: bool| {
        let run = limits.command.clone().or(command.clone());
        // qshd's own SFTP server only where the server chose the command.
        let sftp = run.as_deref().filter(|_| subsystem || limits.command.is_some()).and_then(exec::internal_sftp);
        // Like sshd: no ~/.ssh/rc for subsystems (internal-sftp is one) or
        // under the server's force_command, which the user must not get around.
        let user_rc = (user_rc && !subsystem && sftp.is_none() && cfg.force_command.is_none()).then(|| user.shell.to_string_lossy().into_owned());
        exec::Session {
            prelude: users::Prelude {
                // ~/.ssh/rc as allowed, else the system's /etc/ssh/sshrc. As
                // root, whether the user's exists is checked as the user (it
                // may be in a chroot); `internal-become` runs as root anyway.
                rc: (user_rc.is_some() && (user.switches() || user.home.join(".ssh/rc").is_file()))
                    || std::path::Path::new("/etc/ssh/sshrc").is_file(),
                user_rc,
                x11: display.as_ref().map(|d| (d.auth_display.clone(), d.proto.clone(), d.cookie.clone())),
                xauth: display.as_ref().map(|_| cfg.xauth_location.to_string_lossy().into_owned()),
                motd: cfg.print_motd
                    && login_shell(limits, &command, &pty)
                    && std::fs::metadata("/etc/motd").is_ok_and(|m| m.len() > 0),
                last_login: None,
                chroot: user.chroot.clone(),
                // A PAM session around the program, opened as root.
                pam: (cfg.use_pam && user.switches()).then(|| (cfg.pam_service.clone(), conn.remote_addr().ip().to_canonical().to_string(), user.name.clone())),
            },
            command: run,
            sftp,
            extra_env: cfg
                .set_env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .chain(match (&limits.command, command) {
                    (Some(_), Some(original)) => Some(("SSH_ORIGINAL_COMMAND".into(), original)),
                    _ => None,
                })
                .chain(ssh_connection(conn, cfg, state.port))
                .chain(agent.path().map(|p| ("SSH_AUTH_SOCK".to_string(), p.to_string_lossy().into_owned())))
                .chain(display.as_ref().map(|d| ("DISPLAY".to_string(), d.display.clone())))
                .collect(),
            client_env: client_env.into_iter().filter(|(k, _)| cfg.accepts_env(k)).collect(),
            pty: pty.filter(|_| !limits.no_pty),
            remote: Some(conn.remote_addr().ip().to_canonical()),
            agent: None,
        }
    };
    let files_denied = || Reply::Err("file transfer is not allowed for this key (forced command)".into());
    match request {
        Request::Exec { command, env, pty } => {
            let mut spec = session(command, env, pty, false);
            if let Some(feature) = session_left_out(&spec, false) {
                return write_msg(&mut send, &Reply::Err(format!("this qshd was built without {feature}"))).await;
            }
            spec.prelude.last_login = last_login(cfg, user, limits, &spec).await;
            exec::run(send, recv, user, spec, closed).await
        }
        Request::Persistent { command, env, pty } => {
            let mut spec = session(command, env, Some(pty), false);
            if let Some(feature) = session_left_out(&spec, false) {
                return write_msg(&mut send, &Reply::Err(format!("this qshd was built without {feature}"))).await;
            }
            spec.prelude.last_login = last_login(cfg, user, limits, &spec).await;
            // Without a terminal (no-pty) or with sessions turned off: a plain session.
            if spec.pty.is_none() || !state.sessions.enabled() || spec.sftp.is_some() {
                return exec::run(send, recv, user, spec, closed).await;
            }
            spec.agent = agent.relay();
            state.sessions.start(send, recv, user, limits, spec, closed).await
        }
        Request::Resume { token, received } => state.sessions.resume(send, recv, user, limits, &token, received, closed).await,
        Request::Hold => state.sessions.hold(send, recv, user, limits, closed).await,
        // Like sshd, through the user's shell, so restricted shells (nologin, git-shell) apply.
        Request::Subsystem { name, env } => match subsystem_command(cfg, user, &name) {
            Some(cmd) => {
                let spec = session(Some(cmd), env, None, true);
                // A forced command runs in the subsystem's place: a command like any other.
                if let Some(feature) = session_left_out(&spec, limits.command.is_none()) {
                    return write_msg(&mut send, &Reply::Err(format!("this qshd was built without {feature}"))).await;
                }
                exec::run(send, recv, user, spec, closed).await
            }
            None => write_msg(&mut send, &Reply::Err(format!("subsystem {name:?} is not available"))).await,
        },
        Request::RemoteForward { bind, port } => {
            // No address (older clients): loopback, as ssh asks for by
            // default, unless gateway_ports = "clientspecified" takes it as
            // all addresses, which a host-less permitlisten does not allow.
            let bind = match (bind.as_str(), cfg.gateway_ports) {
                ("", GatewayPorts::ClientSpecified) => "*".to_string(),
                ("", _) => "localhost".to_string(),
                _ => bind,
            };
            if !cfg.remote_forwarding() {
                return write_msg(&mut send, &Reply::Err("remote port forwarding is disabled".into())).await;
            }
            // Checked against where qshd will listen, not what was asked:
            // gateway_ports = "yes" listens on all addresses, and a
            // `permit_listen = ["localhost:N"]` must not let that through.
            let listening = match cfg.gateway_ports {
                GatewayPorts::No => "localhost",
                GatewayPorts::Yes => "*",
                GatewayPorts::ClientSpecified => bind.as_str(),
            };
            if !limits.may_listen(listening, port) {
                return write_msg(&mut send, &Reply::Err(format!("listening on port {port} is not permitted for this key"))).await;
            }
            if !cfg.may_listen(listening, port) {
                return write_msg(&mut send, &Reply::Err(format!("listening on port {port} is not permitted (permit_listen)"))).await;
            }
            remote_forward(send, recv, conn.clone(), user, cfg.gateway_ports, &bind, port).await
        }
        Request::Upload { .. }
        | Request::Download { .. }
        | Request::UploadTree { .. }
        | Request::DownloadTree { .. }
        | Request::UploadResume { .. }
        | Request::DownloadFrom { .. }
            if limits.command.is_some() =>
        {
            write_msg(&mut send, &files_denied()).await
        }
        Request::UploadTree { path, name } => until_closed(closed, files::upload_tree(send, recv, user, &path, &name, compressed)).await,
        Request::DownloadTree { path } => until_closed(closed, files::download_tree(send, user, &path, compressed)).await,
        Request::DirectTcp { host, port } => {
            if !cfg.local_forwarding() {
                return write_msg(&mut send, &Reply::Err("port forwarding is disabled".into())).await;
            }
            if !limits.may_open(&host, port) {
                return write_msg(&mut send, &Reply::Err(format!("forwarding to {host}:{port} is not permitted for this key"))).await;
            }
            if !cfg.may_open(&host, port) {
                return write_msg(&mut send, &Reply::Err(format!("forwarding to {host}:{port} is not permitted (permit_open)"))).await;
            }
            // The other loopback must pass the same checks.
            let fallback = cfg
                .loopback_fallback
                .then(|| crate::platform::other_loopback(&host))
                .flatten()
                .filter(|other| limits.may_open(other, port) && cfg.may_open(other, port));
            // Tests reach the system-mode path without root (debug builds only).
            let testing = cfg!(debug_assertions) && std::env::var_os("QSHD_TEST_FORWARD_HELPER").is_some();
            #[cfg(unix)]
            if user.switches() || testing {
                let mut tcp = connect_as(user, &host, port).await;
                if let (Err(_), Some(other)) = (&tcp, fallback) {
                    // The helper's error is text only: any failure tries the other loopback.
                    if let Ok(t) = connect_as(user, other, port).await {
                        tcp = Ok(t);
                    }
                }
                return match tcp {
                    Ok(tcp) => {
                        write_msg(&mut send, &Reply::Ok).await?;
                        crate::transport::splice(tcp, send, recv).await
                    }
                    Err(e) => write_msg(&mut send, &Reply::Err(format!("{e:#}"))).await,
                };
            }
            #[cfg(not(unix))]
            let _ = testing;
            match crate::platform::connect_tcp(&host, port, CONNECT_TIMEOUT, fallback).await {
                Ok(tcp) => {
                    let _ = tcp.set_nodelay(true);
                    write_msg(&mut send, &Reply::Ok).await?;
                    crate::transport::splice(tcp, send, recv).await
                }
                Err(e) => write_msg(&mut send, &Reply::Err(format!("connect {host}:{port}: {e}"))).await,
            }
        }
        Request::Upload { path, name, size, mode } => {
            until_closed(closed, files::upload(send, recv, user, &path, &name, (size, mode), compressed)).await
        }
        Request::Download { path } => until_closed(closed, files::download(send, user, &path, compressed)).await,
        Request::UploadResume { path, name, size, mode } => {
            until_closed(closed, files::upload_resume(send, recv, user, &path, &name, (size, mode), compressed)).await
        }
        Request::DownloadFrom { path, offset, prefix } => {
            until_closed(closed, files::download_from(send, user, &path, (offset, &prefix), compressed)).await
        }
        #[cfg(windows)]
        Request::DirectStreamLocal { .. } | Request::RemoteForwardStreamLocal { .. } | Request::X11Forward { .. } => {
            write_msg(&mut send, &Reply::Err("not available from a qshd on Windows".into())).await
        }
        Request::AgentForward => {
            if !cfg.agent_forwarding() || limits.no_agent_forwarding {
                return write_msg(&mut send, &Reply::Err("agent forwarding is not allowed".into())).await;
            }
            let kept = resume_only.and_then(|token| state.sessions.agent(token, user.uid, limits));
            agent::forward(send, recv, conn.clone(), user, agent, kept).await
        }
        #[cfg(unix)]
        Request::DirectStreamLocal { path } => {
            if !cfg.local_stream_forwarding() || limits.no_port_forwarding {
                return write_msg(&mut send, &Reply::Err("Unix socket forwarding is not allowed".into())).await;
            }
            if !limits.permit_open.is_empty() || cfg.limits_open() {
                return write_msg(&mut send, &Reply::Err("Unix socket forwarding is not allowed with permit_open/permitopen".into())).await;
            }
            if user.switches() {
                return match connect_unix_as(user, &path).await {
                    Ok(sock) => {
                        write_msg(&mut send, &Reply::Ok).await?;
                        let (r, w) = sock.into_split();
                        crate::transport::bridge(r, w, send, recv).await
                    }
                    Err(e) => write_msg(&mut send, &Reply::Err(format!("{e:#}"))).await,
                };
            }
            match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::UnixStream::connect(&path)).await {
                Ok(Ok(sock)) => {
                    write_msg(&mut send, &Reply::Ok).await?;
                    let (r, w) = sock.into_split();
                    crate::transport::bridge(r, w, send, recv).await
                }
                Ok(Err(e)) => write_msg(&mut send, &Reply::Err(format!("connect {path}: {e}"))).await,
                Err(_) => write_msg(&mut send, &Reply::Err(format!("connect {path}: timed out"))).await,
            }
        }
        #[cfg(unix)]
        Request::RemoteForwardStreamLocal { path } => {
            if !cfg.remote_stream_forwarding() || limits.no_port_forwarding {
                return write_msg(&mut send, &Reply::Err("Unix socket forwarding is not allowed".into())).await;
            }
            if !limits.permit_listen.is_empty() || cfg.limits_listen() {
                return write_msg(&mut send, &Reply::Err("Unix socket forwarding is not allowed with permit_listen/permitlisten".into())).await;
            }
            remote_forward_local(send, recv, conn.clone(), user, cfg, &path).await
        }
        #[cfg(unix)]
        Request::X11Forward { proto, cookie, screen } => {
            if !cfg.x11() || limits.no_x11_forwarding {
                return write_msg(&mut send, &Reply::Err("X11 forwarding is not allowed".into())).await;
            }
            x11::forward(send, recv, conn.clone(), cfg, x11, x11::Request { proto, cookie, screen }).await
        }
        Request::Tunnel { ethernet, unit } => {
            if !cfg.permit_tunnel.allows(ethernet) || cfg.disable_forwarding || limits.no_port_forwarding {
                return write_msg(&mut send, &Reply::Err("tunnel forwarding is not allowed".into())).await;
            }
            tunnel(send, recv, conn, user, ethernet, unit).await
        }
        Request::Ping | Request::MayStart => write_msg(&mut send, &Reply::Ok).await,
        // A key bound to one command gets nothing else, bandwidth included.
        Request::SpeedDown { .. } | Request::SpeedUp { .. } if limits.command.is_some() => {
            write_msg(&mut send, &Reply::Err("speed tests are not allowed for this key (forced command)".into())).await
        }
        Request::SpeedDown { bytes } => speed_down(send, bytes).await,
        Request::SpeedUp { bytes } => speed_up(send, recv, bytes).await,
        Request::Compressed(_) => unreachable!("unwrapped above"),
    }
}

/// A login shell on a terminal: what sshd shows the motd and last login for.
fn login_shell(limits: &crate::authkeys::Restrictions, command: &Option<String>, pty: &Option<PtySpec>) -> bool {
    limits.command.is_none() && command.is_none() && pty.is_some() && !limits.no_pty
}

/// "Last login: ..." for a login shell, when the server keeps login
/// records (system mode) and `print_last_log` is on.
async fn last_login(cfg: &ServerConfig, user: &User, limits: &crate::authkeys::Restrictions, spec: &exec::Session) -> Option<String> {
    if !cfg.print_last_log || !user.switches() || spec.command.is_some() || spec.pty.is_none() || limits.command.is_some() {
        return None;
    }
    #[cfg(not(unix))]
    return None;
    #[cfg(unix)]
    {
        let (uid, name) = (user.uid, user.name.clone());
        tokio::task::spawn_blocking(move || login_record::last_login(uid, &name)).await.ok().flatten()
    }
}

/// Where OpenSSH's sftp-server usually lives.
#[cfg(unix)]
const SFTP_SERVERS: [&str; 5] = [
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/sftp-server",
];

/// Command line for a subsystem: from the config, or a detected sftp-server.
fn subsystem_command(cfg: &ServerConfig, user: &User, name: &str) -> Option<String> {
    if let Some(cmd) = cfg.subsystems.get(name) {
        return (!cmd.trim().is_empty()).then(|| cmd.clone());
    }
    if name == "sftp" {
        // OpenSSH's sftp-server if installed, else the built-in one: in a
        // chroot (set up for it) directly, otherwise through the user's
        // shell like any other subsystem, so nologin and git-shell refuse it.
        #[cfg(unix)]
        if let Some(installed) = SFTP_SERVERS.iter().find(|p| std::path::Path::new(p).exists()) {
            return Some(installed.to_string());
        }
        if user.chroot.is_some() {
            return Some(users::INTERNAL_SFTP.to_string());
        }
        #[cfg(unix)]
        return users::shell_sftp_command().ok();
        // No login shell to go through, and qshd is this user already.
        #[cfg(windows)]
        return Some(users::INTERNAL_SFTP.to_string());
    }
    None
}

/// What to say when `path` (/etc/nologin) exists: its text (the first KiB,
/// printable), or a plain refusal when it is empty or cannot be read.
fn nologin(path: &std::path::Path) -> Option<String> {
    std::fs::symlink_metadata(path).ok()?;
    let mut text = String::new();
    let _ = std::io::Read::read_to_string(&mut std::io::Read::take(std::fs::File::open(path).ok()?, 1024), &mut text);
    let text: String = text.chars().filter(|&c| !crate::proto::hidden(c) || c == '\n').collect();
    let text = text.trim();
    Some(if text.is_empty() { "logins are disabled (/etc/nologin)".into() } else { text.to_string() })
}

/// The build feature a request needs, if this qshd was built without it.
fn left_out(request: &Request) -> Option<&'static str> {
    let needs = match request {
        Request::Compressed(_) => "compress",
        Request::Upload { .. }
        | Request::Download { .. }
        | Request::UploadTree { .. }
        | Request::DownloadTree { .. }
        | Request::UploadResume { .. }
        | Request::DownloadFrom { .. }
        | Request::Subsystem { .. } => "files",
        Request::DirectTcp { .. } | Request::DirectStreamLocal { .. } | Request::RemoteForward { .. } | Request::RemoteForwardStreamLocal { .. } => "forwarding",
        Request::AgentForward => "agent",
        Request::X11Forward { .. } => "x11",
        Request::Tunnel { .. } => "tunnel",
        Request::Persistent { .. } | Request::Resume { .. } | Request::Hold => "persist",
        Request::SpeedDown { .. } | Request::SpeedUp { .. } => "speed",
        _ => return None,
    };
    let built = match needs {
        "compress" => cfg!(feature = "compress"),
        "files" => cfg!(feature = "files"),
        "forwarding" => cfg!(feature = "forwarding"),
        "agent" => cfg!(feature = "agent"),
        "x11" => cfg!(feature = "x11"),
        "tunnel" => cfg!(feature = "tunnel"),
        "persist" => cfg!(feature = "persist"),
        _ => cfg!(feature = "speed"),
    };
    (!built).then_some(needs)
}

/// The build feature a session needs (`shell` for a login shell, `exec` for
/// a command), if this qshd was built without it. Asked of what will run: a
/// forced command is a command whatever the client asked for, a subsystem
/// too. qshd's own SFTP server runs no program and needs neither, and
/// `subsystem` (the server's own command for one, no forced command in its
/// place) belongs to `files`.
fn session_left_out(spec: &exec::Session, subsystem: bool) -> Option<&'static str> {
    session_needs(spec.command.is_some(), spec.sftp.is_some(), subsystem).filter(|f| match *f {
        "shell" => !cfg!(feature = "shell"),
        _ => !cfg!(feature = "exec"),
    })
}

fn session_needs(command: bool, internal_sftp: bool, subsystem: bool) -> Option<&'static str> {
    match (internal_sftp || subsystem, command) {
        (true, _) => None,
        (false, false) => Some("shell"),
        (false, true) => Some("exec"),
    }
}

/// Addresses to listen on for `-R`, following `gateway_ports` like sshd's
/// GatewayPorts; `None` for a host name (qshd does no DNS lookups).
fn remote_listen_addrs(gateway: GatewayPorts, bind: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let loopback = vec![SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], port))];
    let any = vec![SocketAddr::from(([0u8; 4], port)), SocketAddr::from(([0u16; 8], port))];
    Some(match gateway {
        GatewayPorts::No => loopback,
        GatewayPorts::Yes => any,
        GatewayPorts::ClientSpecified => match bind {
            "" | "*" => any,
            "localhost" => loopback,
            addr => vec![SocketAddr::new(addr.parse::<IpAddr>().ok()?, port)],
        },
    })
}

/// `-R`: listens on the server and hands each connection to the client on a
/// server-opened stream, until the client closes the request stream.
async fn remote_forward(
    mut send: SendHalf,
    mut recv: RecvHalf,
    conn: Arc<Conn>,
    user: &User,
    gateway: GatewayPorts,
    bind: &str,
    port: u16,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    // Windows has no privileged ports (and no uid 0: see users_windows.rs).
    if cfg!(unix) && port != 0 && port < 1024 && user.uid != 0 {
        return write_msg(&mut send, &Reply::Err(format!("only root may listen on port {port}"))).await;
    }
    let Some(addrs) = remote_listen_addrs(gateway, bind, port) else {
        return write_msg(&mut send, &Reply::Err(format!("cannot listen on {bind:?}: give an address, not a host name"))).await;
    };
    // Tests reach the system-mode path without root (debug builds only).
    let as_user = user.switches() || cfg!(debug_assertions) && std::env::var_os("QSHD_TEST_FORWARD_HELPER").is_some();
    let mut listeners = Vec::new();
    let mut bound_port = port;
    let mut last_err = None;
    for mut addr in addrs {
        // With port 0, the first listener picks a port and the others reuse it.
        addr.set_port(bound_port);
        let listener = if as_user { listen_tcp_as(user, addr).await } else { crate::platform::listen_tcp(addr).map_err(Into::into) };
        match listener {
            Ok(l) => {
                bound_port = l.local_addr()?.port();
                listeners.push(l);
            }
            Err(e) => last_err = Some(e),
        }
    }
    if listeners.is_empty() {
        let e = last_err.map(|e| e.to_string()).unwrap_or_default();
        return write_msg(&mut send, &Reply::Err(format!("cannot listen on port {port}: {e}"))).await;
    }
    write_msg(&mut send, &Reply::Bound { port: bound_port }).await?;
    info!("{}: {} listens on port {bound_port} (-R)", conn.remote_addr(), user.name);

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let acceptors: Vec<_> = listeners
        .into_iter()
        .map(|l| {
            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    match l.accept().await {
                        Ok(accepted) => {
                            if tx.send(accepted).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => crate::transport::accept_failed(&e).await,
                    }
                }
            })
        })
        .collect();
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            Some((tcp, origin)) = rx.recv() => {
                let conn = conn.clone();
                tokio::spawn(async move {
                    let _ = tcp.set_nodelay(true);
                    let result = async {
                        let (mut s, r) = conn.open_bi().await?;
                        write_msg(&mut s, &crate::proto::Opened::Forwarded { port: bound_port, origin: origin.to_string() }).await?;
                        crate::transport::splice(tcp, s, r).await
                    }
                    .await;
                    if let Err(e) = result {
                        debug!("-R connection from {origin}: {e:#}");
                    }
                });
            }
            // The client closed the request stream (or the connection is gone).
            _ = recv.read(&mut probe) => break,
        }
    }
    for a in acceptors {
        a.abort();
    }
    Ok(())
}

/// A TCP listener for `-R` in system mode, bound by a helper running as the
/// user (see `helpers::listen_tcp_fd`).
#[cfg(unix)]
async fn listen_tcp_as(user: &User, addr: SocketAddr) -> Result<tokio::net::TcpListener> {
    let fd = socket_from_helper(user.helper(&["internal-listen-tcp-fd", &addr.to_string()])?).await?;
    let std = std::net::TcpListener::from(fd);
    std.set_nonblocking(true)?;
    Ok(tokio::net::TcpListener::from_std(std)?)
}

#[cfg(not(unix))]
async fn listen_tcp_as(_: &User, addr: SocketAddr) -> Result<tokio::net::TcpListener> {
    Ok(crate::platform::listen_tcp(addr)?)
}

#[cfg(unix)]
/// A listening Unix socket at `path` that belongs to the user: bound by a
/// helper running as them, which hands the socket over.
async fn listen_unix_as(user: &User, cfg: &ServerConfig, path: &str) -> Result<tokio::net::UnixListener> {
    let mask = format!("{:o}", cfg.bind_mask());
    let unlink = if cfg.stream_local_bind_unlink { "yes" } else { "no" };
    // Bound by a helper also when the server is the user: it sets the umask
    // before binding (a process-wide setting), so the socket is never open
    // to others for a moment.
    let fd = socket_from_helper(user.confined_helper(&["internal-listen-unix", path, &mask, unlink])?).await?;
    let std = std::os::unix::net::UnixListener::from(fd);
    std.set_nonblocking(true)?;
    Ok(tokio::net::UnixListener::from_std(std)?)
}

#[cfg(unix)]
/// `-L` in system mode: a socket connected by a helper running as the user,
/// so uid-based firewall rules (iptables --uid-owner) apply, as in sshd
/// (compare CVE-2016-10010). The helper ends once it has handed it over.
async fn connect_as(user: &User, host: &str, port: u16) -> Result<tokio::net::TcpStream> {
    let fd = socket_from_helper(user.helper(&["internal-connect-fd", host, &port.to_string()])?).await?;
    let std = std::net::TcpStream::from(fd);
    std.set_nonblocking(true)?;
    let tcp = tokio::net::TcpStream::from_std(std)?;
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

#[cfg(unix)]
/// Like [`connect_as`], to a Unix socket (inside the user's chroot, if any).
async fn connect_unix_as(user: &User, path: &str) -> Result<tokio::net::UnixStream> {
    let fd = socket_from_helper(user.confined_helper(&["internal-connect-unix-fd", path])?).await?;
    let std = std::os::unix::net::UnixStream::from(fd);
    std.set_nonblocking(true)?;
    Ok(tokio::net::UnixStream::from_std(std)?)
}

#[cfg(unix)]
/// Runs a helper that hands a socket over its stdout (see
/// `helpers::hand_over`); its stderr is the error otherwise.
async fn socket_from_helper(mut helper: tokio::process::Command) -> Result<std::os::fd::OwnedFd> {
    use tokio::io::AsyncReadExt;
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    let mut child = helper
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(theirs)))
        .stderr(Stdio::piped())
        .spawn()?;
    // The command holds the helper's end of the pair: closed, a helper that
    // ends without a socket is noticed at once.
    drop(helper);
    // Waited for without a thread of its own, and not forever: the helper
    // runs as the user, who can stop it.
    ours.set_nonblocking(true)?;
    let ours = tokio::net::UnixStream::from_std(ours)?;
    let receive = async {
        loop {
            ours.readable().await?;
            match ours.try_io(tokio::io::Interest::READABLE, || receive_fd(&ours)) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    };
    let received = match tokio::time::timeout(CONNECT_TIMEOUT, receive).await {
        Ok(r) => r.map_err(anyhow::Error::from).and_then(|fd| fd.context("no socket from the helper")),
        Err(_) => {
            let _ = child.start_kill();
            Err(anyhow::anyhow!("the helper did not answer"))
        }
    };
    // Lets the helper go: it waits until we have the socket.
    drop(ours);
    let status = child.wait().await?;
    match received {
        Ok(fd) => Ok(fd),
        Err(e) => {
            let mut err = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = (&mut stderr).take(4096).read_to_string(&mut err).await;
            }
            let msg = err.trim().trim_start_matches("qshd: ");
            bail!("{}", if msg.is_empty() { format!("{e:#} ({status})") } else { msg.to_string() })
        }
    }
}

#[cfg(unix)]
/// Takes a descriptor sent with SCM_RIGHTS (see `helpers::hand_over`);
/// `None` if the helper sent none.
fn receive_fd(sock: impl std::os::fd::AsFd) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
    use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut byte = [0u8; 1];
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let flags = RecvFlags::CMSG_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let flags = RecvFlags::empty();
    recvmsg(sock, &mut [std::io::IoSliceMut::new(&mut byte)], &mut control, flags)?;
    for msg in control.drain() {
        if let RecvAncillaryMessage::ScmRights(mut fds) = msg {
            if let Some(fd) = fds.next() {
                // Where the flag above does not exist: not for programs qshd starts.
                nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
                return Ok(Some(fd));
            }
        }
    }
    Ok(None)
}

#[cfg(unix)]
/// `-R` from a Unix socket: like [`remote_forward`], on a socket file of the user's.
async fn remote_forward_local(mut send: SendHalf, mut recv: RecvHalf, conn: Arc<Conn>, user: &User, cfg: &ServerConfig, path: &str) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let listener = match listen_unix_as(user, cfg, path).await {
        Ok(l) => l,
        Err(e) => return write_msg(&mut send, &Reply::Err(format!("{e:#}"))).await,
    };
    write_msg(&mut send, &Reply::Ok).await?;
    info!("{}: {} listens on {path:?} (-R)", conn.remote_addr(), user.name);
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (sock, _) = match accepted {
                    Ok(a) => a,
                    Err(e) => {
                        crate::transport::accept_failed(&e).await;
                        continue;
                    }
                };
                let (conn, path) = (conn.clone(), path.to_string());
                tokio::spawn(async move {
                    let result = async {
                        let (mut s, r) = conn.open_bi().await?;
                        write_msg(&mut s, &crate::proto::Opened::ForwardedStreamLocal { path }).await?;
                        let (sr, sw) = sock.into_split();
                        crate::transport::bridge(sr, sw, s, r).await
                    }
                    .await;
                    if let Err(e) = result {
                        debug!("-R socket connection: {e:#}");
                    }
                });
            }
            _ = recv.read(&mut probe) => break,
        }
    }
    Ok(())
}

/// `-w`: a tunnel device here, its packets to and from the client.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn tunnel(mut send: SendHalf, recv: RecvHalf, conn: &Arc<Conn>, user: &User, ethernet: bool, unit: Option<u32>) -> Result<()> {
    // Like sshd: a user other than root opens the device with their own
    // rights (a helper hands it over), so the kernel lets them use only a
    // device made for them, and not create one with qshd's.
    let opened = if user.uid == 0 {
        crate::tunnel::open(ethernet, unit).map(|(d, name)| (crate::tunnel::Device::Own(d), name))
    } else {
        tunnel_as_user(user, ethernet, unit).await
    };
    let (dev, name) = match opened {
        Ok(d) => d,
        Err(e) => return write_msg(&mut send, &Reply::Err(format!("{e:#}"))).await,
    };
    write_msg(&mut send, &Reply::Ok).await?;
    info!("{}: {} opened tunnel device {name}", conn.remote_addr(), user.name);
    let result = crate::tunnel::relay(dev, send, recv).await;
    info!("{}: tunnel device {name} closed", conn.remote_addr());
    result
}

#[cfg(target_os = "linux")]
async fn tunnel_as_user(user: &User, ethernet: bool, unit: Option<u32>) -> Result<(crate::tunnel::Device, String)> {
    // A new device needs rights a user does not have: only a named one can be theirs.
    let Some(unit) = unit else { bail!("name the tunnel device (-w any:N): a user other than root can only use one made for them") };
    let fd = socket_from_helper(user.helper(&["internal-tun-fd", if ethernet { "tap" } else { "tun" }, &unit.to_string()])?).await?;
    Ok((crate::tunnel::Device::handed(fd)?, crate::tunnel::device_name(ethernet, unit)))
}

#[cfg(target_os = "macos")]
async fn tunnel_as_user(_user: &User, _ethernet: bool, _unit: Option<u32>) -> Result<(crate::tunnel::Device, String)> {
    bail!("only root may use tunnel devices on this system")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn tunnel(mut send: SendHalf, _recv: RecvHalf, _conn: &Arc<Conn>, _user: &User, _ethernet: bool, _unit: Option<u32>) -> Result<()> {
    write_msg(&mut send, &Reply::Err("tunnel devices are not supported on this system".into())).await
}

/// Largest speed test transfer the server agrees to.
const SPEED_TEST_MAX: u64 = 4 << 30;

async fn speed_down(mut send: SendHalf, bytes: u64) -> Result<()> {
    write_msg(&mut send, &Reply::Ok).await?;
    let chunk = vec![0u8; 64 * 1024];
    let mut left = bytes.min(SPEED_TEST_MAX);
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        // The client may stop reading early; that ends the test.
        if send.write_all(&chunk[..n]).await.is_err() {
            return Ok(());
        }
        left -= n as u64;
    }
    send.shutdown().await?;
    Ok(())
}

async fn speed_up(mut send: SendHalf, mut recv: RecvHalf, bytes: u64) -> Result<()> {
    use tokio::io::AsyncReadExt;
    write_msg(&mut send, &Reply::Ok).await?;
    let received = tokio::io::copy(&mut (&mut recv).take(bytes.min(SPEED_TEST_MAX)), &mut tokio::io::sink()).await?;
    write_msg(&mut send, &Reply::File { size: received, mode: 0 }).await?;
    send.shutdown().await?;
    Ok(())
}

/// Runs a helper as the user and returns its trimmed stdout, or its stderr
/// as the error (at most 4 KiB of each).
async fn run_helper(user: &User, args: &[&str]) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut child = user.helper(args)?.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (mut stdout, mut stderr) = (child.stdout.take().expect("piped").take(4096), child.stderr.take().expect("piped").take(4096));
    let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
    a?;
    b?;
    if out.len() == 4096 || err.len() == 4096 {
        let _ = child.start_kill();
    }
    let status = child.wait().await?;
    if status.success() {
        Ok(String::from_utf8_lossy(&out).trim().to_string())
    } else {
        bail!("{}", String::from_utf8_lossy(&err).trim())
    }
}

async fn pair(conn: &Arc<Conn>, state: &State, user: &User, mut send: SendHalf, mut recv: RecvHalf) -> Result<bool> {
    let addr = conn.remote_addr();
    let key = conn.peer_key();
    let started = tokio::time::Instant::now();
    let code = match run_helper(user, &["internal-pair-take"]).await {
        Ok(code) => code,
        Err(e) => {
            warn!("{addr}: pairing for {} refused: {e:#}", user.name);
            refuse_pairing(&mut send, started).await?;
            return Ok(false);
        }
    };
    write_msg(&mut send, &Reply::Ok).await?;
    let verified = match crate::pair::server_verify(
        &mut send,
        &mut recv,
        &code,
        &conn.exporter(),
        key,
        state.host_key,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("{addr}: pairing for {} failed: {e:#}", user.name);
            return Ok(false);
        }
    };
    let line = key.to_openssh("qsh-paired");
    if let Err(e) = run_helper(user, &["internal-add-key", &line]).await {
        write_msg(&mut send, &Reply::Err(format!("cannot store key: {e:#}"))).await?;
        return Ok(false);
    }
    verified.confirm(&mut send).await?;
    send.shutdown().await?;
    info!("{addr}: paired key {} for {}", key.fingerprint(), user.name);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_forward_binds_loopback_by_default() {
        let addrs = remote_listen_addrs(GatewayPorts::No, "0.0.0.0", 8080).unwrap();
        assert!(addrs.iter().all(|a| a.ip().is_loopback()), "client asked for all, got {addrs:?}");
        assert!(remote_listen_addrs(GatewayPorts::Yes, "", 1).unwrap().iter().all(|a| a.ip().is_unspecified()));
        let cs = remote_listen_addrs(GatewayPorts::ClientSpecified, "192.0.2.5", 1);
        assert_eq!(cs, Some(vec!["192.0.2.5:1".parse().unwrap()]));
        assert!(remote_listen_addrs(GatewayPorts::ClientSpecified, "localhost", 1).unwrap().iter().all(|a| a.ip().is_loopback()));
        assert_eq!(remote_listen_addrs(GatewayPorts::ClientSpecified, "db.example", 1), None);
        // Without clientspecified the name does not matter: loopback.
        assert!(remote_listen_addrs(GatewayPorts::No, "db.example", 1).is_some());
    }

    #[test]
    fn sessions_need_shell_or_exec() {
        assert_eq!(session_needs(false, false, false), Some("shell"));
        assert_eq!(session_needs(true, false, false), Some("exec"));
        assert_eq!(session_needs(true, true, false), None, "internal-sftp runs no program");
        assert_eq!(session_needs(true, false, true), None, "the server's own subsystem command: files");
    }

    #[test]
    fn nologin_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nologin");
        assert_eq!(nologin(&path), None);
        std::fs::write(&path, "down for maintenance\x1b[2J\n").unwrap();
        assert_eq!(nologin(&path).as_deref(), Some("down for maintenance[2J"));
        std::fs::write(&path, "").unwrap();
        assert_eq!(nologin(&path).as_deref(), Some("logins are disabled (/etc/nologin)"));
    }

    #[test]
    fn startup_limits() {
        let s = Startups::new(3, 2);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let a1 = s.try_acquire(a).unwrap();
        let _a2 = s.try_acquire(a).unwrap();
        assert!(s.try_acquire(a).is_none(), "per-IP limit");
        // IPv4-mapped IPv6 counts as the same address.
        assert!(s.try_acquire("::ffff:192.0.2.1".parse().unwrap()).is_none());
        let _b1 = s.try_acquire(b).unwrap();
        assert!(s.try_acquire(b).is_none(), "total limit");
        drop(a1);
        assert!(s.try_acquire(b).is_some(), "slot released on drop");

        // IPv6 counts per /64; half the slots in use asks for a Retry.
        let s = Startups::new(10, 4);
        let c: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!s.busy(c));
        let _c1 = s.try_acquire(c).unwrap();
        let _c2 = s.try_acquire("2001:db8::2".parse().unwrap()).unwrap();
        assert!(s.busy("2001:db8::3".parse().unwrap()), "same /64");
        assert!(!s.busy("2001:db8:1::1".parse().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn session_scope_needs_a_restart() {
        let old = ServerConfig::default();
        let new = ServerConfig { session_scope: !old.session_scope, ..ServerConfig::default() };
        assert_eq!(restart_needed(&old, &new), ["session_scope"]);
    }

    /// The same checks for `qshd -t`, the start and a reload.
    #[test]
    fn problems_include_passwords_and_config_warnings() {
        let cfg: ServerConfig = toml::from_str("[[match]]\nuser = \"!root\"\npassword_authentication = true\n").unwrap();
        let problems = config_problems(&cfg, None);
        assert!(problems.iter().any(|p| p.contains("matches no one")), "{problems:?}");
        #[cfg(unix)]
        let can_read_shadow = cfg!(target_os = "linux") && nix::unistd::geteuid().is_root();
        #[cfg(not(unix))]
        let can_read_shadow = false;
        assert_eq!(problems.iter().any(|p| p.contains("no password will match")), !can_read_shadow, "{problems:?}");
    }

    #[test]
    fn check_login_refuses_bad_names() {
        let (_, verdict) = check_login(&ServerConfig::default(), "-oops", "192.0.2.1".parse().unwrap());
        assert_eq!(verdict.as_deref(), Some("invalid user name"));
    }

    /// An IPv4-mapped address matches IPv4 blocks, as in a real login.
    #[cfg(unix)]
    #[test]
    fn check_login_canonical_address() {
        let me = nix::unistd::User::from_uid(nix::unistd::getuid()).unwrap().unwrap().name;
        let cfg: ServerConfig = toml::from_str("[[match]]\naddress = \"192.0.2.0/24\"\nmax_sessions = 2\n").unwrap();
        let (login, _) = check_login(&cfg, &me, "::ffff:192.0.2.1".parse().unwrap());
        assert_eq!(login.max_sessions, 2);
    }
}
