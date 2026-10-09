//! The `qshd` daemon.

mod agent;
mod auth;
mod exec;
mod files;
pub mod helpers;
mod login_record;
pub mod keys_command;
mod persist;
pub mod revoked;
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
use crate::proto::{read_msg, valid_user_name, write_msg, Hello, PtySpec, Reply, Request, MIN_VERSION, VERSION};
use crate::transport::{Conn, Listener, RecvHalf, SendHalf};
use users::User;

/// Time a connected client has to open its first stream and say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
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
    totp_used: auth::UsedCodes,
    sessions: Arc<persist::Sessions>,
}

impl State {
    fn cfg(&self) -> Arc<ServerConfig> {
        self.cfg.read().unwrap().clone()
    }
}

/// Reads the config again (for SIGHUP).
pub type Reload = Box<dyn Fn() -> Result<ServerConfig> + Send + Sync>;

/// Settings that only take effect when qshd starts.
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

    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<Startup> {
        let ip = ip.to_canonical();
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

/// The groups of user `name` (none if there is no such user), for `qshd -T -C`.
pub fn user_group_names(name: &str) -> Vec<String> {
    User::lookup(name).map(|u| u.group_names()).unwrap_or_default()
}

/// Why this (existing) user may not log in: allow/deny lists, root login.
fn refused(cfg: &ServerConfig, who: &crate::config::Login, user: &User) -> Option<String> {
    if user.uid == 0 && cfg.permit_root_login == PermitRootLogin::No {
        return Some("root login is not permitted (permit_root_login)".into());
    }
    cfg.login_refused(who)
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
    use ssh_key::certificate::CertType;
    let path = cfg.host_certificate.as_ref()?;
    let loaded = std::fs::read_to_string(path)
        .context("cannot read")
        .and_then(|t| ssh_key::Certificate::from_openssh(t.trim()).context("cannot parse"));
    let cert = match loaded {
        Ok(c) => c,
        Err(e) => {
            warn!("host certificate {}: {e:#}", path.display());
            return None;
        }
    };
    let own = ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(host.public().0));
    if cert.cert_type() != CertType::Host || cert.public_key() != &own {
        warn!("host certificate {} is not a host certificate for this host key; not used", path.display());
        return None;
    }
    info!("host certificate {:?} for {:?}", cert.key_id(), cert.valid_principals());
    cert.to_bytes().ok()
}

/// Binds the configured address on UDP and TCP. If the default dual-stack
/// address is unavailable (IPv6 disabled), falls back to IPv4.
pub async fn bind(cfg: &ServerConfig, host: &Identity) -> Result<Listener> {
    let tls = crate::tls::server_config(host, host_certificate(cfg, host))?;
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
    let limit = Arc::new(Semaphore::new(cfg.max_connections));
    let startups = Startups::new(cfg.max_startups, cfg.max_startups_per_ip);
    let sessions = Arc::new(persist::Sessions::new(Duration::from_secs(cfg.session_timeout)));
    let state = Arc::new(State { cfg: std::sync::RwLock::new(Arc::new(cfg)), host_key: host.public(), totp_used: Default::default(), sessions });
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
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            warn!("connection limit reached, dropping {addr}");
            incoming.reject();
            continue;
        };
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
                    if let Err(e) = handle_conn(&conn, state, startup).await {
                        debug!("{addr}: {e:#}");
                    }
                    // Dropping a QUIC connection discards unsent data, so let the
                    // client read the final reply (e.g. "access denied") and hang up first.
                    let _ = tokio::time::timeout(LINGER, conn.closed()).await;
                }
                Err(e) => debug!("{addr}: handshake failed: {e:#}"),
            }
            drop(permit);
        });
    }
}

async fn handle_conn(conn: &Arc<Conn>, state: Arc<State>, startup: Startup) -> Result<()> {
    let addr = conn.remote_addr();
    let key = conn.peer_key();
    let (mut send, mut recv, hello) = tokio::time::timeout(HELLO_TIMEOUT, async {
        let (send, mut recv) = conn.accept_bi().await.context("closed before hello")?;
        let hello: Hello = read_msg(&mut recv).await?;
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
    let looked_up = if valid_user_name(&name) {
        let (n, groups) = (name.clone(), global.needs_groups());
        tokio::task::spawn_blocking(move || User::lookup(&n).map(|u| {
            let names = if groups { u.group_names() } else { Vec::new() };
            (u, names)
        }))
        .await?
    } else {
        Err(anyhow::anyhow!("invalid user name"))
    };
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
    let grace = match cfg.login_grace_time {
        0 => Duration::MAX,
        s => Duration::from_secs(s),
    };
    if pairing {
        match user {
            Some(user) => return pair(conn, &state, &user, send, recv).await,
            // Same answer, after the same time, as for an existing user
            // without a code, so names cannot be probed.
            None => return refuse_pairing(&mut send, tokio::time::Instant::now()).await,
        }
    }

    // An unknown user goes through the same steps with no keys, so names cannot be probed.
    let (entries, cas, revoked) = {
        let (cfg, user) = (cfg.clone(), user.clone());
        tokio::task::spawn_blocking(move || {
            let entries = user.as_ref().map(|u| auth::authorized_entries(&cfg, u)).unwrap_or_default();
            (entries, auth::trusted_cas(&cfg), revoked::Revocation::load(cfg.revoked_keys.as_deref()))
        })
        .await?
    };
    let command = user.as_ref().and_then(|u| keys_command::KeysCommand::new(&cfg, u));
    let checker = auth::Checker {
        entries: &entries,
        cas: &cas,
        revoked: &revoked,
        command: command.as_ref(),
        login: crate::authkeys::Login { user: &name, ip: addr.ip().to_canonical(), now: auth::now() },
        exporter: conn.exporter(),
    };
    let mut granted = checker.check(&auth::tls_key(key)).await.ok().map(|g| (g, format!("ED25519 {}", key.fingerprint())));
    if granted.is_none() && version >= 4 {
        let attempt = auth::key_auth(&mut send, &mut recv, &checker, cfg.max_auth_tries);
        granted = tokio::time::timeout(grace, attempt).await.context("login took too long")??;
    }
    // Root with forced-commands-only: only keys with a forced command.
    let granted = granted.filter(|(grant, _)| {
        let forced = grant.restrictions.command.is_some() || cfg.force_command.is_some();
        let ok = user.as_ref().is_none_or(|u| u.uid != 0) || cfg.permit_root_login != PermitRootLogin::ForcedCommandsOnly || forced;
        if !ok {
            warn!("{addr}: root login refused: the key has no forced command (permit_root_login = forced-commands-only)");
        }
        ok
    });
    let (Some(user), Some((mut grant, how))) = (user, granted) else {
        warn!("{addr}: no authorized key for {name} (TLS key {})", key.fingerprint());
        write_msg(&mut send, &Reply::Err("access denied".into())).await?;
        return Ok(());
    };
    // Resuming a session that this user started after a full login: the
    // session token stands in for the second factor, but such a connection
    // can do nothing except resume that one session (see StreamCtx::resume_only).
    if let Some(token) = &resume {
        if !state.sessions.owns(token, user.uid) {
            write_msg(&mut send, &Reply::Err(persist::GONE.into())).await?;
            return Ok(());
        }
    }
    let second = async {
        if resume.is_some() {
            return Ok(Ok(()));
        }
        auth::second_factor(&mut send, &mut recv, &user, cfg.totp, version, &state.totp_used).await
    };
    if let Err(msg) = tokio::time::timeout(grace, second).await.context("login took too long")?? {
        warn!("{addr}: {name}: second factor failed");
        write_msg(&mut send, &Reply::Err(msg)).await?;
        return Ok(());
    }
    info!("{addr}: {name} logged in with {how} over {}", conn.transport_name());
    conn.logged_in();
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
    let agent = Arc::new(agent::AgentSocket::default());
    // Lets running sessions notice a dead connection even after the client
    // finished sending on their stream.
    let (closed_tx, closed_rx) = watch::channel(false);
    while let Some((send, recv)) = conn.accept_bi().await {
        let (user, state, closed, conn, grant, agent, resume, cfg, sessions_limit) = (
            user.clone(),
            state.clone(),
            closed_rx.clone(),
            conn.clone(),
            grant.clone(),
            agent.clone(),
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
                resume_only: resume.as_deref(),
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
    /// Logged in with `Hello::Resume` (no second factor): only this session may be resumed.
    resume_only: Option<&'a [u8]>,
}

async fn handle_stream(mut send: SendHalf, mut recv: RecvHalf, ctx: StreamCtx<'_>, closed: watch::Receiver<bool>) -> Result<()> {
    let StreamCtx { conn, user, grant, state, cfg, sessions, agent, resume_only } = ctx;
    let request = match read_msg(&mut recv).await {
        Ok(r) => r,
        // A request type from a newer client: say so instead of dropping the stream.
        Err(e) if e.is::<crate::proto::Malformed>() => {
            return write_msg(&mut send, &Reply::Err("request not supported by this qshd (update it)".into())).await;
        }
        Err(e) => return Err(e),
    };
    if let Some(allowed) = resume_only {
        if !matches!(&request, Request::Resume { token, .. } if token == allowed) {
            return write_msg(&mut send, &Reply::Err("this connection may only resume its session".into())).await;
        }
    }
    // Compression only wraps file transfers.
    let (request, compressed) = match request {
        Request::Compressed(transfer) => (Request::from(transfer), true),
        other => (other, false),
    };
    let limits = &grant.restrictions;
    // Sessions hold one of the connection's slots while they run.
    let _slot = if matches!(request, Request::Exec { .. } | Request::Persistent { .. } | Request::Resume { .. } | Request::Subsystem { .. }) {
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
    // A forced command (`command=`, a certificate's force-command) replaces
    // whatever the client asked to run, which is passed on like sshd does.
    let session = |command: Option<String>, client_env: Vec<(String, String)>, pty: Option<PtySpec>| exec::Session {
        prelude: users::Prelude {
            rc: cfg.permit_user_rc && (user.home.join(".ssh/rc").is_file() || std::path::Path::new("/etc/ssh/sshrc").is_file()),
            motd: cfg.print_motd
                && login_shell(limits, &command, &pty)
                && std::fs::metadata("/etc/motd").is_ok_and(|m| m.len() > 0),
            last_login: None,
        },
        command: limits.command.clone().or(command.clone()),
        extra_env: cfg
            .set_env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .chain(match (&limits.command, command) {
                (Some(_), Some(original)) => Some(("SSH_ORIGINAL_COMMAND".into(), original)),
                _ => None,
            })
            .chain(agent.path().map(|p| ("SSH_AUTH_SOCK".to_string(), p.to_string_lossy().into_owned())))
            .collect(),
        client_env: client_env.into_iter().filter(|(k, _)| cfg.accepts_env(k)).collect(),
        pty: pty.filter(|_| !limits.no_pty),
        remote: Some(conn.remote_addr().ip().to_canonical()),
    };
    let files_denied = || Reply::Err("file transfer is not allowed for this key (forced command)".into());
    match request {
        Request::Exec { command, env, pty } => {
            let mut spec = session(command, env, pty);
            spec.prelude.last_login = last_login(cfg, user, limits, &spec).await;
            exec::run(send, recv, user, spec, closed).await
        }
        Request::Persistent { command, env, pty } => {
            let mut spec = session(command, env, Some(pty));
            spec.prelude.last_login = last_login(cfg, user, limits, &spec).await;
            // Without a terminal (no-pty) or with sessions turned off: a plain session.
            if spec.pty.is_none() || !state.sessions.enabled() {
                return exec::run(send, recv, user, spec, closed).await;
            }
            state.sessions.start(send, recv, user, limits, spec, closed).await
        }
        Request::Resume { token, received } => state.sessions.resume(send, recv, user, limits, &token, received, closed).await,
        // Like sshd, through the user's shell, so restricted shells (nologin, git-shell) apply.
        Request::Subsystem { name, env } => match subsystem_command(cfg, &name) {
            Some(cmd) => exec::run(send, recv, user, session(Some(cmd), env, None), closed).await,
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
            if !limits.may_listen(&bind, port) {
                return write_msg(&mut send, &Reply::Err(format!("listening on port {port} is not permitted for this key"))).await;
            }
            if !cfg.may_listen(&bind, port) {
                return write_msg(&mut send, &Reply::Err(format!("listening on port {port} is not permitted (permit_listen)"))).await;
            }
            remote_forward(send, recv, conn.clone(), user, cfg.gateway_ports, &bind, port).await
        }
        Request::Upload { .. } | Request::Download { .. } | Request::UploadTree { .. } | Request::DownloadTree { .. }
            if limits.command.is_some() =>
        {
            write_msg(&mut send, &files_denied()).await
        }
        Request::UploadTree { path, name } => files::upload_tree(send, recv, user, &path, &name, compressed).await,
        Request::DownloadTree { path } => files::download_tree(send, user, &path, compressed).await,
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
            if user.switches() {
                // Connect as the user, not as root, so uid-based firewall rules
                // (iptables --uid-owner) apply (compare CVE-2016-10010).
                return forward_as_user(send, recv, user, &host, port).await;
            }
            let connect = tokio::net::TcpStream::connect((host.as_str(), port));
            match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
                Ok(Ok(tcp)) => {
                    let _ = tcp.set_nodelay(true);
                    write_msg(&mut send, &Reply::Ok).await?;
                    crate::transport::splice(tcp, send, recv).await
                }
                Ok(Err(e)) => write_msg(&mut send, &Reply::Err(format!("connect {host}:{port}: {e}"))).await,
                Err(_) => write_msg(&mut send, &Reply::Err(format!("connect {host}:{port}: timed out"))).await,
            }
        }
        Request::Upload { path, name, size, mode } => {
            files::upload(send, recv, user, &path, &name, (size, mode), compressed).await
        }
        Request::Download { path } => files::download(send, user, &path, compressed).await,
        Request::AgentForward => {
            if !cfg.agent_forwarding() || limits.no_agent_forwarding {
                return write_msg(&mut send, &Reply::Err("agent forwarding is not allowed".into())).await;
            }
            agent::forward(send, recv, conn.clone(), user, agent).await
        }
        Request::Ping => write_msg(&mut send, &Reply::Ok).await,
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
    let (uid, name) = (user.uid, user.name.clone());
    tokio::task::spawn_blocking(move || login_record::last_login(uid, &name)).await.ok().flatten()
}

/// Where OpenSSH's sftp-server usually lives.
const SFTP_SERVERS: [&str; 5] = [
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/sftp-server",
];

/// Command line for a subsystem: from the config, or a detected sftp-server.
fn subsystem_command(cfg: &ServerConfig, name: &str) -> Option<String> {
    if let Some(cmd) = cfg.subsystems.get(name) {
        return (!cmd.trim().is_empty()).then(|| cmd.clone());
    }
    if name == "sftp" {
        return SFTP_SERVERS.iter().find(|p| std::path::Path::new(p).exists()).map(|p| p.to_string());
    }
    None
}

/// Addresses to listen on for `-R`, following `gateway_ports` like sshd's GatewayPorts.
fn remote_listen_addrs(gateway: GatewayPorts, bind: &str, port: u16) -> Vec<SocketAddr> {
    let loopback = vec![SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], port))];
    let any = vec![SocketAddr::from(([0u8; 4], port)), SocketAddr::from(([0u16; 8], port))];
    match gateway {
        GatewayPorts::No => loopback,
        GatewayPorts::Yes => any,
        GatewayPorts::ClientSpecified => match bind {
            "" | "*" => any,
            "localhost" => loopback,
            addr => addr.parse::<IpAddr>().map(|ip| vec![SocketAddr::new(ip, port)]).unwrap_or(loopback),
        },
    }
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
    if port != 0 && port < 1024 && user.uid != 0 {
        return write_msg(&mut send, &Reply::Err(format!("only root may listen on port {port}"))).await;
    }
    let mut listeners = Vec::new();
    let mut bound_port = port;
    let mut last_err = None;
    for mut addr in remote_listen_addrs(gateway, bind, port) {
        // With port 0, the first listener picks a port and the others reuse it.
        addr.set_port(bound_port);
        match tokio::net::TcpListener::bind(addr).await {
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
                while let Ok(accepted) = l.accept().await {
                    if tx.send(accepted).await.is_err() {
                        break;
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

/// Port forwarding through `qshd internal-connect`, which runs as the user.
async fn forward_as_user(mut send: SendHalf, recv: RecvHalf, user: &User, host: &str, port: u16) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    let mut child = user
        .helper(&["internal-connect", host, &port.to_string()])?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // The helper prints "ok" once connected; the rest of stdout is the socket's data.
    let mut out = BufReader::new(child.stdout.take().expect("piped"));
    let mut status = String::new();
    out.read_line(&mut status).await?;
    if status.trim() != "ok" {
        let mut err = String::new();
        if let Some(e) = child.stderr.take() {
            let _ = e.take(4096).read_to_string(&mut err).await;
        }
        return write_msg(&mut send, &Reply::Err(err.trim().to_string())).await;
    }
    write_msg(&mut send, &Reply::Ok).await?;
    let stdin = child.stdin.take().expect("piped");
    let result = crate::transport::bridge(out, stdin, send, recv).await;
    let _ = child.kill().await;
    result
}

/// Runs a helper as the user and returns its trimmed stdout, or its stderr as the error.
async fn run_helper(user: &User, args: &[&str]) -> Result<String> {
    let out = user
        .helper(args)?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim())
    }
}

async fn pair(conn: &Arc<Conn>, state: &State, user: &User, mut send: SendHalf, mut recv: RecvHalf) -> Result<()> {
    let addr = conn.remote_addr();
    let key = conn.peer_key();
    let started = tokio::time::Instant::now();
    let code = match run_helper(user, &["internal-pair-take"]).await {
        Ok(code) => code,
        Err(e) => {
            warn!("{addr}: pairing for {} refused: {e:#}", user.name);
            return refuse_pairing(&mut send, started).await;
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
            return Ok(());
        }
    };
    let line = key.to_openssh("qsh-paired");
    if let Err(e) = run_helper(user, &["internal-add-key", &line]).await {
        write_msg(&mut send, &Reply::Err(format!("cannot store key: {e:#}"))).await?;
        return Ok(());
    }
    verified.confirm(&mut send).await?;
    send.shutdown().await?;
    info!("{addr}: paired key {} for {}", key.fingerprint(), user.name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_forward_binds_loopback_by_default() {
        let addrs = remote_listen_addrs(GatewayPorts::No, "0.0.0.0", 8080);
        assert!(addrs.iter().all(|a| a.ip().is_loopback()), "client asked for all, got {addrs:?}");
        assert!(remote_listen_addrs(GatewayPorts::Yes, "", 1).iter().all(|a| a.ip().is_unspecified()));
        let cs = remote_listen_addrs(GatewayPorts::ClientSpecified, "192.0.2.5", 1);
        assert_eq!(cs, vec!["192.0.2.5:1".parse().unwrap()]);
        assert!(remote_listen_addrs(GatewayPorts::ClientSpecified, "localhost", 1).iter().all(|a| a.ip().is_loopback()));
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
    }
}
