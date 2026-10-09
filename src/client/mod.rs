//! The `qsh` client.

pub mod cli;
pub mod auth;
pub mod config;
pub mod control;
pub mod copy;
pub mod doctor;
pub mod forward;
pub mod groups;
pub mod keys_vt;
pub mod keystroke;
pub mod multi;
pub mod predict;
mod known_hosts;
pub mod session;
mod socks;
pub mod speed;
pub mod saved;
pub mod tui;
pub mod ui_state;

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use crate::keys::{home_dir, qsh_dir, Identity, PublicKey};
use crate::proto::{expect_ok, write_msg, Hello, VERSION};
use crate::transport::{self, Conn, Mode};
use known_hosts::{host_id, KnownHosts};

/// How to treat a host key that is not in known_hosts (`StrictHostKeyChecking`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostKeyPolicy {
    /// Ask on the terminal (the default).
    #[default]
    Ask,
    /// Trust and remember new keys (`accept-new`; `no` is treated the same:
    /// a changed key is always refused).
    AcceptNew,
    /// Refuse unknown keys (`yes`).
    Strict,
}

/// `[user@]host[:port]`; IPv6 literals go in brackets: `user@[::1]:4422`.
/// `host` may be an alias from `~/.config/qsh/config` or `~/.ssh/config`.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub user: String,
    /// Real host name (after `HostName` from the config).
    pub host: String,
    pub port: u16,
    /// `--full` only: more ports where qshd may answer, tried in parallel with `port`.
    pub alt_ports: Vec<u16>,
    /// `IdentityFile`s from the config, in order.
    pub identity_files: Vec<PathBuf>,
    /// The destination for handing over to `ssh`: `[user@]alias`, as typed.
    pub ssh_dest: String,
    /// `-o` options that make ssh reach the same host (see `HostConfig::for_ssh`).
    pub ssh_options: Vec<String>,
    /// Port given on the command line (`-p` or `:port`), if any.
    pub cli_port: Option<u16>,
    /// Forwards from the config, as `-L`/`-R`/`-D` specs.
    pub local_forwards: Vec<String>,
    pub remote_forwards: Vec<String>,
    pub dynamic_forwards: Vec<String>,
    /// Jump hosts (`ProxyJump` in qsh's config or `-o`, or `-J`).
    pub proxy_jump: Option<String>,
    /// `RequestTTY` from the config.
    pub request_tty: Option<String>,
    /// ssh's config routes this host through ProxyJump/ProxyCommand.
    pub needs_proxy: bool,
    /// Keystroke timing obfuscation interval (`None` = off).
    pub keystroke_interval: Option<std::time::Duration>,
    /// Never prompt (`BatchMode`).
    pub batch_mode: bool,
    pub host_key_policy: HostKeyPolicy,
    /// `UserKnownHostsFile` (qsh config or `-o` only).
    pub known_hosts_file: Option<PathBuf>,
    pub clear_all_forwardings: bool,
    /// Session escape character; `None` disables escapes (`EscapeChar none`).
    pub escape_char: Option<u8>,
    pub family: transport::Family,
    /// Where connections leave from (`-b`/`BindAddress`, `-B`/`BindInterface`).
    pub bind: transport::Bind,
    /// `LogLevel QUIET` or `-q`: no informational messages.
    pub quiet: bool,
    pub forward_agent: bool,
    /// `IdentitiesOnly`: offer only agent keys that match an identity file.
    pub identities_only: bool,
    /// `IdentityAgent`: `None` = `SSH_AUTH_SOCK`; `Some(None)` = no agent.
    pub identity_agent: Option<Option<PathBuf>>,
    /// `CertificateFile`s from the config.
    pub certificate_files: Vec<PathBuf>,
    /// Keep terminal sessions across lost connections (`PersistSession`, default yes).
    pub persist_session: bool,
    /// `ServerAliveInterval` and `ServerAliveCountMax`: ping the server when
    /// it has been quiet this long, give up after this many unanswered pings.
    pub server_alive: Option<(std::time::Duration, u32)>,
    /// Connection sharing (`ControlMaster` and friends).
    pub sharing: control::Sharing,
    /// `PredictiveEcho`: local echo prediction in terminal sessions.
    pub predict: predict::Mode,
    /// `Compression`: compress file copies.
    pub compression: bool,
    /// The config sources, reused for jump hosts.
    pub sources: config::Sources,
    /// The host as given, before `HostName` (`%n`).
    pub alias: String,
    /// `ProxyCommand` (qsh's config or `-o`): the connection runs over its
    /// stdin and stdout.
    pub proxy_command: Option<String>,
    /// `SendEnv` patterns and `SetEnv` variables for sessions.
    pub send_env: Vec<String>,
    pub set_env: Vec<(String, String)>,
    /// `RemoteCommand`, used when the command line has none.
    pub remote_command: Option<String>,
    /// `SessionType`: `none` (like -N), `subsystem` (like -s), `default`.
    pub session_type: Option<String>,
    /// `StdinNull` (like -n) and `ForkAfterAuthentication` (like -f).
    pub stdin_null: bool,
    pub fork_after_authentication: bool,
    /// `ExitOnForwardFailure`: a forward that cannot be set up ends qsh.
    pub exit_on_forward_failure: bool,
    /// `LocalCommand`, when `PermitLocalCommand` allows it.
    pub local_command: Option<String>,
    /// `HostKeyAlias`: the name the host key is known under.
    pub host_key_alias: Option<String>,
    /// `ConnectTimeout` and `ConnectionAttempts`.
    pub connect_timeout: Option<std::time::Duration>,
    pub connection_attempts: u32,
}

/// The server refused the login (as opposed to a network problem).
#[derive(Debug)]
pub struct LoginRefused(pub String);

impl std::fmt::Display for LoginRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoginRefused {}

/// Host names and aliases: no option-looking names, whitespace or control
/// characters (they could reach ssh's argument list or %-expansions).
fn valid_host(host: &str) -> bool {
    !host.is_empty() && !host.starts_with('-') && !host.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// `EscapeChar`: `none`, a single character, or `^X` for a control character.
pub fn parse_escape(v: Option<&str>) -> Option<u8> {
    match v {
        None => Some(b'~'),
        Some(v) if v.eq_ignore_ascii_case("none") => None,
        Some(v) if v.len() == 2 && v.starts_with('^') => Some(v.as_bytes()[1].to_ascii_uppercase() & 0x1f),
        Some(v) if v.len() == 1 => Some(v.as_bytes()[0]),
        Some(_) => Some(b'~'),
    }
}

impl Target {
    /// The name the host key is looked up and stored under (`HostKeyAlias`).
    pub fn key_name(&self) -> &str {
        self.host_key_alias.as_deref().unwrap_or(&self.host)
    }

    /// Replaces ssh's tokens in commands: `%%`, `%C` (connection hash), `%d`
    /// (home), `%h` (host), `%i` (uid), `%j` (ProxyJump), `%L`/`%l` (local
    /// host name, short/full), `%n` (host as given), `%p` (port), `%r`
    /// (remote user), `%u` (local user). Unknown tokens are an error, as in ssh.
    pub fn expand_tokens(&self, text: &str) -> Result<String> {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('%') => out.push('%'),
                Some('C') => out.push_str(&control::connection_hash(&self.host, self.port, &self.user)),
                Some('d') => out.push_str(&home_dir().map(|h| h.display().to_string()).unwrap_or_default()),
                Some('h') => out.push_str(&self.host),
                Some('i') => out.push_str(&crate::platform::uid().to_string()),
                Some('j') => out.push_str(self.proxy_jump.as_deref().unwrap_or("")),
                Some('L') => out.push_str(crate::platform::hostname().split('.').next().unwrap_or("")),
                Some('l') => out.push_str(&crate::platform::hostname()),
                Some('n') => out.push_str(&self.alias),
                Some('p') => out.push_str(&self.port.to_string()),
                Some('r') => out.push_str(&self.user),
                Some('u') => out.push_str(&local_user().unwrap_or_default()),
                other => bail!("unknown token %{} in {text:?}", other.map(String::from).unwrap_or_default()),
            }
        }
        Ok(out)
    }

    /// Variables a session sends: LANG, LC_* and COLORTERM (which qshd
    /// accepts by default), what `SendEnv` adds or removes (`-PATTERN`),
    /// then `SetEnv`.
    pub fn session_env(&self) -> Vec<(String, String)> {
        let mut patterns: Vec<String> = vec!["LANG".into(), "LC_*".into(), "COLORTERM".into()];
        for p in &self.send_env {
            match p.strip_prefix('-') {
                Some(remove) => patterns.retain(|q| !crate::pattern::wildcard(remove, q)),
                None => patterns.push(p.clone()),
            }
        }
        let mut env: Vec<(String, String)> = std::env::vars()
            .filter(|(k, _)| patterns.iter().any(|p| crate::pattern::wildcard(p, k)))
            .filter(|(k, _)| !self.set_env.iter().any(|(s, _)| s == k))
            .collect();
        env.extend(self.set_env.iter().cloned());
        env
    }

    /// Parses a destination and applies the matching config entries.
    /// Precedence: `-p`/`user@`/`:port` on the command line, then `-o`, then
    /// `~/.config/qsh/config`, then `~/.ssh/config`. The latter's `Port` is
    /// the SSH port and only used with `full` (`qsh --full`), where the
    /// default port is 22 instead of 4422.
    pub fn parse(s: &str, port: Option<u16>, full: bool) -> Result<Target> {
        Self::resolve(s, port, &config::Sources { full, ..Default::default() })
    }

    pub fn resolve(s: &str, port: Option<u16>, sources: &config::Sources) -> Result<Target> {
        Self::resolve_with(s, port, home_dir().ok().as_deref(), sources)
    }

    /// Like [`Target::parse`], reading the configs under `home` (none if `None`).
    pub fn parse_with(s: &str, port: Option<u16>, home: Option<&Path>, full: bool) -> Result<Target> {
        Self::resolve_with(s, port, home, &config::Sources { full, ..Default::default() })
    }

    pub fn resolve_with(s: &str, port: Option<u16>, home: Option<&Path>, sources: &config::Sources) -> Result<Target> {
        let full = sources.full;
        let (user, rest) = match s.rsplit_once('@') {
            Some((u, r)) if !u.is_empty() => (Some(u.to_string()), r),
            Some(_) => bail!("empty user name in {s:?}"),
            None => (None, s),
        };
        let (alias, parsed_port) = if let Some(r) = rest.strip_prefix('[') {
            let (h, after) = r.split_once(']').context("unclosed '[' in host")?;
            match after.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None if after.is_empty() => (h, None),
                None => bail!("unexpected text after ']' in {s:?}"),
            }
        } else if rest.matches(':').count() >= 2 {
            // An IPv6 address without brackets (as scp, sftp, rsync and git
            // pass it): no port in it.
            (rest, None)
        } else {
            match rest.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (rest, None),
            }
        };
        if !valid_host(alias) {
            bail!("invalid host {alias:?}");
        }
        let parsed_port = parsed_port.map(|p| p.parse::<u16>().context("invalid port")).transpose()?;
        let cfg = home.map(|h| config::lookup(h, alias, sources)).unwrap_or_default();

        let host = cfg.hostname.clone().map(|h| h.replace("%h", alias)).unwrap_or_else(|| alias.to_string());
        if !valid_host(&host) {
            bail!("invalid HostName {host:?} for {alias}");
        }
        let ssh_dest = match &user {
            Some(u) => format!("{u}@{alias}"),
            None => alias.to_string(),
        };
        let user = match user.or(cfg.user.clone()) {
            Some(u) => u,
            None => local_user()?,
        };
        if !crate::proto::valid_user_name(&user) {
            bail!("invalid user name {user:?}");
        }
        let local = local_user().unwrap_or_default();
        let expand = |f: &str| home.map(|h| config::expand_path(f, h, &host, &user, &local));
        let identity_files = cfg.identity_files.iter().filter_map(|f| expand(f)).collect();
        let known_hosts_file = cfg.user_known_hosts_file.as_deref().and_then(expand);
        let certificate_files = cfg.certificate_files.iter().filter_map(|f| expand(f)).collect();
        let identity_agent = match cfg.identity_agent.as_deref() {
            None => None,
            Some(v) if v.eq_ignore_ascii_case("none") => Some(None),
            Some(v) if v == "SSH_AUTH_SOCK" || v == "$SSH_AUTH_SOCK" => None,
            Some(v) => Some(expand(v)),
        };
        let cli_port = port.or(parsed_port);
        // An explicit qsh port (command line, -o or ~/.config/qsh/config) is used
        // as is. Otherwise `--full` looks for qshd both on the ssh port (UDP-only
        // qshd next to sshd) and on the standard qsh port.
        let (port, alt_ports) = match cli_port.or(cfg.port) {
            Some(p) => (p, Vec::new()),
            None if full => {
                let ssh_port = cfg.ssh_port.unwrap_or(22);
                let alt = if ssh_port == crate::DEFAULT_PORT { vec![] } else { vec![crate::DEFAULT_PORT] };
                (ssh_port, alt)
            }
            None => (crate::DEFAULT_PORT, Vec::new()),
        };
        let host_key_policy = match cfg.strict_host_key_checking.as_deref() {
            Some("yes") => HostKeyPolicy::Strict,
            Some("accept-new" | "no" | "off") => HostKeyPolicy::AcceptNew,
            _ => HostKeyPolicy::Ask,
        };
        let sharing = match home {
            Some(h) => control::sharing(
                [cfg.control_master.as_deref(), cfg.control_path.as_deref(), cfg.control_persist.as_deref()],
                h,
                &host,
                port,
                &user,
                &local,
            ),
            None => control::Sharing::default(),
        };
        let family = match cfg.address_family.as_deref() {
            Some("inet") => transport::Family::V4,
            Some("inet6") => transport::Family::V6,
            _ => transport::Family::Any,
        };
        let bind = match (&cfg.bind_address, &cfg.bind_interface) {
            (Some(a), _) => transport::Bind::Address(a.parse().with_context(|| format!("invalid BindAddress {a:?}"))?),
            (None, Some(i)) => transport::Bind::Interface(i.clone()),
            (None, None) => transport::Bind::Any,
        };
        Ok(Target {
            user,
            alt_ports,
            identity_files,
            ssh_dest,
            ssh_options: cfg.for_ssh.clone(),
            cli_port,
            local_forwards: cfg.local_forwards,
            remote_forwards: cfg.remote_forwards,
            dynamic_forwards: cfg.dynamic_forwards,
            proxy_jump: cfg.proxy_jump,
            request_tty: cfg.request_tty,
            needs_proxy: cfg.needs_proxy,
            keystroke_interval: config::keystroke_interval(cfg.obscure_keystrokes.as_deref()),
            batch_mode: cfg.batch_mode.unwrap_or(false),
            host_key_policy,
            known_hosts_file,
            clear_all_forwardings: cfg.clear_all_forwardings.unwrap_or(false),
            escape_char: parse_escape(cfg.escape_char.as_deref()),
            family,
            bind,
            quiet: cfg.log_level.as_deref() == Some("quiet"),
            forward_agent: cfg.forward_agent.unwrap_or(false),
            identities_only: cfg.identities_only.unwrap_or(false),
            identity_agent,
            certificate_files,
            persist_session: cfg.persist_session.unwrap_or(true),
            server_alive: cfg
                .server_alive_interval
                .filter(|&s| s > 0)
                .map(|s| (std::time::Duration::from_secs(s), cfg.server_alive_count_max.unwrap_or(3).max(1))),
            sharing,
            predict: cfg.predictive_echo.as_deref().map(predict::parse_mode).unwrap_or_default(),
            compression: cfg.compression.unwrap_or(false),
            sources: sources.clone(),
            alias: alias.to_string(),
            proxy_command: cfg.proxy_command,
            send_env: cfg.send_env,
            set_env: cfg.set_env.iter().filter_map(|e| e.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            remote_command: cfg.remote_command,
            session_type: cfg.session_type,
            stdin_null: cfg.stdin_null.unwrap_or(false),
            fork_after_authentication: cfg.fork_after_authentication.unwrap_or(false),
            exit_on_forward_failure: cfg.exit_on_forward_failure.unwrap_or(false),
            local_command: cfg.local_command.filter(|_| cfg.permit_local_command.unwrap_or(false)),
            host_key_alias: cfg.host_key_alias,
            connect_timeout: cfg.connect_timeout.filter(|&t| t > 0).map(std::time::Duration::from_secs),
            connection_attempts: cfg.connection_attempts.unwrap_or(1).max(1),
            host,
            port,
        })
    }
}

fn local_user() -> Result<String> {
    crate::platform::local_user()
}

#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// `-i` keys, tried in order (the first Ed25519 one is used).
    pub identities: Vec<PathBuf>,
    pub transport: Mode,
    /// Trust unknown host keys without asking (still refuses changed keys).
    pub accept_new_host: bool,
    /// `qsh --full`: QUIC only, give up quickly so the caller can hand over to ssh.
    pub full: bool,
    /// Log in to resume the persistent session with this token.
    pub resume: Option<Vec<u8>>,
    /// May use the connection of a master qsh (`ControlMaster`/`ControlPath`).
    pub share: bool,
}

/// Remembers for an hour that a host has no qshd, so `--full` goes straight to ssh.
struct NoQshdCache {
    path: PathBuf,
}

const NO_QSHD_TTL: u64 = 3600;
/// Time for the TLS handshake with a host behind a jump host.
const JUMP_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl NoQshdCache {
    fn new() -> Result<NoQshdCache> {
        Ok(NoQshdCache { path: qsh_dir(&home_dir()?).join("no-qshd") })
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn entries(&self) -> Vec<(String, u64)> {
        std::fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let (id, t) = l.rsplit_once(' ')?;
                Some((id.to_string(), t.parse().ok()?))
            })
            .filter(|(_, t)| Self::now().saturating_sub(*t) < NO_QSHD_TTL)
            .collect()
    }

    fn contains(&self, id: &str) -> bool {
        self.entries().iter().any(|(e, _)| e == id)
    }

    fn set(&self, id: &str, present: bool) {
        let mut entries: Vec<_> = self.entries().into_iter().filter(|(e, _)| e != id).collect();
        if present {
            entries.push((id.to_string(), Self::now()));
        }
        let text: String = entries.iter().map(|(e, t)| format!("{e} {t}\n")).collect();
        if let Some(dir) = self.path.parent() {
            let _ = crate::keys::create_private_dir(dir);
        }
        // Several qsh at once (qsh multi): never a half-written file.
        let _ = crate::platform::replace_file(&self.path, text.as_bytes());
    }
}

fn default_identity_paths() -> Result<[PathBuf; 2]> {
    let home = home_dir()?;
    Ok([home.join(".ssh").join("id_ed25519"), qsh_dir(&home).join("id_ed25519")])
}

/// Loads the key for the TLS handshake: the first Ed25519 key among `-i`,
/// else among the config's `IdentityFile`s, else `~/.ssh/id_ed25519`, else
/// `~/.config/qsh/id_ed25519`. With `create`, generates the latter when no key
/// exists. With `batch`, an encrypted key is an error instead of a prompt.
pub fn load_identity(explicit: &[PathBuf], configured: &[PathBuf], create: bool, batch: bool) -> Result<Identity> {
    // No Ed25519 key: a throwaway one for TLS; agent keys and other key types
    // are offered after the handshake.
    Ok(find_identity(explicit, configured, create, batch)?.unwrap_or_else(Identity::generate))
}

/// Like [`load_identity`], but `None` instead of a throwaway key.
fn find_identity(explicit: &[PathBuf], configured: &[PathBuf], create: bool, batch: bool) -> Result<Option<Identity>> {
    if !explicit.is_empty() {
        if let Some(p) = explicit.iter().find(|p| Identity::is_ed25519_file(p)) {
            return Identity::load_with(p, !batch).map(Some);
        }
        if create {
            // Pairing registers the TLS key, so it has to be a real Ed25519 key.
            return Identity::load_with(&explicit[0], !batch).map(Some);
        }
        for p in explicit.iter().filter(|p| !p.exists()) {
            eprintln!("Warning: identity file {} not accessible", p.display());
        }
        // Other key types are offered after the handshake.
        return Ok(None);
    }
    // Config entries may list RSA/ECDSA keys for ssh; skip those (without asking for a passphrase).
    for p in configured {
        if p.exists() {
            if Identity::is_ed25519_file(p) {
                return Identity::load_with(p, !batch).map(Some);
            }
            tracing::debug!("skipping {}: not an ed25519 key", p.display());
        }
    }
    let paths = default_identity_paths()?;
    if let Some(p) = paths.iter().find(|p| p.exists()) {
        return Identity::load_with(p, !batch).map(Some);
    }
    if create {
        let (id, _) = Identity::load_or_generate(&paths[1], "qsh")?;
        eprintln!("Generated new key {}", paths[1].display());
        return Ok(Some(id));
    }
    Ok(None)
}

/// The pinned key for `host:port`, if any.
pub fn known_host_key(host: &str, port: u16) -> Result<Option<PublicKey>> {
    known_hosts()?.lookup(&host_id(host, port))
}

/// Host ids from known_hosts (`host` or `[host]:port`), usable as destinations.
pub fn known_host_ids() -> Vec<String> {
    known_hosts().map(|k| k.ids()).unwrap_or_default()
}

fn known_hosts() -> Result<KnownHosts> {
    Ok(KnownHosts::new(qsh_dir(&home_dir()?).join("known_hosts")))
}

/// known_hosts for a target: its `UserKnownHostsFile`, or the default.
fn known_hosts_for(target: &Target) -> Result<(KnownHosts, PathBuf)> {
    let path = match &target.known_hosts_file {
        Some(p) => p.clone(),
        None => qsh_dir(&home_dir()?).join("known_hosts"),
    };
    Ok((KnownHosts::new(path.clone()), path))
}

/// Asks on the terminal whether to trust an unknown host key.
fn confirm_new_host(id: &str, key: PublicKey) -> Result<bool> {
    let (input, tty) = crate::platform::terminal().context(
        "host key is unknown and there is no terminal to confirm it; use --accept-new-host or `qsh pair`",
    )?;
    let mut out = &tty;
    write!(
        out,
        "The authenticity of host '{id}' can't be established.\n\
         ED25519 key fingerprint is {}.\n\
         Are you sure you want to continue connecting (yes/no)? ",
        key.fingerprint()
    )?;
    out.flush()?;
    let mut answer = String::new();
    std::io::BufReader::new(&input).read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

/// Why the TLS host check refused a server (see [`host_check`]).
type Rejection = Arc<std::sync::Mutex<Option<String>>>;

/// Connects to the target, with the TLS config `tls` has for each port. A
/// server refused by a host check is reported as such, never as unreachable
/// (so `--full` does not hand it to ssh, nor remember it as qshd-less).
async fn open(target: &Target, opts: &ConnectOptions, tls: &HashMap<u16, rustls::ClientConfig>, rejected: &Rejection, via: Option<&Conn>) -> Result<Conn> {
    let result = open_any(target, opts, tls, rejected, via).await;
    if let Some(reason) = rejected.lock().unwrap().take() {
        bail!("{reason}");
    }
    result
}

async fn open_any(target: &Target, opts: &ConnectOptions, tls: &HashMap<u16, rustls::ClientConfig>, rejected: &Rejection, via: Option<&Conn>) -> Result<Conn> {
    if let (Some(command), None) = (&target.proxy_command, via) {
        // TLS + yamux over the command's stdin and stdout (like `ssh -W` or nc).
        let line = target.expand_tokens(command)?;
        let stream = transport::ProxyCommand::spawn(&line)?;
        let label = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), target.port);
        let timeout = target.connect_timeout.unwrap_or(JUMP_HANDSHAKE_TIMEOUT);
        let conn = tokio::time::timeout(timeout, transport::connect_stream(stream, tls[&target.port].clone(), label))
            .await
            .map_err(|_| anyhow::anyhow!("no TLS answer through ProxyCommand {line:?}"))?
            .with_context(|| format!("no qshd through ProxyCommand {line:?}"))?;
        tracing::info!("connected to {}:{} through ProxyCommand", target.host, target.port);
        return Ok(conn);
    }
    if let Some(via) = via {
        // Through a jump host: TLS + yamux over a stream forwarded to the qshd TCP port.
        // In --full mode the target port may be sshd's, so the other candidates are tried too.
        let mut last = None;
        for port in std::iter::once(target.port).chain(target.alt_ports.iter().copied()) {
            let attempt = async {
                let (send, recv) = crate::client::forward::open_direct(via, &target.host, port)
                    .await
                    .with_context(|| format!("jump host cannot reach {}:{port}", target.host))?;
                let label = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port);
                tokio::time::timeout(JUMP_HANDSHAKE_TIMEOUT, transport::connect_stream(tokio::io::join(recv, send), tls[&port].clone(), label))
                    .await
                    .map_err(|_| anyhow::anyhow!("no TLS answer from {}:{port}", target.host))?
                    .with_context(|| format!("no qshd at {}:{port}", target.host))
            };
            match attempt.await {
                Ok(conn) => {
                    tracing::info!("connected to {}:{port} through a jump host", target.host);
                    return Ok(conn);
                }
                Err(e) => last = Some(e),
            }
        }
        let e = last.expect("at least one port");
        // In --full mode a missing qshd behind the jump host means: use ssh instead.
        return Err(if opts.full { transport::Unreachable(format!("{e:#}")).into() } else { e });
    }
    let conn = if opts.full {
        // `--transport quic` forces a fresh attempt even for hosts cached as qshd-less.
        let cache = NoQshdCache::new()?;
        let hid = host_id(&target.host, target.port);
        if opts.transport != Mode::Quic && cache.contains(&hid) {
            return Err(transport::Unreachable(format!("no qshd at {hid} (cached for up to an hour)")).into());
        }
        let result = transport::connect_probe(&target.host, &target_ports(target), target.family, &target.bind, |p| tls[&p].clone()).await;
        let refused = rejected.lock().unwrap().is_some();
        cache.set(&hid, !refused && result.as_ref().is_err_and(|e| e.is::<transport::Unreachable>()));
        result?
    } else {
        // ConnectionAttempts, one second apart, each within ConnectTimeout.
        let mut attempt = 1;
        loop {
            let connect = transport::connect(&target.host, target.port, opts.transport, target.family, &target.bind, tls[&target.port].clone());
            let result = match target.connect_timeout {
                Some(t) => tokio::time::timeout(t, connect).await.unwrap_or_else(|_| {
                    Err(transport::Unreachable(format!("{}:{}: connection timed out", target.host, target.port)).into())
                }),
                None => connect.await,
            };
            match result {
                Ok(conn) => break conn,
                Err(e) if attempt < target.connection_attempts && rejected.lock().unwrap().is_none() => {
                    tracing::debug!("attempt {attempt}: {e:#}");
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(e) => return Err(e),
            }
        }
    };
    tracing::info!("connected to {} over {}", conn.remote_addr(), conn.transport_name());
    Ok(conn)
}

/// Files with `@cert-authority` and `@revoked` lines: qsh's known_hosts and OpenSSH's.
fn marker_files(target: &Target) -> Vec<KnownHosts> {
    let mut files = Vec::new();
    if let Ok((kh, _)) = known_hosts_for(target) {
        files.push(kh);
    }
    if let Ok(home) = home_dir() {
        files.push(KnownHosts::new(home.join(".ssh").join("known_hosts")));
    }
    files.push(KnownHosts::new(PathBuf::from("/etc/ssh/ssh_known_hosts")));
    files
}

/// What a host certificate says about the server.
enum CertVerdict {
    /// Signed by a trusted CA for this host (how, for the log).
    Valid(String),
    /// Not signed by a CA trusted for this host: the key is checked as if
    /// there were no certificate.
    Unusable(String),
    /// Signed by a revoked CA, or by a trusted CA but expired, for another
    /// host or another key: the server is refused, as by OpenSSH.
    Invalid(String),
}

/// Checks the server's host certificate against the `@cert-authority` and
/// `@revoked` keys for this host.
fn check_host_cert(cert: &[u8], key: PublicKey, target: &Target, revoked: &[ssh_key::public::KeyData], cas: &[ssh_key::public::KeyData]) -> CertVerdict {
    use ssh_key::certificate::CertType;
    let cert = match ssh_key::Certificate::from_bytes(cert) {
        Ok(c) => c,
        Err(e) => return CertVerdict::Unusable(format!("cannot parse the host certificate: {e}")),
    };
    if revoked.contains(cert.signature_key()) {
        return CertVerdict::Invalid("its certificate authority is revoked".into());
    }
    if !cas.contains(cert.signature_key()) {
        return CertVerdict::Unusable(format!("no @cert-authority for {} with the certificate's CA key", target.key_name()));
    }
    let own = ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(key.0));
    if cert.cert_type() != CertType::Host || cert.public_key() != &own {
        return CertVerdict::Invalid("its certificate is not a host certificate for the key it presented".into());
    }
    let fingerprints: Vec<_> = cas.iter().map(|k| k.fingerprint(ssh_key::HashAlg::Sha256)).collect();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if cert.validate_at(now, &fingerprints).is_err() {
        return CertVerdict::Invalid("its certificate has expired or its signature does not verify".into());
    }
    if !cert.valid_principals().iter().any(|p| p.eq_ignore_ascii_case(target.key_name())) {
        return CertVerdict::Invalid(format!("its certificate is not valid for {} (principals {:?})", target.key_name(), cert.valid_principals()));
    }
    CertVerdict::Valid(format!("certificate {:?} signed by {}", cert.key_id(), cert.signature_key().fingerprint(ssh_key::HashAlg::Sha256)))
}

/// What the client makes of a server's key.
enum HostTrust {
    /// In known_hosts, or vouched for by a trusted CA (how, for the log).
    Trusted(String),
    /// Not known yet: the host key policy decides.
    Unknown,
    /// Never accepted; the message says why.
    Refused(String),
}

/// Judges the key (and host certificate) that the server at `port` presents.
/// Revoked keys never pass.
fn judge_host(target: &Target, port: u16, key: PublicKey, cert: Option<&[u8]>) -> Result<HostTrust> {
    let (kh, kh_path) = known_hosts_for(target)?;
    let hid = host_id(target.key_name(), port);
    let names = if hid == target.key_name() { vec![hid.clone()] } else { vec![hid.clone(), target.key_name().to_string()] };
    let files = marker_files(target);
    let own = ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(key.0));
    let marked = |marker: &str| -> Result<Vec<_>> {
        let mut keys = Vec::new();
        for f in &files {
            keys.extend(f.marked(marker, &names)?);
        }
        Ok(keys)
    };
    let revoked = marked("@revoked")?;
    if revoked.contains(&own) {
        return Ok(HostTrust::Refused(format!("the host key of '{hid}' ({}) is marked as revoked in known_hosts", key.fingerprint())));
    }
    if let Some(cert) = cert {
        match check_host_cert(cert, key, target, &revoked, &marked("@cert-authority")?) {
            CertVerdict::Valid(how) => return Ok(HostTrust::Trusted(how)),
            CertVerdict::Unusable(why) => tracing::debug!("host certificate not used: {why}"),
            CertVerdict::Invalid(why) => return Ok(HostTrust::Refused(format!("host '{hid}' is refused: {why}"))),
        }
    }
    Ok(match kh.lookup(&hid)? {
        Some(known) if known == key => HostTrust::Trusted("known_hosts".into()),
        Some(known) => HostTrust::Refused(format!(
            "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n\
             Someone could be eavesdropping on you right now (man-in-the-middle attack),\n\
             or the host key has just been changed.\n\
             Host '{hid}' now presents {}, expected {}.\n\
             If the change is legitimate, remove the line for '{hid}' from {}.",
            key.fingerprint(),
            known.fingerprint(),
            kh_path.display()
        )),
        None => other_ports(target, port, key, &kh)?,
    })
}

/// A key not known for this port: in `--full`, the same host may be known
/// on another of its candidate ports. The same key there vouches for it; a
/// different one means someone else answers on this port (a probe takes
/// whichever port answers first), which must not pass as a new host.
fn other_ports(target: &Target, port: u16, key: PublicKey, kh: &KnownHosts) -> Result<HostTrust> {
    for other in target_ports(target).into_iter().filter(|&p| p != port) {
        match kh.lookup(&host_id(target.key_name(), other))? {
            Some(known) if known == key => return Ok(HostTrust::Trusted(format!("the key known for port {other}"))),
            Some(known) => {
                return Ok(HostTrust::Refused(format!(
                    "'{}' presents {} on port {port}, but this host is known with {} on port {other}; \
                     a different key on another port is refused (if it is right, add it with `qsh -p {port} --accept-new-host`)",
                    target.host,
                    key.fingerprint(),
                    known.fingerprint()
                )))
            }
            None => {}
        }
    }
    Ok(HostTrust::Unknown)
}

/// The check run inside the TLS handshake, before the client sends its own
/// certificate: a server that would be refused afterwards (changed or
/// revoked key, bad host certificate) never learns which key the client has.
/// Unknown servers pass here and go through the host key policy afterwards.
fn host_check(target: &Target, port: u16, rejected: &Rejection) -> crate::tls::HostCheck {
    let (target, rejected) = (target.clone(), rejected.clone());
    Arc::new(move |key, cert| match judge_host(&target, port, key, cert) {
        Ok(HostTrust::Refused(reason)) => {
            *rejected.lock().unwrap() = Some(reason.clone());
            Err(reason)
        }
        // Errors (an unreadable known_hosts) come up again after the handshake.
        _ => Ok(()),
    })
}

/// The ports a connection to the target may end up on.
fn target_ports(target: &Target) -> Vec<u16> {
    std::iter::once(target.port).chain(target.alt_ports.iter().copied()).collect()
}

/// TLS configs for the target's ports. The handshake carries the client's
/// own key only where known_hosts already has the server's key (and the
/// host check refuses any other); elsewhere it uses a throwaway key, and the
/// own key is offered after the host is accepted, so that a server the user
/// has not accepted (or an impostor) does not learn who is connecting.
/// Also returns the ports that use the throwaway key.
fn tls_configs(target: &Target, own: &Identity, throwaway: &Identity, rejected: &Rejection) -> Result<(HashMap<u16, rustls::ClientConfig>, Vec<u16>)> {
    let (kh, _) = known_hosts_for(target)?;
    let (mut configs, mut hidden) = (HashMap::new(), Vec::new());
    for port in target_ports(target) {
        let pinned = matches!(kh.lookup(&host_id(target.key_name(), port)), Ok(Some(_)));
        if !pinned {
            hidden.push(port);
        }
        let id = if pinned { own } else { throwaway };
        configs.insert(port, crate::tls::checked_client_config(id, Some(host_check(target, port, rejected)))?);
    }
    Ok((configs, hidden))
}

/// Checks the server's key after the handshake: a host certificate from a
/// trusted CA, or known_hosts following the host key policy.
async fn verify_host_key(conn: &Conn, target: &Target, opts: &ConnectOptions) -> Result<()> {
    let port = conn.remote_addr().port();
    let hid = host_id(target.key_name(), port);
    let key = conn.peer_key();
    match judge_host(target, port, key, conn.host_cert())? {
        HostTrust::Trusted(how) => {
            tracing::info!("host '{hid}' verified by {how}");
            Ok(())
        }
        HostTrust::Refused(reason) => {
            conn.close().await;
            bail!("{reason}");
        }
        HostTrust::Unknown => {
            let policy = if opts.accept_new_host { HostKeyPolicy::AcceptNew } else { target.host_key_policy };
            let trusted = match policy {
                HostKeyPolicy::AcceptNew => true,
                HostKeyPolicy::Strict => false,
                HostKeyPolicy::Ask if target.batch_mode => false,
                HostKeyPolicy::Ask => confirm_new_host(&hid, key)?,
            };
            if !trusted {
                conn.close().await;
                bail!("host key verification failed for '{hid}' ({}); use `qsh pair` or --accept-new-host", key.fingerprint());
            }
            known_hosts_for(target)?.0.add(&hid, key)?;
            if !target.quiet {
                eprintln!("Permanently added '{hid}' (ED25519) to the list of known hosts.");
            }
            Ok(())
        }
    }
}

/// Opens, verifies and logs in to one host (directly or through `via`).
/// Connecting directly could bypass a proxy the user relies on (e.g. Tor).
fn refuse_proxy(target: &Target) -> Result<()> {
    if target.needs_proxy {
        bail!(
            "ssh's config routes {} through ProxyCommand or ProxyJump, which lead to sshd; \
             use --full to connect with ssh instead, or set ProxyJump or ProxyCommand in ~/.config/qsh/config",
            target.host
        );
    }
    Ok(())
}

async fn establish(target: &Target, opts: &ConnectOptions, via: Option<&Conn>) -> Result<Conn> {
    refuse_proxy(target)?;
    let own = find_identity(&opts.identities, &target.identity_files, false, target.batch_mode)?;
    match login_once(target, opts, via, own.as_ref(), false).await {
        // qshd before 0.5 knows only the TLS key: log in again with the own key
        // in the handshake (the host has been accepted by now, so this is no leak).
        Err(e) if e.is::<TlsKeyOnly>() => login_once(target, opts, via, own.as_ref(), true).await,
        result => result,
    }
}

/// The server refused a throwaway TLS key without asking for other keys.
#[derive(Debug)]
struct TlsKeyOnly;

impl std::fmt::Display for TlsKeyOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server only accepts the key from the TLS handshake")
    }
}

impl std::error::Error for TlsKeyOnly {}

/// One connection and login. `own`: the client's Ed25519 key, if it has
/// one; `real_tls`: use it in the handshake on every port.
async fn login_once(target: &Target, opts: &ConnectOptions, via: Option<&Conn>, own: Option<&Identity>, real_tls: bool) -> Result<Conn> {
    let throwaway = Identity::generate();
    let own = own.unwrap_or(&throwaway);
    let rejected = Rejection::default();
    let (tls, hidden) = if real_tls {
        let check = |p| crate::tls::checked_client_config(own, Some(host_check(target, p, &rejected))).map(|c| (p, c));
        (target_ports(target).into_iter().map(check).collect::<Result<_>>()?, Vec::new())
    } else {
        tls_configs(target, own, &throwaway, &rejected)?
    };
    let mut conn = open(target, opts, &tls, &rejected, via).await?;
    verify_host_key(&conn, target, opts).await?;
    let hidden = hidden.contains(&conn.remote_addr().port()) && !std::ptr::eq(own, &throwaway);
    let tls_id = if hidden { &throwaway } else { own };
    let (mut send, mut recv) = conn.open_bi().await?;
    let hello = match &opts.resume {
        Some(token) => Hello::Resume { version: VERSION, user: target.user.clone(), token: token.clone() },
        None => Hello::Login { version: VERSION, user: target.user.clone() },
    };
    write_msg(&mut send, &hello).await?;
    match auth::login(&conn, &mut send, &mut recv, target, &opts.identities, tls_id, own).await {
        Ok(auth::Outcome::Welcome(version)) => {
            tracing::debug!("logged in, server protocol version {version}");
            conn.set_server_version(version);
            Ok(conn)
        }
        Ok(auth::Outcome::Denied { reason: e, asked_for_keys }) => {
            conn.close().await;
            if hidden && !asked_for_keys {
                return Err(TlsKeyOnly.into());
            }
            if opts.resume.is_some() {
                return Err(LoginRefused(e).into());
            }
            Err(LoginRefused(format!(
                "{e} for {}@{}.\nAdd your key on the server with `qsh pair`, or to ~/.ssh/authorized_keys there (ssh-copy-id).",
                target.user, target.host,
            ))
            .into())
        }
        Err(e) => {
            conn.close().await;
            Err(e)
        }
    }
}

/// Connects, verifies the host key against known_hosts and logs in, going
/// through the target's jump hosts (`-J`/`ProxyJump`) if it has any.
pub async fn connect(target: &Target, opts: &ConnectOptions) -> Result<Conn> {
    // A resumed session logs in on its own: its master may be what went away.
    #[cfg(unix)]
    if let (true, None, Some(path)) = (opts.share, &opts.resume, &target.sharing.path) {
        if let Some(conn) = transport::shared::attach(path).await {
            tracing::info!("using the shared connection at {}", path.display());
            return Ok(conn);
        }
    }
    // Before any jump host is contacted.
    refuse_proxy(target)?;
    let hops = jump_hosts(target, opts).await?;
    let mut conn = establish(target, opts, hops.last().map(|c| c.as_ref())).await?;
    conn.set_hops(hops);
    Ok(conn)
}

/// Connections to the target's jump hosts (`-J`/`ProxyJump`), in order.
async fn jump_hosts(target: &Target, opts: &ConnectOptions) -> Result<Vec<Arc<Conn>>> {
    let mut hops: Vec<Arc<Conn>> = Vec::new();
    if let Some(jumps) = &target.proxy_jump {
        // Jump hosts use the config files, but not this host's -o options.
        let sources = config::Sources { full: false, overrides: Vec::new(), ssh_config: target.sources.ssh_config.clone() };
        let hop_opts = ConnectOptions { identities: opts.identities.clone(), full: false, transport: opts.transport, resume: None, share: false, ..opts.clone() };
        for spec in jumps.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let mut hop = Target::resolve(spec, None, &sources).with_context(|| format!("jump host {spec}"))?;
            // Nothing may stop to ask on the way when this host may not (qsh multi).
            hop.batch_mode |= target.batch_mode;
            let conn = establish(&hop, &hop_opts, hops.last().map(|c| c.as_ref()))
                .await
                .with_context(|| format!("jump host {spec}"))?;
            hops.push(Arc::new(conn));
        }
    }
    Ok(hops)
}

/// Pairs this client with the server using a one-time code from `qshd pair`.
pub async fn pair(target: &Target, opts: &ConnectOptions, code: &str) -> Result<()> {
    refuse_proxy(target)?;
    let id = load_identity(&opts.identities, &target.identity_files, true, target.batch_mode)?;
    // Through qsh's jump hosts, like a login.
    let hops = jump_hosts(target, opts).await?;
    // The server is checked by the pairing code, not by known_hosts.
    let tls = target_ports(target).into_iter().map(|p| crate::tls::client_config(&id).map(|c| (p, c))).collect::<Result<_>>()?;
    let mut conn = open(target, opts, &tls, &Rejection::default(), hops.last().map(|c| c.as_ref())).await?;
    conn.set_hops(hops);
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Hello::Pair { version: VERSION, user: target.user.clone() }).await?;
    let result = async {
        expect_ok(&mut recv).await?;
        crate::pair::client(&mut send, &mut recv, code, &conn.exporter(), id.public(), conn.peer_key()).await
    }
    .await;
    conn.close().await;
    result?;

    // The server proved knowledge of the code inside this TLS session, so its key is authentic.
    let (kh, _) = known_hosts_for(target)?;
    let hid = host_id(target.key_name(), conn.remote_addr().port());
    let key = conn.peer_key();
    match kh.lookup(&hid)? {
        Some(known) if known == key => {}
        Some(_) => bail!(
            "paired, but '{hid}' is in known_hosts with a different key; remove that line and pair again"
        ),
        None => kh.add(&hid, key)?,
    }
    eprintln!("Paired with {hid} as {} (host key {}).", target.user, key.fingerprint());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_targets() {
        let t = Target::parse_with("alice@example.com", None, None, false).unwrap();
        assert_eq!((t.user.as_str(), t.host.as_str(), t.port), ("alice", "example.com", crate::DEFAULT_PORT));
        let t = Target::parse_with("bob@example.com:2200", None, None, false).unwrap();
        assert_eq!(t.port, 2200);
        let t = Target::parse_with("bob@example.com:2200", Some(99), None, false).unwrap();
        assert_eq!(t.port, 99);
        let t = Target::parse_with("u@2001:db8::5", None, None, false).unwrap();
        assert_eq!((t.host.as_str(), t.port), ("2001:db8::5", crate::DEFAULT_PORT), "unbracketed IPv6");
        assert_eq!(Target::parse_with("::1", None, None, false).unwrap().host, "::1");
        let t = Target::parse_with("c@[::1]:5", None, None, false).unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 5));
        let t = Target::parse_with("c@[::1]", None, None, false).unwrap();
        assert_eq!(t.host, "::1");
        assert!(Target::parse_with("@host", None, None, false).is_err());
        assert!(Target::parse_with("", None, None, false).is_err());
        assert!(Target::parse_with("a@host:notaport", None, None, false).is_err());
    }

    #[test]
    fn config_aliases() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
        std::fs::write(
            home.path().join(".ssh/config"),
            "Host myserver\n  Port 22\n  User root\n  HostName 192.0.2.10\n  IdentityFile ~/.ssh/work_key\n",
        )
        .unwrap();
        let t = Target::parse_with("myserver", None, Some(home.path()), false).unwrap();
        assert_eq!((t.user.as_str(), t.host.as_str(), t.port), ("root", "192.0.2.10", crate::DEFAULT_PORT));
        assert_eq!(t.identity_files, vec![home.path().join(".ssh/work_key")]);
        // Command line wins over the config.
        let t = Target::parse_with("admin@myserver:9000", None, Some(home.path()), false).unwrap();
        assert_eq!((t.user.as_str(), t.port), ("admin", 9000));
        // --full: ssh's Port (22 here), and 22 by default.
        let t = Target::parse_with("myserver", None, Some(home.path()), true).unwrap();
        assert_eq!((t.port, t.alt_ports.as_slice(), t.ssh_dest.as_str()), (22, &[crate::DEFAULT_PORT][..], "myserver"));
        assert_eq!(Target::parse_with("u@other", None, Some(home.path()), true).unwrap().port, 22);
        // An explicit port means exactly that port.
        assert!(Target::parse_with("myserver:2222", None, Some(home.path()), true).unwrap().alt_ports.is_empty());
        // Option-looking or odd names never get through.
        assert!(Target::parse_with("-oProxyCommand=x", None, None, false).is_err());
        assert!(Target::parse_with("a$b@host", None, None, false).is_err());
        assert!(Target::parse_with("u@ho st", None, None, false).is_err());
        // Unknown names pass through unchanged.
        let t = Target::parse_with("u@other", None, Some(home.path()), false).unwrap();
        assert_eq!(t.host, "other");
    }
}
