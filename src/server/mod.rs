//! The `qshd` daemon.

mod agent;
mod auth;
mod exec;
mod files;
pub mod helpers;
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

use crate::config::{GatewayPorts, ServerConfig};
use crate::keys::{Identity, PublicKey};
use crate::authkeys::Grant;
use crate::proto::{read_msg, valid_user_name, write_msg, Hello, PtySpec, Reply, Request, MIN_VERSION, VERSION};
use crate::transport::{Conn, Listener, RecvHalf, SendHalf};
use users::User;

/// Time a connected client has to open its first stream and say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const NO_PAIRING: &str = "no active pairing code for this user (run `qshd pair` on the server; codes expire)";
/// How long a finished connection waits for the client to close it.
const LINGER: Duration = Duration::from_secs(5);

struct State {
    cfg: ServerConfig,
    host_key: PublicKey,
    totp_used: auth::UsedCodes,
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
    match Listener::bind(cfg.listen, tls.clone(), cfg.tcp).await {
        Err(e) if cfg.listen.ip() == Ipv6Addr::UNSPECIFIED => {
            debug!("dual-stack bind failed ({e:#}), using IPv4 only");
            Listener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), cfg.listen.port()), tls, cfg.tcp).await
        }
        other => other,
    }
}

pub async fn serve(listener: Listener, cfg: ServerConfig, host: &Identity) -> Result<()> {
    let limit = Arc::new(Semaphore::new(cfg.max_connections));
    let startups = Startups::new(cfg.max_startups, cfg.max_startups_per_ip);
    let state = Arc::new(State { cfg, host_key: host.public(), totp_used: Default::default() });
    loop {
        let incoming = listener.accept().await?;
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

    let (name, pairing, version) = match hello {
        Hello::Login { version, user } | Hello::Pair { version, user } if version < MIN_VERSION => {
            write_msg(&mut send, &Reply::Err(format!("unsupported protocol version {version}"))).await?;
            bail!("client {user:?} uses protocol version {version}");
        }
        Hello::Login { user, version } => (user, false, version),
        Hello::Pair { user, version } => (user, true, version),
    };
    let looked_up = if valid_user_name(&name) {
        User::lookup(&name)
    } else {
        Err(anyhow::anyhow!("invalid user name"))
    };
    let user = match looked_up {
        Ok(u) => Some(u),
        Err(e) => {
            warn!("{addr}: rejected user {name:?}: {e:#}");
            None
        }
    };
    if pairing {
        match user {
            Some(user) => return pair(conn, &state, &user, send, recv).await,
            None => {
                // Same answer as for an existing user without a code, so names cannot be probed.
                write_msg(&mut send, &Reply::Err(NO_PAIRING.into())).await?;
                return Ok(());
            }
        }
    }

    // An unknown user goes through the same steps with no keys, so names cannot be probed.
    let entries = user.as_ref().map(|u| auth::authorized_entries(&state.cfg, u)).unwrap_or_default();
    let cas = auth::trusted_cas(&state.cfg);
    let checker = auth::Checker {
        entries: &entries,
        cas: &cas,
        login: crate::authkeys::Login { user: &name, ip: addr.ip().to_canonical(), now: auth::now() },
        exporter: conn.exporter(),
    };
    let mut granted = checker.check(&auth::tls_key(key)).ok().map(|g| (g, format!("ED25519 {}", key.fingerprint())));
    if granted.is_none() && version >= 4 {
        let attempt = auth::key_auth(&mut send, &mut recv, &checker, state.cfg.max_auth_tries);
        granted = tokio::time::timeout(auth::AUTH_TIMEOUT, attempt).await.context("login took too long")??;
    }
    let (Some(user), Some((grant, how))) = (user, granted) else {
        warn!("{addr}: no authorized key for {name} (TLS key {})", key.fingerprint());
        write_msg(&mut send, &Reply::Err("access denied".into())).await?;
        return Ok(());
    };
    let second = auth::second_factor(&mut send, &mut recv, &user, state.cfg.totp, version, &state.totp_used);
    if let Err(msg) = tokio::time::timeout(auth::AUTH_TIMEOUT, second).await.context("login took too long")?? {
        warn!("{addr}: {name}: second factor failed");
        write_msg(&mut send, &Reply::Err(msg)).await?;
        return Ok(());
    }
    info!("{addr}: {name} logged in with {how} over {}", conn.transport_name());
    let welcome = if version >= 4 { Reply::Welcome { version: VERSION } } else { Reply::Ok };
    write_msg(&mut send, &welcome).await?;
    drop(startup);

    let user = Arc::new(user);
    let grant = Arc::new(grant);
    let agent = Arc::new(agent::AgentSocket::default());
    // Lets running sessions notice a dead connection even after the client
    // finished sending on their stream.
    let (closed_tx, closed_rx) = watch::channel(false);
    while let Some((send, recv)) = conn.accept_bi().await {
        let (user, state, closed, conn, grant, agent) =
            (user.clone(), state.clone(), closed_rx.clone(), conn.clone(), grant.clone(), agent.clone());
        tokio::spawn(async move {
            let ctx = StreamCtx { conn: &conn, user: &user, grant: &grant, state: &state, agent: &agent };
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
    agent: &'a agent::AgentSocket,
}

async fn handle_stream(mut send: SendHalf, mut recv: RecvHalf, ctx: StreamCtx<'_>, closed: watch::Receiver<bool>) -> Result<()> {
    let StreamCtx { conn, user, grant, state, agent } = ctx;
    let request = match read_msg(&mut recv).await {
        Ok(r) => r,
        // A request type from a newer client: say so instead of dropping the stream.
        Err(e) if e.is::<crate::proto::Malformed>() => {
            return write_msg(&mut send, &Reply::Err("request not supported by this qshd (update it)".into())).await;
        }
        Err(e) => return Err(e),
    };
    let limits = &grant.restrictions;
    // A forced command (`command=`, a certificate's force-command) replaces
    // whatever the client asked to run, which is passed on like sshd does.
    let session = |command: Option<String>, client_env, pty: Option<PtySpec>| exec::Session {
        command: limits.command.clone().or(command.clone()),
        extra_env: match (&limits.command, command) {
            (Some(_), Some(original)) => vec![("SSH_ORIGINAL_COMMAND".into(), original)],
            _ => Vec::new(),
        }
        .into_iter()
        .chain(agent.path().map(|p| ("SSH_AUTH_SOCK".to_string(), p.to_string_lossy().into_owned())))
        .collect(),
        client_env,
        pty: pty.filter(|_| !limits.no_pty),
    };
    let files_denied = || Reply::Err("file transfer is not allowed for this key (forced command)".into());
    match request {
        Request::Exec { command, env, pty } => exec::run(send, recv, user, session(command, env, pty), closed).await,
        // Like sshd, through the user's shell, so restricted shells (nologin, git-shell) apply.
        Request::Subsystem { name, env } => match subsystem_command(&state.cfg, &name) {
            Some(cmd) => exec::run(send, recv, user, session(Some(cmd), env, None), closed).await,
            None => write_msg(&mut send, &Reply::Err(format!("subsystem {name:?} is not available"))).await,
        },
        Request::RemoteForward { bind, port } => {
            if !limits.may_listen(&bind, port) {
                return write_msg(&mut send, &Reply::Err(format!("listening on port {port} is not permitted for this key"))).await;
            }
            remote_forward(send, recv, conn.clone(), user, state, &bind, port).await
        }
        Request::Upload { .. } | Request::Download { .. } | Request::UploadTree { .. } | Request::DownloadTree { .. }
            if limits.command.is_some() =>
        {
            write_msg(&mut send, &files_denied()).await
        }
        Request::UploadTree { path, name } => files::upload_tree(send, recv, user, &path, &name).await,
        Request::DownloadTree { path } => files::download_tree(send, user, &path).await,
        Request::DirectTcp { host, port } => {
            if !state.cfg.allow_tcp_forwarding {
                return write_msg(&mut send, &Reply::Err("port forwarding is disabled".into())).await;
            }
            if !limits.may_open(&host, port) {
                return write_msg(&mut send, &Reply::Err(format!("forwarding to {host}:{port} is not permitted for this key"))).await;
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
            files::upload(send, recv, user, &path, &name, size, mode).await
        }
        Request::Download { path } => files::download(send, user, &path).await,
        Request::AgentForward => {
            if !state.cfg.allow_agent_forwarding || limits.no_agent_forwarding {
                return write_msg(&mut send, &Reply::Err("agent forwarding is not allowed".into())).await;
            }
            agent::forward(send, recv, conn.clone(), user, agent).await
        }
        Request::Ping => write_msg(&mut send, &Reply::Ok).await,
        Request::SpeedDown { bytes } => speed_down(send, bytes).await,
        Request::SpeedUp { bytes } => speed_up(send, recv, bytes).await,
    }
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
    state: &State,
    bind: &str,
    port: u16,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    if !state.cfg.allow_tcp_forwarding {
        return write_msg(&mut send, &Reply::Err("port forwarding is disabled".into())).await;
    }
    if port != 0 && port < 1024 && user.uid != 0 {
        return write_msg(&mut send, &Reply::Err(format!("only root may listen on port {port}"))).await;
    }
    let mut listeners = Vec::new();
    let mut bound_port = port;
    let mut last_err = None;
    for mut addr in remote_listen_addrs(state.cfg.gateway_ports, bind, port) {
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
    let code = match run_helper(user, &["internal-pair-take"]).await {
        Ok(code) => code,
        Err(e) => {
            warn!("{addr}: pairing for {} refused: {e:#}", user.name);
            write_msg(&mut send, &Reply::Err(NO_PAIRING.into())).await?;
            return Ok(());
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
