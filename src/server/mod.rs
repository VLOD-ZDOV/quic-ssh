//! The `qshd` daemon.

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

use crate::config::ServerConfig;
use crate::keys::{qsh_dir, read_key_list_strict, Identity, PublicKey};
use crate::proto::{read_msg, valid_user_name, write_msg, Hello, Reply, Request, MIN_VERSION, VERSION};
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

/// Binds the configured address on UDP and TCP. If the default dual-stack
/// address is unavailable (IPv6 disabled), falls back to IPv4.
pub async fn bind(cfg: &ServerConfig, host: &Identity) -> Result<Listener> {
    let tls = crate::tls::server_config(host)?;
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
    let state = Arc::new(State { cfg, host_key: host.public() });
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

/// Checks the key against the user's authorized_keys files.
fn authorize(state: &State, user: &User, key: PublicKey) -> bool {
    let mut files = vec![qsh_dir(&user.home).join("authorized_keys")];
    if state.cfg.use_ssh_authorized_keys {
        files.push(user.home.join(".ssh").join("authorized_keys"));
    }
    files.iter().any(|path| match read_key_list_strict(path, &user.home, user.uid) {
        Ok(keys) => keys.contains(&key),
        Err(e) => {
            warn!("ignoring {}: {e:#}", path.display());
            false
        }
    })
}

async fn handle_conn(conn: &Conn, state: Arc<State>, startup: Startup) -> Result<()> {
    let addr = conn.remote_addr();
    let key = conn.peer_key();
    let (mut send, recv, hello) = tokio::time::timeout(HELLO_TIMEOUT, async {
        let (send, mut recv) = conn.accept_bi().await.context("closed before hello")?;
        let hello: Hello = read_msg(&mut recv).await?;
        anyhow::Ok((send, recv, hello))
    })
    .await
    .context("no hello in time")??;

    let (name, pairing) = match hello {
        Hello::Login { version, user } | Hello::Pair { version, user } if !(MIN_VERSION..=VERSION).contains(&version) => {
            write_msg(&mut send, &Reply::Err(format!("unsupported protocol version {version}"))).await?;
            bail!("client {user:?} uses protocol version {version}");
        }
        Hello::Login { user, .. } => (user, false),
        Hello::Pair { user, .. } => (user, true),
    };
    let looked_up = if valid_user_name(&name) {
        User::lookup(&name)
    } else {
        Err(anyhow::anyhow!("invalid user name"))
    };
    let user = match looked_up {
        Ok(u) => u,
        Err(e) => {
            warn!("{addr}: rejected user {name:?}: {e:#}");
            // Same answers as for an existing user, so names cannot be probed.
            let msg = if pairing { NO_PAIRING } else { "access denied" };
            write_msg(&mut send, &Reply::Err(msg.into())).await?;
            return Ok(());
        }
    };

    if pairing {
        return pair(conn, &state, &user, send, recv).await;
    }
    if !authorize(&state, &user, key) {
        warn!("{addr}: key {} not authorized for {name}", key.fingerprint());
        write_msg(&mut send, &Reply::Err("access denied".into())).await?;
        return Ok(());
    }
    info!("{addr}: {name} logged in with {} over {}", key.fingerprint(), conn.transport_name());
    write_msg(&mut send, &Reply::Ok).await?;
    drop(startup);

    let user = Arc::new(user);
    // Lets running sessions notice a dead connection even after the client
    // finished sending on their stream.
    let (closed_tx, closed_rx) = watch::channel(false);
    while let Some((send, recv)) = conn.accept_bi().await {
        let (user, state, closed) = (user.clone(), state.clone(), closed_rx.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, &user, &state, closed).await {
                debug!("{addr}: stream error: {e:#}");
            }
        });
    }
    let _ = closed_tx.send(true);
    info!("{addr}: {name} disconnected");
    Ok(())
}

async fn handle_stream(
    mut send: SendHalf,
    mut recv: RecvHalf,
    user: &User,
    state: &State,
    closed: watch::Receiver<bool>,
) -> Result<()> {
    match read_msg(&mut recv).await? {
        Request::Exec { command, env, pty } => exec::run(send, recv, user, command, env, pty, closed).await,
        Request::DirectTcp { host, port } => {
            if !state.cfg.allow_tcp_forwarding {
                return write_msg(&mut send, &Reply::Err("port forwarding is disabled".into())).await;
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
        Request::Ping => write_msg(&mut send, &Reply::Ok).await,
        Request::SpeedDown { bytes } => speed_down(send, bytes).await,
        Request::SpeedUp { bytes } => speed_up(send, recv, bytes).await,
    }
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

async fn pair(conn: &Conn, state: &State, user: &User, mut send: SendHalf, mut recv: RecvHalf) -> Result<()> {
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
