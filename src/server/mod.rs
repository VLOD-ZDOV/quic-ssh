//! The `qshd` daemon.

mod exec;
mod files;
pub mod helpers;
mod users;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

use crate::config::ServerConfig;
use crate::keys::{qsh_dir, read_key_list_strict, Identity, PublicKey};
use crate::proto::{read_msg, write_msg, Hello, Reply, Request, VERSION};
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

/// Binds the configured address on UDP and TCP. If the default dual-stack
/// address is unavailable (IPv6 disabled), falls back to IPv4.
pub async fn bind(cfg: &ServerConfig, host: &Identity) -> Result<Listener> {
    let tls = crate::tls::server_config(host)?;
    match Listener::bind(cfg.listen, tls.clone()).await {
        Err(e) if cfg.listen.ip() == Ipv6Addr::UNSPECIFIED => {
            debug!("dual-stack bind failed ({e:#}), using IPv4 only");
            Listener::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), cfg.listen.port()), tls).await
        }
        other => other,
    }
}

pub async fn serve(listener: Listener, cfg: ServerConfig, host: &Identity) -> Result<()> {
    let limit = Arc::new(Semaphore::new(cfg.max_connections));
    let state = Arc::new(State { cfg, host_key: host.public() });
    loop {
        let incoming = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            warn!("connection limit reached, dropping {}", incoming.remote_addr());
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let addr = incoming.remote_addr();
            match incoming.handshake().await {
                Ok(conn) => {
                    if let Err(e) = handle_conn(&conn, state).await {
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

async fn handle_conn(conn: &Conn, state: Arc<State>) -> Result<()> {
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
        Hello::Login { version, user } | Hello::Pair { version, user } if version != VERSION => {
            write_msg(&mut send, &Reply::Err(format!("unsupported protocol version {version}"))).await?;
            bail!("client {user:?} uses protocol version {version}");
        }
        Hello::Login { user, .. } => (user, false),
        Hello::Pair { user, .. } => (user, true),
    };
    let user = match User::lookup(&name) {
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
    }
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
