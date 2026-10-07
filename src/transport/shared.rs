//! Connection sharing (like ssh's `ControlMaster`): the qsh that holds a
//! connection listens on a Unix socket, and later qsh runs for the same
//! `user@host:port` open their streams through it. They skip the handshake
//! and the login, and each stream behaves exactly like one of its own.
//!
//! On the socket, every connection starts with a [`MuxRequest`]. `Open` is
//! answered with `MuxReply::Opened`, after which the socket carries the raw
//! bytes of a new stream on the shared connection, with half-closes passed on.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{watch, Notify};
use tracing::debug;

use super::{Conn, Inner, RecvHalf, SendHalf};
use crate::keys::PublicKey;
use crate::proto::{read_msg, write_msg};

/// Changes whenever the messages below change; a master and a client of
/// different versions do not share (the client connects on its own).
const MUX_VERSION: u32 = 1;
/// How long a client waits for a master's answer before connecting on its own.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Serialize, Deserialize, Debug)]
pub enum MuxRequest {
    /// Describe the connection; the socket then stays open until the
    /// connection ends (that is how clients notice the master is gone).
    Info { version: u32 },
    /// Open a stream on the shared connection.
    Open,
    /// End the master now (`-O exit`).
    Exit,
    /// Stop accepting new clients (`-O stop`).
    Stop,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MuxReply {
    Info { version: u32, server_version: u32, remote: SocketAddr, transport: String, peer_key: [u8; 32], pid: u32 },
    Opened,
    Ok,
    Err(String),
}

/// Client side: a connection whose streams go through a master.
pub struct SharedConn {
    path: PathBuf,
    alive: watch::Receiver<bool>,
    transport: &'static str,
}

impl SharedConn {
    pub async fn open_bi(&self) -> Result<(SendHalf, RecvHalf)> {
        let mut sock = UnixStream::connect(&self.path).await.context("connection master is gone")?;
        write_msg(&mut sock, &MuxRequest::Open).await?;
        match tokio::time::timeout(ANSWER_TIMEOUT, read_msg(&mut sock)).await.context("connection master does not answer")?? {
            MuxReply::Opened => {}
            MuxReply::Err(e) => bail!("{e}"),
            other => bail!("unexpected answer from the connection master: {other:?}"),
        }
        let (r, w) = sock.into_split();
        Ok((Box::new(w), Box::new(r)))
    }

    pub fn transport(&self) -> &'static str {
        self.transport
    }

    pub async fn closed(&self) {
        let mut alive = self.alive.clone();
        let _ = alive.wait_for(|a| !*a).await;
    }
}

/// Uses the master listening on `path`, if there is one that works.
pub async fn attach(path: &Path) -> Option<Conn> {
    match tokio::time::timeout(ANSWER_TIMEOUT, try_attach(path)).await {
        Ok(Ok(conn)) => Some(conn),
        Ok(Err(e)) => {
            debug!("not sharing a connection through {}: {e:#}", path.display());
            None
        }
        Err(_) => {
            debug!("connection master at {} does not answer", path.display());
            None
        }
    }
}

async fn try_attach(path: &Path) -> Result<Conn> {
    let mut control = UnixStream::connect(path).await?;
    write_msg(&mut control, &MuxRequest::Info { version: MUX_VERSION }).await?;
    let MuxReply::Info { version, server_version, remote, transport, peer_key, pid } = read_msg(&mut control).await? else {
        bail!("unexpected answer");
    };
    if version != MUX_VERSION {
        bail!("the master uses sharing version {version}, this qsh {MUX_VERSION}");
    }
    let (alive_tx, alive) = watch::channel(true);
    // The master closes this socket when its connection ends.
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 64];
        while matches!(control.read(&mut buf).await, Ok(n) if n > 0) {}
        let _ = alive_tx.send(false);
    });
    let transport = match transport.as_str() {
        "quic" => "quic, shared",
        "tcp" => "tcp, shared",
        _ => "shared",
    };
    debug!("sharing the connection of qsh process {pid} to {remote} ({transport})");
    Ok(Conn {
        inner: Inner::Shared(SharedConn { path: path.to_path_buf(), alive, transport }),
        peer_key: PublicKey(peer_key),
        exporter: [0; 32],
        remote,
        hops: Vec::new(),
        server_version,
        host_cert: None,
    })
}

/// `-O` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Check,
    Exit,
    Stop,
}

/// Sends a control command to the master at `path`; returns its process id.
pub async fn control(path: &Path, command: Command) -> Result<u32> {
    let connect = async {
        let mut sock = UnixStream::connect(path).await?;
        write_msg(&mut sock, &MuxRequest::Info { version: MUX_VERSION }).await?;
        let MuxReply::Info { pid, .. } = read_msg(&mut sock).await? else { bail!("unexpected answer") };
        let request = match command {
            Command::Check => return Ok(pid),
            Command::Exit => MuxRequest::Exit,
            Command::Stop => MuxRequest::Stop,
        };
        let mut sock = UnixStream::connect(path).await?;
        write_msg(&mut sock, &request).await?;
        match read_msg(&mut sock).await? {
            MuxReply::Ok => Ok(pid),
            MuxReply::Err(e) => bail!("{e}"),
            other => bail!("unexpected answer {other:?}"),
        }
    };
    tokio::time::timeout(ANSWER_TIMEOUT, connect)
        .await
        .context("the master does not answer")?
        .with_context(|| format!("control socket {}", path.display()))
}

/// The master's socket file; removed only while it is still ours (after
/// `-O stop` another master may have taken the name).
struct SocketFile {
    path: PathBuf,
    ino: u64,
}

impl SocketFile {
    fn remove(&self) {
        use std::os::unix::fs::MetadataExt;
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.ino) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Master side: serves the connection to other qsh runs.
pub struct Master {
    file: Arc<SocketFile>,
    /// Streams currently open for clients.
    active: Arc<AtomicUsize>,
    /// Signalled whenever a stream ends, and on `-O exit`.
    changed: Arc<Notify>,
    exit: Arc<watch::Sender<bool>>,
    accepting: tokio::task::JoinHandle<()>,
}

/// Another master already listens at the path.
#[derive(Debug)]
pub struct InUse;

impl std::fmt::Display for InUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("another qsh already shares a connection there")
    }
}

impl std::error::Error for InUse {}

/// Binds `path` the way ssh does: on a temporary name first, then a hard
/// link to the real name, so two qsh starting at once cannot both win. A
/// leftover socket whose master died is replaced.
fn bind(path: &Path) -> Result<(UnixListener, SocketFile)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Short: socket paths are limited to about 100 bytes.
    let tmp = path.with_extension(format!("{:08x}", rand::random::<u32>()));
    let listener = UnixListener::bind(&tmp).with_context(|| format!("cannot listen on {}", tmp.display()))?;
    let result = (|| {
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        for attempt in 0..2 {
            match std::fs::hard_link(&tmp, path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                    match std::os::unix::net::UnixStream::connect(path) {
                        Ok(_) => return Err(InUse.into()),
                        Err(_) => {
                            debug!("removing stale control socket {}", path.display());
                            let _ = std::fs::remove_file(path);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(InUse.into()),
                Err(e) => return Err(anyhow::Error::from(e).context(format!("cannot create {}", path.display()))),
            }
        }
        Err(InUse.into())
    })();
    let ino = std::fs::symlink_metadata(&tmp).map(|m| m.ino());
    let _ = std::fs::remove_file(&tmp);
    result?;
    Ok((listener, SocketFile { path: path.to_path_buf(), ino: ino? }))
}

impl Master {
    /// Starts sharing `conn` at `path`. Fails with [`InUse`] if another
    /// master is there.
    pub fn start(conn: Arc<Conn>, path: &Path) -> Result<Master> {
        let (listener, file) = bind(path)?;
        let file = Arc::new(file);
        let active = Arc::new(AtomicUsize::new(0));
        let changed = Arc::new(Notify::new());
        let (exit, exit_rx) = watch::channel(false);
        let exit = Arc::new(exit);
        let accepting = {
            let (active, changed, exit, file) = (active.clone(), changed.clone(), exit.clone(), file.clone());
            tokio::spawn(async move {
                let me = nix::unistd::geteuid().as_raw();
                loop {
                    let sock = tokio::select! {
                        s = listener.accept() => match s {
                            Ok((s, _)) => s,
                            Err(_) => break,
                        },
                        () = conn.closed() => break,
                    };
                    // The socket's directory is private; this is a second check.
                    match sock.peer_cred() {
                        Ok(c) if c.uid() == me => {}
                        _ => continue,
                    }
                    let (conn, active, changed, exit, exit_rx) = (conn.clone(), active.clone(), changed.clone(), exit.clone(), exit_rx.clone());
                    let file = file.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_client(sock, &conn, &active, &changed, &exit, exit_rx, &file).await {
                            debug!("shared connection client: {e:#}");
                        }
                    });
                }
                // The connection is gone: wake whoever waits for the end.
                changed.notify_waiters();
            })
        };
        Ok(Master { file, active, changed, exit, accepting })
    }

    /// Stops accepting new clients (streams already open keep working).
    pub fn stop_accepting(&self) {
        self.accepting.abort();
        self.file.remove();
    }

    /// Waits until no client has a stream open any more, the connection is
    /// gone, or `-O exit` was sent. With `linger`, the master stays this long
    /// after the last stream ended (`None` = until `-O exit` or the connection ends).
    pub async fn wait_idle(&self, conn: &Conn, linger: Option<Option<Duration>>) {
        let exit = self.exit.subscribe();
        loop {
            if *exit.borrow() {
                break;
            }
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let idle = self.active.load(Ordering::SeqCst) == 0;
            let wait_for_quiet = async {
                match (idle, linger) {
                    (true, None) => {}
                    (true, Some(Some(d))) => tokio::time::sleep(d).await,
                    _ => std::future::pending().await,
                }
            };
            let mut exit = exit.clone();
            tokio::select! {
                () = wait_for_quiet => {
                    if self.active.load(Ordering::SeqCst) == 0 {
                        break;
                    }
                }
                () = notified => {}
                () = conn.closed() => break,
                _ = exit.wait_for(|e| *e) => break,
            }
        }
    }

    /// Resolves once `-O exit` was sent.
    pub async fn exit_requested(&self) {
        let mut exit = self.exit.subscribe();
        let _ = exit.wait_for(|e| *e).await;
    }

    /// Streams clients have open right now.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

impl Drop for Master {
    fn drop(&mut self) {
        self.stop_accepting();
    }
}

async fn serve_client(
    mut sock: UnixStream,
    conn: &Arc<Conn>,
    active: &Arc<AtomicUsize>,
    changed: &Notify,
    exit: &watch::Sender<bool>,
    mut exit_rx: watch::Receiver<bool>,
    file: &SocketFile,
) -> Result<()> {
    let request: MuxRequest = tokio::time::timeout(ANSWER_TIMEOUT, read_msg(&mut sock)).await.context("no request")??;
    match request {
        MuxRequest::Info { .. } => {
            let transport = match conn.transport_name() {
                "quic" => "quic",
                "tcp" => "tcp",
                _ => "other",
            };
            let info = MuxReply::Info {
                version: MUX_VERSION,
                server_version: conn.server_version(),
                remote: conn.remote_addr(),
                transport: transport.into(),
                peer_key: conn.peer_key().0,
                pid: std::process::id(),
            };
            write_msg(&mut sock, &info).await?;
            // Held open until the connection (or the master) ends.
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1];
            tokio::select! {
                () = conn.closed() => {}
                _ = sock.read(&mut buf) => {}
                _ = exit_rx.wait_for(|e| *e) => {}
            }
        }
        MuxRequest::Open => {
            let (send, recv) = match conn.open_bi().await {
                Ok(s) => s,
                Err(e) => return write_msg(&mut sock, &MuxReply::Err(format!("{e:#}"))).await,
            };
            write_msg(&mut sock, &MuxReply::Opened).await?;
            active.fetch_add(1, Ordering::SeqCst);
            let (r, w) = sock.into_split();
            let result = super::bridge(r, w, send, recv).await;
            active.fetch_sub(1, Ordering::SeqCst);
            changed.notify_waiters();
            result?;
        }
        MuxRequest::Exit => {
            write_msg(&mut sock, &MuxReply::Ok).await?;
            file.remove();
            let _ = exit.send(true);
            changed.notify_waiters();
        }
        MuxRequest::Stop => {
            write_msg(&mut sock, &MuxReply::Ok).await?;
            file.remove();
        }
    }
    Ok(())
}
