//! ssh-agent forwarding (`qsh -A`): a Unix socket on the server, owned by the
//! user, whose connections are relayed to the client's agent.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use tokio::task::AbortHandle;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tracing::{debug, warn};

use super::users::User;
use crate::proto::{write_msg, Opened, Reply};
use crate::transport::{Conn, RecvHalf, SendHalf};

/// The forwarded agent socket of one connection, for its sessions' `SSH_AUTH_SOCK`.
#[derive(Default)]
pub struct AgentSocket {
    /// Set while a forwarding is being set up or active (one per connection).
    active: std::sync::atomic::AtomicBool,
    relay: Mutex<Option<Arc<Relay>>>,
}

impl AgentSocket {
    pub fn path(&self) -> Option<PathBuf> {
        self.relay().map(|r| r.path.clone())
    }

    pub fn relay(&self) -> Option<Arc<Relay>> {
        self.relay.lock().unwrap().clone()
    }
}

/// A socket and the connection its clients go to. A persistent session keeps
/// it: its programs have the path in `SSH_AUTH_SOCK`, so a new connection takes
/// over the same socket. While there is none, clients are turned away.
pub struct Relay {
    conn: watch::Sender<Option<Arc<Conn>>>,
    path: PathBuf,
    dir: AgentDir,
    listening: AbortHandle,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.listening.abort();
        cleanup(&self.dir);
    }
}

/// The socket's directory, kept open: cleaning up goes through this
/// descriptor, never through the path inside a directory the user owns
/// (they could swap it for a symlink to make root delete elsewhere).
struct AgentDir {
    fd: std::os::fd::OwnedFd,
    dir: PathBuf,
}

impl AgentDir {
    fn socket(&self) -> PathBuf {
        self.dir.join(SOCKET)
    }
}

const SOCKET: &str = "agent.sock";

/// A fresh private directory with a listening socket in it, both owned by the
/// user. Root creates them in a directory nobody else can enter yet, and only
/// then hands it over, so no path the user controls is ever followed.
fn listen(user: &User) -> Result<(UnixListener, AgentDir)> {
    use nix::fcntl::OFlag;
    // /tmp like sshd: root's own TMPDIR (e.g. on macOS) may be out of the user's reach.
    let template = Path::new("/tmp").join("qsh-XXXXXXXX");
    let dir = nix::unistd::mkdtemp(&template).context("cannot create agent directory")?;
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let fd = match nix::fcntl::open(&dir, flags, nix::sys::stat::Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = std::fs::remove_dir(&dir);
            return Err(e).context("cannot open agent directory");
        }
    };
    let agent_dir = AgentDir { fd, dir };
    let path = agent_dir.socket();
    let dir = &agent_dir.dir;
    let setup = || -> Result<UnixListener> {
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        if user.switches() {
            std::os::unix::fs::chown(&path, Some(user.uid), Some(user.gid))?;
            std::os::unix::fs::chown(dir, Some(user.uid), Some(user.gid))?;
        }
        Ok(listener)
    };
    match setup() {
        Ok(l) => Ok((l, agent_dir)),
        Err(e) => {
            cleanup(&agent_dir);
            Err(e)
        }
    }
}

fn cleanup(d: &AgentDir) {
    use nix::unistd::{unlinkat, UnlinkatFlags};
    // Relative to the directory itself, wherever its path now leads. Then the
    // directory, if its name in /tmp is still a directory (rmdir does not
    // follow a symlink put there instead) and empty.
    let _ = unlinkat(&d.fd, SOCKET, UnlinkatFlags::NoRemoveDir);
    let _ = unlinkat(nix::fcntl::AT_FDCWD, &d.dir, UnlinkatFlags::RemoveDir);
}

/// Serves `Request::AgentForward` until the client closes the request stream.
/// `kept`: the socket of the session this connection resumed, if it has one.
pub async fn forward(mut send: SendHalf, mut recv: RecvHalf, conn: Arc<Conn>, user: &User, socket: &AgentSocket, kept: Option<Arc<Relay>>) -> Result<()> {
    use std::sync::atomic::Ordering;
    if socket.active.swap(true, Ordering::SeqCst) {
        return write_msg(&mut send, &Reply::Err("agent forwarding is already active".into())).await;
    }
    let relay = match kept {
        Some(relay) => relay,
        None => match listen(user) {
            Ok((listener, dir)) => Arc::new(relay(listener, dir, user.uid)),
            Err(e) => {
                socket.active.store(false, Ordering::SeqCst);
                return write_msg(&mut send, &Reply::Err(format!("{e:#}"))).await;
            }
        },
    };
    relay.conn.send_replace(Some(conn.clone()));
    *socket.relay.lock().unwrap() = Some(relay.clone());
    let result = async {
        write_msg(&mut send, &Reply::Ok).await?;
        debug!("{}: agent forwarded at {}", user.name, relay.path.display());
        // Until the client closes the request stream (or the connection is gone).
        let mut probe = [0u8; 1];
        let _ = recv.read(&mut probe).await;
        Ok(())
    }
    .await;
    *socket.relay.lock().unwrap() = None;
    // A new connection may have taken over by now.
    relay.conn.send_if_modified(|c| {
        let ours = c.as_ref().is_some_and(|c| Arc::ptr_eq(c, &conn));
        if ours {
            *c = None;
        }
        ours
    });
    socket.active.store(false, Ordering::SeqCst);
    result
}

fn relay(listener: UnixListener, dir: AgentDir, uid: u32) -> Relay {
    let (conn, current) = watch::channel(None::<Arc<Conn>>);
    let path = dir.socket();
    let task = tokio::spawn(async move {
        loop {
            let sock = match listener.accept().await {
                Ok((sock, _)) => sock,
                Err(e) => {
                    crate::transport::accept_failed(&e).await;
                    continue;
                }
            };
            // Only the user (and root) may use the agent, whatever the file modes say.
            match sock.peer_cred() {
                Ok(c) if c.uid() == uid || c.uid() == 0 => {}
                other => {
                    warn!("refusing agent connection from {other:?}");
                    continue;
                }
            }
            let Some(conn) = current.borrow().clone() else { continue };
            tokio::spawn(async move {
                let result = async {
                    let (mut s, r) = conn.open_bi().await?;
                    write_msg(&mut s, &Opened::Agent).await?;
                    let (sr, sw) = sock.into_split();
                    crate::transport::bridge(sr, sw, s, r).await
                }
                .await;
                if let Err(e) = result {
                    debug!("forwarded agent connection: {e:#}");
                }
            });
        }
    });
    Relay { conn, path, dir, listening: task.abort_handle() }
}
