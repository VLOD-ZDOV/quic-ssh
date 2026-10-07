//! ssh-agent forwarding (`qsh -A`): a Unix socket on the server, owned by the
//! user, whose connections are relayed to the client's agent.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tracing::{debug, warn};

use super::users::User;
use crate::proto::{write_msg, Opened, Reply};
use crate::transport::{Conn, RecvHalf, SendHalf};

/// The forwarded agent socket of one connection, for its sessions' `SSH_AUTH_SOCK`.
#[derive(Default)]
pub struct AgentSocket(Mutex<Option<PathBuf>>);

impl AgentSocket {
    pub fn path(&self) -> Option<PathBuf> {
        self.0.lock().unwrap().clone()
    }
}

/// A fresh private directory with a listening socket in it, both owned by the
/// user. Root creates them in a directory nobody else can enter yet, and only
/// then hands it over, so no path the user controls is ever followed.
fn listen(user: &User) -> Result<(UnixListener, PathBuf)> {
    let template = std::env::temp_dir().join("qsh-XXXXXXXX");
    let dir = nix::unistd::mkdtemp(&template).context("cannot create agent directory")?;
    let path = dir.join("agent.sock");
    let setup = || -> Result<UnixListener> {
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        if user.switches() {
            std::os::unix::fs::chown(&path, Some(user.uid), Some(user.gid))?;
            std::os::unix::fs::chown(&dir, Some(user.uid), Some(user.gid))?;
        }
        Ok(listener)
    };
    match setup() {
        Ok(l) => Ok((l, path)),
        Err(e) => {
            cleanup(&path);
            Err(e)
        }
    }
}

fn cleanup(path: &Path) {
    // unlink and rmdir never follow links, even if the user swapped the socket.
    let _ = std::fs::remove_file(path);
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir(dir);
    }
}

/// Serves `Request::AgentForward` until the client closes the request stream.
pub async fn forward(mut send: SendHalf, mut recv: RecvHalf, conn: Arc<Conn>, user: &User, socket: &AgentSocket) -> Result<()> {
    if socket.path().is_some() {
        return write_msg(&mut send, &Reply::Err("agent forwarding is already active".into())).await;
    }
    let (listener, path) = match listen(user) {
        Ok(x) => x,
        Err(e) => return write_msg(&mut send, &Reply::Err(format!("{e:#}"))).await,
    };
    *socket.0.lock().unwrap() = Some(path.clone());
    write_msg(&mut send, &Reply::Ok).await?;
    debug!("{}: agent forwarded at {}", user.name, path.display());

    let uid = user.uid;
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((sock, _)) = accepted else { break };
                // Only the user (and root) may use the agent, whatever the file modes say.
                match sock.peer_cred() {
                    Ok(c) if c.uid() == uid || c.uid() == 0 => {}
                    other => {
                        warn!("refusing agent connection from {other:?}");
                        continue;
                    }
                }
                let conn = conn.clone();
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
            // The client closed the request stream (or the connection is gone).
            _ = recv.read(&mut probe) => break,
        }
    }
    *socket.0.lock().unwrap() = None;
    cleanup(&path);
    Ok(())
}
