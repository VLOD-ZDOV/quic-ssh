//! Sessions that survive the connection (like mosh): the terminal and its
//! program keep running for `session_timeout` after the client is gone, and
//! a reconnecting client gets the output it missed.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tracing::{debug, info};

use super::exec::{self, Session};
use super::users::User;
use crate::proto::{read_msg_opt, write_msg, ClientMsg, Reply, ServerMsg};
use crate::transport::{RecvHalf, SendHalf};

/// Output kept for a reconnecting client.
const BUFFER: usize = 1 << 20;
/// Persistent sessions per user, attached or not.
const MAX_PER_USER: usize = 16;
const CHUNK: usize = 32 * 1024;

type Token = [u8; 16];

/// Exit status: (code, signal).
type Status = (Option<i32>, Option<i32>);

struct Output {
    /// The last up to [`BUFFER`] bytes of output; `start` is the offset of the first.
    buf: VecDeque<u8>,
    start: u64,
    exit: Option<Status>,
    /// Bumped on every attach, so an older attachment knows it was replaced.
    generation: u64,
    attached: bool,
}

impl Output {
    fn end(&self) -> u64 {
        self.start + self.buf.len() as u64
    }
}

struct Detachable {
    uid: u32,
    /// Process group of the session (its leader's pid).
    group: nix::unistd::Pid,
    writer: tokio::sync::Mutex<pty_process::OwnedWritePty>,
    out: Mutex<Output>,
    /// Signals new output, exit, or a new attachment.
    changed: watch::Sender<()>,
}

/// All persistent sessions of the server.
pub struct Sessions {
    map: Mutex<HashMap<Token, Arc<Detachable>>>,
    timeout: Duration,
}

impl Sessions {
    pub fn new(timeout: Duration) -> Sessions {
        Sessions { map: Mutex::default(), timeout }
    }

    pub fn enabled(&self) -> bool {
        !self.timeout.is_zero()
    }

    /// Starts a terminal session that can be resumed, and attaches `send`/`recv` to it.
    pub async fn start(
        self: &Arc<Self>,
        mut send: SendHalf,
        recv: RecvHalf,
        user: &User,
        mut session: Session,
        closed: watch::Receiver<bool>,
    ) -> Result<()> {
        let count = self.map.lock().unwrap().values().filter(|s| s.uid == user.uid).count();
        if count >= MAX_PER_USER {
            return write_msg(&mut send, &Reply::Err(format!("too many sessions ({MAX_PER_USER}) for this user"))).await;
        }
        let env = session.env(user);
        let spec = session.pty.clone().expect("persistent sessions have a terminal");
        let (mut child, pty) = match exec::spawn_pty(user, session.command.take(), env, &spec) {
            Ok(x) => x,
            Err(e) => return write_msg(&mut send, &Reply::Err(format!("cannot start session: {e:#}"))).await,
        };
        let Some(pid) = child.id() else {
            return write_msg(&mut send, &Reply::Err("session ended at once".into())).await;
        };
        let (mut reader, writer) = pty.into_split();
        let (changed, _) = watch::channel(());
        let sess = Arc::new(Detachable {
            uid: user.uid,
            group: nix::unistd::Pid::from_raw(-(pid as i32)),
            writer: tokio::sync::Mutex::new(writer),
            out: Mutex::new(Output { buf: VecDeque::new(), start: 0, exit: None, generation: 0, attached: false }),
            changed,
        });
        let mut token = Token::default();
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
        self.map.lock().unwrap().insert(token, sess.clone());
        info!("{}: persistent session started", user.name);

        // Output collector: everything the program writes goes into the buffer.
        let collector = {
            let sess = sess.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; CHUNK];
                // EIO is how a PTY master reports that the slave side was closed.
                while let Ok(n @ 1..) = reader.read(&mut buf).await {
                    let mut out = sess.out.lock().unwrap();
                    out.buf.extend(&buf[..n]);
                    let excess = out.buf.len().saturating_sub(BUFFER);
                    out.buf.drain(..excess);
                    out.start += excess as u64;
                    drop(out);
                    sess.changed.send_replace(());
                }
            })
        };
        // Waits for the program, then for the rest of its output.
        {
            let sess = sess.clone();
            tokio::spawn(async move {
                use std::os::unix::process::ExitStatusExt;
                let status = child.wait().await.ok();
                let _ = tokio::time::timeout(exec::DRAIN_GRACE, collector).await;
                sess.out.lock().unwrap().exit = Some(status.map(|s| (s.code(), s.signal())).unwrap_or((None, None)));
                sess.changed.send_replace(());
            });
        }
        self.attach(send, recv, token, sess, 0, closed).await
    }

    /// `Request::Resume`.
    pub async fn resume(
        self: &Arc<Self>,
        mut send: SendHalf,
        recv: RecvHalf,
        user: &User,
        token: &[u8],
        received: u64,
        closed: watch::Receiver<bool>,
    ) -> Result<()> {
        let found = Token::try_from(token).ok().and_then(|t| self.map.lock().unwrap().get(&t).map(|s| (t, s.clone())));
        match found {
            Some((token, sess)) if sess.uid == user.uid => {
                info!("{}: persistent session resumed", user.name);
                self.attach(send, recv, token, sess, received, closed).await
            }
            _ => write_msg(&mut send, &Reply::Err("the session is gone (it ended or timed out)".into())).await,
        }
    }

    /// Whether `token` is a live session of user `uid`.
    pub fn owns(&self, token: &[u8], uid: u32) -> bool {
        Token::try_from(token).ok().and_then(|t| self.map.lock().unwrap().get(&t).map(|s| s.uid == uid)).unwrap_or(false)
    }

    fn remove(&self, token: &Token) {
        self.map.lock().unwrap().remove(token);
    }

    /// Ends a session: hangs up its programs and forgets it.
    async fn hang_up(&self, token: &Token, sess: &Detachable) {
        self.remove(token);
        let mut changed = sess.changed.subscribe();
        let exited = async {
            while sess.out.lock().unwrap().exit.is_none() {
                if changed.changed().await.is_err() {
                    break;
                }
            }
        };
        exec::hang_up_group(sess.group, exited).await;
    }

    /// Streams the session to the client from byte `from` on, and applies its
    /// input, until the session ends, the client leaves, or another attach takes over.
    async fn attach(
        self: &Arc<Self>,
        mut send: SendHalf,
        mut recv: RecvHalf,
        token: Token,
        sess: Arc<Detachable>,
        from: u64,
        mut closed: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut changed = sess.changed.subscribe();
        let generation = {
            let mut out = sess.out.lock().unwrap();
            out.generation += 1;
            out.attached = true;
            out.generation
        };
        // Wake an older attachment so it notices it has been replaced.
        sess.changed.send_replace(());
        changed.mark_changed();
        write_msg(&mut send, &Reply::Session { token: token.to_vec() }).await?;

        let mut sent = from;
        let reason = loop {
            tokio::select! {
                res = changed.changed() => {
                    if res.is_err() {
                        break "session gone";
                    }
                    let (data, exit, lost) = {
                        let out = sess.out.lock().unwrap();
                        if out.generation != generation {
                            return Ok(()); // replaced by a newer attachment
                        }
                        let lost = sent < out.start;
                        sent = sent.max(out.start);
                        let skip = (sent - out.start) as usize;
                        let data: Vec<u8> = out.buf.iter().skip(skip).copied().collect();
                        sent = out.end();
                        (data, out.exit, lost)
                    };
                    if lost {
                        write_msg(&mut send, &ServerMsg::Stderr(b"\r\n[qsh: some output was lost while disconnected]\r\n".to_vec())).await?;
                    }
                    for chunk in data.chunks(CHUNK) {
                        write_msg(&mut send, &ServerMsg::Stdout(chunk.to_vec())).await?;
                    }
                    if let Some((code, signal)) = exit {
                        write_msg(&mut send, &ServerMsg::Exit { code, signal }).await?;
                        let _ = send.shutdown().await;
                        self.remove(&token);
                        return Ok(());
                    }
                }
                msg = read_msg_opt::<_, ClientMsg>(&mut recv) => match msg {
                    Ok(Some(msg)) => {
                        let mut w = sess.writer.lock().await;
                        match msg {
                            ClientMsg::Stdin(data) => { let _ = w.write_all(&data).await; }
                            ClientMsg::Typed { data, .. } if data.is_empty() => {
                                drop(w);
                                write_msg(&mut send, &ServerMsg::Pong(vec![0])).await?;
                            }
                            ClientMsg::Typed { data, .. } => { let _ = w.write_all(&data).await; }
                            ClientMsg::Resize { cols, rows } => { let _ = w.resize(pty_process::Size::new(rows, cols)); }
                            ClientMsg::StdinEof => {}
                            ClientMsg::Hangup => {
                                drop(w);
                                self.hang_up(&token, &sess).await;
                                return Ok(());
                            }
                        }
                    }
                    Err(e) if e.is::<crate::proto::Malformed>() => {}
                    // The stream ended without a hangup: the client is gone.
                    Ok(None) | Err(_) => break "client gone",
                },
                _ = async { closed.wait_for(|c| *c).await.is_ok() } => break "connection closed",
            }
        };
        // Detached: keep the session for a while, unless a newer attachment exists.
        let still_ours = {
            let mut out = sess.out.lock().unwrap();
            let ours = out.generation == generation;
            if ours {
                out.attached = false;
            }
            ours
        };
        if still_ours {
            debug!("persistent session detached ({reason}), kept for {:?}", self.timeout);
            let sessions = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(sessions.timeout).await;
                let abandoned = {
                    let out = sess.out.lock().unwrap();
                    out.generation == generation && !out.attached
                };
                if abandoned {
                    info!("persistent session timed out");
                    sessions.hang_up(&token, &sess).await;
                }
            });
        }
        Ok(())
    }
}
