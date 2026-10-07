//! Sessions that survive the connection (like mosh): the terminal and its
//! program keep running for `session_timeout` after the client is gone, and
//! a reconnecting client gets the output it missed.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info};

use super::exec::{self, Session};
use super::users::User;
use crate::authkeys::Restrictions;
use crate::proto::{write_msg, ClientMsg, Reader, Reply, ServerMsg};
use crate::transport::{RecvHalf, SendHalf};

/// Output kept for a reconnecting client.
const BUFFER: usize = 1 << 20;
/// Persistent sessions per user and in total, attached or not.
const MAX_PER_USER: usize = 16;
const MAX_TOTAL: usize = 256;
/// Input waiting for a program that does not read it; more is dropped.
const MAX_PENDING_INPUT: usize = 1 << 20;
/// How long a finished session waits for its client to fetch the end.
const KEEP_FINISHED: Duration = Duration::from_secs(300);
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

/// Input for the terminal, applied in order by the session's input task.
enum Input {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

struct Detachable {
    uid: u32,
    /// What the key that started the session was allowed; resuming needs the same.
    restrictions: Restrictions,
    input: mpsc::UnboundedSender<Input>,
    pending_input: Arc<AtomicUsize>,
    /// Asks the task that owns the child to hang up the session.
    kill: Mutex<Option<oneshot::Sender<()>>>,
    out: Mutex<Output>,
    /// Signals new output, exit, or a new attachment.
    changed: watch::Sender<()>,
}

impl Detachable {
    fn send_input(&self, input: Input) {
        let len = match &input {
            Input::Data(d) => d.len(),
            Input::Resize { .. } => 0,
        };
        // A program that does not read its terminal must not make us buffer without limit.
        if self.pending_input.fetch_add(len, Ordering::SeqCst) + len > MAX_PENDING_INPUT {
            self.pending_input.fetch_sub(len, Ordering::SeqCst);
            return;
        }
        let _ = self.input.send(input);
    }
}

/// All persistent sessions of the server.
pub struct Sessions {
    map: Mutex<Map>,
    timeout: Duration,
}

#[derive(Default)]
struct Map {
    sessions: HashMap<Token, Arc<Detachable>>,
    /// Sessions per uid, counted from the moment one is about to start.
    per_user: HashMap<u32, usize>,
    total: usize,
}

impl Map {
    fn release(&mut self, uid: u32) {
        self.total -= 1;
        if let Some(n) = self.per_user.get_mut(&uid) {
            *n -= 1;
            if *n == 0 {
                self.per_user.remove(&uid);
            }
        }
    }
}

/// Why an attachment stopped.
enum Detach {
    /// The session is over (or another attachment took over): nothing to keep.
    Done,
    /// The client is gone: keep the session for a reconnect.
    Lost(&'static str),
}

impl Sessions {
    pub fn new(timeout: Duration) -> Sessions {
        Sessions { map: Mutex::default(), timeout }
    }

    pub fn enabled(&self) -> bool {
        !self.timeout.is_zero()
    }

    /// Whether `token` is a live session of user `uid`.
    pub fn owns(&self, token: &[u8], uid: u32) -> bool {
        Token::try_from(token)
            .ok()
            .and_then(|t| self.map.lock().unwrap().sessions.get(&t).map(|s| s.uid == uid))
            .unwrap_or(false)
    }

    fn remove(&self, token: &Token) {
        let mut map = self.map.lock().unwrap();
        if let Some(s) = map.sessions.remove(token) {
            map.release(s.uid);
        }
    }

    /// Starts a terminal session that can be resumed, and attaches `send`/`recv` to it.
    pub async fn start(
        self: &Arc<Self>,
        mut send: SendHalf,
        recv: RecvHalf,
        user: &User,
        restrictions: &Restrictions,
        mut session: Session,
        closed: watch::Receiver<bool>,
    ) -> Result<()> {
        // Reserve a slot first, so concurrent requests cannot all pass the check.
        let reserved = {
            let mut map = self.map.lock().unwrap();
            let mine = map.per_user.get(&user.uid).copied().unwrap_or(0);
            if mine >= MAX_PER_USER || map.total >= MAX_TOTAL {
                false
            } else {
                *map.per_user.entry(user.uid).or_default() += 1;
                map.total += 1;
                true
            }
        };
        if !reserved {
            return write_msg(&mut send, &Reply::Err(format!("too many sessions (at most {MAX_PER_USER} per user)"))).await;
        }
        let env = session.env(user);
        let spec = session.pty.clone().expect("persistent sessions have a terminal");
        let (mut child, pty, tty) = match exec::spawn_pty(user, session.command.take(), env, &spec) {
            Ok(x) => x,
            Err(e) => {
                self.map.lock().unwrap().release(user.uid);
                return write_msg(&mut send, &Reply::Err(format!("cannot start session: {e:#}"))).await;
            }
        };
        let record = exec::login_record(user, &tty, &child, session.remote);
        let (mut reader, mut writer) = pty.into_split();
        let (input_tx, mut input_rx) = mpsc::unbounded_channel();
        let (kill_tx, kill_rx) = oneshot::channel();
        let (changed, _) = watch::channel(());
        let pending_input = Arc::new(AtomicUsize::new(0));
        let sess = Arc::new(Detachable {
            uid: user.uid,
            restrictions: restrictions.clone(),
            input: input_tx,
            pending_input: pending_input.clone(),
            kill: Mutex::new(Some(kill_tx)),
            out: Mutex::new(Output { buf: VecDeque::new(), start: 0, exit: None, generation: 0, attached: false }),
            changed,
        });
        let mut token = Token::default();
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
        self.map.lock().unwrap().sessions.insert(token, sess.clone());
        info!("{}: persistent session started", user.name);

        // Input: written by its own task, so a program that stops reading
        // cannot block the attachment (output, pings, detaching).
        tokio::spawn(async move {
            while let Some(input) = input_rx.recv().await {
                match input {
                    Input::Data(data) => {
                        let _ = writer.write_all(&data).await;
                        pending_input.fetch_sub(data.len(), Ordering::SeqCst);
                    }
                    Input::Resize { cols, rows } => {
                        let _ = writer.resize(pty_process::Size::new(rows, cols));
                    }
                }
            }
        });
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
        // The only owner of the child: waits for it, or hangs it up on request.
        // Signals go through `child`, which never addresses a reaped (and
        // possibly reused) process ID.
        {
            let (sessions, sess) = (self.clone(), sess.clone());
            tokio::spawn(async move {
                use std::os::unix::process::ExitStatusExt;
                let status = tokio::select! {
                    s = child.wait() => s.ok(),
                    _ = kill_rx => {
                        exec::hang_up(&mut child).await;
                        None
                    }
                };
                drop(record); // the logout
                let _ = tokio::time::timeout(exec::DRAIN_GRACE, collector).await;
                let attached = {
                    let mut out = sess.out.lock().unwrap();
                    out.exit = Some(status.map(|s| (s.code(), s.signal())).unwrap_or((None, None)));
                    out.attached
                };
                sess.changed.send_replace(());
                // Nobody is there to collect the end: keep it only for a while.
                if !attached {
                    tokio::time::sleep(KEEP_FINISHED.min(sessions.timeout)).await;
                    if !sess.out.lock().unwrap().attached {
                        sessions.remove(&token);
                    }
                }
            });
        }
        self.attach(send, recv, token, sess, 0, closed).await
    }

    /// `Request::Resume`: only for the same user, with the same restrictions
    /// as the key that started the session.
    #[allow(clippy::too_many_arguments)]
    pub async fn resume(
        self: &Arc<Self>,
        mut send: SendHalf,
        recv: RecvHalf,
        user: &User,
        restrictions: &Restrictions,
        token: &[u8],
        received: u64,
        closed: watch::Receiver<bool>,
    ) -> Result<()> {
        let found = Token::try_from(token).ok().and_then(|t| self.map.lock().unwrap().sessions.get(&t).map(|s| (t, s.clone())));
        match found {
            Some((token, sess)) if sess.uid == user.uid && &sess.restrictions == restrictions => {
                info!("{}: persistent session resumed", user.name);
                self.attach(send, recv, token, sess, received, closed).await
            }
            _ => write_msg(&mut send, &Reply::Err(GONE.into())).await,
        }
    }

    /// Ends a session: hangs up its programs (through the task that owns
    /// them) and forgets it.
    async fn hang_up(&self, token: &Token, sess: &Detachable) {
        self.remove(token);
        let kill = sess.kill.lock().unwrap().take();
        if let Some(kill) = kill {
            let _ = kill.send(());
        }
    }

    /// Streams the session to the client from byte `from` on, and applies its
    /// input, until the session ends, the client leaves, or another attach
    /// takes over. Whatever happens, a lost client leaves the session detached
    /// with its timeout running.
    async fn attach(
        self: &Arc<Self>,
        send: SendHalf,
        recv: RecvHalf,
        token: Token,
        sess: Arc<Detachable>,
        from: u64,
        closed: watch::Receiver<bool>,
    ) -> Result<()> {
        let generation = {
            let mut out = sess.out.lock().unwrap();
            out.generation += 1;
            out.attached = true;
            out.generation
        };
        // Wake an older attachment so it notices it has been replaced.
        sess.changed.send_replace(());
        let outcome = self.serve(send, recv, token, &sess, generation, from, closed).await;
        let reason = match outcome {
            Ok(Detach::Done) => return Ok(()),
            Ok(Detach::Lost(reason)) => reason.to_string(),
            Err(e) => format!("{e:#}"),
        };
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

    #[allow(clippy::too_many_arguments)]
    async fn serve(
        &self,
        mut send: SendHalf,
        recv: RecvHalf,
        token: Token,
        sess: &Detachable,
        generation: u64,
        from: u64,
        mut closed: watch::Receiver<bool>,
    ) -> Result<Detach> {
        // Output wakes the loop below all the time: client messages are read
        // in a task, so a frame is never cut short (see `Reader`).
        let mut incoming = Reader::<ClientMsg>::spawn(recv);
        let mut changed = sess.changed.subscribe();
        changed.mark_changed();
        write_msg(&mut send, &Reply::Session { token: token.to_vec() }).await?;
        let mut sent = from;
        loop {
            tokio::select! {
                res = changed.changed() => {
                    if res.is_err() {
                        return Ok(Detach::Done);
                    }
                    let (data, exit, lost) = {
                        let out = sess.out.lock().unwrap();
                        if out.generation != generation {
                            return Ok(Detach::Done); // replaced by a newer attachment
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
                        return Ok(Detach::Done);
                    }
                }
                msg = incoming.next() => match msg {
                    Ok(Some(ClientMsg::Stdin(data))) => sess.send_input(Input::Data(data)),
                    // Chaff gets an echo-sized reply, like in other sessions.
                    Ok(Some(ClientMsg::Typed { data, .. })) if data.is_empty() => write_msg(&mut send, &ServerMsg::Pong(vec![0])).await?,
                    Ok(Some(ClientMsg::Typed { data, .. })) => sess.send_input(Input::Data(data)),
                    Ok(Some(ClientMsg::Resize { cols, rows })) => sess.send_input(Input::Resize { cols, rows }),
                    Ok(Some(ClientMsg::StdinEof)) => {}
                    // Hang up, then report the exit like any other end, so the
                    // client knows the hangup arrived before it disconnects.
                    Ok(Some(ClientMsg::Hangup)) => self.hang_up(&token, sess).await,
                    Err(e) if e.is::<crate::proto::Malformed>() => {}
                    // The stream ended without a hangup: the client is gone.
                    Ok(None) | Err(_) => return Ok(Detach::Lost("client gone")),
                },
                _ = async { closed.wait_for(|c| *c).await.is_ok() } => return Ok(Detach::Lost("connection closed")),
            }
        }
    }
}

/// The answer when a session cannot be resumed.
pub const GONE: &str = "the session is gone (it ended or timed out)";
