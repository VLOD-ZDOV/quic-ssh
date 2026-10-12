//! Sessions that survive the connection (like mosh): the terminal and its
//! program keep running for `session_timeout` after the client is gone, and
//! a reconnecting client gets the output it missed.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::{mpsc, oneshot, watch, Notify};
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
/// Input waiting for a program that does not read it; beyond this, the
/// client's messages wait (flow control then holds the client back).
const MAX_PENDING_INPUT: usize = 1 << 20;
/// What a resize counts as input, so those cannot pile up without limit.
const RESIZE_COST: usize = 64;
/// While detached, output beyond the buffer is still taken so the program
/// goes on, dropping the oldest, but one chunk per this at most: a program
/// like `yes` must not keep a core busy for nobody.
const DETACHED_PACE: Duration = Duration::from_millis(20);
/// The longest wait for the rest of the output after the program exited
/// (see [`drain`]).
const DRAIN_LIMIT: Duration = Duration::from_secs(60);
/// How long a finished session waits for its client to fetch the end.
const KEEP_FINISHED: Duration = Duration::from_secs(300);
const CHUNK: usize = 32 * 1024;
/// Output read ahead of an attached client; the rest of the buffer is what
/// it already got, for a reconnect. More would scroll by after a ^C.
const READ_AHEAD: u64 = 2 * CHUNK as u64;

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
    /// Output up to here went to the attached client. The program waits
    /// while [`READ_AHEAD`] bytes have not, so nothing is dropped meanwhile.
    sent: u64,
    /// A resuming client says how many bytes it got, which is behind our
    /// offsets by what was dropped while it was away.
    skew: u64,
    /// When output was last read, and whether reading waits for the client
    /// (see [`drain`]).
    last_read: Instant,
    waiting: bool,
    /// Since when nobody is attached (see [`Sessions::evict`]).
    detached_at: Instant,
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
    pending_input: AtomicUsize,
    /// Signals that input was written, or output sent to the client.
    input_taken: Notify,
    output_taken: Notify,
    /// For the attached client.
    pacing: exec::Pacing,
    /// Asks the task that owns the child to hang up the session.
    kill: Mutex<Option<oneshot::Sender<()>>>,
    out: Mutex<Output>,
    /// Signals new output, exit, or a new attachment.
    changed: watch::Sender<()>,
}

impl Input {
    fn cost(&self) -> usize {
        match self {
            Input::Data(d) => d.len(),
            Input::Resize { .. } => RESIZE_COST,
        }
    }
}

impl Detachable {
    fn send_input(&self, input: Input) {
        let cost = input.cost();
        self.pending_input.fetch_add(cost, Ordering::SeqCst);
        if self.input.send(input).is_err() {
            self.pending_input.fetch_sub(cost, Ordering::SeqCst);
        }
    }

    /// Whether more input may be taken from the client: a program that does
    /// not read its terminal must not make us buffer without limit.
    fn input_room(&self) -> bool {
        self.pending_input.load(Ordering::SeqCst) < MAX_PENDING_INPUT
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
    /// The client has the end of the session: nothing to keep.
    Done,
    /// Another attachment took over.
    Replaced,
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

    /// Takes a session slot for user `uid`. At the user's limit, the session
    /// detached the longest goes (a client killed while reconnecting leaves
    /// one behind, which would otherwise lock the user out for the timeout).
    async fn reserve(&self, uid: u32) -> bool {
        for _ in 0..2 {
            let oldest = {
                let mut map = self.map.lock().unwrap();
                if map.total >= MAX_TOTAL {
                    return false;
                }
                if map.per_user.get(&uid).copied().unwrap_or(0) < MAX_PER_USER {
                    *map.per_user.entry(uid).or_default() += 1;
                    map.total += 1;
                    return true;
                }
                map.sessions
                    .iter()
                    .filter(|(_, s)| s.uid == uid)
                    .filter_map(|(t, s)| {
                        let out = s.out.lock().unwrap();
                        (!out.attached).then_some((out.detached_at, *t, s.clone()))
                    })
                    .min_by_key(|(at, ..)| *at)
            };
            let Some((_, token, sess)) = oldest else { return false };
            info!("too many sessions: closing the one detached the longest");
            self.hang_up(&token, &sess).await;
        }
        false
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
        if !self.reserve(user.uid).await {
            return write_msg(&mut send, &Reply::Err(format!("too many sessions (at most {MAX_PER_USER} per user)"))).await;
        }
        let env = session.env(user);
        let spec = session.pty.clone().expect("persistent sessions have a terminal");
        let spawned = exec::spawn_pty(user, session.command.take(), env, &spec, &session.prelude)
            .and_then(|(child, pty, tty)| Ok((child, exec::PtyInput::new(&pty)?, pty, tty)));
        let (mut child, pty_input, pty, tty) = match spawned {
            Ok(x) => x,
            Err(e) => {
                self.map.lock().unwrap().release(user.uid);
                return write_msg(&mut send, &Reply::Err(format!("cannot start session: {e:#}"))).await;
            }
        };
        let record = exec::login_record(user, &tty, &child, session.remote);
        let (mut reader, resizer) = pty.into_split();
        let (input_tx, mut input_rx) = mpsc::unbounded_channel();
        let (kill_tx, kill_rx) = oneshot::channel();
        let (changed, _) = watch::channel(());
        let now = Instant::now();
        let sess = Arc::new(Detachable {
            uid: user.uid,
            restrictions: restrictions.clone(),
            input: input_tx,
            pending_input: AtomicUsize::new(0),
            input_taken: Notify::new(),
            output_taken: Notify::new(),
            pacing: exec::Pacing::default(),
            kill: Mutex::new(Some(kill_tx)),
            out: Mutex::new(Output {
                buf: VecDeque::new(),
                start: 0,
                exit: None,
                generation: 0,
                attached: false,
                sent: 0,
                skew: 0,
                last_read: now,
                waiting: false,
                detached_at: now,
            }),
            changed,
        });
        let mut token = Token::default();
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
        self.map.lock().unwrap().sessions.insert(token, sess.clone());
        info!("{}: persistent session started", user.name);

        // Input: written by its own task, so a program that stops reading
        // cannot block the attachment (output, pings, detaching).
        let input = {
            let sess = sess.clone();
            tokio::spawn(async move {
                while let Some(input) = input_rx.recv().await {
                    let cost = input.cost();
                    match input {
                        Input::Data(data) => {
                            sess.pacing.input_waits(true);
                            let _ = pty_input.write_all(&data).await;
                            sess.pacing.input_waits(false);
                        }
                        Input::Resize { cols, rows } => {
                            let _ = resizer.resize(pty_process::Size::new(rows, cols));
                        }
                    }
                    sess.pending_input.fetch_sub(cost, Ordering::SeqCst);
                    sess.input_taken.notify_one();
                }
            })
        };
        // Output collector: everything the program writes goes into the buffer.
        let mut collector = {
            let sess = sess.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; CHUNK];
                loop {
                    // An attached client gets everything: the program waits for
                    // it, as it would for a slow connection over ssh.
                    loop {
                        let wait = {
                            let mut out = sess.out.lock().unwrap();
                            out.waiting = out.attached && out.end() - out.sent >= READ_AHEAD;
                            out.waiting
                        };
                        if !wait {
                            break;
                        }
                        sess.output_taken.notified().await;
                    }
                    // EIO is how a PTY master reports that the slave side was closed.
                    let Ok(n @ 1..) = exec::read_ready(&mut reader, &mut buf).await else { break };
                    let dropped = {
                        let mut out = sess.out.lock().unwrap();
                        out.buf.extend(&buf[..n]);
                        let mut excess = out.buf.len().saturating_sub(BUFFER);
                        if out.attached {
                            excess = excess.min(out.sent.saturating_sub(out.start) as usize);
                        }
                        out.buf.drain(..excess);
                        out.start += excess as u64;
                        out.last_read = Instant::now();
                        excess > 0 && !out.attached
                    };
                    sess.changed.send_replace(());
                    if dropped {
                        tokio::time::sleep(DETACHED_PACE).await;
                    }
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
                drain(&sess, &mut collector).await;
                // Whatever still holds the terminal (a background job) gets a
                // hangup once the master is closed.
                collector.abort();
                input.abort();
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

    /// Streams the session to the client from the `received`th byte on, and
    /// applies its input, until the session ends, the client leaves, or
    /// another attach takes over. Whatever happens, a lost client leaves the
    /// session detached with its timeout running.
    async fn attach(
        self: &Arc<Self>,
        send: SendHalf,
        recv: RecvHalf,
        token: Token,
        sess: Arc<Detachable>,
        received: u64,
        closed: watch::Receiver<bool>,
    ) -> Result<()> {
        let (generation, lost) = {
            let mut out = sess.out.lock().unwrap();
            out.generation += 1;
            out.attached = true;
            let from = received.saturating_add(out.skew).min(out.end());
            let lost = from < out.start;
            if lost {
                out.skew += out.start - from;
            }
            out.sent = from.max(out.start);
            (out.generation, lost)
        };
        sess.pacing.reset();
        // Wake an older attachment so it notices it has been replaced.
        sess.changed.send_replace(());
        sess.output_taken.notify_one();
        let outcome = self.serve(send, recv, token, &sess, generation, lost, closed).await;
        let reason = match outcome {
            Ok(Detach::Done) => {
                self.remove(&token);
                return Ok(());
            }
            Ok(Detach::Replaced) => return Ok(()),
            Ok(Detach::Lost(reason)) => reason.to_string(),
            Err(e) => format!("{e:#}"),
        };
        let (still_ours, finished) = {
            let mut out = sess.out.lock().unwrap();
            let ours = out.generation == generation;
            if ours {
                out.attached = false;
                out.detached_at = Instant::now();
            }
            (ours, out.exit.is_some())
        };
        sess.output_taken.notify_one();
        if still_ours {
            let keep = if finished { KEEP_FINISHED.min(self.timeout) } else { self.timeout };
            debug!("persistent session detached ({reason}), kept for {keep:?}");
            let sessions = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(keep).await;
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
        lost: bool,
        mut closed: watch::Receiver<bool>,
    ) -> Result<Detach> {
        // Client messages are read in a task, so waiting for one can be
        // given up without cutting a frame short (see `Reader`).
        let mut incoming = Reader::<ClientMsg>::spawn(recv);
        write_msg(&mut send, &Reply::Session { token: token.to_vec() }).await?;
        if lost {
            write_msg(&mut send, &ServerMsg::Stderr(b"\r\n[qsh: some output was lost while disconnected]\r\n".to_vec())).await?;
        }
        // Output and replies are written by a task of their own, so input
        // (a ^C among it) is taken while a slow client holds output up.
        let (out_tx, mut out_rx) = mpsc::channel::<ServerMsg>(4);
        // After the exit status, the stream stays open until the client
        // answers (see below), so its answer is not cut off.
        let mut writer = Abort(tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                write_msg(&mut send, &msg).await?;
            }
            std::future::pending::<Result<()>>().await
        }));
        let producer = produce(sess, generation, out_tx.clone());
        tokio::pin!(producer);
        let (mut producing, mut exited) = (true, false);
        loop {
            tokio::select! {
                end = &mut producer, if producing => {
                    producing = false;
                    match end {
                        Produced::Exit => exited = true,
                        Produced::Replaced => return Ok(Detach::Replaced),
                        // The writer's error comes next.
                        Produced::WriterGone => {}
                    }
                }
                res = &mut writer.0 => match res {
                    Ok(Err(e)) => return Err(e),
                    _ => return Ok(Detach::Lost("cannot write")),
                },
                // After the end, the client's hangup (or its end of the stream)
                // says it got it; until then it may resume to fetch it.
                msg = incoming.next(), if exited || sess.input_room() => match msg {
                    Ok(Some(ClientMsg::Stdin(data))) => sess.send_input(Input::Data(data)),
                    // Chaff gets an echo-sized reply, like in other sessions,
                    // when there is room: it must not hold up real input.
                    Ok(Some(ClientMsg::Typed { data, .. })) if data.is_empty() => {
                        let _ = out_tx.try_send(ServerMsg::Pong(vec![0]));
                    }
                    Ok(Some(ClientMsg::Typed { data, .. })) => sess.send_input(Input::Data(data)),
                    Ok(Some(ClientMsg::Resize { cols, rows })) => sess.send_input(Input::Resize { cols, rows }),
                    Ok(Some(ClientMsg::StdinEof)) => {}
                    Ok(Some(ClientMsg::Shown(n))) => sess.pacing.shown(n),
                    Ok(Some(ClientMsg::Hangup)) if exited => return Ok(Detach::Done),
                    // Hang up, then report the exit like any other end, so the
                    // client knows the hangup arrived before it disconnects.
                    Ok(Some(ClientMsg::Hangup)) => self.hang_up(&token, sess).await,
                    Err(e) if e.is::<crate::proto::Malformed>() => {}
                    Ok(None) if exited => return Ok(Detach::Done),
                    // The stream ended without a hangup: the client is gone.
                    Ok(None) | Err(_) => return Ok(Detach::Lost("client gone")),
                },
                () = sess.input_taken.notified(), if !exited && !sess.input_room() => {}
                _ = async { closed.wait_for(|c| *c).await.is_ok() } => return Ok(Detach::Lost("connection closed")),
            }
        }
    }
}

/// Why an attachment's output stopped.
enum Produced {
    Exit,
    Replaced,
    WriterGone,
}

/// Hands the session's output to the writer from where the client is, then
/// the exit status once the program is done and all of it went out.
async fn produce(sess: &Detachable, generation: u64, out: mpsc::Sender<ServerMsg>) -> Produced {
    let mut changed = sess.changed.subscribe();
    let mut on_stream = 0u64;
    loop {
        let (data, exit) = {
            let mut out = sess.out.lock().unwrap();
            if out.generation != generation {
                return Produced::Replaced;
            }
            let from = (out.sent - out.start) as usize;
            let to = out.buf.len().min(from + CHUNK);
            let data: Vec<u8> = out.buf.range(from..to).copied().collect();
            out.sent += data.len() as u64;
            (data, out.exit)
        };
        if !data.is_empty() {
            sess.output_taken.notify_one();
            on_stream += data.len() as u64;
            sess.pacing.wait(on_stream).await;
            if out.send(ServerMsg::Stdout(data)).await.is_err() {
                return Produced::WriterGone;
            }
            continue;
        }
        if let Some((code, signal)) = exit {
            let _ = out.send(ServerMsg::Exit { code, signal }).await;
            return Produced::Exit;
        }
        if changed.changed().await.is_err() {
            return Produced::Replaced;
        }
    }
}

/// Waits for the rest of the program's output: until the terminal is closed,
/// or nothing came for [`exec::DRAIN_GRACE`] while not waiting for the
/// client (a background job may hold the terminal open forever), and for
/// [`DRAIN_LIMIT`] at most.
async fn drain(sess: &Detachable, collector: &mut tokio::task::JoinHandle<()>) {
    let deadline = Instant::now() + DRAIN_LIMIT;
    loop {
        if tokio::time::timeout(exec::DRAIN_GRACE, &mut *collector).await.is_ok() {
            return;
        }
        let out = sess.out.lock().unwrap();
        if (!out.waiting && out.last_read.elapsed() >= exec::DRAIN_GRACE) || Instant::now() >= deadline {
            return;
        }
    }
}

/// Aborts the task when dropped.
struct Abort<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The answer when a session cannot be resumed.
pub const GONE: &str = "the session is gone (it ended or timed out)";
