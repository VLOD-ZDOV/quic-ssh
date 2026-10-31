//! Command execution and interactive shells, with or without a PTY.

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};

use super::users::{Prelude, User};
use crate::proto::{read_msg_opt, write_msg, ClientMsg, PtySpec, Reply, ServerMsg, SHOWN_WINDOW};
use crate::transport::{RecvHalf, SendHalf};

/// How long to keep draining output after the process exited (background
/// jobs may hold the pipes/pty open forever).
pub(super) const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// What to start: `$SHELL -c command`, or a login shell for `None`.
pub struct Session {
    pub command: Option<String>,
    /// Variables from the client (already filtered by `accept_env`).
    pub client_env: Vec<(String, String)>,
    /// Variables set by the server (`set_env`, `SSH_ORIGINAL_COMMAND`...);
    /// they replace the client's.
    pub extra_env: Vec<(String, String)>,
    pub pty: Option<PtySpec>,
    /// Where the client connects from: in system mode, terminal sessions get
    /// a login record (utmp/wtmp/lastlog) for it.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub remote: Option<std::net::IpAddr>,
    /// What runs first (motd, `~/.ssh/rc`...).
    pub prelude: Prelude,
    /// Run qshd's built-in SFTP server with these options instead of a
    /// shell: only for `internal-sftp` as a command the server chose (a
    /// subsystem, `force_command`, a key's `command=`), never the client's.
    pub sftp: Option<Vec<String>>,
    /// The forwarded agent's socket, which a persistent session keeps.
    pub agent: Option<Arc<super::agent::Relay>>,
    /// When the one-time code of the login that started it runs out.
    pub code_expires: Option<tokio::time::Instant>,
}

impl Session {
    /// The session's environment: the user's base variables, accepted client
    /// variables, `TERM` for a terminal, and server-set ones.
    pub(super) fn env(&mut self, user: &User) -> Vec<(String, String)> {
        let mut env = user.env();
        env.extend(std::mem::take(&mut self.client_env));
        // The server's set_env wins over the client's TERM, as SetEnv in sshd.
        if let Some(p) = &self.pty {
            env.push(("TERM".into(), p.term.clone()));
        }
        env.extend(std::mem::take(&mut self.extra_env));
        env
    }
}

/// `internal-sftp [options]`: the built-in SFTP server, run without a
/// shell (its options, if `command` is one).
pub(super) fn internal_sftp(command: &str) -> Option<Vec<String>> {
    let mut words = command.split_whitespace();
    (words.next()? == super::users::INTERNAL_SFTP).then(|| words.map(str::to_string).collect())
}

pub async fn run(mut send: SendHalf, recv: RecvHalf, user: &User, mut session: Session, closed: watch::Receiver<bool>) -> Result<()> {
    // SFTP speaks a binary protocol: never on a terminal.
    if session.sftp.is_some() {
        session.pty = None;
    }
    let env = session.env(user);
    #[cfg(windows)]
    if let Some(spec) = session.pty.take() {
        return windows::run_pty(send, recv, user, session.command, env, &spec, closed).await;
    }
    #[cfg(unix)]
    let mut record = None;
    let spawned = match session.pty {
        #[cfg(unix)]
        Some(spec) => spawn_pty(user, session.command, env, &spec, &session.prelude).map(|(c, p, tty)| {
            record = login_record(user, &tty, &c, session.remote);
            (c, Io::Pty(p))
        }),
        #[cfg(windows)]
        Some(_) => unreachable!("taken above"),
        None => spawn_pipes(user, session.command, session.sftp, env, &session.prelude),
    };
    let (child, io) = match spawned {
        Ok(x) => x,
        Err(e) => {
            write_msg(&mut send, &Reply::Err(format!("cannot start session: {e:#}"))).await?;
            return Ok(());
        }
    };
    write_msg(&mut send, &Reply::Ok).await?;
    let result = supervise(send, recv, child, io, closed).await;
    #[cfg(unix)]
    drop(record); // the logout
    result
}

/// A login record for a terminal session in system mode (see `login_record`).
#[cfg(unix)]
pub(super) fn login_record(
    user: &User,
    tty: &Option<String>,
    child: &tokio::process::Child,
    remote: Option<std::net::IpAddr>,
) -> Option<super::login_record::LoginRecord> {
    match (user.switches(), tty, child.id(), remote) {
        (true, Some(tty), Some(pid), Some(ip)) => Some(super::login_record::login(&user.name, tty, pid, ip)),
        _ => None,
    }
}

/// Child I/O, either three pipes or one PTY master.
enum Io {
    Pipes {
        stdin: tokio::process::ChildStdin,
        stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
    },
    #[cfg(unix)]
    Pty(pty_process::Pty),
}

fn spawn_pipes(
    user: &User,
    command: Option<String>,
    sftp: Option<Vec<String>>,
    env: Vec<(String, String)>,
    prelude: &Prelude,
) -> Result<(tokio::process::Child, Io)> {
    let arg0 = command.is_none().then(|| user.login_arg0());
    #[cfg(unix)]
    let program = if sftp.is_some() { std::path::PathBuf::from(super::users::INTERNAL_SFTP) } else { user.shell.clone() };
    // Nothing to become first: qshd itself, as the helper it is.
    #[cfg(windows)]
    let program = if sftp.is_some() { super::users::exe_path()? } else { user.shell.clone() };
    let mut cmd = user.command_as(&program, arg0.as_deref(), prelude, env, true);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Own process group, so the whole command tree can be stopped (see `hang_up`).
    #[cfg(unix)]
    cmd.process_group(0);
    match (sftp, command) {
        (Some(opts), _) => {
            #[cfg(windows)]
            cmd.arg(super::users::INTERNAL_SFTP);
            cmd.args(opts);
        }
        #[cfg(unix)]
        (None, Some(c)) => {
            cmd.arg("-c").arg(c);
        }
        // cmd.exe parses its command line itself: given as typed.
        #[cfg(windows)]
        (None, Some(c)) if user.command_flag() == "/c" => {
            cmd.arg("/c").raw_arg(c);
        }
        #[cfg(windows)]
        (None, Some(c)) => {
            cmd.arg(user.command_flag()).arg(c);
        }
        (None, None) => {}
    }
    let mut child = cmd.spawn()?;
    let io = Io::Pipes {
        stdin: child.stdin.take().expect("piped"),
        stdout: child.stdout.take().expect("piped"),
        stderr: child.stderr.take().expect("piped"),
    };
    Ok((child, io))
}

#[cfg(unix)]
pub(super) fn spawn_pty(
    user: &User,
    command: Option<String>,
    env: Vec<(String, String)>,
    spec: &PtySpec,
    prelude: &Prelude,
) -> Result<(tokio::process::Child, pty_process::Pty, Option<String>)> {
    let (pty, pts) = pty_process::open()?;
    pty.resize(pty_process::Size::new(spec.rows, spec.cols))?;
    let tty = nix::unistd::ttyname(&pts).ok().map(|p| p.to_string_lossy().into_owned());
    let arg0 = command.is_none().then(|| user.login_arg0());
    let mut env = env;
    env.extend(tty.clone().map(|t| ("SSH_TTY".to_string(), t)));
    let mut cmd = user.pty_command(&user.shell, arg0.as_deref(), env, prelude);
    if let Some(c) = command {
        cmd = cmd.arg("-c").arg(c);
    }
    let child = cmd.spawn(pts)?;
    Ok((child, pty, tty))
}

/// Writes to a PTY master. pty-process's writer spins when the terminal's
/// other side is closed: a hangup keeps the master "writable" while writes
/// fail with EAGAIN, so a paste into a program that exited without reading
/// it would take a whole core forever.
#[cfg(unix)]
pub(super) struct PtyInput(tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>);

#[cfg(unix)]
impl PtyInput {
    pub(super) fn new(pty: &pty_process::Pty) -> std::io::Result<PtyInput> {
        use std::os::fd::AsFd;
        let fd = pty.as_fd().try_clone_to_owned()?;
        Ok(PtyInput(tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::WRITABLE)?))
    }

    pub(super) async fn write_all(&self, mut data: &[u8]) -> std::io::Result<()> {
        let mut pause = Duration::from_millis(1);
        while !data.is_empty() {
            // The kernel may wake writers before the room is there, and then
            // not again: so try again after a while even without a wakeup.
            let mut ready = match tokio::time::timeout(pause, self.0.writable()).await {
                Ok(ready) => ready?,
                Err(_) => {
                    pause = (pause * 2).min(Duration::from_millis(50));
                    match nix::unistd::write(self.0.get_ref(), data) {
                        Ok(n) => {
                            data = &data[n..];
                            pause = Duration::from_millis(1);
                        }
                        Err(nix::errno::Errno::EAGAIN) => {}
                        Err(e) => return Err(e.into()),
                    }
                    continue;
                }
            };
            // Read before trying: a failed try clears it.
            let hung_up = ready.ready().is_write_closed();
            match ready.try_io(|fd| nix::unistd::write(fd.get_ref(), data).map_err(std::io::Error::from)) {
                Ok(Ok(n)) => {
                    data = &data[n..];
                    pause = Duration::from_millis(1);
                }
                Ok(Err(e)) => return Err(e),
                // Nobody has the terminal open any more: the input has no reader.
                Err(_) if hung_up => return Err(std::io::ErrorKind::BrokenPipe.into()),
                Err(_) => {}
            }
        }
        Ok(())
    }
}

/// Holds terminal output back while more than [`SHOWN_WINDOW`] of it has
/// not been shown (see [`ClientMsg::Shown`]), so a ^C takes effect on the
/// screen soon. Only for a client that reports, and never while input
/// waits for the program: it may be waiting for its output to go first.
#[derive(Default)]
pub(super) struct Pacing {
    shown: AtomicU64,
    reports: AtomicBool,
    input_waits: AtomicBool,
    changed: tokio::sync::Notify,
}

impl Pacing {
    /// Forgets the reports, for a new stream.
    pub(super) fn reset(&self) {
        self.shown.store(0, Ordering::SeqCst);
        self.reports.store(false, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    pub(super) fn shown(&self, n: u64) {
        self.shown.fetch_max(n, Ordering::SeqCst);
        self.reports.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    pub(super) fn input_waits(&self, waits: bool) {
        self.input_waits.store(waits, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    /// Waits until `sent` bytes of output in total may be on the way.
    pub(super) async fn wait(&self, sent: u64) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.reports.load(Ordering::SeqCst)
                || self.input_waits.load(Ordering::SeqCst)
                || sent <= self.shown.load(Ordering::SeqCst) + SHOWN_WINDOW
            {
                return;
            }
            changed.await;
        }
    }
}

/// Reads what is there, at least one byte (0 at the end), then whatever
/// else is ready without waiting: a terminal hands output over in pieces of
/// a line or so, and a message for each costs more than the bytes.
pub(super) async fn read_ready<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    use futures::FutureExt;
    let mut n = r.read(buf).await?;
    while n > 0 && n < buf.len() {
        match r.read(&mut buf[n..]).now_or_never() {
            Some(Ok(more @ 1..)) => n += more,
            _ => break,
        }
    }
    Ok(n)
}

/// Forwards a child output stream as `ServerMsg`s until EOF.
async fn pump<R: AsyncRead + Unpin>(mut r: R, tx: mpsc::Sender<ServerMsg>, wrap: fn(Vec<u8>) -> ServerMsg) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match read_ready(&mut r, &mut buf).await {
            // EIO is how a PTY master reports that the slave side was closed.
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tx.send(wrap(buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Stops a session whose client is gone: SIGHUP to its process group (like a
/// terminal hangup), then SIGKILL if it is still running after a grace period.
/// The child leads its own group (`process_group(0)` or `setsid` for a PTY).
#[cfg(unix)]
pub(super) async fn hang_up(child: &mut tokio::process::Child) {
    let Some(pid) = child.id() else { return };
    let group = nix::unistd::Pid::from_raw(-(pid as i32));
    hang_up_group(group, child.wait()).await;
}

/// Windows has no hangup: the program is ended.
#[cfg(windows)]
pub(super) async fn hang_up(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
}

/// SIGHUP to a process group, then SIGKILL unless `exited` resolves within the grace period.
#[cfg(unix)]
pub(super) async fn hang_up_group<F: std::future::Future>(group: nix::unistd::Pid, exited: F) {
    let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGHUP);
    tokio::pin!(exited);
    if tokio::time::timeout(DRAIN_GRACE, &mut exited).await.is_err() {
        let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGKILL);
        let _ = exited.await;
    } else {
        // The leader exited; make sure nothing of the group lingers.
        let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGKILL);
    }
}

/// Where client input goes.
enum Input {
    Pipe(Option<tokio::process::ChildStdin>),
    /// The writer only resizes; data goes through [`PtyInput`].
    #[cfg(unix)]
    Pty(pty_process::OwnedWritePty, PtyInput),
}

/// Applies client input to the child. Sends on `gone` when the stream ends:
/// clients never end their side of a command's stream themselves (the end
/// of input is `StdinEof`), so an end, clean or not, means the client is
/// gone. A clean one is how a client that was killed looks through a shared
/// connection (its master just passes the closed socket on).
async fn feed(mut recv: RecvHalf, mut input: Input, gone: oneshot::Sender<()>, tx: mpsc::Sender<ServerMsg>, pacing: Arc<Pacing>) {
    loop {
        let msg = match read_msg_opt::<_, ClientMsg>(&mut recv).await {
            Ok(Some(msg)) => msg,
            // Unknown message type from a newer client: skip it.
            Err(e) if e.is::<crate::proto::Malformed>() => continue,
            Ok(None) | Err(_) => {
                pacing.reset(); // no more reports
                let _ = gone.send(());
                return;
            }
        };
        // Obfuscated keystrokes: chaff gets an echo-sized reply so that, on the
        // wire, it looks like a real keystroke and its echo.
        let msg = match msg {
            // Only when there is room: chaff must not hold up real input.
            ClientMsg::Typed { data, .. } if data.is_empty() => {
                let _ = tx.try_send(ServerMsg::Pong(vec![0]));
                continue;
            }
            ClientMsg::Typed { data, .. } => ClientMsg::Stdin(data),
            ClientMsg::Shown(n) => {
                pacing.shown(n);
                continue;
            }
            other => other,
        };
        pacing.input_waits(true);
        match (msg, &mut input) {
            (ClientMsg::Stdin(data), Input::Pipe(stdin)) => {
                if let Some(w) = stdin {
                    if w.write_all(&data).await.is_err() {
                        *stdin = None;
                    }
                }
            }
            #[cfg(unix)]
            (ClientMsg::Stdin(data), Input::Pty(_, w)) => {
                let _ = w.write_all(&data).await;
            }
            (ClientMsg::StdinEof, Input::Pipe(stdin)) => {
                if let Some(mut w) = stdin.take() {
                    let _ = w.shutdown().await;
                }
            }
            #[cfg(unix)]
            (ClientMsg::Resize { cols, rows }, Input::Pty(w, _)) => {
                let _ = w.resize(pty_process::Size::new(rows, cols));
            }
            // EOF on a terminal is the user's ^D; resize without a PTY is meaningless.
            #[cfg(unix)]
            (ClientMsg::StdinEof, Input::Pty(..)) => {}
            (ClientMsg::Resize { .. }, Input::Pipe(_)) => {}
            (ClientMsg::Typed { .. } | ClientMsg::Shown(_), _) => unreachable!("handled above"),
            // Only persistent sessions outlive the stream; this one ends with it anyway.
            (ClientMsg::Hangup, _) => {}
        }
        pacing.input_waits(false);
    }
}

async fn supervise(
    mut send: SendHalf,
    recv: RecvHalf,
    mut child: tokio::process::Child,
    io: Io,
    mut closed: watch::Receiver<bool>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<ServerMsg>(32);
    let (gone_tx, mut gone_rx) = oneshot::channel();

    let mut readers = Vec::new();
    let pacing = Arc::new(Pacing::default());
    #[cfg(unix)]
    let terminal = matches!(io, Io::Pty(_));
    #[cfg(windows)]
    let terminal = false;
    let feeder = match io {
        Io::Pipes { stdin, stdout, stderr } => {
            readers.push(tokio::spawn(pump(stdout, tx.clone(), ServerMsg::Stdout)));
            readers.push(tokio::spawn(pump(stderr, tx.clone(), ServerMsg::Stderr)));
            tokio::spawn(feed(recv, Input::Pipe(Some(stdin)), gone_tx, tx.clone(), pacing.clone()))
        }
        #[cfg(unix)]
        Io::Pty(pty) => {
            let input = PtyInput::new(&pty)?;
            let (r, w) = pty.into_split();
            readers.push(tokio::spawn(pump(r, tx.clone(), ServerMsg::Stdout)));
            tokio::spawn(feed(recv, Input::Pty(w, input), gone_tx, tx.clone(), pacing.clone()))
        }
    };

    let writer_pacing = pacing.clone();
    let writer = tokio::spawn(async move {
        let pacing = writer_pacing;
        let mut sent = 0u64;
        while let Some(msg) = rx.recv().await {
            if let (ServerMsg::Stdout(data), true) = (&msg, terminal) {
                sent += data.len() as u64;
                pacing.wait(sent).await;
            }
            let last = matches!(msg, ServerMsg::Exit { .. });
            if write_msg(&mut send, &msg).await.is_err() {
                return;
            }
            if last {
                break;
            }
        }
        let _ = send.shutdown().await;
    });

    let status: Option<ExitStatus> = tokio::select! {
        s = child.wait() => s.ok(),
        // The client's side of the stream ended, or the connection closed.
        Ok(()) = &mut gone_rx => {
            hang_up(&mut child).await;
            None
        }
        _ = async { closed.wait_for(|c| *c).await.is_ok() } => {
            hang_up(&mut child).await;
            None
        }
    };
    feeder.abort();
    pacing.reset(); // nobody takes reports now: let the rest of the output go

    // Whatever still holds the output open (a background job) gets a hangup
    // once the readers, and with them the terminal's master, are gone.
    let stop: Vec<_> = readers.iter().map(|r| r.abort_handle()).collect();
    let drain = futures::future::join_all(readers);
    let _ = tokio::time::timeout(DRAIN_GRACE, drain).await;
    stop.iter().for_each(tokio::task::AbortHandle::abort);
    if let Some(status) = status {
        #[cfg(unix)]
        let signal = status.signal();
        #[cfg(windows)]
        let signal = None;
        let _ = tx.send(ServerMsg::Exit { code: status.code(), signal }).await;
    }
    drop(tx);
    let _ = writer.await;
    Ok(())
}

/// Terminal sessions on Windows: a ConPTY. Its pipes are blocking, so they
/// are read and written by threads of their own.
#[cfg(windows)]
mod windows {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use portable_pty::{CommandBuilder, MasterPty, PtySize};
    use tokio::io::AsyncWriteExt;
    use tokio::sync::{mpsc, watch};

    use super::super::users::User;
    use super::DRAIN_GRACE;
    use crate::proto::{read_msg_opt, write_msg, ClientMsg, PtySpec, Reply, ServerMsg};
    use crate::transport::{RecvHalf, SendHalf};

    /// How long a client terminal has to say where its cursor is.
    const CURSOR_ANSWER: std::time::Duration = std::time::Duration::from_secs(1);

    type Master = Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>;

    fn size(rows: u16, cols: u16) -> PtySize {
        PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }
    }

    /// What a terminal's program printed.
    pub(in super::super) struct Output {
        chunks: mpsc::Receiver<Vec<u8>>,
        left: Vec<u8>,
    }

    impl Output {
        /// 0 once the pseudo console is closed.
        pub(in super::super) async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.left.is_empty() {
                match self.chunks.recv().await {
                    Some(chunk) => self.left = chunk,
                    None => return Ok(0),
                }
            }
            let n = self.left.len().min(buf.len());
            buf[..n].copy_from_slice(&self.left[..n]);
            self.left.drain(..n);
            Ok(n)
        }
    }

    /// Writes to a terminal's program.
    pub(in super::super) struct Input {
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
        answered: Arc<AtomicBool>,
    }

    impl Input {
        pub(in super::super) async fn write_all(&self, data: &[u8]) -> std::io::Result<()> {
            // A cursor position report (ESC [ row ; col R).
            if data.starts_with(b"\x1b[") && data.ends_with(b"R") {
                self.answered.store(true, Ordering::Relaxed);
            }
            let (writer, data) = (self.writer.clone(), data.to_vec());
            let write = move || {
                let mut w = writer.lock().unwrap();
                w.write_all(&data).and_then(|()| w.flush())
            };
            tokio::task::spawn_blocking(write).await.map_err(std::io::Error::other)?
        }
    }

    /// Changes a terminal's size.
    #[derive(Clone)]
    pub(in super::super) struct Resizer(Master);

    impl Resizer {
        pub(in super::super) fn resize(&self, rows: u16, cols: u16) {
            if let Some(m) = self.0.lock().unwrap().as_ref() {
                let _ = m.resize(size(rows, cols));
            }
        }
    }

    /// A terminal's program.
    pub(in super::super) struct Process {
        waiting: tokio::task::JoinHandle<std::io::Result<portable_pty::ExitStatus>>,
        killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
        master: Master,
        stand_in: tokio::task::JoinHandle<()>,
    }

    impl Process {
        /// The exit code. The output ends once the pseudo console is closed,
        /// which it is here. Cancel safe.
        pub(in super::super) async fn wait(&mut self) -> Option<super::super::persist::Status> {
            let status = (&mut self.waiting).await.ok().and_then(Result::ok);
            self.closed();
            status.map(|s| (Some(s.exit_code() as i32), None))
        }

        /// Windows has no hangup: the program is ended.
        pub(in super::super) async fn hang_up(&mut self) {
            let _ = self.killer.kill();
            let _ = (&mut self.waiting).await;
            self.closed();
        }

        fn closed(&self) {
            self.stand_in.abort();
            drop(self.master.lock().unwrap().take());
        }
    }

    pub(in super::super) struct Terminal {
        pub(in super::super) output: Output,
        pub(in super::super) input: Input,
        pub(in super::super) resizer: Resizer,
        pub(in super::super) process: Process,
    }

    impl Terminal {
        pub(in super::super) fn spawn(user: &User, command: Option<String>, env: Vec<(String, String)>, spec: &PtySpec) -> Result<Terminal> {
            let pair = portable_pty::native_pty_system().openpty(size(spec.rows, spec.cols))?;
            let mut cmd = CommandBuilder::new(&user.shell);
            if let Some(c) = &command {
                cmd.arg(user.command_flag());
                cmd.arg(c);
            }
            cmd.env_clear();
            for (k, v) in &env {
                cmd.env(k, v);
            }
            cmd.cwd(&user.home);
            let mut child = pair.slave.spawn_command(cmd)?;
            drop(pair.slave);
            let mut reader = pair.master.try_clone_reader()?;
            let writer = Arc::new(Mutex::new(pair.master.take_writer()?));
            let master: Master = Arc::new(Mutex::new(Some(pair.master)));

            // portable-pty makes the pseudo console inherit the cursor: it asks
            // where the cursor is (ESC [6n) and shows nothing until it hears. A
            // client terminal answers; without one (`qsh -tt cmd | tee`, scripts)
            // qshd answers for it, or the session would wait forever.
            let asked = Arc::new(tokio::sync::Notify::new());
            let answered = Arc::new(AtomicBool::new(false));
            let (chunks_tx, chunks) = mpsc::channel(4);
            let ask = asked.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 32 * 1024];
                let mut first = true;
                while let Ok(n @ 1..) = reader.read(&mut buf) {
                    if first && buf[..n].windows(4).any(|w| w == b"\x1b[6n") {
                        first = false;
                        ask.notify_one();
                    }
                    if chunks_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            });
            let input = Input { writer: writer.clone(), answered: answered.clone() };
            let stand_in = tokio::spawn(async move {
                asked.notified().await;
                tokio::time::sleep(CURSOR_ANSWER).await;
                if !answered.load(Ordering::Relaxed) {
                    let write = move || writer.lock().unwrap().write_all(b"\x1b[1;1R");
                    let _ = tokio::task::spawn_blocking(write).await;
                }
            });
            let killer = child.clone_killer();
            let waiting = tokio::task::spawn_blocking(move || child.wait());
            let process = Process { waiting, killer, master: master.clone(), stand_in };
            Ok(Terminal { output: Output { chunks, left: Vec::new() }, input, resizer: Resizer(master), process })
        }
    }

    pub(in super::super) async fn run_pty(
        mut send: SendHalf,
        mut recv: RecvHalf,
        user: &User,
        command: Option<String>,
        env: Vec<(String, String)>,
        spec: &PtySpec,
        mut closed: watch::Receiver<bool>,
    ) -> Result<()> {
        let Terminal { mut output, input, resizer, mut process } = match Terminal::spawn(user, command, env, spec) {
            Ok(t) => t,
            Err(e) => return write_msg(&mut send, &Reply::Err(format!("cannot start session: {e:#}"))).await,
        };
        write_msg(&mut send, &Reply::Ok).await?;
        let (tx, mut rx) = mpsc::channel::<ServerMsg>(32);
        let out_tx = tx.clone();
        let output = tokio::spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            while let Ok(n @ 1..) = output.read(&mut buf).await {
                if out_tx.send(ServerMsg::Stdout(buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
        });
        let (gone_tx, mut gone_rx) = tokio::sync::oneshot::channel::<()>();
        let feeder = tokio::spawn(async move {
            loop {
                match read_msg_opt::<_, ClientMsg>(&mut recv).await {
                    Ok(Some(ClientMsg::Stdin(data) | ClientMsg::Typed { data, .. })) if !data.is_empty() => {
                        let _ = input.write_all(&data).await;
                    }
                    Ok(Some(ClientMsg::Resize { cols, rows })) => resizer.resize(rows, cols),
                    Ok(Some(_)) => {}
                    Err(e) if e.is::<crate::proto::Malformed>() => {}
                    Ok(None) | Err(_) => {
                        let _ = gone_tx.send(());
                        return;
                    }
                }
            }
        });
        let writer_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let last = matches!(msg, ServerMsg::Exit { .. });
                if write_msg(&mut send, &msg).await.is_err() || last {
                    break;
                }
            }
            let _ = send.shutdown().await;
        });

        let status = tokio::select! {
            s = process.wait() => s,
            Ok(()) = &mut gone_rx => {
                process.hang_up().await;
                None
            }
            _ = async { closed.wait_for(|c| *c).await.is_ok() } => {
                process.hang_up().await;
                None
            }
        };
        feeder.abort();
        let _ = tokio::time::timeout(DRAIN_GRACE, output).await;
        if let Some((code, signal)) = status {
            let _ = tx.send(ServerMsg::Exit { code, signal }).await;
        }
        drop(tx);
        let _ = writer_task.await;
        Ok(())
    }
}

#[cfg(windows)]
pub(super) use windows::Terminal;

/// A terminal and the program in it, in parts that go to separate tasks.
#[cfg(unix)]
pub(super) struct Terminal {
    pub(super) output: Output,
    pub(super) input: PtyInput,
    pub(super) resizer: Resizer,
    pub(super) process: Process,
}

#[cfg(unix)]
impl Terminal {
    pub(super) fn spawn(user: &User, command: Option<String>, env: Vec<(String, String)>, spec: &PtySpec, prelude: &Prelude, remote: Option<std::net::IpAddr>) -> Result<Terminal> {
        let (child, pty, tty) = spawn_pty(user, command, env, spec, prelude)?;
        let input = PtyInput::new(&pty)?;
        let record = login_record(user, &tty, &child, remote);
        let (reader, resizer) = pty.into_split();
        Ok(Terminal { output: Output(reader), input, resizer: Resizer(resizer), process: Process { child, record } })
    }
}

#[cfg(unix)]
pub(super) struct Output(pty_process::OwnedReadPty);

#[cfg(unix)]
impl Output {
    /// EIO is how a PTY master reports that the slave side was closed.
    pub(super) async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        read_ready(&mut self.0, buf).await
    }
}

#[cfg(unix)]
pub(super) struct Resizer(pty_process::OwnedWritePty);

#[cfg(unix)]
impl Resizer {
    pub(super) fn resize(&self, rows: u16, cols: u16) {
        let _ = self.0.resize(pty_process::Size::new(rows, cols));
    }
}

/// The only owner of the child. Signals go through it, which never addresses
/// a reaped (and possibly reused) process ID.
#[cfg(unix)]
pub(super) struct Process {
    child: tokio::process::Child,
    record: Option<super::login_record::LoginRecord>,
}

#[cfg(unix)]
impl Process {
    /// The exit status. Cancel safe.
    pub(super) async fn wait(&mut self) -> Option<super::persist::Status> {
        use std::os::unix::process::ExitStatusExt;
        let status = self.child.wait().await.ok();
        self.logged_out();
        status.map(|s| (s.code(), s.signal()))
    }

    pub(super) async fn hang_up(&mut self) {
        hang_up(&mut self.child).await;
        self.logged_out();
    }

    fn logged_out(&mut self) {
        drop(self.record.take());
    }
}
