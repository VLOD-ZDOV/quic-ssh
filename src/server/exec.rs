//! Command execution and interactive shells, with or without a PTY.

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
    pub remote: Option<std::net::IpAddr>,
    /// What runs first (motd, `~/.ssh/rc`...).
    pub prelude: Prelude,
    /// Run qshd's built-in SFTP server with these options instead of a
    /// shell: only for `internal-sftp` as a command the server chose (a
    /// subsystem, `force_command`, a key's `command=`), never the client's.
    pub sftp: Option<Vec<String>>,
}

impl Session {
    /// The session's environment: the user's base variables, accepted client
    /// variables, server-set ones, and `TERM` for a terminal.
    pub(super) fn env(&mut self, user: &User) -> Vec<(String, String)> {
        let mut env = user.env();
        env.extend(std::mem::take(&mut self.client_env));
        env.extend(std::mem::take(&mut self.extra_env));
        if let Some(p) = &self.pty {
            env.push(("TERM".into(), p.term.clone()));
        }
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
    let mut record = None;
    let spawned = match session.pty {
        Some(spec) => spawn_pty(user, session.command, env, &spec, &session.prelude).map(|(c, p, tty)| {
            record = login_record(user, &tty, &c, session.remote);
            (c, Io::Pty(p))
        }),
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
    drop(record); // the logout
    result
}

/// A login record for a terminal session in system mode (see `login_record`).
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
    let program = if sftp.is_some() { std::path::PathBuf::from(super::users::INTERNAL_SFTP) } else { user.shell.clone() };
    let mut cmd = user.command_as(&program, arg0.as_deref(), prelude, env);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Own process group, so the whole command tree can be stopped (see `hang_up`).
    cmd.process_group(0);
    match (sftp, command) {
        (Some(opts), _) => {
            cmd.args(opts);
        }
        (None, Some(c)) => {
            cmd.arg("-c").arg(c);
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
pub(super) struct PtyInput(tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>);

impl PtyInput {
    pub(super) fn new(pty: &pty_process::Pty) -> std::io::Result<PtyInput> {
        use std::os::fd::AsFd;
        let fd = pty.as_fd().try_clone_to_owned()?;
        Ok(PtyInput(tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::WRITABLE)?))
    }

    pub(super) async fn write_all(&self, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            let mut ready = self.0.writable().await?;
            // Read before trying: a failed try clears it.
            let hung_up = ready.ready().is_write_closed();
            match ready.try_io(|fd| nix::unistd::write(fd.get_ref(), data).map_err(std::io::Error::from)) {
                Ok(Ok(n)) => data = &data[n..],
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
pub(super) async fn hang_up(child: &mut tokio::process::Child) {
    let Some(pid) = child.id() else { return };
    let group = nix::unistd::Pid::from_raw(-(pid as i32));
    hang_up_group(group, child.wait()).await;
}

/// SIGHUP to a process group, then SIGKILL unless `exited` resolves within the grace period.
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
            (ClientMsg::Stdin(data), Input::Pty(_, w)) => {
                let _ = w.write_all(&data).await;
            }
            (ClientMsg::StdinEof, Input::Pipe(stdin)) => {
                if let Some(mut w) = stdin.take() {
                    let _ = w.shutdown().await;
                }
            }
            (ClientMsg::Resize { cols, rows }, Input::Pty(w, _)) => {
                let _ = w.resize(pty_process::Size::new(rows, cols));
            }
            // EOF on a terminal is the user's ^D; resize without a PTY is meaningless.
            (ClientMsg::StdinEof, Input::Pty(..)) | (ClientMsg::Resize { .. }, Input::Pipe(_)) => {}
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
    let terminal = matches!(io, Io::Pty(_));
    let feeder = match io {
        Io::Pipes { stdin, stdout, stderr } => {
            readers.push(tokio::spawn(pump(stdout, tx.clone(), ServerMsg::Stdout)));
            readers.push(tokio::spawn(pump(stderr, tx.clone(), ServerMsg::Stderr)));
            tokio::spawn(feed(recv, Input::Pipe(Some(stdin)), gone_tx, tx.clone(), pacing.clone()))
        }
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

    let drain = futures::future::join_all(readers);
    let _ = tokio::time::timeout(DRAIN_GRACE, drain).await;
    if let Some(status) = status {
        let _ = tx.send(ServerMsg::Exit { code: status.code(), signal: status.signal() }).await;
    }
    drop(tx);
    let _ = writer.await;
    Ok(())
}
