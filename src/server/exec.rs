//! Command execution and interactive shells, with or without a PTY.

use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};

use super::users::{Prelude, User};
use crate::proto::{read_msg_opt, write_msg, ClientMsg, PtySpec, Reply, ServerMsg};
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
pub(super) fn internal_sftp(command: &Option<String>) -> Option<Vec<String>> {
    let mut words = command.as_deref()?.split_whitespace();
    (words.next()? == super::users::INTERNAL_SFTP).then(|| words.map(str::to_string).collect())
}

pub async fn run(mut send: SendHalf, recv: RecvHalf, user: &User, mut session: Session, closed: watch::Receiver<bool>) -> Result<()> {
    // SFTP speaks a binary protocol: never on a terminal.
    if internal_sftp(&session.command).is_some() {
        session.pty = None;
    }
    let env = session.env(user);
    let mut record = None;
    let spawned = match session.pty {
        Some(spec) => spawn_pty(user, session.command, env, &spec, &session.prelude).map(|(c, p, tty)| {
            record = login_record(user, &tty, &c, session.remote);
            (c, Io::Pty(p))
        }),
        None => spawn_pipes(user, session.command, env, &session.prelude),
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

fn spawn_pipes(user: &User, command: Option<String>, env: Vec<(String, String)>, prelude: &Prelude) -> Result<(tokio::process::Child, Io)> {
    let arg0 = command.is_none().then(|| user.login_arg0());
    let sftp = internal_sftp(&command);
    let program = if sftp.is_some() { std::path::PathBuf::from(super::users::INTERNAL_SFTP) } else { user.shell.clone() };
    let mut cmd = user.command_as(&program, arg0.as_deref(), prelude);
    cmd.envs(env).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
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
    let mut cmd = user.pty_command(&user.shell, arg0.as_deref(), env, prelude);
    if let Some(c) = command {
        cmd = cmd.arg("-c").arg(c);
    }
    let child = cmd.spawn(pts)?;
    Ok((child, pty, tty))
}

/// Forwards a child output stream as `ServerMsg`s until EOF.
async fn pump<R: AsyncRead + Unpin>(mut r: R, tx: mpsc::Sender<ServerMsg>, wrap: fn(Vec<u8>) -> ServerMsg) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match r.read(&mut buf).await {
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
    Pty(pty_process::OwnedWritePty),
}

/// Applies client input to the child. Sends on `gone` when the stream ends:
/// clients never end their side of a command's stream themselves (the end
/// of input is `StdinEof`), so an end, clean or not, means the client is
/// gone. A clean one is how a client that was killed looks through a shared
/// connection (its master just passes the closed socket on).
async fn feed(mut recv: RecvHalf, mut input: Input, gone: oneshot::Sender<()>, tx: mpsc::Sender<ServerMsg>) {
    loop {
        let msg = match read_msg_opt::<_, ClientMsg>(&mut recv).await {
            Ok(Some(msg)) => msg,
            // Unknown message type from a newer client: skip it.
            Err(e) if e.is::<crate::proto::Malformed>() => continue,
            Ok(None) | Err(_) => {
                let _ = gone.send(());
                return;
            }
        };
        // Obfuscated keystrokes: chaff gets an echo-sized reply so that, on the
        // wire, it looks like a real keystroke and its echo.
        let msg = match msg {
            ClientMsg::Typed { data, .. } if data.is_empty() => {
                let _ = tx.send(ServerMsg::Pong(vec![0])).await;
                continue;
            }
            ClientMsg::Typed { data, .. } => ClientMsg::Stdin(data),
            other => other,
        };
        match (msg, &mut input) {
            (ClientMsg::Stdin(data), Input::Pipe(stdin)) => {
                if let Some(w) = stdin {
                    if w.write_all(&data).await.is_err() {
                        *stdin = None;
                    }
                }
            }
            (ClientMsg::Stdin(data), Input::Pty(w)) => {
                let _ = w.write_all(&data).await;
            }
            (ClientMsg::StdinEof, Input::Pipe(stdin)) => {
                if let Some(mut w) = stdin.take() {
                    let _ = w.shutdown().await;
                }
            }
            (ClientMsg::Resize { cols, rows }, Input::Pty(w)) => {
                let _ = w.resize(pty_process::Size::new(rows, cols));
            }
            // EOF on a terminal is the user's ^D; resize without a PTY is meaningless.
            (ClientMsg::StdinEof, Input::Pty(_)) | (ClientMsg::Resize { .. }, Input::Pipe(_)) => {}
            (ClientMsg::Typed { .. }, _) => unreachable!("converted above"),
            // Only persistent sessions outlive the stream; this one ends with it anyway.
            (ClientMsg::Hangup, _) => {}
        }
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
    let feeder = match io {
        Io::Pipes { stdin, stdout, stderr } => {
            readers.push(tokio::spawn(pump(stdout, tx.clone(), ServerMsg::Stdout)));
            readers.push(tokio::spawn(pump(stderr, tx.clone(), ServerMsg::Stderr)));
            tokio::spawn(feed(recv, Input::Pipe(Some(stdin)), gone_tx, tx.clone()))
        }
        Io::Pty(pty) => {
            let (r, w) = pty.into_split();
            readers.push(tokio::spawn(pump(r, tx.clone(), ServerMsg::Stdout)));
            tokio::spawn(feed(recv, Input::Pty(w), gone_tx, tx.clone()))
        }
    };

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
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

    let drain = futures::future::join_all(readers);
    let _ = tokio::time::timeout(DRAIN_GRACE, drain).await;
    if let Some(status) = status {
        let _ = tx.send(ServerMsg::Exit { code: status.code(), signal: status.signal() }).await;
    }
    drop(tx);
    let _ = writer.await;
    Ok(())
}
