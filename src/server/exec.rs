//! Command execution and interactive shells, with or without a PTY.

use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};

use super::users::User;
use crate::proto::{read_msg_opt, write_msg, ClientMsg, PtySpec, Reply, ServerMsg};
use crate::transport::{RecvHalf, SendHalf};

/// How long to keep draining output after the process exited (background
/// jobs may hold the pipes/pty open forever).
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Client variables passed through to the session (like sshd's AcceptEnv).
fn accept_env(name: &str) -> bool {
    // Only plain names: no `=`, NUL or other tricks (compare CVE-2014-2532).
    let plain = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    plain && (matches!(name, "LANG" | "COLORTERM") || name.starts_with("LC_"))
}

pub async fn run(
    mut send: SendHalf,
    recv: RecvHalf,
    user: &User,
    command: Option<String>,
    client_env: Vec<(String, String)>,
    pty: Option<PtySpec>,
    closed: watch::Receiver<bool>,
) -> Result<()> {
    let mut env = user.env();
    env.extend(client_env.into_iter().filter(|(k, _)| accept_env(k)));
    if let Some(p) = &pty {
        env.push(("TERM".into(), p.term.clone()));
    }
    let spawned = match pty {
        Some(spec) => spawn_pty(user, command, env, &spec),
        None => spawn_pipes(user, command, env),
    };
    let (child, io) = match spawned {
        Ok(x) => x,
        Err(e) => {
            write_msg(&mut send, &Reply::Err(format!("cannot start session: {e:#}"))).await?;
            return Ok(());
        }
    };
    write_msg(&mut send, &Reply::Ok).await?;
    supervise(send, recv, child, io, closed).await
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
    env: Vec<(String, String)>,
) -> Result<(tokio::process::Child, Io)> {
    let mut cmd = user.command(&user.shell);
    cmd.envs(env).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Own process group, so the whole command tree can be stopped (see `hang_up`).
    cmd.process_group(0);
    match command {
        Some(c) => cmd.arg("-c").arg(c),
        None => cmd.arg0(user.login_arg0()),
    };
    let mut child = cmd.spawn()?;
    let io = Io::Pipes {
        stdin: child.stdin.take().expect("piped"),
        stdout: child.stdout.take().expect("piped"),
        stderr: child.stderr.take().expect("piped"),
    };
    Ok((child, io))
}

fn spawn_pty(
    user: &User,
    command: Option<String>,
    env: Vec<(String, String)>,
    spec: &PtySpec,
) -> Result<(tokio::process::Child, Io)> {
    let (pty, pts) = pty_process::open()?;
    pty.resize(pty_process::Size::new(spec.rows, spec.cols))?;
    let mut cmd = pty_process::Command::new(&user.shell)
        .env_clear()
        .envs(env)
        .current_dir(&user.home)
        .kill_on_drop(true);
    cmd = match command {
        Some(c) => cmd.arg("-c").arg(c),
        None => cmd.arg0(user.login_arg0()),
    };
    // SAFETY: the closure only performs async-signal-safe syscalls.
    cmd = unsafe { cmd.pre_exec(user.drop_privileges(true)) };
    let child = cmd.spawn(pts)?;
    Ok((child, Io::Pty(pty)))
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
async fn hang_up(child: &mut tokio::process::Child) {
    let Some(pid) = child.id() else { return };
    let group = nix::unistd::Pid::from_raw(-(pid as i32));
    let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGHUP);
    if tokio::time::timeout(DRAIN_GRACE, child.wait()).await.is_err() {
        let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGKILL);
        let _ = child.wait().await;
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

/// Applies client input to the child. Sends on `gone` if the client vanished
/// (stream error), as opposed to a clean end of its input.
async fn feed(mut recv: RecvHalf, mut input: Input, gone: oneshot::Sender<()>) {
    loop {
        let msg = match read_msg_opt::<_, ClientMsg>(&mut recv).await {
            Ok(Some(msg)) => msg,
            Ok(None) => return,
            Err(_) => {
                let _ = gone.send(());
                return;
            }
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
            tokio::spawn(feed(recv, Input::Pipe(Some(stdin)), gone_tx))
        }
        Io::Pty(pty) => {
            let (r, w) = pty.into_split();
            readers.push(tokio::spawn(pump(r, tx.clone(), ServerMsg::Stdout)));
            tokio::spawn(feed(recv, Input::Pty(w), gone_tx))
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
        // A clean end of client input drops the sender without sending; only
        // an explicit signal (stream error) or a closed connection means the client is gone.
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

#[cfg(test)]
mod tests {
    use super::accept_env;

    #[test]
    fn env_filter() {
        assert!(accept_env("LANG") && accept_env("LC_ALL") && accept_env("COLORTERM"));
        for bad in ["LD_PRELOAD", "PATH", "LC_X=LD_PRELOAD", "LC_\0", "LC_ ", "", "BASH_ENV"] {
            assert!(!accept_env(bad), "{bad:?}");
        }
    }
}
