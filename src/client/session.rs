//! Interactive shells and remote commands.

use std::io::IsTerminal;

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::client::keystroke::Obfuscator;
use crate::proto::{expect_ok, read_msg_opt, write_msg, ClientMsg, PtySpec, Request, ServerMsg};
use crate::transport::Conn;

/// Local variables forwarded to the server (the server filters them again).
fn forwarded_env() -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(k, _)| k == "LANG" || k == "COLORTERM" || k.starts_with("LC_"))
        .collect()
}

/// Puts the local terminal into raw mode and restores it on drop.
struct RawMode;

impl RawMode {
    fn enable() -> Result<RawMode> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawMode)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Resolves with `128 + signal` when the local process is asked to stop, so the
/// caller can close the connection cleanly (over QUIC the server would otherwise
/// only notice after the idle timeout). In raw mode ^C is sent as a byte, so
/// SIGINT is only watched in line mode.
pub async fn termination_signal(watch_sigint: bool) -> i32 {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("signal handler");
    let mut hup = signal(SignalKind::hangup()).expect("signal handler");
    let mut int = signal(SignalKind::interrupt()).expect("signal handler");
    tokio::select! {
        _ = term.recv() => 128 + libc::SIGTERM,
        _ = hup.recv() => 128 + libc::SIGHUP,
        _ = int.recv(), if watch_sigint => 128 + libc::SIGINT,
    }
}

/// Runs `command` (or a login shell) and returns the remote exit code.
/// `keystroke_interval`: obfuscate keystroke timing in interactive sessions
/// with this packet interval (`None` disables it).
pub async fn run(
    conn: &Conn,
    command: Option<String>,
    want_pty: bool,
    keystroke_interval: Option<std::time::Duration>,
) -> Result<i32> {
    let pty = if want_pty {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
        Some(PtySpec { term, cols, rows })
    } else {
        None
    };
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::Exec { command, env: forwarded_env(), pty: pty.clone() }).await?;
    expect_ok(&mut recv).await?;

    let raw = match pty.is_some() && std::io::stdin().is_terminal() {
        true => Some(RawMode::enable()?),
        false => None,
    };
    let stop = termination_signal(raw.is_none());
    tokio::pin!(stop);

    let (tx, mut rx) = mpsc::channel::<ClientMsg>(32);
    // Only a person typing into a terminal needs timing protection.
    let mut obfuscator = keystroke_interval.filter(|_| raw.is_some()).map(Obfuscator::new);
    let writer = tokio::spawn(async move {
        loop {
            let deadline = obfuscator.as_ref().and_then(Obfuscator::deadline);
            let tick = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d.into()).await,
                    None => std::future::pending().await,
                }
            };
            let out: Vec<ClientMsg> = tokio::select! {
                msg = rx.recv() => match (msg, obfuscator.as_mut()) {
                    (None, _) => break,
                    (Some(ClientMsg::Stdin(data)), Some(o)) => o.input(std::time::Instant::now(), &data),
                    (Some(msg), _) => vec![msg],
                },
                () = tick => obfuscator.as_mut().and_then(|o| o.tick(std::time::Instant::now())).into_iter().collect(),
            };
            for msg in out {
                if write_msg(&mut send, &msg).await.is_err() {
                    return;
                }
            }
        }
    });

    let stdin_tx = tx.clone();
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = stdin_tx.send(ClientMsg::StdinEof).await;
                    break;
                }
                Ok(n) => {
                    if stdin_tx.send(ClientMsg::Stdin(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    if pty.is_some() {
        let resize_tx = tx.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let Ok(mut winch) = signal(SignalKind::window_change()) else { return };
            while winch.recv().await.is_some() {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    if resize_tx.send(ClientMsg::Resize { cols, rows }).await.is_err() {
                        break;
                    }
                }
            }
        });
    }
    drop(tx);

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let code = loop {
        let msg = tokio::select! {
            msg = read_msg_opt::<_, ServerMsg>(&mut recv) => match msg {
                // Unknown message type from a newer server: skip it.
                Err(e) if e.is::<crate::proto::Malformed>() => continue,
                other => other?,
            },
            code = &mut stop => break code,
        };
        match msg {
            Some(ServerMsg::Stdout(d)) => {
                stdout.write_all(&d).await?;
                stdout.flush().await?;
            }
            Some(ServerMsg::Stderr(d)) => {
                stderr.write_all(&d).await?;
                stderr.flush().await?;
            }
            Some(ServerMsg::Exit { code, signal }) => break code.or(signal.map(|s| 128 + s)).unwrap_or(255),
            Some(ServerMsg::Pong(_)) => {}
            None => bail!("connection closed without exit status"),
        }
    };
    writer.abort();
    drop(raw);
    Ok(code)
}
