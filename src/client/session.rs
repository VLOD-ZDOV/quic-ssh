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

/// What to run and how.
#[derive(Debug, Default, Clone)]
pub struct SessionOptions {
    /// Command line; `None` = login shell.
    pub command: Option<String>,
    /// Run this subsystem (`-s`) instead of a command.
    pub subsystem: Option<String>,
    pub pty: bool,
    /// Keystroke timing obfuscation interval for interactive sessions (`None` = off).
    pub keystroke_interval: Option<std::time::Duration>,
    /// Escape character for `~.` and friends (`None` = off).
    pub escape_char: Option<u8>,
    /// `-n`: do not read stdin.
    pub stdin_null: bool,
}

/// Local handling of escape sequences (`~.`, `~?`, `~~`) typed at the start of a line.
struct Escapes {
    ch: u8,
    at_line_start: bool,
    pending: bool,
}

enum EscapeAction {
    Disconnect,
    Help,
}

impl Escapes {
    fn new(ch: u8) -> Escapes {
        Escapes { ch, at_line_start: true, pending: false }
    }

    /// Returns the bytes to send and an action, if an escape was completed.
    fn process(&mut self, input: &[u8]) -> (Vec<u8>, Option<EscapeAction>) {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            if self.pending {
                self.pending = false;
                match b {
                    b'.' => return (out, Some(EscapeAction::Disconnect)),
                    b'?' => {
                        self.at_line_start = false;
                        return (out, Some(EscapeAction::Help));
                    }
                    b if b == self.ch => out.push(b),
                    b => {
                        out.push(self.ch);
                        out.push(b);
                    }
                }
            } else if self.at_line_start && b == self.ch {
                self.pending = true;
                continue;
            } else {
                out.push(b);
            }
            self.at_line_start = b == b'\r' || b == b'\n';
        }
        (out, None)
    }

    fn help(&self) -> String {
        let c = self.ch as char;
        format!(
            "\r\nSupported escape sequences:\r\n {c}.   - terminate connection\r\n {c}?   - this message\r\n              {c}{c}   - send the escape character by typing it twice\r\n\
             (Note that escapes are only recognized immediately after newline.)\r\n"
        )
    }
}

/// Runs a command, subsystem or login shell and returns the remote exit code.
pub async fn run(conn: &Conn, opts: SessionOptions) -> Result<i32> {
    let pty = if opts.pty && opts.subsystem.is_none() {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
        Some(PtySpec { term, cols, rows })
    } else {
        None
    };
    let (mut send, mut recv) = conn.open_bi().await?;
    let request = match opts.subsystem.clone() {
        Some(name) => Request::Subsystem { name, env: forwarded_env() },
        None => Request::Exec { command: opts.command.clone(), env: forwarded_env(), pty: pty.clone() },
    };
    write_msg(&mut send, &request).await?;
    expect_ok(&mut recv).await?;
    let keystroke_interval = opts.keystroke_interval;

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

    // Escapes only apply when a person types into a terminal (as in ssh).
    let mut escapes = opts.escape_char.filter(|_| raw.is_some()).map(Escapes::new);
    let disconnect = std::sync::Arc::new(tokio::sync::Notify::new());
    let stdin_tx = tx.clone();
    if opts.stdin_null {
        let _ = stdin_tx.send(ClientMsg::StdinEof).await;
    } else {
        let disconnect = disconnect.clone();
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
                        let (data, action) = match escapes.as_mut() {
                            Some(e) => e.process(&buf[..n]),
                            None => (buf[..n].to_vec(), None),
                        };
                        if !data.is_empty() && stdin_tx.send(ClientMsg::Stdin(data)).await.is_err() {
                            break;
                        }
                        match action {
                            Some(EscapeAction::Disconnect) => {
                                disconnect.notify_one();
                                break;
                            }
                            Some(EscapeAction::Help) => {
                                let help = escapes.as_ref().map(Escapes::help).unwrap_or_default();
                                let _ = tokio::io::stderr().write_all(help.as_bytes()).await;
                            }
                            None => {}
                        }
                    }
                }
            }
        });
    }

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
            () = disconnect.notified() => {
                let _ = stderr.write_all(b"\r\nConnection closed.\r\n").await;
                break 255;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_only_at_line_start() {
        let mut e = Escapes::new(b'~');
        let (out, a) = e.process(b"a~.b");
        assert_eq!(out, b"a~.b");
        assert!(a.is_none());
        let (out, a) = e.process(b"\r~~x");
        assert_eq!(out, b"\r~x");
        assert!(a.is_none());
        let (out, a) = e.process(b"\r~");
        assert_eq!(out, b"\r");
        assert!(a.is_none(), "waits for the next byte");
        let (out, a) = e.process(b".");
        assert!(out.is_empty());
        assert!(matches!(a, Some(EscapeAction::Disconnect)));
    }

    #[test]
    fn escape_at_session_start_and_unknown_sequences() {
        let mut e = Escapes::new(b'~');
        assert!(matches!(e.process(b"~?").1, Some(EscapeAction::Help)));
        let mut e = Escapes::new(b'~');
        assert_eq!(e.process(b"~z").0, b"~z");
        let mut e = Escapes::new(b'%');
        assert!(matches!(e.process(b"%.").1, Some(EscapeAction::Disconnect)));
    }
}
