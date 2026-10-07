//! Interactive shells and remote commands.

use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::client::keystroke::Obfuscator;
use crate::client::predict::{Mode, Predictor};
use crate::proto::{expect_ok, read_msg_opt, write_msg, ClientMsg, PtySpec, Reader, Reply, Request, ServerMsg};
use crate::transport::{Conn, RecvHalf, SendHalf};

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
        // Windows consoles: interpret the remote side's VT output (colors,
        // cursor movement). Keys are encoded by `keys_vt`.
        #[cfg(windows)]
        crossterm::ansi_support::supports_ansi();
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
pub fn termination_signal(watch_sigint: bool) -> impl std::future::Future<Output = i32> {
    // Registered right away, so a signal that arrives before the first poll
    // is not handled by the default action (which would skip the clean close).
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("signal handler");
        let mut hup = signal(SignalKind::hangup()).expect("signal handler");
        let mut int = signal(SignalKind::interrupt()).expect("signal handler");
        async move {
            tokio::select! {
                _ = term.recv() => 128 + libc::SIGTERM,
                _ = hup.recv() => 128 + libc::SIGHUP,
                _ = int.recv(), if watch_sigint => 128 + libc::SIGINT,
            }
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};
        let mut close = ctrl_close().expect("console handler");
        let mut brk = ctrl_break().expect("console handler");
        let mut int = ctrl_c().expect("console handler");
        async move {
            tokio::select! {
                _ = close.recv() => 128 + 1,
                _ = brk.recv() => 128 + 3,
                _ = int.recv(), if watch_sigint => 128 + 2,
            }
        }
    }
}

/// What the user types: stdin, or on a Windows console the key presses,
/// encoded as a terminal would send them.
enum Input {
    Stdin(tokio::io::Stdin, Vec<u8>),
    #[cfg(windows)]
    Keys(mpsc::Receiver<Vec<u8>>),
}

impl Input {
    #[cfg_attr(not(windows), allow(unused_variables))]
    fn new(console: bool, cursor_keys: Arc<std::sync::Mutex<super::keys_vt::CursorKeys>>) -> Input {
        #[cfg(windows)]
        if console {
            let (tx, rx) = mpsc::channel(64);
            std::thread::spawn(move || loop {
                use crossterm::event::Event;
                let bytes = match crossterm::event::read() {
                    Ok(Event::Key(k)) => super::keys_vt::encode(k, cursor_keys.lock().unwrap().app),
                    Ok(Event::Paste(text)) => text.into_bytes(),
                    Ok(_) => continue,
                    Err(_) => break,
                };
                if !bytes.is_empty() && tx.blocking_send(bytes).is_err() {
                    break;
                }
            });
            return Input::Keys(rx);
        }
        Input::Stdin(tokio::io::stdin(), vec![0u8; 16 * 1024])
    }

    /// The next chunk; `None` at the end.
    async fn next(&mut self) -> Option<Vec<u8>> {
        match self {
            Input::Stdin(stdin, buf) => match stdin.read(buf).await {
                Ok(0) | Err(_) => None,
                Ok(n) => Some(buf[..n].to_vec()),
            },
            #[cfg(windows)]
            Input::Keys(rx) => rx.recv().await,
        }
    }
}

/// Resolves on every change of the local terminal size.
async fn window_changes(tx: mpsc::Sender<ClientMsg>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let Ok(mut winch) = signal(SignalKind::window_change()) else { return };
        while winch.recv().await.is_some() {
            if let Ok((cols, rows)) = crossterm::terminal::size() {
                if tx.send(ClientMsg::Resize { cols, rows }).await.is_err() {
                    break;
                }
            }
        }
    }
    // Windows has no resize signal for console programs: poll.
    #[cfg(windows)]
    {
        let mut last = crossterm::terminal::size().ok();
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let now = crossterm::terminal::size().ok();
            if now != last {
                last = now;
                if let Some((cols, rows)) = now {
                    if tx.send(ClientMsg::Resize { cols, rows }).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

/// What to run and how.
#[derive(Default, Clone)]
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
    /// Keep a terminal session across lost connections, reconnecting with this.
    pub reconnect: Option<Reconnect>,
    /// `ServerAliveInterval`/`ServerAliveCountMax` (persistent sessions default to 5 s × 3).
    pub server_alive: Option<(Duration, u32)>,
    /// Local echo prediction for a person typing into a terminal.
    pub predict: super::predict::Mode,
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
    /// Input after `~.` is dropped; input after `~?` is still sent.
    fn process(&mut self, input: &[u8]) -> (Vec<u8>, Option<EscapeAction>) {
        let mut out = Vec::with_capacity(input.len());
        let mut action = None;
        for &b in input {
            if self.pending {
                self.pending = false;
                match b {
                    b'.' => return (out, Some(EscapeAction::Disconnect)),
                    b'?' => {
                        self.at_line_start = false;
                        action = Some(EscapeAction::Help);
                        continue;
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
        (out, action)
    }

    fn help(&self) -> String {
        let c = self.ch as char;
        format!(
            "\r\nSupported escape sequences:\r\n {c}.   - terminate connection\r\n {c}?   - this message\r\n              {c}{c}   - send the escape character by typing it twice\r\n\
             (Note that escapes are only recognized immediately after newline.)\r\n"
        )
    }
}

/// Logs in again after a lost connection, to resume the session with this
/// token (without prompting: the terminal is in use by the session).
pub type Reconnect = Arc<dyn Fn(Vec<u8>) -> futures::future::BoxFuture<'static, Result<Arc<Conn>>> + Send + Sync>;

/// Default liveness check of persistent sessions: ping after 5 s of silence,
/// count the connection as lost after 3 unanswered pings.
const DEFAULT_ALIVE: (Duration, u32) = (Duration::from_secs(5), 3);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);
/// How long quitting waits for the server to confirm the hangup.
const HANGUP_WAIT: Duration = Duration::from_secs(3);

/// Why a resume attempt failed.
enum ResumeError {
    /// The server no longer has the session.
    Gone(String),
    Retry(anyhow::Error),
}

async fn resume(reconnect: &Reconnect, token: &[u8], received: u64) -> Result<(Arc<Conn>, SendHalf, RecvHalf), ResumeError> {
    // A refused login (the session expired, or a question that cannot be
    // asked now) will not get better by retrying.
    let conn = reconnect(token.to_vec()).await.map_err(|e| match e.downcast_ref::<super::LoginRefused>() {
        Some(refused) => ResumeError::Gone(refused.0.clone()),
        None => ResumeError::Retry(e),
    })?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(ResumeError::Retry)?;
    write_msg(&mut send, &Request::Resume { token: token.to_vec(), received }).await.map_err(ResumeError::Retry)?;
    match read_msg_opt::<_, Reply>(&mut recv).await {
        Ok(Some(Reply::Session { .. })) => Ok((conn, send, recv)),
        Ok(Some(Reply::Err(e))) => Err(ResumeError::Gone(e)),
        Ok(other) => Err(ResumeError::Retry(anyhow::anyhow!("unexpected answer {other:?}"))),
        Err(e) => Err(ResumeError::Retry(e)),
    }
}

/// Runs a command, subsystem or login shell and returns the remote exit code.
/// With `reconnect`, an interactive session survives lost connections.
pub async fn run(mut conn: Arc<Conn>, opts: SessionOptions) -> Result<i32> {
    let pty = if opts.pty && opts.subsystem.is_none() {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
        Some(PtySpec { term, cols, rows })
    } else {
        None
    };
    let persistent = opts.reconnect.is_some() && conn.server_version() >= 4;
    let raw_wanted = pty.is_some() && std::io::stdin().is_terminal();
    // Before the session exists, so a quitting user always ends it properly.
    let stop = termination_signal(!raw_wanted);
    tokio::pin!(stop);
    let (send, mut recv) = conn.open_bi().await?;
    let mut send = send;
    let request = match (opts.subsystem.clone(), &pty) {
        (Some(name), _) => Request::Subsystem { name, env: forwarded_env() },
        (None, Some(spec)) if persistent => Request::Persistent { command: opts.command.clone(), env: forwarded_env(), pty: spec.clone() },
        (None, _) => Request::Exec { command: opts.command.clone(), env: forwarded_env(), pty: pty.clone() },
    };
    write_msg(&mut send, &request).await?;
    let token = match expect_ok(&mut recv).await? {
        Reply::Session { token } => Some(token),
        _ => None,
    };
    // The loop below waits for keys and timers too: read the server's messages
    // in a task, so a frame is never cut short by another event.
    let mut incoming = Reader::<ServerMsg>::spawn(recv);
    let keystroke_interval = opts.keystroke_interval;

    let raw = match raw_wanted {
        true => Some(RawMode::enable()?),
        false => None,
    };

    let (tx, mut rx) = mpsc::channel::<ClientMsg>(32);
    // Where messages go; replaced after a reconnect. Messages sent while there
    // is no working stream are dropped (typing during an outage is lost).
    let (sink_tx, mut sink_rx) = mpsc::channel::<SendHalf>(1);
    sink_tx.send(send).await.ok();
    // Only a person typing into a terminal needs timing protection.
    let mut obfuscator = keystroke_interval.filter(|_| raw.is_some()).map(Obfuscator::new);
    let writer = {
        tokio::spawn(async move {
            let mut sink: Option<SendHalf> = None;
            loop {
                let deadline = obfuscator.as_ref().and_then(Obfuscator::deadline);
                let tick = async {
                    match deadline {
                        Some(d) => tokio::time::sleep_until(d.into()).await,
                        None => std::future::pending().await,
                    }
                };
                let out: Vec<ClientMsg> = tokio::select! {
                    // A new stream first, so messages queued after a reconnect go to it.
                    biased;
                    new = sink_rx.recv() => match new {
                        Some(s) => {
                            sink = Some(s);
                            continue;
                        }
                        None => break,
                    },
                    msg = rx.recv() => match (msg, obfuscator.as_mut()) {
                        (None, _) => break,
                        (Some(ClientMsg::Stdin(data)), Some(o)) => o.input(std::time::Instant::now(), &data),
                        (Some(msg), _) => vec![msg],
                    },
                    () = tick => obfuscator.as_mut().and_then(|o| o.tick(std::time::Instant::now())).into_iter().collect(),
                };
                for msg in out {
                    if let Some(s) = sink.as_mut() {
                        if write_msg(s, &msg).await.is_err() {
                            sink = None;
                        }
                    }
                }
            }
        })
    };

    // Escapes only apply when a person types into a terminal (as in ssh).
    let mut escapes = opts.escape_char.filter(|_| raw.is_some()).map(Escapes::new);
    // Echo prediction, likewise; it sees what is typed and what comes back.
    let mut predictor = (raw.is_some() && opts.predict != Mode::Never).then(|| {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        Predictor::new(opts.predict, rows, cols)
    });
    let (typed_tx, mut typed_rx) = mpsc::channel::<Vec<u8>>(64);
    // Whether the remote program wants application cursor keys (followed on
    // Windows, where qsh encodes the keys itself).
    let cursor_keys = std::sync::Arc::new(std::sync::Mutex::new(super::keys_vt::CursorKeys::default()));
    let typed_tx = predictor.is_some().then_some(typed_tx);
    let disconnect = std::sync::Arc::new(tokio::sync::Notify::new());
    let stdin_tx = tx.clone();
    if opts.stdin_null {
        let _ = stdin_tx.send(ClientMsg::StdinEof).await;
    } else {
        let disconnect = disconnect.clone();
        let mut input = Input::new(raw.is_some(), cursor_keys.clone());
        tokio::spawn(async move {
            loop {
                match input.next().await {
                    None => {
                        let _ = stdin_tx.send(ClientMsg::StdinEof).await;
                        break;
                    }
                    Some(chunk) => {
                        let (data, action) = match escapes.as_mut() {
                            Some(e) => e.process(&chunk),
                            None => (chunk, None),
                        };
                        if !data.is_empty() {
                            if let Some(t) = &typed_tx {
                                let _ = t.try_send(data.clone());
                            }
                            if stdin_tx.send(ClientMsg::Stdin(data)).await.is_err() {
                                break;
                            }
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
        tokio::spawn(window_changes(tx.clone()));
    }

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    // Ends a persistent session for good (not kept for a reconnect), and
    // waits for the server's exit report so the hangup is not lost when the
    // connection closes right after it.
    async fn hang_up(tx: &mpsc::Sender<ClientMsg>, incoming: &mut Reader<ServerMsg>) {
        if tx.send(ClientMsg::Hangup).await.is_err() {
            return;
        }
        let _ = tokio::time::timeout(HANGUP_WAIT, async {
            loop {
                match incoming.next().await {
                    Ok(Some(ServerMsg::Exit { .. })) | Ok(None) => break,
                    Err(e) if !e.is::<crate::proto::Malformed>() => break,
                    _ => {}
                }
            }
        })
        .await;
    }
    let mut received: u64 = 0;
    let alive = opts.server_alive.or(token.is_some().then_some(DEFAULT_ALIVE));
    let (alive_interval, alive_max) = alive.unwrap_or(DEFAULT_ALIVE);
    let mut heartbeat = tokio::time::interval(alive_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Writes to the terminal, with predictions erased first and redrawn after.
    async fn show<W: AsyncWriteExt + Unpin>(w: &mut W, predictor: &mut Option<Predictor>, data: &[u8]) -> std::io::Result<()> {
        match predictor {
            Some(p) => {
                let mut out = match crossterm::terminal::size() {
                    Ok((cols, rows)) => p.resize(rows, cols),
                    Err(_) => Vec::new(),
                };
                out.extend(p.output(data, std::time::Instant::now()));
                w.write_all(&out).await?;
            }
            None => w.write_all(data).await?,
        }
        w.flush().await
    }
    // qsh's own messages: predictions must not be in the way.
    async fn clear(predictor: &mut Option<Predictor>) {
        if let Some(p) = predictor {
            let mut out = tokio::io::stdout();
            let _ = out.write_all(&p.clear()).await;
            let _ = out.flush().await;
        }
    }
    let code = loop {
        let deadline = predictor.as_ref().and_then(Predictor::deadline);
        let lost = tokio::select! {
            Some(data) = typed_rx.recv() => {
                if let Some(p) = predictor.as_mut() {
                    let mut out = match crossterm::terminal::size() {
                        Ok((cols, rows)) => p.resize(rows, cols),
                        Err(_) => Vec::new(),
                    };
                    out.extend(p.typed(&data, std::time::Instant::now()));
                    if !out.is_empty() {
                        stdout.write_all(&out).await?;
                        stdout.flush().await?;
                    }
                }
                false
            }
            () = async { tokio::time::sleep_until(deadline.expect("checked").into()).await }, if deadline.is_some() => {
                if let Some(p) = predictor.as_mut() {
                    stdout.write_all(&p.expire(std::time::Instant::now())).await?;
                    stdout.flush().await?;
                }
                false
            }
            msg = incoming.next() => match msg {
                // Unknown message type from a newer server: skip it.
                Err(e) if e.is::<crate::proto::Malformed>() => continue,
                Ok(Some(msg)) => {
                    match msg {
                        ServerMsg::Stdout(d) => {
                            received += d.len() as u64;
                            if cfg!(windows) {
                                cursor_keys.lock().unwrap().feed(&d);
                            }
                            show(&mut stdout, &mut predictor, &d).await?;
                        }
                        ServerMsg::Stderr(d) => show(&mut stderr, &mut predictor, &d).await?,
                        ServerMsg::Exit { code, signal } => break code.or(signal.map(|s| 128 + s)).unwrap_or(255),
                        ServerMsg::Pong(_) => {}
                    }
                    false
                }
                Ok(None) | Err(_) if token.is_some() => true,
                Ok(None) => bail!("connection closed without exit status"),
                Err(e) => return Err(e),
            },
            code = &mut stop => {
                if token.is_some() {
                    hang_up(&tx, &mut incoming).await;
                }
                break code;
            }
            () = disconnect.notified() => {
                if token.is_some() {
                    hang_up(&tx, &mut incoming).await;
                }
                clear(&mut predictor).await;
                let _ = stderr.write_all(b"\r\nConnection closed.\r\n").await;
                break 255;
            }
            _ = heartbeat.tick(), if alive.is_some() => {
                // When a message last arrived, not when the loop got to it
                // (writing to a stalled terminal must not look like silence).
                let quiet = incoming.last_received().elapsed();
                if quiet >= alive_interval {
                    // Chaff gets a Pong back; it looks like a keystroke on the wire.
                    let _ = tx.send(ClientMsg::Typed { data: Vec::new(), pad: vec![0; super::keystroke::PAD_TO] }).await;
                }
                quiet >= alive_interval * alive_max
            }
        };
        if !lost {
            continue;
        }
        clear(&mut predictor).await;
        if token.is_none() {
            let _ = stderr.write_all(b"\r\nTimeout, server not responding.\r\n").await;
            break 255;
        }
        // The connection is gone: reconnect and pick the session up where we were.
        let (Some(token), Some(reconnect)) = (token.as_ref(), opts.reconnect.as_ref()) else { unreachable!() };
        let _ = stderr.write_all(b"\r\n[qsh: connection lost, reconnecting... type ~. to give up]\r\n").await;
        let old = conn.clone();
        tokio::spawn(async move { old.close().await });
        let mut delay = Duration::from_secs(1);
        let resumed = loop {
            tokio::select! {
                () = disconnect.notified() => break None,
                code = &mut stop => return Ok(code),
                res = resume(reconnect, token, received) => match res {
                    Ok(x) => break Some(x),
                    Err(ResumeError::Gone(e)) => {
                        let _ = stderr.write_all(format!("[qsh: {e}]\r\n").as_bytes()).await;
                        drop(raw);
                        return Ok(255);
                    }
                    Err(ResumeError::Retry(e)) => {
                        tracing::debug!("reconnect: {e:#}");
                        tokio::select! {
                            () = tokio::time::sleep(delay) => {}
                            () = disconnect.notified() => break None,
                        }
                        delay = (delay * 2).min(MAX_RETRY_DELAY);
                    }
                }
            }
        };
        let Some((new_conn, new_send, new_recv)) = resumed else {
            let _ = stderr.write_all(b"\r\nConnection closed (the session is kept on the server for a while).\r\n").await;
            break 255;
        };
        conn = new_conn;
        incoming = Reader::spawn(new_recv);
        let _ = sink_tx.send(new_send).await;
        let _ = stderr.write_all(b"[qsh: reconnected]\r\n").await;
        // Two size changes make full-screen programs redraw what was lost.
        if let Ok((cols, rows)) = crossterm::terminal::size() {
            if rows > 1 {
                let _ = tx.send(ClientMsg::Resize { cols, rows: rows - 1 }).await;
            }
            let _ = tx.send(ClientMsg::Resize { cols, rows }).await;
        }
    };
    clear(&mut predictor).await;
    drop(tx);
    writer.abort();
    drop(raw);
    conn.close().await;
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
        // Input after ~? in the same read is kept.
        let mut e = Escapes::new(b'~');
        let (out, a) = e.process(b"\r~?ls\r");
        assert_eq!(out, b"\rls\r");
        assert!(matches!(a, Some(EscapeAction::Help)));
    }
}
