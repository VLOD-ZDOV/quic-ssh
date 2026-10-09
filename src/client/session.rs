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
    /// Variables sent to the server (`Target::session_env`; it filters them again).
    pub env: Vec<(String, String)>,
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
    /// Ends the session (a persistent one for good) when notified, as `~.`
    /// does: `-O exit` to a master that runs this session.
    pub quit: Arc<tokio::sync::Notify>,
    /// The connection's forwards, for `~C` and `~#`.
    pub forwarder: Option<Arc<super::forward::Forwarder>>,
}

/// Local handling of escape sequences (`~.`, `~?`, `~~`) typed at the start of a line.
struct Escapes {
    ch: u8,
    at_line_start: bool,
    pending: bool,
    /// `~C`: the command line being typed.
    command: Option<String>,
}

#[derive(Debug, PartialEq)]
enum EscapeAction {
    Disconnect,
    Help,
    /// Text for the terminal (the echo of the `~C` line).
    Echo(String),
    /// A finished `~C` line.
    Command(String),
    /// `~#`: list the forwards.
    ListForwards,
    /// `~^Z`: suspend qsh.
    Suspend,
    /// An escape qsh knows but cannot do (`~B`, `~R`...): why.
    Note(&'static str),
}

impl Escapes {
    fn new(ch: u8) -> Escapes {
        Escapes { ch, at_line_start: true, pending: false, command: None }
    }

    /// Returns the bytes to send and the escapes completed in `input`.
    /// Input after `~.` is dropped; input after the others is still sent.
    fn process(&mut self, input: &[u8]) -> (Vec<u8>, Vec<EscapeAction>) {
        let mut out = Vec::with_capacity(input.len());
        let mut actions = Vec::new();
        for b in input.iter().copied() {
            if let Some(line) = self.command.as_mut() {
                match b {
                    b'\r' | b'\n' => {
                        let line = self.command.take().unwrap_or_default();
                        actions.push(EscapeAction::Echo("\r\n".into()));
                        actions.push(EscapeAction::Command(line));
                        self.at_line_start = true;
                    }
                    // ^C, ^U or Esc: forget the line.
                    0x03 | 0x15 | 0x1b => {
                        self.command = None;
                        actions.push(EscapeAction::Echo("\r\n".into()));
                        self.at_line_start = true;
                    }
                    0x7f | 0x08 => {
                        if line.pop().is_some() {
                            actions.push(EscapeAction::Echo("\x08 \x08".into()));
                        }
                    }
                    b if (0x20..0x7f).contains(&b) && line.len() < 512 => {
                        line.push(b as char);
                        actions.push(EscapeAction::Echo((b as char).to_string()));
                    }
                    _ => {}
                }
                continue;
            }
            if self.pending {
                self.pending = false;
                let action = match b {
                    b'.' => {
                        actions.push(EscapeAction::Disconnect);
                        return (out, actions);
                    }
                    b'?' => EscapeAction::Help,
                    b'C' => {
                        self.command = Some(String::new());
                        EscapeAction::Echo("\r\nqsh> ".into())
                    }
                    b'#' => EscapeAction::ListForwards,
                    0x1a => EscapeAction::Suspend,
                    b'B' => EscapeAction::Note("qsh cannot send a BREAK"),
                    b'R' => EscapeAction::Note("keys are renewed automatically (TLS 1.3 key updates)"),
                    b'V' | b'v' => EscapeAction::Note("the log level is set when qsh starts (-v, LogLevel)"),
                    b'&' => EscapeAction::Note("qsh does not wait for forwarded connections at logout"),
                    b if b == self.ch => {
                        out.push(b);
                        self.at_line_start = false;
                        continue;
                    }
                    b => {
                        out.push(self.ch);
                        out.push(b);
                        self.at_line_start = b == b'\r' || b == b'\n';
                        continue;
                    }
                };
                actions.push(action);
                self.at_line_start = false;
                continue;
            }
            if self.at_line_start && b == self.ch {
                self.pending = true;
                continue;
            }
            out.push(b);
            self.at_line_start = b == b'\r' || b == b'\n';
        }
        (out, actions)
    }

    fn help(&self) -> String {
        let c = self.ch as char;
        format!(
            "\r\nSupported escape sequences:\r\n\
             \x20{c}.   - terminate connection\r\n\
             \x20{c}C   - open a command line (-L, -R, -D to add forwards; -KL, -KR, -KD to cancel)\r\n\
             \x20{c}#   - list forwarded connections\r\n\
             \x20{c}^Z  - suspend qsh\r\n\
             \x20{c}?   - this message\r\n\
             \x20{c}{c}   - send the escape character by typing it twice\r\n\
             (Note that escapes are only recognized immediately after newline.)\r\n"
        )
    }
}

/// Runs a `~C` line (`-L spec`, `-R spec`, `-D spec`, `-KL listen`,
/// `-KR listen`, `-KD listen`) and returns what to tell the user.
async fn escape_command(line: &str, forwarder: Option<&super::forward::Forwarder>) -> String {
    use super::forward::Forward;
    let line = line.trim();
    if line.is_empty() {
        return String::new();
    }
    let help = "Commands:\r\n      -L[bind_address:]port:host:hostport    Request local forward\r\n      \
                -R[bind_address:]port:host:hostport    Request remote forward\r\n      \
                -D[bind_address:]port                  Request dynamic forward\r\n      \
                -KL[bind_address:]port                 Cancel local forward\r\n      \
                -KR[bind_address:]port                 Cancel remote forward\r\n      \
                -KD[bind_address:]port                 Cancel dynamic forward\r\n";
    if matches!(line, "?" | "-h" | "help") {
        return help.into();
    }
    let Some(f) = forwarder else { return "forwarding cannot be changed in this session\r\n".into() };
    let (flag, spec) = line.split_at(line.find(|c: char| c.is_whitespace() || c.is_ascii_digit() || c == '[' || c == '/').unwrap_or(line.len()));
    let spec = spec.trim();
    let result = match flag {
        "-L" => match Forward::parse(spec) {
            Ok(fwd) => f.local('L', fwd).await.map(|()| "Forwarding port.".to_string()),
            Err(e) => Err(e),
        },
        "-D" => match Forward::parse_dynamic(spec) {
            Ok(fwd) => f.local('D', fwd).await.map(|()| "Forwarding port.".to_string()),
            Err(e) => Err(e),
        },
        "-R" => match Forward::parse_remote(spec) {
            Ok(fwd) => f.remote(fwd).await.map(|bound| match bound {
                Some(p) => format!("Allocated port {p} for remote forward."),
                None => "Forwarding port.".to_string(),
            }),
            Err(e) => Err(e),
        },
        "-KL" | "-KR" | "-KD" => {
            let kind = flag.as_bytes()[2] as char;
            match f.cancel(kind, spec) {
                Ok(true) => Ok(format!("Canceled forwarding {spec}.")),
                Ok(false) => Err(anyhow::anyhow!("no such forward: {spec}")),
                Err(e) => Err(e),
            }
        }
        _ => return format!("Invalid command.\r\n{help}"),
    };
    match result {
        Ok(msg) => format!("{msg}\r\n"),
        Err(e) => format!("{e:#}\r\n"),
    }
}

/// `~^Z`: gives the terminal back and stops qsh until the shell resumes it.
#[cfg(unix)]
fn suspend() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = nix::sys::signal::raise(nix::sys::signal::Signal::SIGTSTP);
    // Running again (fg).
    let _ = crossterm::terminal::enable_raw_mode();
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
        (Some(name), _) => Request::Subsystem { name, env: opts.env.clone() },
        (None, Some(spec)) if persistent => Request::Persistent { command: opts.command.clone(), env: opts.env.clone(), pty: spec.clone() },
        (None, _) => Request::Exec { command: opts.command.clone(), env: opts.env.clone(), pty: pty.clone() },
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
    // Only when the output goes to the terminal too (not `| tee log`).
    let mut predictor = (raw.is_some() && std::io::stdout().is_terminal() && opts.predict != Mode::Never).then(|| {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        Predictor::new(opts.predict, rows, cols)
    });
    let (typed_tx, mut typed_rx) = mpsc::channel::<Vec<u8>>(64);
    // Whether the remote program wants application cursor keys (followed on
    // Windows, where qsh encodes the keys itself).
    let cursor_keys = std::sync::Arc::new(std::sync::Mutex::new(super::keys_vt::CursorKeys::default()));
    let typed_tx = predictor.is_some().then_some(typed_tx);
    let disconnect = std::sync::Arc::new(tokio::sync::Notify::new());
    // qsh's own messages (the `~?` help) are written by the main loop, after
    // predictions are taken off the screen.
    let (notice_tx, mut notice_rx) = mpsc::unbounded_channel::<String>();
    let stdin_tx = tx.clone();
    if opts.stdin_null {
        let _ = stdin_tx.send(ClientMsg::StdinEof).await;
    } else {
        let disconnect = disconnect.clone();
        let forwarder = opts.forwarder.clone();
        let mut input = Input::new(raw.is_some(), cursor_keys.clone());
        tokio::spawn(async move {
            loop {
                match input.next().await {
                    None => {
                        let _ = stdin_tx.send(ClientMsg::StdinEof).await;
                        break;
                    }
                    Some(chunk) => {
                        let (data, actions) = match escapes.as_mut() {
                            Some(e) => e.process(&chunk),
                            None => (chunk, Vec::new()),
                        };
                        if !data.is_empty() {
                            if let Some(t) = &typed_tx {
                                let _ = t.try_send(data.clone());
                            }
                            if stdin_tx.send(ClientMsg::Stdin(data)).await.is_err() {
                                break;
                            }
                        }
                        let mut quit = false;
                        for action in actions {
                            match action {
                                EscapeAction::Disconnect => {
                                    disconnect.notify_one();
                                    quit = true;
                                }
                                EscapeAction::Help => {
                                    let _ = notice_tx.send(escapes.as_ref().map(Escapes::help).unwrap_or_default());
                                }
                                EscapeAction::Echo(text) => {
                                    let _ = notice_tx.send(text);
                                }
                                EscapeAction::Command(line) => {
                                    let (forwarder, notice_tx) = (forwarder.clone(), notice_tx.clone());
                                    tokio::spawn(async move {
                                        let reply = escape_command(&line, forwarder.as_deref()).await;
                                        let _ = notice_tx.send(reply);
                                    });
                                }
                                EscapeAction::ListForwards => {
                                    let list = forwarder.as_ref().map(|f| f.list()).unwrap_or_default();
                                    let text = if list.is_empty() { "No forwarded connections.".to_string() } else { list.join("\r\n") };
                                    let _ = notice_tx.send(format!("\r\n{text}\r\n"));
                                }
                                EscapeAction::Suspend => {
                                    #[cfg(unix)]
                                    suspend();
                                    #[cfg(not(unix))]
                                    let _ = notice_tx.send("\r\nqsh cannot be suspended here\r\n".into());
                                }
                                EscapeAction::Note(why) => {
                                    let _ = notice_tx.send(format!("\r\nqsh: {why}\r\n"));
                                }
                            }
                        }
                        if quit {
                            break;
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
        // The queue may be full behind input the server does not take.
        if !matches!(tokio::time::timeout(HANGUP_WAIT, tx.send(ClientMsg::Hangup)).await, Ok(Ok(()))) {
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
    type Heard = Arc<std::sync::Mutex<std::time::Instant>>;
    // Asks whether the server is there when the session has been quiet:
    // with a ping on a stream of its own, since the session's stream can be
    // held up by flow control (a slow terminal, a command that does not read
    // its input) while the connection is fine. In a task of its own, as the
    // main loop may be stuck writing to a slow terminal meanwhile.
    struct Pinger(tokio::task::JoinHandle<()>);
    impl Drop for Pinger {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    fn pinger(conn: Arc<Conn>, heard: Heard, answered: Heard, every: Duration) -> Pinger {
        Pinger(tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let last = (*heard.lock().unwrap()).max(*answered.lock().unwrap());
                if last.elapsed() < every {
                    continue;
                }
                let asked = async {
                    let (mut s, mut r) = conn.open_bi().await?;
                    write_msg(&mut s, &Request::Ping).await?;
                    expect_ok(&mut r).await?;
                    anyhow::Ok(())
                };
                if let Ok(Ok(())) = tokio::time::timeout(every, asked).await {
                    *answered.lock().unwrap() = std::time::Instant::now();
                }
            }
        }))
    }
    let answered: Heard = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let mut received: u64 = 0;
    let alive = opts.server_alive.or(token.is_some().then_some(DEFAULT_ALIVE));
    let (alive_interval, alive_max) = alive.unwrap_or(DEFAULT_ALIVE);
    let mut heartbeat = tokio::time::interval(alive_interval);
    let mut pings = alive.map(|_| pinger(conn.clone(), incoming.heard(), answered.clone(), alive_interval));
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
            Some(text) = notice_rx.recv() => {
                clear(&mut predictor).await;
                stderr.write_all(text.as_bytes()).await?;
                stderr.flush().await?;
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
            () = opts.quit.notified() => {
                if token.is_some() {
                    hang_up(&tx, &mut incoming).await;
                }
                clear(&mut predictor).await;
                break 255;
            }
            _ = heartbeat.tick(), if alive.is_some() => {
                // When a message last arrived (not when the loop got to it), or
                // a ping was answered.
                let heard = incoming.last_received().max(*answered.lock().unwrap());
                heard.elapsed() >= alive_interval * alive_max
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
        if pings.take().is_some() {
            *answered.lock().unwrap() = std::time::Instant::now();
            pings = Some(pinger(conn.clone(), incoming.heard(), answered.clone(), alive_interval));
        }
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
    drop(pings);
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
        assert!(a.is_empty());
        let (out, a) = e.process(b"\r~~x");
        assert_eq!(out, b"\r~x");
        assert!(a.is_empty());
        let (out, a) = e.process(b"\r~");
        assert_eq!(out, b"\r");
        assert!(a.is_empty(), "waits for the next byte");
        let (out, a) = e.process(b".");
        assert!(out.is_empty());
        assert_eq!(a, vec![EscapeAction::Disconnect]);
    }

    #[test]
    fn escape_at_session_start_and_unknown_sequences() {
        let mut e = Escapes::new(b'~');
        assert_eq!(e.process(b"~?").1, vec![EscapeAction::Help]);
        let mut e = Escapes::new(b'~');
        assert_eq!(e.process(b"~z").0, b"~z");
        let mut e = Escapes::new(b'%');
        assert_eq!(e.process(b"%.").1, vec![EscapeAction::Disconnect]);
        // Input after ~? in the same read is kept.
        let mut e = Escapes::new(b'~');
        let (out, a) = e.process(b"\r~?ls\r");
        assert_eq!(out, b"\rls\r");
        assert_eq!(a, vec![EscapeAction::Help]);
    }

    #[test]
    fn command_line_escape() {
        let mut e = Escapes::new(b'~');
        let (out, a) = e.process(b"~C-L 80x\x7f80:h:80\rls\r");
        assert_eq!(out, b"ls\r", "typing goes to the line, then to the session again");
        let commands: Vec<_> = a.iter().filter_map(|x| if let EscapeAction::Command(c) = x { Some(c.as_str()) } else { None }).collect();
        assert_eq!(commands, vec!["-L 8080:h:80"]);
        let (out, a) = e.process(b"~Cxyz\x03echo\r");
        assert_eq!(out, b"echo\r", "^C drops the line");
        assert!(!a.iter().any(|x| matches!(x, EscapeAction::Command(_))));
        assert_eq!(e.process(b"~#").1, vec![EscapeAction::ListForwards]);
        assert_eq!(e.process(b"\r~\x1a").1, vec![EscapeAction::Suspend]);
    }
}
