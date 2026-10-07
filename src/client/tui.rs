//! `qsh ui`: an interactive host menu with live qshd status and a speed test.
//!
//! Hosts come from `~/.config/qsh/config`, `~/.ssh/config` and known_hosts.
//! Each is probed in the background with a throwaway key (TLS handshake only,
//! no login), so the list shows where qshd answers and how fast. Sessions are
//! started as `qsh -f`, so hosts without qshd open with plain ssh. Works with
//! the keyboard and with a mouse or touch screen (e.g. Termux).

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Circle, Line as CanvasLine, Points};
use ratatui::widgets::{Block, BorderType, List, ListItem, ListState, Paragraph, Sparkline, Wrap};
use ratatui::{DefaultTerminal, Frame};
use tokio::sync::mpsc;

use super::{speed, ConnectOptions, Target};
use crate::keys::{home_dir, Identity};
use crate::transport::{self, Conn, Mode as Transport};

const PROBE_TCP_TIMEOUT: Duration = Duration::from_secs(3);
const SPEED_SECONDS: Duration = Duration::from_secs(5);
/// Top of the speedometer scale (log scale from 0).
const GAUGE_MAX_MBPS: f64 = 1000.0;

#[derive(Clone, Debug, PartialEq)]
enum Probe {
    Pending,
    Quic { handshake: Duration, port: u16 },
    Tcp { handshake: Duration, port: u16 },
    /// No qshd: sessions go through ssh.
    NoQshd,
    Invalid(String),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum KeyState {
    Known,
    Unknown,
    Changed,
}

struct Host {
    alias: String,
    target: Option<Target>,
    probe: Probe,
    key: Option<KeyState>,
}

#[derive(Clone, Debug, PartialEq)]
enum Phase {
    Connecting,
    Ping,
    Download,
    Upload,
    Done,
    Failed(String),
}

struct SpeedTest {
    alias: String,
    transport: &'static str,
    phase: Phase,
    ping: Option<Duration>,
    down: Option<f64>,
    up: Option<f64>,
    /// Current reading in Mbit/s (drives the needle).
    current: f64,
    /// Readings for the sparkline, in kbit/s.
    history: Vec<u64>,
}

enum Msg {
    Probed { index: usize, probe: Probe, key: Option<KeyState> },
    Speed(SpeedEvent),
}

enum SpeedEvent {
    Phase(Phase),
    Ping(Duration),
    Reading(f64),
    Down(f64),
    Up(f64),
}

enum InputMode {
    Normal,
    Filter,
    PairCode(String),
}

/// What the event loop must do after an input event.
enum Action {
    None,
    Quit,
    Connect(usize),
    Speed(usize),
    Pair(usize, String),
    Refresh,
}

struct App {
    hosts: Vec<Host>,
    /// Position in the filtered list.
    selected: usize,
    filter: String,
    mode: InputMode,
    speed: Option<SpeedTest>,
    status: String,
    list_state: ListState,
    /// Where the host list was drawn, for mouse clicks.
    list_area: Rect,
}

impl App {
    fn new(hosts: Vec<Host>) -> App {
        let status = if hosts.is_empty() {
            "No hosts yet: add some to ~/.ssh/config or ~/.config/qsh/config".to_string()
        } else {
            String::new()
        };
        App {
            hosts,
            selected: 0,
            filter: String::new(),
            mode: InputMode::Normal,
            speed: None,
            status,
            list_state: ListState::default(),
            list_area: Rect::default(),
        }
    }

    /// Indices into `hosts` that match the filter.
    fn visible(&self) -> Vec<usize> {
        let f = self.filter.to_lowercase();
        (0..self.hosts.len())
            .filter(|&i| {
                let h = &self.hosts[i];
                f.is_empty()
                    || h.alias.to_lowercase().contains(&f)
                    || h.target.as_ref().is_some_and(|t| t.host.to_lowercase().contains(&f))
            })
            .collect()
    }

    fn current(&self) -> Option<usize> {
        self.visible().get(self.selected).copied()
    }

    fn move_selection(&mut self, delta: isize) {
        let n = self.visible().len();
        if n > 0 {
            self.selected = (self.selected as isize + delta).clamp(0, n as isize - 1) as usize;
        }
    }

    fn apply(&mut self, msg: Msg) {
        match msg {
            Msg::Probed { index, probe, key } => {
                if let Some(h) = self.hosts.get_mut(index) {
                    h.probe = probe;
                    h.key = key;
                }
            }
            Msg::Speed(ev) => {
                let Some(s) = self.speed.as_mut() else { return };
                match ev {
                    SpeedEvent::Phase(p) => {
                        if matches!(p, Phase::Download | Phase::Upload) {
                            s.history.clear();
                        }
                        if p == Phase::Done {
                            s.current = s.down.unwrap_or(0.0);
                        }
                        s.phase = p;
                    }
                    SpeedEvent::Ping(d) => s.ping = Some(d),
                    SpeedEvent::Reading(v) => {
                        s.current = v;
                        s.history.push((v * 1000.0) as u64);
                        if s.history.len() > 200 {
                            s.history.remove(0);
                        }
                    }
                    SpeedEvent::Down(v) => s.down = Some(v),
                    SpeedEvent::Up(v) => s.up = Some(v),
                }
            }
        }
    }

    fn on_event(&mut self, ev: Event) -> Action {
        match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => self.on_key(k),
            Event::Mouse(m) => {
                let area = self.list_area;
                let inside = m.column >= area.x
                    && m.column < area.x + area.width
                    && m.row > area.y
                    && m.row < area.y + area.height.saturating_sub(1);
                match m.kind {
                    MouseEventKind::ScrollDown => self.move_selection(1),
                    MouseEventKind::ScrollUp => self.move_selection(-1),
                    MouseEventKind::Down(MouseButton::Left) if inside => {
                        let row = self.list_state.offset() + (m.row - area.y - 1) as usize;
                        if row < self.visible().len() {
                            // Tap to select, tap the selected host again to connect.
                            if row == self.selected {
                                return self.current().map_or(Action::None, Action::Connect);
                            }
                            self.selected = row;
                        }
                    }
                    _ => {}
                }
                Action::None
            }
            _ => Action::None,
        }
    }

    fn on_key(&mut self, k: KeyEvent) -> Action {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        match &mut self.mode {
            InputMode::Filter => {
                match k.code {
                    KeyCode::Esc => {
                        self.filter.clear();
                        self.mode = InputMode::Normal;
                    }
                    KeyCode::Enter => self.mode = InputMode::Normal,
                    KeyCode::Backspace => {
                        self.filter.pop();
                    }
                    KeyCode::Char(c) => self.filter.push(c),
                    _ => {}
                }
                self.selected = 0;
                Action::None
            }
            InputMode::PairCode(code) => match k.code {
                KeyCode::Esc => {
                    self.mode = InputMode::Normal;
                    Action::None
                }
                KeyCode::Enter => {
                    let code = std::mem::take(code);
                    self.mode = InputMode::Normal;
                    self.current().map_or(Action::None, |i| Action::Pair(i, code))
                }
                KeyCode::Backspace => {
                    code.pop();
                    Action::None
                }
                KeyCode::Char(c) => {
                    code.push(c);
                    Action::None
                }
                _ => Action::None,
            },
            InputMode::Normal => match k.code {
                KeyCode::Char('q') => Action::Quit,
                KeyCode::Esc if self.speed.is_some() => {
                    self.speed = None;
                    Action::None
                }
                KeyCode::Esc => Action::Quit,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_selection(1);
                    Action::None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_selection(-1);
                    Action::None
                }
                KeyCode::Home => {
                    self.selected = 0;
                    Action::None
                }
                KeyCode::End => {
                    self.selected = self.visible().len().saturating_sub(1);
                    Action::None
                }
                KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                    self.current().map_or(Action::None, Action::Connect)
                }
                KeyCode::Char('s') => self.current().map_or(Action::None, Action::Speed),
                KeyCode::Char('p') => {
                    if self.current().is_some() {
                        self.mode = InputMode::PairCode(String::new());
                    }
                    Action::None
                }
                KeyCode::Char('/') => {
                    self.mode = InputMode::Filter;
                    Action::None
                }
                KeyCode::Char('r') => Action::Refresh,
                _ => Action::None,
            },
        }
    }

    fn draw(&mut self, f: &mut Frame) {
        let area = f.area();
        let [title, main, footer] = Layout::vertical([Constraint::Length(1), Constraint::Min(5), Constraint::Length(2)]).areas(area);
        let wide = area.width >= 90;
        let [list_area, detail_area] = Layout::default()
            .direction(if wide { Direction::Horizontal } else { Direction::Vertical })
            .constraints(if wide {
                [Constraint::Percentage(42), Constraint::Percentage(58)]
            } else {
                [Constraint::Percentage(40), Constraint::Percentage(60)]
            })
            .areas(main);

        self.draw_title(f, title);
        self.draw_list(f, list_area);
        self.draw_details(f, detail_area);
        self.draw_footer(f, footer, wide);
    }

    fn draw_title(&self, f: &mut Frame, area: Rect) {
        let quic = self.hosts.iter().filter(|h| matches!(h.probe, Probe::Quic { .. })).count();
        let probing = self.hosts.iter().filter(|h| h.probe == Probe::Pending).count();
        let mut spans = vec![
            " qsh ".bold().black().on_cyan(),
            Span::raw(format!("  {} hosts", self.hosts.len())),
            Span::raw("  ·  "),
            Span::styled(format!("{quic} with qshd"), Style::new().fg(Color::Green)),
        ];
        if probing > 0 {
            spans.push(Span::styled(format!("  ·  checking {probing}…"), Style::new().fg(Color::DarkGray)));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_list(&mut self, f: &mut Frame, area: Rect) {
        let visible = self.visible();
        self.selected = self.selected.min(visible.len().saturating_sub(1));
        let items: Vec<ListItem> = visible
            .iter()
            .map(|&i| {
                let h = &self.hosts[i];
                let (dot, color, label) = probe_badge(&h.probe);
                let mut spans = vec![
                    Span::styled(format!("{dot} "), Style::new().fg(color)),
                    Span::styled(h.alias.clone(), Style::new().bold()),
                ];
                if let Some(t) = &h.target {
                    if t.host != h.alias {
                        spans.push(Span::styled(format!("  {}", t.host), Style::new().fg(Color::DarkGray)));
                    }
                }
                spans.push(Span::styled(format!("  {label}"), Style::new().fg(color)));
                if h.key == Some(KeyState::Changed) {
                    spans.push(Span::styled("  KEY CHANGED", Style::new().fg(Color::Red).bold()));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();
        let title = match &self.mode {
            InputMode::Filter => format!(" hosts  /{}▏", self.filter),
            _ if !self.filter.is_empty() => format!(" hosts  /{} ", self.filter),
            _ => " hosts ".to_string(),
        };
        let list = List::new(items)
            .block(Block::bordered().border_type(BorderType::Rounded).title(title))
            .highlight_style(Style::new().bg(Color::Rgb(40, 60, 90)).add_modifier(Modifier::BOLD))
            .highlight_symbol("▶ ");
        self.list_state.select((!visible.is_empty()).then_some(self.selected));
        self.list_area = area;
        f.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn draw_details(&self, f: &mut Frame, area: Rect) {
        let Some(i) = self.current() else {
            f.render_widget(Block::bordered().border_type(BorderType::Rounded), area);
            return;
        };
        let h = &self.hosts[i];
        let block = Block::bordered().border_type(BorderType::Rounded).title(format!(" {} ", h.alias).bold());
        let inner = block.inner(area);
        f.render_widget(block, area);

        let mut lines = Vec::new();
        let field = |name: &str, value: Span<'static>| Line::from(vec![Span::styled(format!("{name:<10}"), Style::new().fg(Color::DarkGray)), value]);
        if let Some(t) = &h.target {
            lines.push(field("address", Span::raw(t.host.clone())));
            lines.push(field("user", Span::raw(t.user.clone())));
        }
        let (_, color, label) = probe_badge(&h.probe);
        let status = match &h.probe {
            Probe::Quic { port, .. } => format!("{label}  (udp {port})"),
            Probe::Tcp { port, .. } => format!("{label}  (tcp {port}, UDP blocked?)"),
            Probe::NoQshd => "no qshd: ⏎ opens plain ssh".to_string(),
            Probe::Invalid(e) => e.clone(),
            Probe::Pending => "checking…".to_string(),
        };
        lines.push(field("qshd", Span::styled(status, Style::new().fg(color))));
        if let Some(k) = h.key {
            let (text, color) = match k {
                KeyState::Known => ("known, matches", Color::Green),
                KeyState::Unknown => ("not seen yet (asked on connect)", Color::Yellow),
                KeyState::Changed => ("CHANGED — possible MitM, refusing", Color::Red),
            };
            lines.push(field("host key", Span::styled(text, Style::new().fg(color))));
        }

        match self.speed.as_ref().filter(|s| s.alias == h.alias) {
            Some(s) => {
                let [info, gauge, stats, spark] = Layout::vertical([
                    Constraint::Length(lines.len() as u16),
                    Constraint::Min(6),
                    Constraint::Length(2),
                    Constraint::Length(3),
                ])
                .areas(inner);
                f.render_widget(Paragraph::new(lines), info);
                draw_speedometer(f, gauge, s);
                f.render_widget(Paragraph::new(speed_lines(s)), stats);
                let spark_widget = Sparkline::default().data(s.history.iter().copied()).style(Style::new().fg(Color::Cyan));
                f.render_widget(spark_widget, spark);
            }
            None => {
                lines.push(Line::raw(""));
                lines.push(Line::styled("⏎ connect   s speed test   p pair with a code", Style::new().fg(Color::DarkGray)));
                f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
            }
        }
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect, wide: bool) {
        let hint = match &self.mode {
            InputMode::Filter => "type to filter · ⏎ done · Esc clear".to_string(),
            InputMode::PairCode(code) => format!("pairing code from `qshd pair`: {code}▏  (⏎ pair, Esc cancel)"),
            InputMode::Normal if wide => "⏎/tap connect · s speed · p pair · / filter · r refresh · Esc close · q quit".to_string(),
            InputMode::Normal => "⏎ connect · s speed · p pair · / find · q quit".to_string(),
        };
        let lines = vec![
            Line::styled(self.status.clone(), Style::new().fg(Color::Yellow)),
            Line::styled(hint, Style::new().fg(Color::DarkGray)),
        ];
        f.render_widget(Paragraph::new(lines), area);
    }
}

fn probe_badge(p: &Probe) -> (&'static str, Color, String) {
    match p {
        Probe::Pending => ("◌", Color::Blue, String::new()),
        Probe::Quic { handshake, .. } => ("●", Color::Green, format!("quic {}", fmt_ms(*handshake))),
        Probe::Tcp { handshake, .. } => ("●", Color::Yellow, format!("tcp {}", fmt_ms(*handshake))),
        Probe::NoQshd => ("○", Color::DarkGray, "ssh".to_string()),
        Probe::Invalid(_) => ("✗", Color::Red, "invalid".to_string()),
    }
}

fn fmt_ms(d: Duration) -> String {
    format!("{:.0} ms", d.as_secs_f64() * 1000.0)
}

fn fmt_mbps(v: f64) -> String {
    if v >= 1000.0 { format!("{:.2} Gbit/s", v / 1000.0) } else { format!("{v:.1} Mbit/s") }
}

fn speed_lines(s: &SpeedTest) -> Vec<Line<'static>> {
    let phase = match &s.phase {
        Phase::Connecting => "connecting…".to_string(),
        Phase::Ping => "measuring latency…".to_string(),
        Phase::Download => "download…".to_string(),
        Phase::Upload => "upload…".to_string(),
        Phase::Done => format!("done over {} · Esc to close · s to repeat", s.transport),
        Phase::Failed(e) => format!("failed: {e}"),
    };
    let opt = |v: Option<f64>| v.map(fmt_mbps).unwrap_or_else(|| "—".into());
    vec![
        Line::from(vec![
            Span::styled("ping ", Style::new().fg(Color::DarkGray)),
            Span::raw(s.ping.map(fmt_ms).unwrap_or_else(|| "—".into())).bold(),
            Span::styled("   ↓ ", Style::new().fg(Color::DarkGray)),
            Span::raw(opt(s.down)).bold().green(),
            Span::styled("   ↑ ", Style::new().fg(Color::DarkGray)),
            Span::raw(opt(s.up)).bold().magenta(),
        ]),
        Line::styled(phase, Style::new().fg(if matches!(s.phase, Phase::Failed(_)) { Color::Red } else { Color::DarkGray })),
    ]
}

/// Position on the log-scale dial, 0..=1.
fn dial_fraction(mbps: f64) -> f64 {
    ((1.0 + mbps.max(0.0)).ln() / (1.0 + GAUGE_MAX_MBPS).ln()).clamp(0.0, 1.0)
}

/// A half-circle speedometer with a needle on a log scale.
fn draw_speedometer(f: &mut Frame, area: Rect, s: &SpeedTest) {
    let angle = |frac: f64| std::f64::consts::PI * (1.0 - frac);
    let arc = |from: f64, to: f64| -> Vec<(f64, f64)> {
        (0..=120)
            .map(|i| from + (to - from) * i as f64 / 120.0)
            .flat_map(|frac| {
                let a = angle(frac);
                [(a.cos(), a.sin()), (0.95 * a.cos(), 0.95 * a.sin())]
            })
            .collect()
    };
    let (green, yellow, red) = (arc(0.0, 0.5), arc(0.5, 0.8), arc(0.8, 1.0));
    let value = s.current;
    let needle = angle(dial_fraction(value));
    let canvas = Canvas::default()
        .marker(Marker::Braille)
        .x_bounds([-1.35, 1.35])
        .y_bounds([-0.45, 1.2])
        .paint(move |ctx| {
            ctx.draw(&Points { coords: &green, color: Color::Green });
            ctx.draw(&Points { coords: &yellow, color: Color::Yellow });
            ctx.draw(&Points { coords: &red, color: Color::Red });
            for (v, label) in [(0.0, "0"), (1.0, "1"), (10.0, "10"), (100.0, "100"), (1000.0, "1G")] {
                let a = angle(dial_fraction(v));
                ctx.draw(&CanvasLine { x1: 0.85 * a.cos(), y1: 0.85 * a.sin(), x2: 0.95 * a.cos(), y2: 0.95 * a.sin(), color: Color::Gray });
                ctx.print(1.1 * a.cos() - 0.05, 1.08 * a.sin(), Span::styled(label, Style::new().fg(Color::DarkGray)));
            }
            ctx.layer();
            ctx.draw(&CanvasLine { x1: 0.0, y1: 0.0, x2: 0.8 * needle.cos(), y2: 0.8 * needle.sin(), color: Color::White });
            ctx.draw(&Circle { x: 0.0, y: 0.0, radius: 0.06, color: Color::White });
            let text = fmt_mbps(value);
            ctx.print(-(text.len() as f64) * 0.025, -0.3, Span::styled(text, Style::new().bold().fg(Color::Cyan)));
        });
    f.render_widget(canvas, area);
}

/// Hosts from the configs, then known_hosts entries not covered by them.
fn load_hosts() -> Vec<Host> {
    let mut aliases = home_dir().map(|h| super::config::host_aliases(&h)).unwrap_or_default();
    for id in super::known_host_ids() {
        // `[host]:port` → `host:port`, which the parser accepts as a destination.
        let dest = match id.strip_prefix('[').and_then(|r| r.split_once("]:")) {
            Some((h, p)) if !h.contains(':') => format!("{h}:{p}"),
            Some((h, p)) => format!("[{h}]:{p}"),
            None => id.clone(),
        };
        let covered = aliases.iter().any(|a| a == &dest);
        if !covered {
            aliases.push(dest);
        }
    }
    aliases
        .into_iter()
        .map(|alias| match Target::parse(&alias, None, true) {
            Ok(t) => Host { alias, target: Some(t), probe: Probe::Pending, key: None },
            Err(e) => Host { alias, target: None, probe: Probe::Invalid(format!("{e:#}")), key: None },
        })
        .collect()
}

fn key_state(host: &str, port: u16, key: crate::keys::PublicKey) -> KeyState {
    match super::known_host_key(host, port) {
        Ok(Some(k)) if k == key => KeyState::Known,
        Ok(Some(_)) => KeyState::Changed,
        _ => KeyState::Unknown,
    }
}

/// TLS handshake only (no login) with a throwaway key: is qshd there, how fast?
async fn probe(target: Target, id: Arc<Identity>) -> (Probe, Option<KeyState>) {
    let Ok(tls) = crate::tls::client_config(&id) else { return (Probe::NoQshd, None) };
    let ports: Vec<u16> = std::iter::once(target.port).chain(target.alt_ports.iter().copied()).collect();
    let start = Instant::now();
    if let Ok(conn) = transport::connect_probe(&target.host, &ports, target.family, tls.clone()).await {
        let handshake = start.elapsed();
        let port = conn.remote_addr().port();
        let key = key_state(&target.host, port, conn.peer_key());
        conn.close().await;
        return (Probe::Quic { handshake, port }, Some(key));
    }
    // UDP may be blocked: try the TLS-over-TCP fallback on the qsh port.
    let port = target.alt_ports.first().copied().unwrap_or(target.port);
    let start = Instant::now();
    match tokio::time::timeout(PROBE_TCP_TIMEOUT, transport::connect(&target.host, port, Transport::Tcp, target.family, tls)).await {
        Ok(Ok(conn)) => {
            let handshake = start.elapsed();
            let key = key_state(&target.host, port, conn.peer_key());
            conn.close().await;
            (Probe::Tcp { handshake, port }, Some(key))
        }
        _ => (Probe::NoQshd, None),
    }
}

fn start_probes(app: &mut App, only: Option<usize>, tx: &mpsc::UnboundedSender<Msg>, id: &Arc<Identity>) {
    for (index, h) in app.hosts.iter_mut().enumerate() {
        if only.is_some_and(|o| o != index) {
            continue;
        }
        let Some(target) = h.target.clone() else { continue };
        h.probe = Probe::Pending;
        let (tx, id) = (tx.clone(), id.clone());
        tokio::spawn(async move {
            let (probe, key) = probe(target, id).await;
            let _ = tx.send(Msg::Probed { index, probe, key });
        });
    }
}

fn run_speed_test(conn: Arc<Conn>, tx: mpsc::UnboundedSender<Msg>) {
    let send = move |ev| {
        let _ = tx.send(Msg::Speed(ev));
    };
    tokio::spawn(async move {
        let result: Result<()> = async {
            send(SpeedEvent::Phase(Phase::Ping));
            let mut pings = Vec::new();
            for _ in 0..5 {
                pings.push(speed::ping(&conn).await?);
            }
            pings.sort();
            send(SpeedEvent::Ping(pings[2]));
            send(SpeedEvent::Phase(Phase::Download));
            let (b, t) = speed::download(&conn, SPEED_SECONDS, |b, t| send(SpeedEvent::Reading(speed::mbps(b, t)))).await?;
            send(SpeedEvent::Down(speed::mbps(b, t)));
            send(SpeedEvent::Phase(Phase::Upload));
            let (b, t) = speed::upload(&conn, SPEED_SECONDS, |b, t| send(SpeedEvent::Reading(speed::mbps(b, t)))).await?;
            send(SpeedEvent::Up(speed::mbps(b, t)));
            Ok(())
        }
        .await;
        conn.close().await;
        send(SpeedEvent::Phase(match result {
            Ok(()) => Phase::Done,
            Err(e) => Phase::Failed(format!("{e:#}")),
        }));
    });
}

fn enter() -> std::io::Result<DefaultTerminal> {
    let terminal = ratatui::init();
    crossterm::execute!(std::io::stdout(), crossterm::event::EnableMouseCapture)?;
    Ok(terminal)
}

fn leave() {
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableMouseCapture);
    ratatui::restore();
}

fn wait_for_enter() {
    use std::io::BufRead;
    eprint!("\n[press Enter to return to the menu]");
    let _ = std::io::stdin().lock().read_line(&mut String::new());
}

/// Runs this binary with `args` in the plain terminal and waits for it.
async fn run_child(args: &[String]) -> std::io::Result<std::process::ExitStatus> {
    let exe = std::env::current_exe()?;
    tokio::process::Command::new(exe).args(args).status().await
}

/// Common flags passed on to sessions started from the menu.
fn child_flags(opts: &ConnectOptions) -> Vec<String> {
    let mut args = Vec::new();
    for i in &opts.identities {
        args.push("-i".into());
        args.push(i.display().to_string());
    }
    if opts.accept_new_host {
        args.push("--accept-new-host".into());
    }
    args
}

pub async fn run(opts: ConnectOptions) -> Result<i32> {
    // ^C reaches us too while a session runs in the foreground; never die from it.
    let _sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut app = App::new(load_hosts());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let probe_key = Arc::new(Identity::generate());
    start_probes(&mut app, None, &tx, &probe_key);

    let mut terminal = enter()?;
    let result = loop {
        while let Ok(msg) = rx.try_recv() {
            app.apply(msg);
        }
        if let Err(e) = terminal.draw(|f| app.draw(f)) {
            break Err(e.into());
        }
        // Poll synchronously so nothing reads the terminal while a session owns it.
        let ev = tokio::task::block_in_place(|| -> std::io::Result<Option<Event>> {
            if event::poll(Duration::from_millis(50))? { Ok(Some(event::read()?)) } else { Ok(None) }
        });
        let action = match ev {
            Ok(Some(ev)) => app.on_event(ev),
            Ok(None) => Action::None,
            Err(e) => break Err(e.into()),
        };
        match action {
            Action::None => {}
            Action::Quit => break Ok(0),
            Action::Refresh => {
                app.hosts = load_hosts();
                start_probes(&mut app, None, &tx, &probe_key);
                app.status = "refreshing…".into();
            }
            Action::Connect(i) => {
                leave();
                let mut args = child_flags(&opts);
                args.push("--full".into());
                args.push(app.hosts[i].alias.clone());
                let status = run_child(&args).await;
                terminal = enter()?;
                app.status = match status {
                    Ok(s) if s.success() => format!("session to {} ended", app.hosts[i].alias),
                    Ok(s) => format!("session to {} ended ({s})", app.hosts[i].alias),
                    Err(e) => format!("cannot start session: {e}"),
                };
                start_probes(&mut app, Some(i), &tx, &probe_key);
            }
            Action::Pair(i, code) => {
                leave();
                let mut args = vec!["pair".to_string(), "--full".into()];
                args.extend(child_flags(&opts));
                args.push(app.hosts[i].alias.clone());
                args.push(code);
                let status = run_child(&args).await;
                wait_for_enter();
                terminal = enter()?;
                app.status = match status {
                    Ok(s) if s.success() => format!("paired with {}", app.hosts[i].alias),
                    _ => "pairing failed".to_string(),
                };
                start_probes(&mut app, Some(i), &tx, &probe_key);
            }
            Action::Speed(i) => {
                let host = &app.hosts[i];
                let (port, mode) = match host.probe {
                    Probe::Quic { port, .. } => (port, Transport::Quic),
                    Probe::Tcp { port, .. } => (port, Transport::Tcp),
                    _ => {
                        app.status = format!("{}: the speed test needs qshd on the host", host.alias);
                        continue;
                    }
                };
                let Some(mut target) = host.target.clone() else { continue };
                target.port = port;
                target.alt_ports.clear();
                let alias = host.alias.clone();
                // Log in outside the TUI: it may ask about the host key or a passphrase.
                leave();
                eprintln!("Connecting to {alias} for a speed test…");
                let conn_opts = ConnectOptions { transport: mode, full: false, ..opts.clone() };
                let conn = super::connect(&target, &conn_opts).await;
                if conn.is_err() {
                    if let Err(e) = &conn {
                        eprintln!("qsh: {e:#}");
                    }
                    wait_for_enter();
                }
                terminal = enter()?;
                match conn {
                    Ok(conn) => {
                        let transport = conn.transport_name();
                        app.speed = Some(SpeedTest {
                            alias,
                            transport,
                            phase: Phase::Connecting,
                            ping: None,
                            down: None,
                            up: None,
                            current: 0.0,
                            history: Vec::new(),
                        });
                        app.status.clear();
                        run_speed_test(Arc::new(conn), tx.clone());
                    }
                    Err(e) => app.status = format!("{alias}: {e:#}"),
                }
            }
        }
    };
    leave();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn host(alias: &str, probe: Probe) -> Host {
        let target = Target::parse_with(&format!("root@{alias}"), None, None, true).ok();
        Host { alias: alias.into(), target, probe, key: Some(KeyState::Known) }
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn sample() -> App {
        App::new(vec![
            host("alpha", Probe::Quic { handshake: Duration::from_millis(42), port: 4422 }),
            host("beta", Probe::NoQshd),
            host("gamma", Probe::Pending),
        ])
    }

    #[test]
    fn renders_host_list_and_details() {
        let mut app = sample();
        let screen = render(&mut app, 100, 24);
        assert!(screen.contains("alpha") && screen.contains("quic 42 ms"), "{screen}");
        assert!(screen.contains("beta") && screen.contains("ssh"));
        assert!(screen.contains("known, matches"));
        assert!(screen.contains("1 with qshd"));
    }

    #[test]
    fn renders_speedometer_on_a_phone_sized_screen() {
        let mut app = sample();
        app.speed = Some(SpeedTest {
            alias: "alpha".into(),
            transport: "quic",
            phase: Phase::Done,
            ping: Some(Duration::from_millis(41)),
            down: Some(85.2),
            up: Some(70.1),
            current: 85.2,
            history: vec![10, 50, 80],
        });
        let screen = render(&mut app, 46, 30);
        assert!(screen.contains("85.2 Mbit/s"), "{screen}");
        assert!(screen.contains("70.1 Mbit/s"));
        assert!(screen.contains("41 ms"));
        assert!(screen.contains("100") && screen.contains("1G"), "dial labels");
    }

    #[test]
    fn keys_filter_and_select() {
        let mut app = sample();
        let key = |c| Event::Key(KeyEvent::new(c, KeyModifiers::NONE));
        assert!(matches!(app.on_event(key(KeyCode::Down)), Action::None));
        assert_eq!(app.current(), Some(1));
        app.on_event(key(KeyCode::Char('/')));
        for c in "gam".chars() {
            app.on_event(key(KeyCode::Char(c)));
        }
        app.on_event(key(KeyCode::Enter));
        assert_eq!(app.visible(), vec![2]);
        assert!(matches!(app.on_event(key(KeyCode::Enter)), Action::Connect(2)));
        assert!(matches!(app.on_event(key(KeyCode::Char('s'))), Action::Speed(2)));
        app.on_event(key(KeyCode::Char('p')));
        for c in "ab12".chars() {
            app.on_event(key(KeyCode::Char(c)));
        }
        assert!(matches!(app.on_event(key(KeyCode::Enter)), Action::Pair(2, ref code) if code == "ab12"));
        assert!(matches!(app.on_event(key(KeyCode::Char('q'))), Action::Quit));
    }

    #[test]
    fn dial_is_logarithmic() {
        assert_eq!(dial_fraction(0.0), 0.0);
        assert!((dial_fraction(GAUGE_MAX_MBPS) - 1.0).abs() < 1e-9);
        assert!(dial_fraction(10.0) > 0.3 && dial_fraction(10.0) < 0.4);
        assert_eq!(dial_fraction(1e9), 1.0);
    }
}
