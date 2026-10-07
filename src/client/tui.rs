//! `qsh ui`: an interactive connection menu with live qshd status, saved
//! connections, a history and a speed test.
//!
//! Hosts come from the connections saved here (`~/.config/qsh/ui-hosts`),
//! `~/.config/qsh/config`, `~/.ssh/config` and known_hosts. Each is checked in
//! the background with a throwaway key (TLS handshake only, no login); results
//! are cached in `~/.config/qsh/ui-state.toml` for a few minutes, so opening the
//! menu again does not contact every server. Sessions run as a child `qsh`
//! (with `--full` by default, so hosts without qshd open with plain ssh).
//! Works with the keyboard and with a mouse or touch screen (e.g. Termux).

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Circle, Line as CanvasLine, Points};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Sparkline, Wrap};
use ratatui::{DefaultTerminal, Frame};
use tokio::sync::mpsc;

use super::saved::{self, Saved};
use super::ui_state::{ago, now, CachedProbe, Prefs, UiState};
use super::{speed, ConnectOptions, Target};
use crate::keys::{home_dir, Identity};
use crate::transport::{self, Conn, Mode as Transport};

const PROBE_TCP_TIMEOUT: Duration = Duration::from_secs(3);
const SPEED_SECONDS: Duration = Duration::from_secs(5);
/// Top of the speedometer scale (log scale from 0).
const GAUGE_MAX_MBPS: f64 = 1000.0;
const TRANSPORTS: [&str; 3] = ["auto", "quic", "tcp"];

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

/// Where a host comes from.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Source {
    /// Saved in this menu (`ui-hosts`): can be edited and deleted here.
    Saved,
    /// `~/.config/qsh/config` or `~/.ssh/config`.
    Config,
    /// Only in known_hosts (connected to before).
    KnownHost,
}

struct Host {
    alias: String,
    target: Option<Target>,
    probe: Probe,
    key: Option<KeyState>,
    source: Source,
    /// When `probe` was measured (Unix time), if it was.
    checked_at: Option<u64>,
}

impl Host {
    /// What a probe of this host contacts; a cached result for another endpoint is stale.
    fn endpoint(&self) -> Option<String> {
        let t = self.target.as_ref()?;
        let ports: Vec<String> = std::iter::once(t.port).chain(t.alt_ports.iter().copied()).map(|p| p.to_string()).collect();
        Some(format!("{}:{}", t.host, ports.join(",")))
    }
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
    Probed { alias: String, endpoint: String, probe: Probe, key: Option<KeyState> },
    Speed(SpeedEvent),
}

enum SpeedEvent {
    Phase(Phase),
    Ping(Duration),
    Reading(f64),
    Down(f64),
    Up(f64),
}

/// The new/edit connection form.
#[derive(Clone, Debug, PartialEq)]
struct Form {
    /// The saved name being edited (`None` for a new connection).
    original: Option<String>,
    name: String,
    host: String,
    user: String,
    port: String,
    key: String,
    transport: usize,
    fallback: bool,
    focus: usize,
    error: Option<String>,
    /// A host from the user's own config files: only the menu's preferences
    /// (transport, ssh fallback) can change here, never the config itself.
    locked: bool,
}

const FORM_FIELDS: [&str; 7] = ["name", "host", "user", "port", "key file", "transport", "no qshd"];

impl Form {
    fn new() -> Form {
        Form {
            original: None,
            name: String::new(),
            host: String::new(),
            user: String::new(),
            port: String::new(),
            key: String::new(),
            transport: 0,
            fallback: true,
            focus: 0,
            error: None,
            locked: false,
        }
    }

    fn with_prefs(mut self, p: &Prefs) -> Form {
        self.transport = TRANSPORTS.iter().position(|t| *t == p.transport).unwrap_or(0);
        self.fallback = p.ssh_fallback;
        self
    }

    /// A form for `user@host[:port]` (from the history or quick connect).
    fn from_dest(dest: &str) -> Form {
        let (user, rest) = match dest.rsplit_once('@') {
            Some((u, r)) => (u.to_string(), r),
            None => (String::new(), dest),
        };
        let (host, port) = match rest.strip_prefix('[').and_then(|r| r.split_once(']')) {
            Some((h, p)) => (h.to_string(), p.trim_start_matches(':').to_string()),
            None => match rest.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => (h.to_string(), p.to_string()),
                _ => (rest.to_string(), String::new()),
            },
        };
        let name = host.split('.').next().unwrap_or_default().replace(':', "-");
        Form { name, host, user, port, ..Form::new() }
    }

    /// A form for editing a host from any source.
    fn from_host(h: &Host, prefs: &Prefs) -> Form {
        let mut f = Form::new().with_prefs(prefs);
        f.original = (h.source != Source::KnownHost).then(|| h.alias.clone());
        f.locked = h.source == Source::Config;
        if f.locked {
            f.focus = 5;
        }
        f.name = h.alias.clone();
        if let Some(t) = &h.target {
            f.host = t.host.clone();
            f.user = t.user.clone();
            if t.cli_port.is_some() || t.port != crate::DEFAULT_PORT {
                f.port = t.port.to_string();
            }
            f.key = t.identity_files.first().map(|p| p.display().to_string()).unwrap_or_default();
        }
        f
    }

    fn text_mut(&mut self) -> Option<&mut String> {
        if self.locked {
            return None;
        }
        match self.focus {
            0 => Some(&mut self.name),
            1 => Some(&mut self.host),
            2 => Some(&mut self.user),
            3 => Some(&mut self.port),
            4 => Some(&mut self.key),
            _ => None,
        }
    }

    /// The saved connection and preferences, or what is wrong with the input.
    fn result(&self) -> Result<(Saved, Prefs), String> {
        let opt = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_string());
        let port = match opt(&self.port) {
            None => None,
            Some(p) => Some(p.parse::<u16>().ok().filter(|&p| p > 0).ok_or("port: a number from 1 to 65535")?),
        };
        let saved = Saved { name: self.name.trim().to_string(), host: self.host.trim().to_string(), user: opt(&self.user), port, identity: opt(&self.key) };
        saved.validate().map_err(|e| e.to_string())?;
        Ok((saved, Prefs { transport: TRANSPORTS[self.transport].to_string(), ssh_fallback: self.fallback }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum View {
    Hosts,
    History,
}

enum InputMode {
    Normal,
    Filter,
    PairCode(String),
    /// One-off connection: `user@host[:port]`.
    Quick(String),
    Form(Box<Form>),
    ConfirmDelete(String),
}

/// What the event loop must do after an input event.
#[derive(Debug, PartialEq)]
enum Action {
    None,
    Quit,
    /// Connect to an alias or `user@host[:port]`.
    Connect(String),
    Speed(usize),
    Pair(usize, String),
    Refresh,
    Save(Box<Form>),
    Delete(String),
}

struct App {
    hosts: Vec<Host>,
    state: UiState,
    view: View,
    /// Position in the visible list.
    selected: usize,
    filter: String,
    mode: InputMode,
    speed: Option<SpeedTest>,
    status: String,
    list_state: ListState,
    /// Where the list was drawn, for mouse clicks.
    list_area: Rect,
    /// Current time for "5 min ago" labels.
    now: u64,
}

impl App {
    fn new(hosts: Vec<Host>, state: UiState) -> App {
        let status = if hosts.is_empty() {
            "No hosts yet: press n to add one, or c to connect once".to_string()
        } else {
            String::new()
        };
        App {
            hosts,
            state,
            view: View::Hosts,
            selected: 0,
            filter: String::new(),
            mode: InputMode::Normal,
            speed: None,
            status,
            list_state: ListState::default(),
            list_area: Rect::default(),
            now: now(),
        }
    }

    fn matches(&self, text: &str) -> bool {
        self.filter.is_empty() || text.to_lowercase().contains(&self.filter.to_lowercase())
    }

    /// Visible rows: indices into `hosts` (recently used first) or into the history.
    fn visible(&self) -> Vec<usize> {
        match self.view {
            View::Hosts => {
                let mut rows: Vec<usize> = (0..self.hosts.len())
                    .filter(|&i| {
                        let h = &self.hosts[i];
                        self.matches(&h.alias) || h.target.as_ref().is_some_and(|t| self.matches(&t.host))
                    })
                    .collect();
                // Stable: hosts never used keep their config order.
                rows.sort_by_key(|&i| std::cmp::Reverse(self.state.last_used(&self.hosts[i].alias).unwrap_or(0)));
                rows
            }
            View::History => (0..self.state.history.len()).filter(|&i| self.matches(&self.state.history[i].dest)).collect(),
        }
    }

    fn current(&self) -> Option<usize> {
        self.visible().get(self.selected).copied()
    }

    /// The host under the cursor (hosts view only).
    fn current_host(&self) -> Option<usize> {
        if self.view == View::Hosts { self.current() } else { None }
    }

    /// What Enter connects to.
    fn current_dest(&self) -> Option<String> {
        let i = self.current()?;
        Some(match self.view {
            View::Hosts => self.hosts[i].alias.clone(),
            View::History => self.state.history[i].dest.clone(),
        })
    }

    fn move_selection(&mut self, delta: isize) {
        let n = self.visible().len();
        if n > 0 {
            self.selected = (self.selected as isize + delta).clamp(0, n as isize - 1) as usize;
        }
    }

    /// Applies a message; returns true if the persistent state changed.
    fn apply(&mut self, msg: Msg) -> bool {
        match msg {
            Msg::Probed { alias, endpoint, probe, key } => {
                let Some(h) = self.hosts.iter_mut().find(|h| h.alias == alias && h.endpoint().as_deref() == Some(&endpoint)) else {
                    return false;
                };
                h.probe = probe;
                h.key = key;
                h.checked_at = Some(now());
                match to_cache(&h.probe, h.key, endpoint) {
                    Some(c) => {
                        self.state.probes.insert(alias, c);
                        true
                    }
                    None => false,
                }
            }
            Msg::Speed(ev) => {
                let Some(s) = self.speed.as_mut() else { return false };
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
                false
            }
        }
    }

    fn on_event(&mut self, ev: Event) -> Action {
        match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => self.on_key(k),
            Event::Mouse(m) if matches!(self.mode, InputMode::Normal) => {
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
                            // Tap to select, tap the selected row again to connect.
                            if row == self.selected {
                                return self.current_dest().map_or(Action::None, Action::Connect);
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
            InputMode::PairCode(code) | InputMode::Quick(code) => match k.code {
                KeyCode::Esc => {
                    self.mode = InputMode::Normal;
                    Action::None
                }
                KeyCode::Enter => {
                    let text = std::mem::take(code).trim().to_string();
                    let quick = matches!(self.mode, InputMode::Quick(_));
                    self.mode = InputMode::Normal;
                    match (quick, text.is_empty()) {
                        (_, true) => Action::None,
                        (true, false) => Action::Connect(text),
                        (false, false) => self.current_host().map_or(Action::None, |i| Action::Pair(i, text)),
                    }
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
            InputMode::Form(form) => {
                let last = FORM_FIELDS.len() - 1;
                match k.code {
                    KeyCode::Esc => self.mode = InputMode::Normal,
                    KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1).min(last),
                    // Locked forms only have the two preference fields.
                    KeyCode::BackTab | KeyCode::Up => form.focus = form.focus.saturating_sub(1).max(if form.locked { 5 } else { 0 }),
                    KeyCode::Enter => match form.result() {
                        Ok(_) => {
                            let InputMode::Form(form) = std::mem::replace(&mut self.mode, InputMode::Normal) else { unreachable!() };
                            return Action::Save(form);
                        }
                        Err(e) => form.error = Some(e),
                    },
                    KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if form.focus == 5 => {
                        let step = if k.code == KeyCode::Left { TRANSPORTS.len() - 1 } else { 1 };
                        form.transport = (form.transport + step) % TRANSPORTS.len();
                    }
                    KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if form.focus == 6 => form.fallback = !form.fallback,
                    KeyCode::Backspace => {
                        if let Some(t) = form.text_mut() {
                            t.pop();
                        }
                    }
                    KeyCode::Char(c) => {
                        if let Some(t) = form.text_mut() {
                            t.push(c);
                            form.error = None;
                        }
                    }
                    _ => {}
                }
                Action::None
            }
            InputMode::ConfirmDelete(name) => {
                let name = name.clone();
                self.mode = InputMode::Normal;
                if matches!(k.code, KeyCode::Char('y') | KeyCode::Char('Y')) { Action::Delete(name) } else { Action::None }
            }
            InputMode::Normal => self.on_normal_key(k),
        }
    }

    fn on_normal_key(&mut self, k: KeyEvent) -> Action {
        match k.code {
            KeyCode::Char('q') => Action::Quit,
            KeyCode::Esc if self.speed.is_some() => {
                self.speed = None;
                Action::None
            }
            KeyCode::Esc if !self.filter.is_empty() => {
                self.filter.clear();
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
            KeyCode::Tab | KeyCode::Char('h') => {
                self.view = if self.view == View::Hosts { View::History } else { View::Hosts };
                self.selected = 0;
                Action::None
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.current_dest().map_or(Action::None, Action::Connect),
            KeyCode::Char('c') => {
                self.mode = InputMode::Quick(String::new());
                Action::None
            }
            KeyCode::Char('n') => {
                self.mode = InputMode::Form(Box::new(Form::new()));
                Action::None
            }
            // Edit a host, or save a history entry as a connection.
            KeyCode::Char('e') | KeyCode::Char('a') => {
                let form = match (self.view, self.current()) {
                    (View::Hosts, Some(i)) => Form::from_host(&self.hosts[i], &self.state.prefs(&self.hosts[i].alias)),
                    (View::History, Some(i)) => {
                        let dest = &self.state.history[i].dest;
                        match self.hosts.iter().find(|h| &h.alias == dest) {
                            Some(h) => Form::from_host(h, &self.state.prefs(dest)),
                            None => Form::from_dest(dest),
                        }
                    }
                    (_, None) => return Action::None,
                };
                self.mode = InputMode::Form(Box::new(form));
                Action::None
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                match (self.view, self.current()) {
                    (View::Hosts, Some(i)) if self.hosts[i].source == Source::Saved => {
                        self.mode = InputMode::ConfirmDelete(self.hosts[i].alias.clone());
                    }
                    (View::Hosts, Some(i)) => {
                        self.status = format!("{} is not saved here (it comes from a config file or known_hosts)", self.hosts[i].alias);
                    }
                    (View::History, Some(i)) => {
                        self.state.history.remove(i);
                        self.selected = self.selected.min(self.visible().len().saturating_sub(1));
                    }
                    (_, None) => {}
                }
                Action::None
            }
            KeyCode::Char('s') => self.current_host().map_or(Action::None, Action::Speed),
            KeyCode::Char('p') => {
                if self.current_host().is_some() {
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
        match self.view {
            View::Hosts => self.draw_details(f, detail_area),
            View::History => self.draw_history_details(f, detail_area),
        }
        self.draw_footer(f, footer, wide);
        if let InputMode::Form(form) = &self.mode {
            draw_form(f, area, form);
        }
    }

    fn draw_title(&self, f: &mut Frame, area: Rect) {
        let quic = self.hosts.iter().filter(|h| matches!(h.probe, Probe::Quic { .. })).count();
        let probing = self.hosts.iter().filter(|h| h.probe == Probe::Pending).count();
        let tab = |name: &str, on: bool| {
            if on { Span::styled(format!(" {name} "), Style::new().bold().black().on_white()) } else { Span::styled(format!(" {name} "), Style::new().fg(Color::DarkGray)) }
        };
        let mut spans = vec![
            " qsh ".bold().black().on_cyan(),
            Span::raw(" "),
            tab(&format!("hosts {}", self.hosts.len()), self.view == View::Hosts),
            tab(&format!("history {}", self.state.history.len()), self.view == View::History),
            Span::raw("  "),
            Span::styled(format!("{quic} with qshd"), Style::new().fg(Color::Green)),
        ];
        if probing > 0 {
            spans.push(Span::styled(format!("  ·  checking {probing}…"), Style::new().fg(Color::DarkGray)));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn host_item(&self, h: &Host) -> ListItem<'static> {
        let (dot, color, label) = probe_badge(&h.probe);
        let mut spans = vec![Span::styled(format!("{dot} "), Style::new().fg(color)), Span::styled(h.alias.clone(), Style::new().bold())];
        if h.source == Source::Saved {
            spans.push(Span::styled(" ★", Style::new().fg(Color::Yellow)));
        }
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
    }

    fn draw_list(&mut self, f: &mut Frame, area: Rect) {
        let visible = self.visible();
        self.selected = self.selected.min(visible.len().saturating_sub(1));
        let items: Vec<ListItem> = match self.view {
            View::Hosts => visible.iter().map(|&i| self.host_item(&self.hosts[i])).collect(),
            View::History => visible
                .iter()
                .map(|&i| {
                    let e = &self.state.history[i];
                    let (mark, color) = if e.ok { ("✓", Color::Green) } else { ("✗", Color::Red) };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{mark} "), Style::new().fg(color)),
                        Span::styled(e.dest.clone(), Style::new().bold()),
                        Span::styled(format!("  {}", ago(e.at, self.now)), Style::new().fg(Color::DarkGray)),
                    ]))
                })
                .collect(),
        };
        let name = if self.view == View::Hosts { "hosts" } else { "history" };
        let title = match &self.mode {
            InputMode::Filter => format!(" {name}  /{}▏", self.filter),
            _ if !self.filter.is_empty() => format!(" {name}  /{} ", self.filter),
            _ => format!(" {name} "),
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
            let hint = Paragraph::new(vec![
                Line::raw(""),
                Line::styled("  n  new connection", Style::new().fg(Color::DarkGray)),
                Line::styled("  c  connect once to user@host", Style::new().fg(Color::DarkGray)),
            ]);
            f.render_widget(hint.block(Block::bordered().border_type(BorderType::Rounded)), area);
            return;
        };
        let h = &self.hosts[i];
        let block = Block::bordered().border_type(BorderType::Rounded).title(format!(" {} ", h.alias).bold());
        let inner = block.inner(area);
        f.render_widget(block, area);

        let mut lines = Vec::new();
        let field = |name: &str, value: Span<'static>| Line::from(vec![Span::styled(format!("{name:<10}"), Style::new().fg(Color::DarkGray)), value]);
        if let Some(t) = &h.target {
            lines.push(field("address", Span::raw(format!("{}@{}", t.user, t.host))));
        }
        let (_, color, label) = probe_badge(&h.probe);
        let status = match &h.probe {
            Probe::Quic { port, .. } => format!("{label}  (udp {port})"),
            Probe::Tcp { port, .. } => format!("{label}  (tcp {port}, UDP blocked?)"),
            Probe::NoQshd => "no qshd".to_string(),
            Probe::Invalid(e) => e.clone(),
            Probe::Pending => "checking…".to_string(),
        };
        let checked = h.checked_at.map(|t| format!("  · {}", ago(t, self.now))).unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled(format!("{:<10}", "qshd"), Style::new().fg(Color::DarkGray)),
            Span::styled(status, Style::new().fg(color)),
            Span::styled(checked, Style::new().fg(Color::DarkGray)),
        ]));
        if let Some(k) = h.key {
            let (text, color) = match k {
                KeyState::Known => ("known, matches", Color::Green),
                KeyState::Unknown => ("not seen yet (asked on connect)", Color::Yellow),
                KeyState::Changed => ("CHANGED — possible MitM, refusing", Color::Red),
            };
            lines.push(field("host key", Span::styled(text, Style::new().fg(color))));
        }
        let prefs = self.state.prefs(&h.alias);
        let via = match (prefs.transport.as_str(), prefs.ssh_fallback) {
            (t, true) => format!("{t}, ssh if no qshd"),
            (t, false) => format!("{t}, qsh only"),
        };
        lines.push(field("connect", Span::raw(via)));
        if let Some(t) = self.state.last_used(&h.alias) {
            lines.push(field("last used", Span::raw(ago(t, self.now))));
        }
        let source = match h.source {
            Source::Saved => "saved here (e edit, d delete)",
            Source::Config => "your config file (e: menu settings)",
            Source::KnownHost => "known_hosts (e saves it here)",
        };
        lines.push(field("from", Span::styled(source, Style::new().fg(Color::DarkGray))));

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

    fn draw_history_details(&self, f: &mut Frame, area: Rect) {
        let block = Block::bordered().border_type(BorderType::Rounded);
        let Some(i) = self.current() else {
            f.render_widget(Paragraph::new("  no connections yet").block(block), area);
            return;
        };
        let e = &self.state.history[i];
        let saved = self.hosts.iter().any(|h| h.alias == e.dest && h.source != Source::KnownHost);
        let lines = vec![
            Line::from(vec![Span::styled("result    ", Style::new().fg(Color::DarkGray)), if e.ok { "connected".green() } else { "failed".red() }]),
            Line::from(vec![Span::styled("when      ", Style::new().fg(Color::DarkGray)), Span::raw(ago(e.at, self.now))]),
            Line::raw(""),
            Line::styled(
                if saved { "⏎ connect again   d remove from history" } else { "⏎ connect again   a save as a connection   d remove" },
                Style::new().fg(Color::DarkGray),
            ),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block.title(format!(" {} ", e.dest).bold())), area);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect, wide: bool) {
        let hint = match &self.mode {
            InputMode::Filter => "type to filter · ⏎ done · Esc clear".to_string(),
            InputMode::PairCode(code) => format!("pairing code from `qshd pair`: {code}▏  (⏎ pair, Esc cancel)"),
            InputMode::Quick(dest) => format!("connect once to user@host[:port]: {dest}▏  (⏎ go, Esc cancel)"),
            InputMode::Form(_) => "Tab next field · ←→ change · ⏎ save · Esc cancel".to_string(),
            InputMode::ConfirmDelete(name) => format!("delete the saved connection {name}? y/n"),
            InputMode::Normal if wide => {
                "⏎ connect · c once · n new · e edit · d delete · Tab history · s speed · p pair · / find · r refresh · q quit".to_string()
            }
            InputMode::Normal => "⏎ go · c once · n new · e edit · Tab history · q quit".to_string(),
        };
        let lines = vec![Line::styled(self.status.clone(), Style::new().fg(Color::Yellow)), Line::styled(hint, Style::new().fg(Color::DarkGray))];
        f.render_widget(Paragraph::new(lines), area);
    }
}

/// The new/edit form as a centered popup.
fn draw_form(f: &mut Frame, area: Rect, form: &Form) {
    let width = area.width.min(64);
    let height = (FORM_FIELDS.len() as u16 + 5).min(area.height);
    let popup = Rect { x: area.x + (area.width - width) / 2, y: area.y + (area.height - height) / 2, width, height };
    let title = match (&form.original, form.locked) {
        (Some(name), true) => format!(" {name}: menu settings "),
        (Some(name), false) => format!(" edit {name} "),
        (None, _) => " new connection ".to_string(),
    };
    let block = Block::bordered().border_type(BorderType::Rounded).title(title.bold()).border_style(Style::new().fg(Color::Cyan));
    let values = [
        form.name.clone(),
        form.host.clone(),
        form.user.clone(),
        if form.port.is_empty() && form.focus != 3 { "4422 (default)".into() } else { form.port.clone() },
        form.key.clone(),
        format!("‹ {} ›", TRANSPORTS[form.transport]),
        if form.fallback { "[x] use plain ssh".into() } else { "[ ] fail".into() },
    ];
    let mut lines: Vec<Line> = FORM_FIELDS
        .iter()
        .zip(values)
        .enumerate()
        .map(|(i, (name, value))| {
            let focused = i == form.focus;
            let label = Span::styled(format!("{name:>9}  "), Style::new().fg(if focused { Color::Cyan } else { Color::DarkGray }));
            let cursor = if focused && i < 5 { "▏" } else { "" };
            let style = match (focused, form.locked && i < 5) {
                (_, true) => Style::new().fg(Color::DarkGray),
                (true, false) => Style::new().bold().bg(Color::Rgb(40, 60, 90)),
                (false, false) => Style::new(),
            };
            Line::from(vec![label, Span::styled(format!("{value}{cursor}"), style)])
        })
        .collect();
    lines.push(if form.locked {
        Line::styled("address, user, port, key: change them in your config file", Style::new().fg(Color::DarkGray))
    } else {
        Line::raw("")
    });
    lines.push(match &form.error {
        Some(e) => Line::styled(e.clone(), Style::new().fg(Color::Red)),
        None => Line::styled("Tab next · ←→ change · ⏎ save · Esc cancel", Style::new().fg(Color::DarkGray)),
    });
    f.render_widget(Clear, popup);
    f.render_widget(Paragraph::new(lines).block(block), popup);
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

/// Hosts saved here, from the configs, then known_hosts entries not covered by them.
fn load_hosts() -> Vec<Host> {
    let home = home_dir().ok();
    let saved: Vec<String> = home.as_deref().map(saved::load).unwrap_or_default().into_iter().map(|s| s.name).collect();
    let mut aliases: Vec<(String, Source)> = home
        .as_deref()
        .map(super::config::host_aliases)
        .unwrap_or_default()
        .into_iter()
        .map(|a| {
            let source = if saved.contains(&a) { Source::Saved } else { Source::Config };
            (a, source)
        })
        .collect();
    for id in super::known_host_ids() {
        // `[host]:port` → `host:port`, which the parser accepts as a destination.
        let dest = match id.strip_prefix('[').and_then(|r| r.split_once("]:")) {
            Some((h, p)) if !h.contains(':') => format!("{h}:{p}"),
            Some((h, p)) => format!("[{h}]:{p}"),
            None => id.clone(),
        };
        if !aliases.iter().any(|(a, _)| a == &dest) {
            aliases.push((dest, Source::KnownHost));
        }
    }
    aliases
        .into_iter()
        .map(|(alias, source)| {
            let (target, probe) = match Target::parse(&alias, None, true) {
                Ok(t) => (Some(t), Probe::Pending),
                Err(e) => (None, Probe::Invalid(format!("{e:#}"))),
            };
            Host { alias, target, probe, key: None, source, checked_at: None }
        })
        .collect()
}

fn to_cache(probe: &Probe, key: Option<KeyState>, endpoint: String) -> Option<CachedProbe> {
    let (kind, port, handshake) = match probe {
        Probe::Quic { handshake, port } => ("quic", *port, *handshake),
        Probe::Tcp { handshake, port } => ("tcp", *port, *handshake),
        Probe::NoQshd => ("ssh", 0, Duration::ZERO),
        Probe::Pending | Probe::Invalid(_) => return None,
    };
    let key = key.map(|k| match k {
        KeyState::Known => "known",
        KeyState::Unknown => "unknown",
        KeyState::Changed => "changed",
    });
    Some(CachedProbe { endpoint, kind: kind.into(), port, handshake_ms: handshake.as_millis() as u64, key: key.map(String::from), at: now() })
}

fn from_cache(c: &CachedProbe) -> (Probe, Option<KeyState>) {
    let handshake = Duration::from_millis(c.handshake_ms);
    let probe = match c.kind.as_str() {
        "quic" => Probe::Quic { handshake, port: c.port },
        "tcp" => Probe::Tcp { handshake, port: c.port },
        _ => Probe::NoQshd,
    };
    let key = match c.key.as_deref() {
        Some("known") => Some(KeyState::Known),
        Some("unknown") => Some(KeyState::Unknown),
        Some("changed") => Some(KeyState::Changed),
        _ => None,
    };
    (probe, key)
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
    if target.needs_proxy {
        // Reached through a proxy: connecting directly could reveal this machine's address.
        return (Probe::NoQshd, None);
    }
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

/// Checks hosts in the background. A recent cached result is used instead,
/// unless `force` (refresh); `only` limits it to one host.
fn start_probes(app: &mut App, only: Option<&str>, force: bool, tx: &mpsc::UnboundedSender<Msg>, id: &Arc<Identity>) {
    let t = now();
    for h in app.hosts.iter_mut() {
        if only.is_some_and(|o| o != h.alias) {
            continue;
        }
        let (Some(target), Some(endpoint)) = (h.target.clone(), h.endpoint()) else { continue };
        if !force {
            if let Some(c) = app.state.fresh_probe(&h.alias, &endpoint, t) {
                (h.probe, h.key) = from_cache(c);
                h.checked_at = Some(c.at);
                continue;
            }
        }
        h.probe = Probe::Pending;
        let (tx, id, alias) = (tx.clone(), id.clone(), h.alias.clone());
        tokio::spawn(async move {
            let (probe, key) = probe(target, id).await;
            let _ = tx.send(Msg::Probed { alias, endpoint, probe, key });
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

/// Arguments for a session to `dest` with its connection preferences.
fn session_args(opts: &ConnectOptions, prefs: &Prefs, dest: &str) -> Vec<String> {
    let mut args = child_flags(opts);
    if prefs.ssh_fallback {
        args.push("--full".into());
    }
    if prefs.transport != "auto" {
        args.push("--transport".into());
        args.push(prefs.transport.clone());
    }
    args.push(dest.to_string());
    args
}

/// Stores a form: the connection in `ui-hosts`, its preferences in the state.
/// Hosts from the user's own config files only get their preferences stored;
/// their files are never written.
fn save_form(app: &mut App, form: &Form) -> Result<String> {
    let home = home_dir()?;
    if form.locked {
        let name = form.original.clone().unwrap_or_else(|| form.name.clone());
        let prefs = Prefs { transport: TRANSPORTS[form.transport].to_string(), ssh_fallback: form.fallback };
        app.state.prefs.insert(name.clone(), prefs);
        return Ok(name);
    }
    let (entry, prefs) = form.result().map_err(anyhow::Error::msg)?;
    let mut all = saved::load(&home);
    // A name from the user's config would be shadowed by theirs anyway: refuse it.
    let own: Vec<String> = all.iter().map(|s| s.name.clone()).collect();
    if super::config::host_aliases(&home).iter().any(|a| a == &entry.name && !own.contains(a)) {
        anyhow::bail!("{} is already a host in your config file; pick another name", entry.name);
    }
    if let Some(old) = &form.original {
        all.retain(|s| &s.name != old);
        if old != &entry.name {
            app.state.prefs.remove(old);
            app.state.probes.remove(old);
        }
    }
    all.retain(|s| s.name != entry.name);
    let name = entry.name.clone();
    all.push(entry);
    saved::save(&home, &all)?;
    app.state.prefs.insert(name.clone(), prefs);
    // The address may have changed: check it again.
    app.state.probes.remove(&name);
    Ok(name)
}

fn delete_saved(app: &mut App, name: &str) -> Result<()> {
    let home = home_dir()?;
    let mut all = saved::load(&home);
    all.retain(|s| s.name != name);
    saved::save(&home, &all)?;
    app.state.prefs.remove(name);
    app.state.probes.remove(name);
    Ok(())
}

/// Reloads the host list (after a change), keeping the cursor on `select`.
fn reload(app: &mut App, select: Option<&str>, tx: &mpsc::UnboundedSender<Msg>, id: &Arc<Identity>) {
    app.hosts = load_hosts();
    start_probes(app, None, false, tx, id);
    app.view = View::Hosts;
    if let Some(name) = select {
        app.selected = app.visible().iter().position(|&i| app.hosts[i].alias == name).unwrap_or(0);
    }
}

pub async fn run(opts: ConnectOptions) -> Result<i32> {
    // ^C reaches us too while a session runs in the foreground; never die from it.
    #[cfg(unix)]
    let _sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    #[cfg(windows)]
    let _sigint = tokio::signal::windows::ctrl_c()?;
    let home = home_dir()?;
    let mut app = App::new(load_hosts(), UiState::load(&home));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let probe_key = Arc::new(Identity::generate());
    start_probes(&mut app, None, false, &tx, &probe_key);
    let mut dirty = false;
    let mut last_save = Instant::now();

    let mut terminal = enter()?;
    let result = loop {
        while let Ok(msg) = rx.try_recv() {
            dirty |= app.apply(msg);
        }
        if dirty && last_save.elapsed() > Duration::from_secs(2) {
            let _ = app.state.save(&home);
            (dirty, last_save) = (false, Instant::now());
        }
        app.now = now();
        if let Err(e) = terminal.draw(|f| app.draw(f)) {
            break Err(e.into());
        }
        // Poll synchronously so nothing reads the terminal while a session owns it.
        let ev = tokio::task::block_in_place(|| -> std::io::Result<Option<Event>> {
            if event::poll(Duration::from_millis(50))? { Ok(Some(event::read()?)) } else { Ok(None) }
        });
        let history_len = app.state.history.len();
        let action = match ev {
            Ok(Some(ev)) => app.on_event(ev),
            Ok(None) => Action::None,
            Err(e) => break Err(e.into()),
        };
        dirty |= app.state.history.len() != history_len;
        match action {
            Action::None => {}
            Action::Quit => break Ok(0),
            Action::Refresh => {
                app.hosts = load_hosts();
                start_probes(&mut app, None, true, &tx, &probe_key);
                app.status = "checking all hosts again…".into();
            }
            Action::Save(form) => match save_form(&mut app, &form) {
                Ok(name) => {
                    app.status = format!("saved {name}: also usable as `qsh {name}`");
                    dirty = true;
                    reload(&mut app, Some(&name), &tx, &probe_key);
                }
                Err(e) => app.status = format!("cannot save: {e:#}"),
            },
            Action::Delete(name) => match delete_saved(&mut app, &name) {
                Ok(()) => {
                    app.status = format!("deleted {name}");
                    dirty = true;
                    reload(&mut app, None, &tx, &probe_key);
                }
                Err(e) => app.status = format!("cannot delete: {e:#}"),
            },
            Action::Connect(dest) => {
                leave();
                let prefs = app.state.prefs(&dest);
                let status = run_child(&session_args(&opts, &prefs, &dest)).await;
                // 255 is how ssh and qsh report a connection that failed.
                let ok = matches!(&status, Ok(s) if s.code() != Some(255));
                if !ok {
                    wait_for_enter();
                }
                terminal = enter()?;
                app.state.record(&dest, ok, now());
                dirty = true;
                app.status = match status {
                    Ok(s) if s.success() => format!("session to {dest} ended"),
                    Ok(s) => format!("session to {dest} ended ({s})"),
                    Err(e) => format!("cannot start session: {e}"),
                };
                start_probes(&mut app, Some(&dest), true, &tx, &probe_key);
            }
            Action::Pair(i, code) => {
                leave();
                let alias = app.hosts[i].alias.clone();
                let mut args = vec!["pair".to_string(), "--full".into()];
                args.extend(child_flags(&opts));
                args.push(alias.clone());
                args.push(code);
                let status = run_child(&args).await;
                wait_for_enter();
                terminal = enter()?;
                app.status = match status {
                    Ok(s) if s.success() => format!("paired with {alias}"),
                    _ => "pairing failed".to_string(),
                };
                start_probes(&mut app, Some(&alias), true, &tx, &probe_key);
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
    let _ = app.state.save(&home);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn host(alias: &str, probe: Probe, source: Source) -> Host {
        let target = Target::parse_with(&format!("root@{alias}"), None, None, true).ok();
        Host { alias: alias.into(), target, probe, key: Some(KeyState::Known), source, checked_at: None }
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
        App::new(
            vec![
                host("alpha", Probe::Quic { handshake: Duration::from_millis(42), port: 4422 }, Source::Config),
                host("beta", Probe::NoQshd, Source::Saved),
                host("gamma", Probe::Pending, Source::KnownHost),
            ],
            UiState::default(),
        )
    }

    fn key(c: KeyCode) -> Event {
        Event::Key(KeyEvent::new(c, KeyModifiers::NONE))
    }

    fn typing(app: &mut App, text: &str) {
        for c in text.chars() {
            app.on_event(key(KeyCode::Char(c)));
        }
    }

    #[test]
    fn renders_host_list_and_details() {
        let mut app = sample();
        let screen = render(&mut app, 110, 24);
        assert!(screen.contains("alpha") && screen.contains("quic 42 ms"), "{screen}");
        assert!(screen.contains("beta ★") && screen.contains("ssh"));
        assert!(screen.contains("known, matches"));
        assert!(screen.contains("1 with qshd"));
        assert!(screen.contains("history 0"));
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
        let screen = render(&mut app, 46, 34);
        assert!(screen.contains("85.2 Mbit/s"), "{screen}");
        assert!(screen.contains("70.1 Mbit/s"));
        assert!(screen.contains("41 ms"));
        assert!(screen.contains("100") && screen.contains("1G"), "dial labels");
    }

    #[test]
    fn keys_filter_select_and_quick_connect() {
        let mut app = sample();
        assert_eq!(app.on_event(key(KeyCode::Down)), Action::None);
        assert_eq!(app.current(), Some(1));
        app.on_event(key(KeyCode::Char('/')));
        typing(&mut app, "gam");
        app.on_event(key(KeyCode::Enter));
        assert_eq!(app.visible(), vec![2]);
        assert_eq!(app.on_event(key(KeyCode::Enter)), Action::Connect("gamma".into()));
        assert_eq!(app.on_event(key(KeyCode::Char('s'))), Action::Speed(2));
        app.on_event(key(KeyCode::Char('p')));
        typing(&mut app, "ab12");
        assert_eq!(app.on_event(key(KeyCode::Enter)), Action::Pair(2, "ab12".into()));
        app.on_event(key(KeyCode::Char('c')));
        typing(&mut app, "bob@192.0.2.7:2222");
        assert_eq!(app.on_event(key(KeyCode::Enter)), Action::Connect("bob@192.0.2.7:2222".into()));
        assert_eq!(app.on_event(key(KeyCode::Char('q'))), Action::Quit);
    }

    #[test]
    fn new_connection_form() {
        let mut app = sample();
        app.on_event(key(KeyCode::Char('n')));
        typing(&mut app, "box");
        app.on_event(key(KeyCode::Tab));
        typing(&mut app, "192.0.2.5");
        app.on_event(key(KeyCode::Tab));
        typing(&mut app, "admin");
        app.on_event(key(KeyCode::Tab));
        typing(&mut app, "70000");
        assert_eq!(app.on_event(key(KeyCode::Enter)), Action::None, "bad port");
        assert!(render(&mut app, 100, 30).contains("port: a number"));
        for _ in 0..5 {
            app.on_event(key(KeyCode::Backspace));
        }
        typing(&mut app, "2222");
        app.on_event(key(KeyCode::Tab));
        app.on_event(key(KeyCode::Tab));
        app.on_event(key(KeyCode::Right)); // transport: quic
        app.on_event(key(KeyCode::Tab));
        app.on_event(key(KeyCode::Char(' '))); // no ssh fallback
        let Action::Save(form) = app.on_event(key(KeyCode::Enter)) else { panic!("not saved") };
        let (saved, prefs) = form.result().unwrap();
        assert_eq!(saved, Saved { name: "box".into(), host: "192.0.2.5".into(), user: Some("admin".into()), port: Some(2222), identity: None });
        assert_eq!(prefs, Prefs { transport: "quic".into(), ssh_fallback: false });
    }

    #[test]
    fn history_view_and_saving_an_entry() {
        let mut app = sample();
        app.state.record("bob@192.0.2.7:2222", false, 100);
        app.state.record("alpha", true, 200);
        app.on_event(key(KeyCode::Tab));
        assert_eq!(app.view, View::History);
        let screen = render(&mut app, 110, 24);
        assert!(screen.contains("✓ alpha") && screen.contains("✗ bob@192.0.2.7:2222"), "{screen}");
        assert_eq!(app.on_event(key(KeyCode::Enter)), Action::Connect("alpha".into()));
        app.on_event(key(KeyCode::Down));
        app.on_event(key(KeyCode::Char('a')));
        let InputMode::Form(form) = &app.mode else { panic!("no form") };
        assert_eq!((form.name.as_str(), form.host.as_str(), form.user.as_str(), form.port.as_str()), ("192", "192.0.2.7", "bob", "2222"));
        // Recently used hosts come first.
        app.mode = InputMode::Normal;
        app.on_event(key(KeyCode::Tab));
        assert_eq!(app.visible()[0], 0);
        app.state.record("gamma", true, 300);
        assert_eq!(app.visible(), vec![2, 0, 1]);
    }

    #[test]
    fn hosts_from_config_files_only_get_menu_settings() {
        let mut app = sample();
        // alpha comes from a config file: its address cannot be changed here.
        app.on_event(key(KeyCode::Char('e')));
        let InputMode::Form(form) = &app.mode else { panic!("no form") };
        assert!(form.locked && form.focus == 5);
        typing(&mut app, "x");
        app.on_event(key(KeyCode::BackTab));
        app.on_event(key(KeyCode::BackTab));
        typing(&mut app, "evil");
        let InputMode::Form(form) = &app.mode else { panic!("no form") };
        assert_eq!((form.name.as_str(), form.host.as_str(), form.focus), ("alpha", "alpha", 5));
        app.on_event(key(KeyCode::Right));
        let Action::Save(form) = app.on_event(key(KeyCode::Enter)) else { panic!("not saved") };
        assert!(form.locked && form.transport == 1);
        assert!(render(&mut app, 100, 30).contains("alpha"));
    }

    #[test]
    fn only_saved_connections_can_be_deleted() {
        let mut app = sample();
        app.on_event(key(KeyCode::Char('d')));
        assert!(matches!(app.mode, InputMode::Normal) && app.status.contains("not saved here"));
        app.on_event(key(KeyCode::Down));
        app.on_event(key(KeyCode::Char('d')));
        assert!(matches!(app.mode, InputMode::ConfirmDelete(ref n) if n == "beta"));
        assert_eq!(app.on_event(key(KeyCode::Char('y'))), Action::Delete("beta".into()));
    }

    #[tokio::test]
    async fn cached_checks_are_reused() {
        let mut app = sample();
        let endpoint = app.hosts[0].endpoint().unwrap();
        app.state.probes.insert(
            "alpha".into(),
            CachedProbe { endpoint, kind: "tcp".into(), port: 4422, handshake_ms: 7, key: Some("known".into()), at: now() },
        );
        app.hosts[0].probe = Probe::Pending;
        let (tx, _rx) = mpsc::unbounded_channel();
        start_probes(&mut app, Some("alpha"), false, &tx, &Arc::new(Identity::generate()));
        assert_eq!(app.hosts[0].probe, Probe::Tcp { handshake: Duration::from_millis(7), port: 4422 });
        assert_eq!(app.hosts[0].key, Some(KeyState::Known));
    }

    #[test]
    fn session_arguments_follow_preferences() {
        let opts = ConnectOptions::default();
        assert_eq!(session_args(&opts, &Prefs::default(), "box"), ["--full", "box"]);
        let p = Prefs { transport: "tcp".into(), ssh_fallback: false };
        assert_eq!(session_args(&opts, &p, "box"), ["--transport", "tcp", "box"]);
    }

    #[test]
    fn dial_is_logarithmic() {
        assert_eq!(dial_fraction(0.0), 0.0);
        assert!((dial_fraction(GAUGE_MAX_MBPS) - 1.0).abs() < 1e-9);
        assert!(dial_fraction(10.0) > 0.3 && dial_fraction(10.0) < 0.4);
        assert_eq!(dial_fraction(1e9), 1.0);
    }
}
