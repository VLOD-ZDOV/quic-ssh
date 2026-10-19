//! The forwards panel of `qsh ui` (`f`): a host's port forwards, added and
//! removed by picking what they do rather than by writing ssh's flags.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::client::forward::Forward;
use crate::client::Target;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Local,
    Remote,
    Socks,
}

const KINDS: [Kind; 3] = [Kind::Local, Kind::Remote, Kind::Socks];

impl Kind {
    fn title(self) -> &'static str {
        match self {
            Kind::Local => "open a server's port here",
            Kind::Remote => "share a port of this machine with the server",
            Kind::Socks => "SOCKS proxy through the server",
        }
    }

    fn listen_label(self) -> &'static str {
        match self {
            Kind::Remote => "port on server",
            _ => "port here",
        }
    }

    fn dest_label(self) -> &'static str {
        match self {
            Kind::Remote => "goes to (here)",
            _ => "goes to (server)",
        }
    }

    fn keyword(self) -> &'static str {
        match self {
            Kind::Local => "LocalForward",
            Kind::Remote => "RemoteForward",
            Kind::Socks => "DynamicForward",
        }
    }

    fn flag(self) -> &'static str {
        match self {
            Kind::Local => "-L",
            Kind::Remote => "-R",
            Kind::Socks => "-D",
        }
    }

    fn parse(self, spec: &str) -> Result<Forward> {
        match self {
            Kind::Local => Forward::parse(spec),
            Kind::Remote => Forward::parse_remote(spec),
            Kind::Socks => Forward::parse_dynamic(spec),
        }
    }
}

/// One forward, as the value of its flag (`8080:localhost:80`).
#[derive(Clone, Debug, PartialEq)]
pub struct Fwd {
    pub kind: Kind,
    pub spec: String,
    /// From a config file the menu does not write: shown, not removable.
    pub fixed: bool,
}

impl Fwd {
    fn describe(&self) -> String {
        let (listen, dest) = match self.kind.parse(&self.spec) {
            Ok(f) => f.config_args(),
            Err(_) => (self.spec.clone(), None),
        };
        let dest = dest.unwrap_or_default();
        match self.kind {
            Kind::Local => format!("here {listen}  →  {dest} as seen from the server"),
            Kind::Remote => format!("server {listen}  →  {dest} here"),
            Kind::Socks => format!("SOCKS proxy here on {listen}, out through the server"),
        }
    }

    /// The `Keyword listen dest` line for the saved connections file.
    fn config_line(&self) -> Result<String> {
        Ok(match self.kind.parse(&self.spec)?.config_args() {
            (listen, Some(dest)) => format!("{} {listen} {dest}", self.kind.keyword()),
            (listen, None) => format!("{} {listen}", self.kind.keyword()),
        })
    }
}

/// A forward being added.
#[derive(Debug, Default)]
struct Draft {
    kind: usize,
    listen: String,
    dest: String,
    /// 0 kind, 1 listen, 2 destination.
    focus: usize,
}

impl Draft {
    fn kind(&self) -> Kind {
        KINDS[self.kind]
    }

    fn fields(&self) -> usize {
        if self.kind() == Kind::Socks { 2 } else { 3 }
    }

    fn finish(&self) -> Result<Fwd, String> {
        let kind = self.kind();
        let listen = self.listen.trim();
        if listen.is_empty() {
            return Err(format!("{}: a port, e.g. 8080", kind.listen_label()));
        }
        let spec = match kind {
            Kind::Socks => listen.to_string(),
            // The same port on the other side when no destination is given.
            _ if self.dest.trim().is_empty() => match listen.rsplit(':').next().filter(|p| p.parse::<u16>().is_ok()) {
                Some(port) => format!("{listen}:localhost:{port}"),
                None => return Err(format!("{}: host:port, e.g. localhost:80", kind.dest_label())),
            },
            _ => format!("{listen}:{}", self.dest.trim()),
        };
        kind.parse(&spec).map_err(|e| format!("{e:#}"))?;
        Ok(Fwd { kind, spec, fixed: false })
    }
}

/// What the panel asks of the menu.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Stay,
    Close,
    /// Connect with these forwards; `tunnel` without a shell (`-N`).
    Connect { tunnel: bool },
}

pub struct Panel {
    pub alias: String,
    /// A connection saved by the menu: changes are written to it. Other
    /// hosts get the added forwards for the next connection only.
    pub saved: bool,
    pub list: Vec<Fwd>,
    selected: usize,
    draft: Option<Draft>,
    pub changed: bool,
    error: Option<String>,
}

impl Panel {
    pub fn new(alias: &str, saved: bool, target: Option<&Target>) -> Panel {
        let mut list = Vec::new();
        if let Some(t) = target {
            for (kind, specs) in [(Kind::Local, &t.local_forwards), (Kind::Remote, &t.remote_forwards), (Kind::Socks, &t.dynamic_forwards)] {
                list.extend(specs.iter().map(|s| Fwd { kind, spec: s.clone(), fixed: !saved }));
            }
        }
        Panel { alias: alias.to_string(), saved, list, selected: 0, draft: None, changed: false, error: None }
    }

    /// Flags for the forwards the configs do not already give.
    pub fn extra_flags(&self) -> Vec<String> {
        if self.saved {
            return Vec::new();
        }
        self.list.iter().filter(|f| !f.fixed).flat_map(|f| [f.kind.flag().to_string(), f.spec.clone()]).collect()
    }

    /// The forward lines to store for a saved connection.
    pub fn config_lines(&self) -> Result<Vec<String>> {
        self.list.iter().map(Fwd::config_line).collect()
    }

    pub fn on_key(&mut self, k: KeyEvent) -> Outcome {
        if let Some(d) = &mut self.draft {
            match k.code {
                KeyCode::Esc => self.draft = None,
                KeyCode::Tab | KeyCode::Down => d.focus = (d.focus + 1).min(d.fields() - 1),
                KeyCode::BackTab | KeyCode::Up => d.focus = d.focus.saturating_sub(1),
                KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if d.focus == 0 => {
                    let step = if k.code == KeyCode::Left { KINDS.len() - 1 } else { 1 };
                    d.kind = (d.kind + step) % KINDS.len();
                }
                KeyCode::Enter if d.focus + 1 < d.fields() => d.focus += 1,
                KeyCode::Enter => match d.finish() {
                    Ok(fwd) => {
                        self.list.push(fwd);
                        self.selected = self.list.len() - 1;
                        self.changed = true;
                        self.draft = None;
                    }
                    Err(e) => self.error = Some(e),
                },
                KeyCode::Backspace => {
                    match d.focus {
                        1 => d.listen.pop(),
                        2 => d.dest.pop(),
                        _ => None,
                    };
                }
                KeyCode::Char(c) => {
                    match d.focus {
                        1 => d.listen.push(c),
                        2 => d.dest.push(c),
                        _ => {}
                    }
                    self.error = None;
                }
                _ => {}
            }
            return Outcome::Stay;
        }
        self.error = None;
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => return Outcome::Close,
            KeyCode::Down | KeyCode::Char('j') => self.selected = (self.selected + 1).min(self.list.len().saturating_sub(1)),
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Char('a') | KeyCode::Char('n') | KeyCode::Insert => self.draft = Some(Draft { focus: 1, ..Draft::default() }),
            KeyCode::Char('d') | KeyCode::Delete => match self.list.get(self.selected) {
                Some(f) if f.fixed => self.error = Some("this one is in your config file; change it there".into()),
                Some(_) => {
                    self.list.remove(self.selected);
                    self.selected = self.selected.min(self.list.len().saturating_sub(1));
                    self.changed = true;
                }
                None => {}
            },
            KeyCode::Enter => return Outcome::Connect { tunnel: false },
            KeyCode::Char('t') => return Outcome::Connect { tunnel: true },
            _ => {}
        }
        Outcome::Stay
    }

    pub fn draw(&self, f: &mut Frame, area: Rect) {
        let width = area.width.min(72);
        let mut lines = Vec::new();
        if self.list.is_empty() {
            lines.push(Line::styled("  no forwards yet: press a to add one", Style::new().fg(Color::DarkGray)));
        }
        for (i, fwd) in self.list.iter().enumerate() {
            let on = i == self.selected && self.draft.is_none();
            let style = if on { Style::new().bold().bg(Color::Rgb(40, 60, 90)) } else { Style::new() };
            let mut spans = vec![Span::styled(if on { "▶ " } else { "  " }, style), Span::styled(fwd.describe(), style)];
            if fwd.fixed {
                spans.push(Span::styled("  (config)", Style::new().fg(Color::DarkGray)));
            }
            lines.push(Line::from(spans));
        }
        if let Some(d) = &self.draft {
            let kind = d.kind();
            lines.push(Line::raw(""));
            let field = |i: usize, name: &str, value: String, hint: &str| {
                let focused = d.focus == i;
                let label = Span::styled(format!("{name:>17}  "), Style::new().fg(if focused { Color::Cyan } else { Color::DarkGray }));
                if value.is_empty() && !focused {
                    return Line::from(vec![label, Span::styled(hint.to_string(), Style::new().fg(Color::DarkGray))]);
                }
                let style = if focused { Style::new().bold().bg(Color::Rgb(40, 60, 90)) } else { Style::new() };
                let cursor = if focused && i > 0 { "▏" } else { "" };
                Line::from(vec![label, Span::styled(format!("{value}{cursor}"), style)])
            };
            lines.push(field(0, "kind", format!("‹ {} ›", kind.title()), ""));
            lines.push(field(1, kind.listen_label(), d.listen.clone(), "8080"));
            if kind != Kind::Socks {
                let same = d.listen.rsplit(':').next().filter(|p| p.parse::<u16>().is_ok()).unwrap_or("80");
                lines.push(field(2, kind.dest_label(), d.dest.clone(), &format!("localhost:{same}")));
            }
        }
        if let Some(e) = &self.error {
            lines.push(Line::raw(""));
            lines.push(Line::styled(e.clone(), Style::new().fg(Color::Red)));
        }
        lines.push(Line::raw(""));
        let hint = if self.draft.is_some() {
            "Tab next · ←→ kind · ⏎ add · Esc cancel"
        } else {
            "a add · d remove · ⏎ connect · t tunnel only (no shell) · Esc close"
        };
        lines.push(Line::styled(hint, Style::new().fg(Color::DarkGray)));
        if !self.saved {
            lines.push(Line::styled("added forwards are for the next connection only", Style::new().fg(Color::DarkGray)));
        }
        let height = (lines.len() as u16 + 2).min(area.height);
        let popup = Rect { x: area.x + (area.width - width) / 2, y: area.y + (area.height - height) / 2, width, height };
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .title(format!(" {}: forwards ", self.alias).bold())
            .border_style(Style::new().fg(Color::Cyan));
        f.render_widget(Clear, popup);
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), popup);
    }
}
