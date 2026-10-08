//! Local echo prediction for interactive sessions, like mosh: on a slow
//! link, typed characters appear at once instead of after a round trip.
//!
//! The server's output is fed through a terminal emulator, so the true
//! screen is known. A typed printable character is predicted at the cursor
//! when that cell is empty, and drawn once the current "epoch" is confirmed:
//! an earlier prediction of it showed up on the server's screen. Every
//! control key (Enter, arrows, ^C...) starts a new epoch, and so does
//! output that typing did not cause, so after a password prompt nothing is
//! drawn until the server echoes something. A wrong prediction (or a `*`
//! echo) confirms nothing until the next control key, and output the
//! emulator does not model stops predictions until the screen is redrawn.
//!
//! Before the server's output is written, drawn predictions are erased (they
//! only ever cover empty cells), so what the terminal shows is the server's
//! output exactly; the predictions that are still pending and still fit are
//! drawn again after it.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// `PredictiveEcho`: when to draw predictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    Never,
    /// Only when echoes take long (the default).
    #[default]
    Auto,
    Always,
}

pub fn parse_mode(v: &str) -> Mode {
    match v.to_ascii_lowercase().as_str() {
        "no" | "never" | "off" | "false" => Mode::Never,
        "yes" | "always" | "on" | "true" => Mode::Always,
        _ => Mode::Auto,
    }
}

/// Echoes slower than this make `Auto` draw predictions...
const SLOW: Duration = Duration::from_millis(30);
/// ...and faster than this stop it again.
const FAST: Duration = Duration::from_millis(20);
/// Most characters predicted ahead of the server.
const MAX_PENDING: usize = 64;
/// Drawn predictions not confirmed within this time (plus a few round trips) are erased.
const EXPIRE: Duration = Duration::from_millis(1000);
/// Smaller terminals (or an unknown size, reported as 0×0) get no
/// predictions: too little room to be useful, and the emulator wants some.
const MIN_COLS: u16 = 20;
const MIN_ROWS: u16 = 2;

fn usable_size(rows: u16, cols: u16) -> bool {
    rows >= MIN_ROWS && cols >= MIN_COLS
}

/// Where the terminal's parser is after the server's output so far. Bytes
/// of ours must not land inside an escape sequence or a UTF-8 character
/// that a chunk of output left unfinished.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Parse {
    #[default]
    Ground,
    /// After ESC.
    Escape,
    /// After ESC and intermediate bytes (0x20–0x2f).
    EscapeIntermediate,
    /// In a CSI sequence (ESC [).
    Csi,
    /// In a string (OSC, DCS, SOS, PM, APC) until BEL or ST.
    Text,
    /// ESC inside a string (the start of ST, ESC \).
    TextEscape,
    /// This many UTF-8 continuation bytes still to come.
    Utf8(u8),
}

impl Parse {
    fn feed(mut self, data: &[u8]) -> Parse {
        for &b in data {
            self = match (self, b) {
                // CAN and SUB abort any sequence.
                (_, 0x18 | 0x1a) => Parse::Ground,
                (Parse::Text, 0x07) => Parse::Ground,
                (Parse::Text, 0x1b) => Parse::TextEscape,
                (Parse::Text, _) => Parse::Text,
                (Parse::TextEscape, b'\\') => Parse::Ground,
                (Parse::TextEscape, 0x1b) => Parse::TextEscape,
                (Parse::TextEscape, _) => Parse::Text,
                (_, 0x1b) => Parse::Escape,
                (Parse::Escape, b'[') => Parse::Csi,
                (Parse::Escape, b']' | b'P' | b'X' | b'^' | b'_') => Parse::Text,
                (Parse::Escape | Parse::EscapeIntermediate, 0x20..=0x2f) => Parse::EscapeIntermediate,
                (Parse::Escape | Parse::EscapeIntermediate, 0x30..=0x7e) => Parse::Ground,
                (Parse::Csi, 0x40..=0x7e) => Parse::Ground,
                (Parse::Escape | Parse::EscapeIntermediate | Parse::Csi, _) => self,
                (Parse::Utf8(n), 0x80..=0xbf) => if n > 1 { Parse::Utf8(n - 1) } else { Parse::Ground },
                (_, 0xc0..=0xdf) => Parse::Utf8(1),
                (_, 0xe0..=0xef) => Parse::Utf8(2),
                (_, 0xf0..=0xf7) => Parse::Utf8(3),
                _ => Parse::Ground,
            };
        }
        self
    }
}

/// Notices output the emulator does not model (insert mode, REP, saving
/// the cursor, character sets...): after it, the emulator's screen may
/// differ from the real terminal's.
#[derive(Default)]
struct Watch {
    drifted: bool,
}

/// DEC private modes that do not change what is on the screen or where the
/// cursor is: mouse and focus reports, blinking, meta/alt key handling
/// (macOS bash sends `?1034h`), urgency hints, synchronized output.
const QUIET_MODES: [u16; 20] = [9, 12, 1000, 1002, 1003, 1004, 1005, 1006, 1007, 1015, 1016, 1034, 1035, 1036, 1039, 1042, 1043, 2026, 2027, 2031];

impl vt100::Callbacks for Watch {
    /// Characters vt100 does not draw (U+FFFD from invalid UTF-8, C1
    /// controls) take a cell, or do something, on a real terminal.
    fn unhandled_char(&mut self, _: &mut vt100::Screen, _: char) {
        self.drifted = true;
    }

    fn unhandled_control(&mut self, _: &mut vt100::Screen, b: u8) {
        // NUL, ENQ, XON/XOFF and DEL do nothing on the screen; SO/SI and
        // the others switch character sets or worse.
        self.drifted |= !matches!(b, 0x00 | 0x05 | 0x11 | 0x13 | 0x7f);
    }

    fn unhandled_escape(&mut self, _: &mut vt100::Screen, i1: Option<u8>, _: Option<u8>, b: u8) {
        // ST, and switching (back) to the ASCII character set.
        let harmless = matches!((i1, b), (None, b'\\') | (Some(b'(' | b')' | b'*' | b'+'), b'B'));
        self.drifted |= !harmless;
    }

    fn unhandled_csi(&mut self, _: &mut vt100::Screen, i1: Option<u8>, i2: Option<u8>, params: &[&[u16]], c: char) {
        let harmless = match (i1, c) {
            // Reports and window operations.
            (None, 'c' | 'n' | 't' | 'x') => true,
            // Keyboard protocols and terminal queries.
            (Some(b'>' | b'=' | b'<'), _) => true,
            // Cursor shape (CSI n SP q).
            (Some(b' '), 'q') => true,
            // Erasing the scrollback (`clear` sends it): the screen stays.
            (None, 'J') => params == [&[3][..]],
            (Some(b'?'), 'n' | 'u') => true,
            (Some(b'?'), 'h' | 'l') => params.iter().all(|p| p.iter().all(|m| QUIET_MODES.contains(m))),
            // Mode queries (DECRQM, CSI ? n $ p).
            (_, 'p') => i2 == Some(b'$'),
            _ => false,
        };
        self.drifted |= !harmless;
    }
}

#[derive(Debug, Clone, Copy)]
struct Prediction {
    ch: u8,
    row: u16,
    col: u16,
    epoch: u64,
    typed: Instant,
}

pub struct Predictor {
    mode: Mode,
    /// The screen as the server drew it (without predictions).
    screen: vt100::Parser<Watch>,
    pending: VecDeque<Prediction>,
    /// How many of `pending` (from the front) are drawn on the terminal.
    drawn: usize,
    epoch: u64,
    /// Highest epoch with a confirmed prediction.
    confirmed: u64,
    /// A control key was typed and the server has not answered since:
    /// where the next character goes is unknown.
    unsettled: bool,
    /// A prediction was wrong: nothing counts as confirmed again until the
    /// next control key (a masked prompt echoing `*` must not confirm).
    burned: bool,
    /// The emulator's screen matches the real terminal's (see [`Watch`]);
    /// false from output it does not model until the screen is redrawn.
    trusted: bool,
    srtt: Option<Duration>,
    slow: bool,
    /// The terminal is big enough (see [`usable_size`]); otherwise output
    /// passes through untouched and nothing is predicted.
    active: bool,
    parse: Parse,
    /// Parameters of the CSI sequence being read.
    csi: Vec<u8>,
}

impl Predictor {
    pub fn new(mode: Mode, rows: u16, cols: u16) -> Predictor {
        Predictor {
            mode,
            screen: vt100::Parser::new_with_callbacks(rows.max(MIN_ROWS), cols.max(MIN_COLS), 0, Watch::default()),
            pending: VecDeque::new(),
            drawn: 0,
            epoch: 1,
            confirmed: 0,
            unsettled: false,
            burned: false,
            trusted: true,
            srtt: None,
            slow: false,
            active: usable_size(rows, cols),
            parse: Parse::Ground,
            csi: Vec::new(),
        }
    }

    /// Bytes that remove the drawn predictions from the terminal.
    fn erase(&mut self, out: &mut Vec<u8>) {
        if self.drawn > 0 {
            // Back to where the server's cursor is, and blank what we drew
            // (those cells are empty on the server's screen, in the current
            // background color).
            out.extend_from_slice(format!("\x1b[{n}D\x1b[{n}X", n = self.drawn).as_bytes());
            self.drawn = 0;
        }
    }

    /// Forgets all predictions; nothing is trusted until the next control key.
    fn fail(&mut self, out: &mut Vec<u8>) {
        self.erase(out);
        self.pending.clear();
        self.epoch += 1;
        self.burned = true;
    }

    fn may_draw(&self, p: &Prediction) -> bool {
        let fast_enough = match self.mode {
            Mode::Never => false,
            Mode::Always => true,
            Mode::Auto => self.slow,
        };
        fast_enough && p.epoch <= self.confirmed && self.trusted && self.parse == Parse::Ground && !self.screen.screen().hide_cursor()
    }

    /// Draws pending predictions after the drawn ones, as far as allowed.
    fn draw(&mut self, out: &mut Vec<u8>) {
        while self.drawn < self.pending.len() && self.may_draw(&self.pending[self.drawn]) {
            out.push(self.pending[self.drawn].ch);
            self.drawn += 1;
        }
    }

    /// Whether `(row, col)` is empty on the server's screen, in the color
    /// an erase would leave, with room for the cursor after it (no wrap).
    fn free(&self, row: u16, col: u16) -> bool {
        let screen = self.screen.screen();
        let (_, cols) = screen.size();
        // The second half of a wide character looks empty, but drawing there
        // would destroy the character.
        col + 1 < cols
            && !screen.inverse()
            && screen
                .cell(row, col)
                // A space (as `\b \b` leaves) looks the same as an empty cell.
                // Erasing a prediction leaves a plain blank: no underline or
                // inverse to lose.
                .is_some_and(|c| {
                    matches!(c.contents(), "" | " ")
                        && !c.is_wide_continuation()
                        && c.bgcolor() == screen.bgcolor()
                        && !c.underline()
                        && !c.inverse()
                })
    }

    /// Handles typed input (as sent to the server); returns bytes to write
    /// to the terminal.
    pub fn typed(&mut self, data: &[u8], now: Instant) -> Vec<u8> {
        let mut out = Vec::new();
        // Unknown positions (see `trusted`): nothing to predict.
        if self.mode == Mode::Never || !self.active || !self.trusted {
            return out;
        }
        // Control keys (and anything with them, like escape sequences) move
        // the cursor in ways only the server knows, and may answer a prompt.
        if data.iter().any(|&b| b < 0x20 || b == 0x7f) {
            self.epoch += 1;
            self.unsettled = true;
            self.burned = false;
            return out;
        }
        // Other scripts (UTF-8) are not predicted; where the cursor ends up
        // is known again from the echo.
        if !data.is_ascii() {
            self.unsettled = true;
            return out;
        }
        for &ch in data {
            // Unsettled (after a control key or a character of another
            // script): where the next character lands is not known.
            let at = match self.pending.back() {
                _ if self.unsettled => None,
                Some(last) if last.epoch == self.epoch => Some((last.row, last.col + 1)),
                Some(_) => None,
                None => Some(self.screen.screen().cursor_position()),
            };
            let Some((row, col)) = at.filter(|&(r, c)| self.free(r, c)) else { break };
            if self.pending.len() >= MAX_PENDING {
                break;
            }
            self.pending.push_back(Prediction { ch, row, col, epoch: self.epoch, typed: now });
        }
        self.draw(&mut out);
        out
    }

    /// Feeds output to the emulator a sequence at a time, so that output it
    /// does not model and a full redraw are seen in their order.
    fn process(&mut self, data: &[u8]) {
        let mut rest = data;
        while !rest.is_empty() {
            let cut = rest[1..].iter().position(|&b| b == 0x1b).map_or(rest.len(), |i| i + 1);
            let (part, tail) = rest.split_at(cut);
            self.screen.process(part);
            let redrawn = self.follow(part);
            if std::mem::take(&mut self.screen.callbacks_mut().drifted) {
                self.trusted = false;
            } else if redrawn {
                self.trusted = true;
            }
            rest = tail;
        }
    }

    /// Handles output from the server; returns the bytes to write instead.
    pub fn output(&mut self, data: &[u8], now: Instant) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 16);
        if self.mode == Mode::Never || !self.active {
            out.extend_from_slice(data);
            return out;
        }
        self.erase(&mut out);
        out.extend_from_slice(data);
        self.process(data);
        self.unsettled = false;
        if !self.trusted {
            self.pending.clear();
            self.epoch += 1;
            return out;
        }
        // Predictions that are now on the server's screen are confirmed.
        let mut explained = false;
        let mut last_confirmed = None;
        while let Some(p) = self.pending.front().copied() {
            let screen = self.screen.screen();
            let shown = screen.cell(p.row, p.col).is_some_and(|c| c.contents().as_bytes() == [p.ch]);
            let (row, col) = screen.cursor_position();
            let passed = row > p.row || (row == p.row && col > p.col);
            if !(shown && passed) {
                break;
            }
            self.pending.pop_front();
            explained = true;
            last_confirmed = Some((p.row, p.col));
            // A `*` may be a masked password prompt answering any key.
            if p.ch != b'*' && !self.burned {
                self.confirmed = self.confirmed.max(p.epoch);
            }
            self.sample(now.saturating_duration_since(p.typed));
        }
        // The rest must still start at the cursor, on empty cells.
        if let Some(first) = self.pending.front() {
            let fits = self.screen.screen().cursor_position() == (first.row, first.col)
                && self.pending.iter().all(|p| p.row == first.row && self.free(p.row, p.col));
            if !fits {
                self.pending.clear();
                self.epoch += 1;
                self.burned = true;
            }
        }
        // Output that typing did not cause (a prompt, say) makes what comes
        // next uncertain: it needs a confirmation of its own. Echoes are
        // only the explanation if the cursor stopped right after the last
        // one: an echo and a prompt arriving together ("y\r\nPassword: ")
        // must not carry the confirmation over to the prompt.
        let just_echoes = last_confirmed.is_some_and(|(row, col)| self.screen.screen().cursor_position() == (row, col + 1));
        let caused_by_typing = explained && just_echoes;
        if !caused_by_typing && !data.is_empty() {
            self.epoch += 1;
        }
        self.draw(&mut out);
        out
    }

    /// Follows the parser state through server output; returns whether the
    /// screen was redrawn as a whole (cleared, reset, or the alternate
    /// screen switched), after which the emulator matches the terminal again.
    fn follow(&mut self, data: &[u8]) -> bool {
        let mut redrawn = false;
        for &b in data {
            let before = self.parse;
            self.parse = self.parse.feed(&[b]);
            match (before, self.parse) {
                (Parse::Escape, Parse::Csi) => self.csi.clear(),
                (Parse::Csi, Parse::Csi) if self.csi.len() < 64 => self.csi.push(b),
                (Parse::Csi, Parse::Ground) => {
                    let params = |p: &[u8]| self.csi.split(|&c| c == b';').any(|x| x == p);
                    let private = self.csi.starts_with(b"?");
                    let cleared = b == b'J' && !private && (params(b"2") || params(b"3"));
                    let csi_private = self.csi.strip_prefix(b"?").unwrap_or(&[]).to_vec();
                    let switched = matches!(b, b'h' | b'l')
                        && private
                        && csi_private.split(|&c| c == b';').any(|x| matches!(x, b"47" | b"1047" | b"1049"));
                    redrawn |= cleared || switched;
                }
                // ESC c: a full reset.
                (Parse::Escape, Parse::Ground) if b == b'c' => redrawn = true,
                _ => {}
            }
        }
        redrawn
    }

    fn sample(&mut self, rtt: Duration) {
        let srtt = match self.srtt {
            Some(s) => (s * 7 + rtt) / 8,
            None => rtt,
        };
        self.srtt = Some(srtt);
        if srtt > SLOW {
            self.slow = true;
        } else if srtt < FAST {
            self.slow = false;
        }
    }

    /// When drawn predictions have waited too long for the server.
    pub fn deadline(&self) -> Option<Instant> {
        let first = self.pending.front().filter(|_| self.drawn > 0)?;
        Some(first.typed + EXPIRE + self.srtt.unwrap_or_default() * 4)
    }

    /// Erases predictions past their deadline.
    pub fn expire(&mut self, now: Instant) -> Vec<u8> {
        let mut out = Vec::new();
        if self.deadline().is_some_and(|d| now >= d) {
            self.fail(&mut out);
        }
        out
    }

    /// The terminal changed size: predictions are erased (while the cursor
    /// is still where they were drawn) and dropped, as lines may reflow.
    /// Returns the bytes for that.
    pub fn resize(&mut self, rows: u16, cols: u16) -> Vec<u8> {
        let mut out = Vec::new();
        let active = usable_size(rows, cols);
        if active == self.active && (!active || self.screen.screen().size() == (rows, cols)) {
            return out;
        }
        self.erase(&mut out);
        if active && !self.active {
            // What the screen showed meanwhile is unknown: start from a blank one.
            self.screen = vt100::Parser::new_with_callbacks(rows, cols, 0, Watch::default());
            self.parse = Parse::Ground;
        } else if active {
            self.screen.screen_mut().set_size(rows, cols);
        }
        self.active = active;
        self.pending.clear();
        self.epoch += 1;
        out
    }

    /// Erases predictions before something else is written to the terminal
    /// (qsh's own messages, a reconnect, the end of the session).
    pub fn clear(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.fail(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A predictor and the terminal it writes to.
    struct Harness {
        p: Predictor,
        term: vt100::Parser,
        /// Only what the server wrote.
        server: vt100::Parser,
        now: Instant,
    }

    impl Harness {
        fn new(mode: Mode) -> Harness {
            Harness { p: Predictor::new(mode, 24, 80), term: vt100::Parser::new(24, 80, 0), server: vt100::Parser::new(24, 80, 0), now: Instant::now() }
        }

        fn key(&mut self, s: &str) {
            let out = self.p.typed(s.as_bytes(), self.now);
            self.term.process(&out);
        }

        fn server(&mut self, s: &str) {
            self.now += Duration::from_millis(100);
            let out = self.p.output(s.as_bytes(), self.now);
            self.term.process(&out);
            self.server.process(s.as_bytes());
        }

        fn line(&self) -> String {
            self.term.screen().rows(0, 80).next().unwrap().trim_end().to_string()
        }

        fn same_as_server(&self) {
            assert_eq!(self.term.screen().contents(), self.server.screen().contents());
            assert_eq!(self.term.screen().cursor_position(), self.server.screen().cursor_position());
        }
    }

    #[test]
    fn echo_is_predicted_once_confirmed() {
        let mut h = Harness::new(Mode::Auto);
        h.server("$ ");
        h.key("l");
        assert_eq!(h.line(), "$", "nothing drawn before the first echo");
        h.server("l");
        h.key("s");
        assert_eq!(h.line(), "$ ls", "drawn right away on a slow link");
        h.key(" -a");
        assert_eq!(h.line(), "$ ls -a");
        h.server("s");
        assert_eq!(h.line(), "$ ls -a");
        h.server(" -a");
        h.same_as_server();
    }

    #[test]
    fn wrong_predictions_are_erased() {
        let mut h = Harness::new(Mode::Always);
        h.server("> ");
        h.key("a");
        h.server("a");
        h.key("bc");
        assert_eq!(h.line(), "> abc");
        // The program shows something else (e.g. upper case).
        h.server("B");
        assert_eq!(h.line(), "> aB");
        h.same_as_server();
        // After a wrong guess, nothing is confirmed until a control key.
        h.key("d");
        h.server("d");
        h.key("e");
        assert_eq!(h.line(), "> aBd");
        h.server("e");
        h.key("\x7f");
        h.server("\x08 \x08");
        h.key("x");
        // Colored echo confirms (the screen is compared, not the bytes).
        h.server("\x1b[31mx\x1b[0m");
        h.key("y");
        assert_eq!(h.line(), "> aBdxy");
    }

    /// Typed ahead, then a password prompt appears without a control key in
    /// between (sudo after `make` finished): nothing is shown.
    #[test]
    fn prompt_after_type_ahead() {
        let mut h = Harness::new(Mode::Always);
        h.server("$ make && sudo make install\r\n");
        h.key("l");
        h.server("l");
        h.server("[sudo] password for u: ");
        h.key("hunter2");
        assert!(!h.term.screen().contents().contains("hunter"), "{}", h.term.screen().contents());
    }

    /// A masked prompt (sudo with pwfeedback) answers every key with `*`.
    #[test]
    fn masked_prompts() {
        let mut h = Harness::new(Mode::Always);
        h.server("Password: ");
        h.key("\r"); // whatever happened before
        h.server("\r\nPassword: ");
        for c in "a*sec".chars() {
            h.key(&c.to_string());
            let screen = h.term.screen().contents();
            assert!(!screen.contains("*s") && !screen.contains("*e") && !screen.contains("*c"), "{screen}");
            h.server("*");
        }
    }

    /// A one-key answer echoed together with the next prompt: the echo
    /// must not vouch for what is typed at that prompt (a password).
    #[test]
    fn echo_and_prompt_in_one_chunk() {
        let mut h = Harness::new(Mode::Always);
        h.server("$ ");
        h.key("a");
        h.server("a");
        h.key("y");
        h.server("y\r\nPassword: ");
        h.key("hunter2");
        assert!(!h.term.screen().contents().contains("hunter"), "{}", h.term.screen().contents());
    }

    /// `clear` (with its scrollback erase) keeps predictions going.
    #[test]
    fn clear_keeps_predicting() {
        let mut h = Harness::new(Mode::Always);
        h.server("\x1b[H\x1b[2J\x1b[3J$ ");
        h.key("a");
        h.server("a");
        h.key("b");
        assert_eq!(h.line(), "$ ab");
    }

    /// Not over underlined cells: erasing would lose the underline.
    #[test]
    fn underlined_fields() {
        let mut h = Harness::new(Mode::Always);
        h.server("$ \x1b[4m      \x1b[0m\x1b[3G");
        h.key("a");
        h.server("a");
        h.key("b");
        h.same_as_server();
    }

    /// Output the emulator does not model (REP, insert mode) stops
    /// predictions until the screen is redrawn.
    #[test]
    fn unmodelled_output() {
        let mut h = Harness::new(Mode::Always);
        h.server("$ ");
        h.key("a");
        h.server("a");
        h.server("\x1b[5b");
        h.key("b");
        assert_eq!(h.line(), "$ a", "after REP the cursor position is unknown");
        h.server("\x1b[2J\x1b[H$ ");
        h.key("c");
        h.server("c");
        h.key("d");
        assert_eq!(h.line(), "$ cd", "trusted again after a full redraw");
    }

    /// Harmless mode switches (macOS bash's meta key mode) keep predictions on.
    #[test]
    fn harmless_modes() {
        let mut h = Harness::new(Mode::Always);
        h.server("\x1b[?1034h\x1b[?2004h$ ");
        h.key("a");
        h.server("a");
        h.key("b");
        assert_eq!(h.line(), "$ ab");
    }

    /// Not over a colored background: erasing would leave a hole.
    #[test]
    fn colored_lines() {
        let mut h = Harness::new(Mode::Always);
        h.server("\x1b[44m\x1b[2K\x1b[0m$ ");
        h.key("a");
        h.server("a");
        h.key("b");
        assert_eq!(h.line(), "$ a");
    }

    /// A resize erases what is drawn while the cursor is still there.
    #[test]
    fn resize_erases() {
        let mut h = Harness::new(Mode::Always);
        h.server("$ ");
        h.key("a");
        h.server("a");
        h.key("bc");
        assert_eq!(h.line(), "$ abc");
        let out = h.p.resize(24, 60);
        h.term.process(&out);
        assert_eq!(h.line(), "$ a");
        h.same_as_server();
    }

    #[test]
    fn nothing_is_drawn_after_a_control_key_until_confirmed() {
        let mut h = Harness::new(Mode::Always);
        h.server("$ ");
        h.key("s");
        h.server("s");
        h.key("udo x");
        h.server("udo x");
        h.key("\r");
        h.server("\r\nPassword: ");
        h.key("secret");
        assert!(!h.term.screen().contents().contains("sec"), "{}", h.term.screen().contents());
        h.key("\r");
        h.server("\r\nok\r\n$ ");
        h.same_as_server();
    }

    #[test]
    fn auto_mode_only_on_slow_links() {
        let mut h = Harness::new(Mode::Auto);
        h.server("$ ");
        h.key("a");
        // Fast echo (the harness advances 100 ms per server message; undo that).
        h.now -= Duration::from_millis(95);
        h.server("a");
        h.key("b");
        assert_eq!(h.line(), "$ a", "fast link: no prediction");
    }

    /// Random typing and server output (echoes, other text, cursor moves,
    /// erasures, colors): whatever was predicted, once the predictions are
    /// cleared the terminal shows exactly the server's screen.
    #[test]
    fn random_sessions_end_as_the_server_drew_them() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rnd = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        let mut drawn = 0;
        let pieces = ["界", "😀", "é", "\r\n", "\x08", "\x1b[K", "\x1b[2D", "\x1b[C", "\x1b[31m", "\x1b[0m", "\x1b[5;10H", "\x1b[?25l", "\x1b[?25h", "$ ", "\x1b[2J", "\t"];
        for round in 0..300 {
            let mut h = Harness::new(if round % 2 == 0 { Mode::Always } else { Mode::Auto });
            if round % 3 == 0 {
                // Narrow terminals, down to sizes that switch prediction off.
                let cols = [MIN_COLS, 21, 25, 3, 0][rnd(5) as usize];
                h.p.resize(24, cols);
                h.term = vt100::Parser::new(24, cols.max(MIN_COLS), 0);
                h.server = vt100::Parser::new(24, cols.max(MIN_COLS), 0);
            }
            let mut typed: Vec<u8> = Vec::new();
            for _ in 0..60 {
                match rnd(4) {
                    0 => {
                        let c = if rnd(6) == 0 { b'\r' } else { b'a' + rnd(26) as u8 };
                        typed.push(c);
                        h.key(std::str::from_utf8(&[c]).unwrap());
                        drawn += h.p.drawn;
                    }
                    // The echo of what was typed (sometimes only part of it).
                    1 if !typed.is_empty() => {
                        let n = 1 + rnd(typed.len() as u64) as usize;
                        let echo: Vec<u8> = typed.drain(..n).map(|c| if c == b'\r' { b'\n' } else { c }).collect();
                        h.server(&String::from_utf8(echo).unwrap());
                    }
                    2 => h.server(pieces[rnd(pieces.len() as u64) as usize]),
                    _ => {
                        let text: String = (0..rnd(5)).map(|_| (b'A' + rnd(26) as u8) as char).collect();
                        h.server(&text);
                    }
                }
                if rnd(10) == 0 {
                    let late = h.now + Duration::from_secs(10);
                    let out = h.p.expire(late);
                    h.term.process(&out);
                }
            }
            let out = h.p.clear();
            h.term.process(&out);
            h.same_as_server();
        }
        assert!(drawn > 30, "predictions were hardly ever drawn ({drawn})");
    }

    /// Server output made of random escape-sequence material (modes,
    /// scrolling regions, insert mode, cursor moves).
    #[test]
    fn random_escape_sequences() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut rnd = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        let alphabet = b"\x1b[;?0123456789hlHJKXDCABPLMm@rsu4 abc\r\n\x08";
        for round in 0..2000 {
            let mut h = Harness::new(Mode::Always);
            for _ in 0..40 {
                if rnd(2) == 0 {
                    let c = [b'a' + rnd(26) as u8];
                    h.key(std::str::from_utf8(&c).unwrap());
                } else {
                    let n = 1 + rnd(12) as usize;
                    let bytes: Vec<u8> = (0..n).map(|_| alphabet[rnd(alphabet.len() as u64) as usize]).collect();
                    h.server(&String::from_utf8(bytes).unwrap());
                }
            }
            let out = h.p.clear();
            h.term.process(&out);
            assert_eq!(h.term.screen().contents(), h.server.screen().contents(), "round {round}");
            assert_eq!(h.term.screen().cursor_position(), h.server.screen().cursor_position(), "round {round}");
        }
    }

    #[test]
    fn unfinished_sequences() {
        assert_eq!(Parse::Ground.feed(b"\x1b[3"), Parse::Csi);
        assert_eq!(Parse::Csi.feed(b"1m"), Parse::Ground);
        assert_eq!(Parse::Ground.feed(b"\x1b]0;title"), Parse::Text);
        assert_eq!(Parse::Text.feed(b"\x1b\\"), Parse::Ground);
        assert_eq!(Parse::Ground.feed("é".as_bytes()), Parse::Ground);
        assert_eq!(Parse::Ground.feed(&"界".as_bytes()[..2]), Parse::Utf8(1));
        assert_eq!(Parse::Ground.feed(b"\x1b(B"), Parse::Ground);
        // A prediction waits until the sequence is over.
        let mut h = Harness::new(Mode::Always);
        h.server("$ ");
        h.key("a");
        h.server("a\x1b[3");
        h.key("b");
        assert_eq!(h.line(), "$ a", "drawn inside an escape sequence");
        h.server("1m");
        assert_eq!(h.line(), "$ ab", "drawn once the sequence is over");
        let out = h.p.clear();
        h.term.process(&out);
        h.same_as_server();
    }

    #[test]
    fn no_predictions_in_insert_mode() {
        let mut h = Harness::new(Mode::Always);
        h.server("$ ");
        h.key("a");
        h.server("a\x1b[4h");
        h.key("b");
        assert_eq!(h.line(), "$ a");
        h.server("b\x1b[4;12l");
        h.key("c");
        assert_eq!(h.line(), "$ ab", "the screen may differ until it is redrawn");
    }

    #[test]
    fn edges() {
        let mut h = Harness::new(Mode::Always);
        // Not over existing text.
        h.server("$ x\x1b[D");
        h.key("y");
        h.server("y");
        h.key("z");
        h.same_as_server();
        // Not at the right margin.
        let mut h = Harness::new(Mode::Always);
        h.server(&"-".repeat(78));
        h.key("a");
        h.server("a");
        h.key("b");
        h.same_as_server();
        // Expired predictions are erased.
        let mut h = Harness::new(Mode::Always);
        h.server("$ ");
        h.key("a");
        h.server("a");
        h.key("b");
        assert_eq!(h.line(), "$ ab");
        let late = h.p.deadline().unwrap();
        let out = h.p.expire(late);
        h.term.process(&out);
        h.same_as_server();
        // Never draws nothing.
        let mut h = Harness::new(Mode::Never);
        h.server("$ ");
        h.key("a");
        h.server("a");
        h.key("b");
        assert_eq!(h.line(), "$ a");
    }
}
