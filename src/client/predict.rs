//! Local echo prediction for interactive sessions, like mosh: on a slow
//! link, typed characters appear at once instead of after a round trip.
//!
//! The server's output is fed through a terminal emulator, so the true
//! screen is known. A typed printable character is predicted at the cursor
//! when that cell is empty, and drawn once the current "epoch" is confirmed:
//! an earlier prediction of it showed up on the server's screen. Every
//! control key (Enter, arrows, ^C...) starts a new epoch, so after a
//! password prompt nothing is drawn until the server echoes something.
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
    screen: vt100::Parser,
    pending: VecDeque<Prediction>,
    /// How many of `pending` (from the front) are drawn on the terminal.
    drawn: usize,
    epoch: u64,
    /// Highest epoch with a confirmed prediction.
    confirmed: u64,
    /// A control key was typed and the server has not answered since:
    /// where the next character goes is unknown.
    unsettled: bool,
    srtt: Option<Duration>,
    slow: bool,
    /// The terminal is big enough (see [`usable_size`]); otherwise output
    /// passes through untouched and nothing is predicted.
    active: bool,
    parse: Parse,
    /// Parameters of the CSI sequence being read, to follow insert mode.
    csi: Vec<u8>,
    /// Insert mode (CSI 4 h) is on: a drawn character would push text
    /// aside, and the emulator does not model that, so nothing is drawn.
    insert: bool,
}

impl Predictor {
    pub fn new(mode: Mode, rows: u16, cols: u16) -> Predictor {
        Predictor {
            mode,
            screen: vt100::Parser::new(rows.max(MIN_ROWS), cols.max(MIN_COLS), 0),
            pending: VecDeque::new(),
            drawn: 0,
            epoch: 1,
            confirmed: 0,
            unsettled: false,
            srtt: None,
            slow: false,
            active: usable_size(rows, cols),
            parse: Parse::Ground,
            csi: Vec::new(),
            insert: false,
        }
    }

    /// Bytes that remove the drawn predictions from the terminal.
    fn erase(&mut self, out: &mut Vec<u8>) {
        if self.drawn > 0 {
            // Back to where the server's cursor is, and blank what we drew
            // (those cells are empty on the server's screen).
            out.extend_from_slice(format!("\x1b[{n}D\x1b[{n}X", n = self.drawn).as_bytes());
            self.drawn = 0;
        }
    }

    /// Forgets all predictions (a new epoch must be confirmed first).
    fn fail(&mut self, out: &mut Vec<u8>) {
        self.erase(out);
        self.pending.clear();
        self.epoch += 1;
    }

    fn may_draw(&self, p: &Prediction) -> bool {
        let fast_enough = match self.mode {
            Mode::Never => false,
            Mode::Always => true,
            Mode::Auto => self.slow,
        };
        fast_enough && p.epoch <= self.confirmed && self.parse == Parse::Ground && !self.insert && !self.screen.screen().hide_cursor()
    }

    /// Draws pending predictions after the drawn ones, as far as allowed.
    fn draw(&mut self, out: &mut Vec<u8>) {
        while self.drawn < self.pending.len() && self.may_draw(&self.pending[self.drawn]) {
            out.push(self.pending[self.drawn].ch);
            self.drawn += 1;
        }
    }

    /// Whether `(row, col)` is empty on the server's screen and leaves room
    /// for the cursor after it (no line wrap).
    fn free(&self, row: u16, col: u16) -> bool {
        let screen = self.screen.screen();
        let (_, cols) = screen.size();
        // The second half of a wide character looks empty, but drawing there
        // would destroy the character.
        col + 1 < cols && screen.cell(row, col).is_some_and(|c| !c.has_contents() && !c.is_wide_continuation())
    }

    /// Handles typed input (as sent to the server); returns bytes to write
    /// to the terminal.
    pub fn typed(&mut self, data: &[u8], now: Instant) -> Vec<u8> {
        let mut out = Vec::new();
        if self.mode == Mode::Never || !self.active {
            return out;
        }
        // Control keys (and anything with them, like escape sequences) move
        // the cursor in ways only the server knows.
        if !data.iter().all(|b| (0x20..0x7f).contains(b)) {
            self.epoch += 1;
            self.unsettled = true;
            return out;
        }
        for &ch in data {
            let at = match self.pending.back() {
                Some(last) if last.epoch == self.epoch => Some((last.row, last.col + 1)),
                Some(_) => None,
                None if self.unsettled => None,
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

    /// Handles output from the server; returns the bytes to write instead.
    pub fn output(&mut self, data: &[u8], now: Instant) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 16);
        if self.mode == Mode::Never || !self.active {
            out.extend_from_slice(data);
            return out;
        }
        self.erase(&mut out);
        out.extend_from_slice(data);
        self.screen.process(data);
        self.follow_modes(data);
        self.unsettled = false;
        // Predictions that are now on the server's screen are confirmed.
        while let Some(p) = self.pending.front().copied() {
            let screen = self.screen.screen();
            let shown = screen.cell(p.row, p.col).is_some_and(|c| c.contents().as_bytes() == [p.ch]);
            let (row, col) = screen.cursor_position();
            let passed = row > p.row || (row == p.row && col > p.col);
            if !(shown && passed) {
                break;
            }
            self.pending.pop_front();
            self.confirmed = self.confirmed.max(p.epoch);
            self.sample(now.saturating_duration_since(p.typed));
        }
        // The rest must still start at the cursor, on empty cells.
        if let Some(first) = self.pending.front() {
            let fits = self.screen.screen().cursor_position() == (first.row, first.col)
                && self.pending.iter().all(|p| p.row == first.row && self.free(p.row, p.col));
            if !fits {
                self.pending.clear();
                self.epoch += 1;
            }
        }
        self.draw(&mut out);
        out
    }

    /// Follows the parser state and insert mode through server output.
    fn follow_modes(&mut self, data: &[u8]) {
        for &b in data {
            let before = self.parse;
            self.parse = self.parse.feed(&[b]);
            match (before, self.parse) {
                (Parse::Escape, Parse::Csi) => self.csi.clear(),
                (Parse::Csi, Parse::Csi) if self.csi.len() < 64 => self.csi.push(b),
                (Parse::Csi, Parse::Ground) if b == b'h' || b == b'l' => {
                    if !self.csi.starts_with(b"?") && self.csi.split(|&c| c == b';').any(|p| p == b"4") {
                        self.insert = b == b'h';
                    }
                }
                // ESC c: a full reset.
                (Parse::Escape, Parse::Ground) if b == b'c' => self.insert = false,
                _ => {}
            }
        }
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

    /// The terminal changed size: predictions are dropped (lines may reflow).
    pub fn resize(&mut self, rows: u16, cols: u16) {
        let active = usable_size(rows, cols);
        if active == self.active && (!active || self.screen.screen().size() == (rows, cols)) {
            return;
        }
        if active && !self.active {
            // What the screen showed meanwhile is unknown: start from a blank one.
            self.screen = vt100::Parser::new(rows, cols, 0);
        } else if active {
            self.screen.screen_mut().set_size(rows, cols);
        }
        self.active = active;
        self.pending.clear();
        self.drawn = 0;
        self.epoch += 1;
    }

    /// Erases predictions before something else is written to the terminal
    /// (qsh's own messages, a reconnect).
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
        // Colored echo still confirms (the screen is compared, not the bytes).
        h.key("d");
        h.server("\x1b[31md\x1b[0m");
        h.key("e");
        assert_eq!(h.line(), "> aBde");
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
        assert!(drawn > 300, "predictions were hardly ever drawn ({drawn})");
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
        h.key("c");
        assert_eq!(h.line(), "$ abc", "drawn once the sequence is over");
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
        assert_eq!(h.line(), "$ abc");
        h.server("\x1b[?4h");
        h.key("d");
        assert_eq!(h.line(), "$ abcd", "private mode 4 is something else");
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
