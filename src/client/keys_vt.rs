//! Keys as a terminal sends them (xterm style), for consoles that report
//! key presses instead of bytes (Windows). The remote program's "cursor
//! keys" mode is followed from its output, as a terminal does.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// The xterm modifier parameter (`1 + shift + 2·alt + 4·ctrl`), if any modifier.
fn modifier_param(m: KeyModifiers) -> Option<u8> {
    let n = 1 + u8::from(m.contains(KeyModifiers::SHIFT)) + 2 * u8::from(m.contains(KeyModifiers::ALT)) + 4 * u8::from(m.contains(KeyModifiers::CONTROL));
    (n > 1).then_some(n)
}

/// `ESC [ 1 ; m X`, or `ESC [ X` / `ESC O X` without modifiers.
fn cursor_like(final_byte: char, m: KeyModifiers, app: bool) -> Vec<u8> {
    match modifier_param(m) {
        Some(n) => format!("\x1b[1;{n}{final_byte}").into_bytes(),
        None if app => format!("\x1bO{final_byte}").into_bytes(),
        None => format!("\x1b[{final_byte}").into_bytes(),
    }
}

/// `ESC [ n ~`, with `; m` for modifiers.
fn tilde(n: u8, m: KeyModifiers) -> Vec<u8> {
    match modifier_param(m) {
        Some(p) => format!("\x1b[{n};{p}~").into_bytes(),
        None => format!("\x1b[{n}~").into_bytes(),
    }
}

/// The bytes a terminal sends for a key; empty for releases and keys
/// without a sequence. `app_cursor`: the remote program asked for
/// application cursor keys (`ESC [ ? 1 h`).
pub fn encode(key: KeyEvent, app_cursor: bool) -> Vec<u8> {
    if key.kind == KeyEventKind::Release {
        return Vec::new();
    }
    let mut m = key.modifiers;
    // Windows reports AltGr as Ctrl+Alt, with the character it makes
    // (`@`, `{`, `€`, `ą`): that character is what was typed. Ctrl+Alt with
    // a Latin letter is a real Ctrl+Alt (ESC and the control code).
    if let KeyCode::Char(c) = key.code {
        if m.contains(KeyModifiers::CONTROL | KeyModifiers::ALT) && !c.is_ascii_alphabetic() {
            m.remove(KeyModifiers::CONTROL | KeyModifiers::ALT);
        }
    }
    let alt = m.contains(KeyModifiers::ALT);
    let mut out = match key.code {
        KeyCode::Char(c) if m.contains(KeyModifiers::CONTROL) => match latin_key(c).to_ascii_lowercase() {
            c @ 'a'..='z' => vec![c as u8 - b'a' + 1],
            ' ' | '@' | '2' => vec![0],
            '[' | '3' => vec![0x1b],
            '\\' | '4' => vec![0x1c],
            ']' | '5' => vec![0x1d],
            '^' | '6' => vec![0x1e],
            '_' | '-' | '7' => vec![0x1f],
            '8' | '?' => vec![0x7f],
            c => c.to_string().into_bytes(),
        },
        KeyCode::Char(c) => c.to_string().into_bytes(),
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Backspace if m.contains(KeyModifiers::CONTROL) => vec![0x08],
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => return cursor_like('A', m, app_cursor),
        KeyCode::Down => return cursor_like('B', m, app_cursor),
        KeyCode::Right => return cursor_like('C', m, app_cursor),
        KeyCode::Left => return cursor_like('D', m, app_cursor),
        KeyCode::Home => return cursor_like('H', m, app_cursor),
        KeyCode::End => return cursor_like('F', m, app_cursor),
        KeyCode::Insert => return tilde(2, m),
        KeyCode::Delete => return tilde(3, m),
        KeyCode::PageUp => return tilde(5, m),
        KeyCode::PageDown => return tilde(6, m),
        KeyCode::F(n @ 1..=4) => {
            let c = (b'P' + n - 1) as char;
            return match modifier_param(m) {
                Some(p) => format!("\x1b[1;{p}{c}").into_bytes(),
                None => format!("\x1bO{c}").into_bytes(),
            };
        }
        KeyCode::F(n @ 5..=12) => {
            const CODES: [u8; 8] = [15, 17, 18, 19, 20, 21, 23, 24];
            return tilde(CODES[(n - 5) as usize], m);
        }
        _ => return Vec::new(),
    };
    // Alt: ESC before the key (as xterm's metaSendsEscape).
    if alt {
        out.insert(0, 0x1b);
    }
    out
}

/// The Latin letter on the same key for a Russian (ЙЦУКЕН) letter, so that
/// Ctrl+C works with that layout active (the console reports Ctrl+С).
fn latin_key(c: char) -> char {
    const RU: &str = "йцукенгшщзхъфывапролджэячсмитьбю";
    const EN: &str = "qwertyuiop[]asdfghjkl;'zxcvbnm,.";
    let lower = c.to_lowercase().next().unwrap_or(c);
    match RU.chars().position(|r| r == lower) {
        Some(i) => EN.chars().nth(i).unwrap_or(c),
        None => c,
    }
}

/// Follows `ESC [ ? 1 h` / `ESC [ ? 1 l` (application cursor keys) in output.
#[derive(Default)]
pub struct CursorKeys {
    state: u8,
    params: Vec<u8>,
    pub app: bool,
}

impl CursorKeys {
    pub fn feed(&mut self, data: &[u8]) {
        for &b in data {
            self.state = match (self.state, b) {
                (_, 0x1b) => 1,
                (1, b'[') => {
                    self.params.clear();
                    2
                }
                (2, 0x20..=0x3f) => {
                    if self.params.len() < 32 {
                        self.params.push(b);
                    }
                    2
                }
                (2, b'h' | b'l') => {
                    if let Some(list) = self.params.strip_prefix(b"?") {
                        if list.split(|&c| c == b';').any(|p| p == b"1") {
                            self.app = b == b'h';
                        }
                    }
                    0
                }
                // ESC c (reset).
                (1, b'c') => {
                    self.app = false;
                    0
                }
                _ => 0,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(code: KeyCode, m: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, m)
    }

    #[test]
    fn keys() {
        let none = KeyModifiers::NONE;
        assert_eq!(encode(k(KeyCode::Char('a'), none), false), b"a");
        assert_eq!(encode(k(KeyCode::Char('ж'), none), false), "ж".as_bytes());
        assert_eq!(encode(k(KeyCode::Char('c'), KeyModifiers::CONTROL), false), [3]);
        assert_eq!(encode(k(KeyCode::Char('x'), KeyModifiers::ALT), false), b"\x1bx");
        assert_eq!(encode(k(KeyCode::Enter, none), false), b"\r");
        assert_eq!(encode(k(KeyCode::Backspace, none), false), [0x7f]);
        assert_eq!(encode(k(KeyCode::Up, none), false), b"\x1b[A");
        assert_eq!(encode(k(KeyCode::Up, none), true), b"\x1bOA");
        assert_eq!(encode(k(KeyCode::Left, KeyModifiers::CONTROL), true), b"\x1b[1;5D");
        assert_eq!(encode(k(KeyCode::Delete, none), false), b"\x1b[3~");
        assert_eq!(encode(k(KeyCode::PageDown, KeyModifiers::SHIFT), false), b"\x1b[6;2~");
        assert_eq!(encode(k(KeyCode::F(1), none), false), b"\x1bOP");
        assert_eq!(encode(k(KeyCode::F(12), none), false), b"\x1b[24~");
        assert_eq!(encode(k(KeyCode::BackTab, KeyModifiers::SHIFT), false), b"\x1b[Z");
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        assert_eq!(encode(k(KeyCode::Char('@'), altgr), false), b"@", "AltGr");
        assert_eq!(encode(k(KeyCode::Char('ą'), altgr), false), "ą".as_bytes());
        assert_eq!(encode(k(KeyCode::Char('a'), altgr), false), b"\x1b\x01", "a real Ctrl+Alt");
        assert_eq!(encode(k(KeyCode::Char('с'), KeyModifiers::CONTROL), false), [3], "Ctrl+C on a Russian layout");
        assert_eq!(encode(k(KeyCode::Char('Д'), KeyModifiers::CONTROL), false), [12]);
        let mut release = k(KeyCode::Char('a'), none);
        release.kind = KeyEventKind::Release;
        assert!(encode(release, false).is_empty());
    }

    #[test]
    fn cursor_mode() {
        let mut c = CursorKeys::default();
        c.feed(b"text\x1b[?1h");
        assert!(c.app);
        c.feed(b"\x1b[?25;1");
        c.feed(b"l");
        assert!(!c.app, "split over two chunks, with other modes");
        c.feed(b"\x1b[?1049h\x1b[1h");
        assert!(!c.app, "not private mode 1, nor 1049");
    }
}
