//! Lines of text the menu lets you edit. The cursor is kept as the number of
//! characters after it (`back`), so 0 is the end of the line, whatever is
//! typed or removed.

use crossterm::event::KeyCode;

pub const CURSOR: char = '▏';

/// Applies `key` to the line. Returns whether the text changed.
pub fn edit(text: &mut String, back: &mut usize, key: KeyCode) -> bool {
    let len = text.chars().count();
    *back = (*back).min(len);
    let at = len - *back;
    let byte = |chars: usize| text.char_indices().nth(chars).map_or(text.len(), |(i, _)| i);
    match key {
        KeyCode::Left => *back = (*back + 1).min(len),
        KeyCode::Right => *back = back.saturating_sub(1),
        KeyCode::Home => *back = len,
        KeyCode::End => *back = 0,
        KeyCode::Backspace if at > 0 => {
            text.remove(byte(at - 1));
            return true;
        }
        KeyCode::Delete if *back > 0 => {
            text.remove(byte(at));
            *back -= 1;
            return true;
        }
        KeyCode::Char(c) => {
            text.insert(byte(at), c);
            return true;
        }
        _ => {}
    }
    false
}

/// The line with the cursor in it.
pub fn with_cursor(text: &str, back: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let at = chars.len() - back.min(chars.len());
    chars[..at].iter().chain([CURSOR].iter()).chain(chars[at..].iter()).collect()
}

/// As [`with_cursor`], in at most `room` characters besides the cursor: the
/// part around the cursor, with `…` where more of the line is cut off.
pub fn window(text: &str, back: usize, room: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let (len, room) = (chars.len(), room.max(2));
    if len <= room {
        return with_cursor(text, back);
    }
    let at = len - back.min(len);
    // Stays at the end of the line while the cursor is there. The cursor must
    // not end up left of a `…`, which takes the place of the first character.
    let start = (len - room).min(at.saturating_sub(1));
    let end = start + room;
    let mut shown = String::new();
    for (i, c) in chars.iter().enumerate().take(end).skip(start) {
        if i == at {
            shown.push(CURSOR);
        }
        shown.push(if (i == start && start > 0) || (i + 1 == end && end < len) { '…' } else { *c });
    }
    if at == end {
        shown.push(CURSOR);
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(text: &str, keys: &[KeyCode]) -> (String, usize) {
        let (mut text, mut back) = (text.to_string(), 0);
        for k in keys {
            edit(&mut text, &mut back, *k);
        }
        (text, back)
    }

    #[test]
    fn moves_and_edits_inside_the_line() {
        use KeyCode::*;
        assert_eq!(keys("host", &[Left, Left, Char('X')]), ("hoXst".to_string(), 2));
        assert_eq!(keys("host", &[Left, Backspace]), ("hot".to_string(), 1));
        assert_eq!(keys("host", &[Home, Delete, Char('c')]), ("cost".to_string(), 3));
        assert_eq!(keys("host", &[Home, Right, End, Char('s')]), ("hosts".to_string(), 0));
    }

    #[test]
    fn stops_at_both_ends() {
        use KeyCode::*;
        assert_eq!(keys("ab", &[Left, Left, Left, Backspace]), ("ab".to_string(), 2));
        assert_eq!(keys("ab", &[Right, Delete]), ("ab".to_string(), 0));
        assert_eq!(keys("", &[Left, Backspace, Delete, Char('x')]), ("x".to_string(), 0));
    }

    #[test]
    fn counts_characters_not_bytes() {
        use KeyCode::*;
        assert_eq!(keys("пирог", &[Left, Left, Char('Я')]), ("пирЯог".to_string(), 2));
        assert_eq!(keys("пирог", &[Left, Backspace]), ("пирг".to_string(), 1));
        assert_eq!(keys("пирог", &[Home, Delete]), ("ирог".to_string(), 4));
    }

    #[test]
    fn shows_the_cursor() {
        assert_eq!(with_cursor("host", 0), "host▏");
        assert_eq!(with_cursor("host", 2), "ho▏st");
        assert_eq!(with_cursor("host", 9), "▏host");
    }

    #[test]
    fn long_lines_scroll_to_the_cursor() {
        let line = "0123456789";
        assert_eq!(window("short", 1, 8), "shor▏t");
        assert_eq!(window(line, 0, 5), "…6789▏");
        assert_eq!(window(line, 10, 5), "▏0123…");
        assert_eq!(window(line, 5, 5), "…▏567…");
        assert_eq!(window(line, 1, 5), "…678▏9");
        for back in 0..=line.len() {
            let shown = window(line, back, 5);
            assert_eq!(shown.chars().count(), 6, "{shown}");
            assert_eq!(shown.matches(CURSOR).count(), 1, "{shown}");
        }
    }
}
