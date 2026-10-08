//! Time-based one-time codes (RFC 6238: HMAC-SHA1, 6 digits, 30 s), the
//! format every authenticator app understands, as a second factor.

use anyhow::{bail, Result};
use hmac::{Hmac, Mac};

/// Where a user's secret lives (`~/.config/qsh/totp`, base32, mode 0600).
pub fn secret_path(home: &std::path::Path) -> std::path::PathBuf {
    crate::keys::qsh_dir(home).join("totp")
}

/// Seconds per code.
pub const STEP: u64 = 30;
const DIGITS: u32 = 6;
/// Codes from one step before or after are accepted too (clock drift).
pub const WINDOW: u64 = 1;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            out.push(BASE32[((bits >> (35 - i * 5)) & 31) as usize] as char);
        }
    }
    out
}

/// Decodes base32, ignoring case, spaces and padding.
pub fn base32_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let Some(v) = BASE32.iter().position(|&b| b as char == c.to_ascii_uppercase()) else {
            bail!("invalid base32 character {c:?}");
        };
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// The code for time step `counter` (RFC 4226 dynamic truncation).
pub fn code(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let offset = (h[19] & 0x0f) as usize;
    let n = u32::from_be_bytes([h[offset] & 0x7f, h[offset + 1], h[offset + 2], h[offset + 3]]);
    n % 10u32.pow(DIGITS)
}

/// Checks `answer` at Unix time `now`. Returns the matched time step, which
/// must be remembered so the same code cannot be used twice; steps up to
/// `used` are rejected.
pub fn verify(secret: &[u8], answer: &str, now: u64, used: Option<u64>) -> Option<u64> {
    let answer: String = answer.chars().filter(|c| !c.is_whitespace()).collect();
    if answer.len() != DIGITS as usize || !answer.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let given: u32 = answer.parse().ok()?;
    let now = now / STEP;
    let mut found = None;
    // Every candidate is computed, so timing does not tell which one matched.
    for step in now.saturating_sub(WINDOW)..=now + WINDOW {
        if code(secret, step) == given && used.is_none_or(|u| step > u) {
            found = Some(step);
        }
    }
    found
}

/// `otpauth://` link for authenticator apps (also shown as a QR code).
pub fn uri(secret: &[u8], account: &str) -> String {
    let escape = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    format!("otpauth://totp/qsh:{}?secret={}&issuer=qsh&algorithm=SHA1&digits={DIGITS}&period={STEP}", escape(account), base32_encode(secret))
}

/// A QR code drawn with half blocks: light modules are drawn, dark ones are
/// left blank, which suits terminals with a dark background.
pub fn qr_text(data: &str) -> Result<String> {
    let qr = qrcode::QrCode::new(data.as_bytes())?;
    let width = qr.width();
    let colors = qr.to_colors();
    const QUIET: usize = 2;
    let size = width + 2 * QUIET;
    let light = |x: usize, y: usize| {
        if x < QUIET || y < QUIET || x >= width + QUIET || y >= width + QUIET {
            return true;
        }
        colors[(y - QUIET) * width + (x - QUIET)] == qrcode::Color::Light
    };
    let mut out = String::new();
    for y in (0..size).step_by(2) {
        for x in 0..size {
            let top = light(x, y);
            let bottom = y + 1 >= size || light(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        // RFC 6238 appendix B, SHA-1 secret "12345678901234567890", last 6 digits.
        let secret = b"12345678901234567890";
        for (time, expected) in [(59u64, 287082u32), (1111111109, 81804), (1234567890, 5924), (2000000000, 279037)] {
            assert_eq!(code(secret, time / STEP), expected, "t={time}");
        }
    }

    #[test]
    fn base32_roundtrip() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("mzxw6ytboi======").unwrap(), b"foobar");
        for n in 0..25 {
            let data: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
            assert_eq!(base32_decode(&base32_encode(&data)).unwrap(), data);
        }
        assert!(base32_decode("not base32!").is_err());
    }

    #[test]
    fn window_and_replay() {
        let secret = b"some secret bytes!!!";
        let now = 1_800_000_000;
        let current = format!("{:06}", code(secret, now / STEP));
        let step = verify(secret, &current, now, None).unwrap();
        assert!(verify(secret, &current, now, Some(step)).is_none(), "replayed");
        let previous = format!("{:06}", code(secret, now / STEP - 1));
        assert!(verify(secret, &previous, now, None).is_some(), "drift of one step");
        let old = format!("{:06}", code(secret, now / STEP - 3));
        assert!(verify(secret, &old, now, None).is_none());
        assert!(verify(secret, "12345", now, None).is_none());
        assert!(uri(secret, "alice@host").starts_with("otpauth://totp/qsh:alice@host?secret="));
        assert!(qr_text("otpauth://totp/x").unwrap().lines().count() > 10);
    }
}
