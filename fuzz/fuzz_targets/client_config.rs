//! Client configs (ssh_config syntax) and the menu's saved connections.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let base = std::path::Path::new("/nonexistent-qsh-fuzz");
    let cfg = qsh::client::config::parse(&text, "web1.example.com", base, true);
    let _ = qsh::client::config::keystroke_interval(cfg.obscure_keystrokes.as_deref());
    let _ = cfg.control_persist.as_deref().map(qsh::client::control::parse_persist);
    let _ = qsh::client::parse_escape(cfg.escape_char.as_deref());
    let _ = qsh::client::saved::parse(&text);
});
