//! authorized_keys lines with options (a user's file, or a key command's output).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for entry in qsh::authkeys::parse_list(&text, |_, _| {}) {
        let _ = entry.restrictions.may_open("db.example.com", 5432);
        let _ = entry.restrictions.may_listen("localhost", 8080);
    }
});
