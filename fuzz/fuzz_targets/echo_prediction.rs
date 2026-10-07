//! Echo prediction against arbitrary keystrokes and server output: once the
//! predictions are cleared, the terminal shows exactly the server's screen.
#![no_main]

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use qsh::client::predict::{Mode, Predictor};

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else { return };
    let (rows, cols) = (24, 20 + (first % 100) as u16);
    let mut p = Predictor::new(if first & 1 == 0 { Mode::Always } else { Mode::Auto }, rows, cols);
    let mut term = vt100::Parser::new(rows, cols, 0);
    let mut server = vt100::Parser::new(rows, cols, 0);
    let mut now = Instant::now();
    // Each chunk: a tag byte (keys, output or a timeout), then up to 16 bytes.
    for chunk in rest.chunks(17) {
        let (&tag, body) = chunk.split_first().unwrap();
        now += Duration::from_millis(u64::from(tag >> 2));
        match tag & 3 {
            0 | 1 => term.process(&p.typed(body, now)),
            2 => {
                term.process(&p.output(body, now));
                server.process(body);
            }
            _ => term.process(&p.expire(now + Duration::from_secs(60))),
        }
    }
    term.process(&p.clear());
    assert_eq!(term.screen().contents(), server.screen().contents());
    assert_eq!(term.screen().cursor_position(), server.screen().cursor_position());
});
