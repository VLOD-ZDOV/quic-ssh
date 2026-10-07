//! Keystroke timing obfuscation for interactive sessions (like OpenSSH's
//! `ObscureKeystrokeTiming`).
//!
//! Without it every keystroke leaves as its own packet the moment it is typed,
//! so anyone on the path can record the rhythm of typing (enough to narrow down
//! typed passwords, and to tell which commands are being typed). Here, once
//! typing starts, packets leave on a fixed clock (default every 20 ms), all of
//! the same size. Ticks with nothing to send carry chaff, which also continues
//! for a random 1–2 s after the last keystroke, so the end of typing is hidden
//! too. Bulk input such as a paste is sent at once: it is not timing-sensitive.

use std::time::{Duration, Instant};

use rand::Rng;

use crate::proto::ClientMsg;

pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(20);
/// Every obfuscated message carries exactly this many bytes of data + padding.
pub const PAD_TO: usize = 32;
/// Pending input above this is treated as bulk and sent unobfuscated.
const BULK: usize = 8 * PAD_TO;
const CHAFF_MIN: Duration = Duration::from_millis(1000);
const CHAFF_MAX: Duration = Duration::from_millis(2000);

pub struct Obfuscator {
    interval: Duration,
    pending: Vec<u8>,
    /// When the next packet leaves; `None` while idle.
    next_tick: Option<Instant>,
    /// Chaff is sent on empty ticks until then.
    chaff_until: Instant,
}

/// A fixed-size keystroke message; empty `data` is chaff.
fn typed(data: Vec<u8>) -> ClientMsg {
    let pad = vec![0u8; PAD_TO.saturating_sub(data.len())];
    ClientMsg::Typed { data, pad }
}

impl Obfuscator {
    pub fn new(interval: Duration) -> Obfuscator {
        Obfuscator { interval, pending: Vec::new(), next_tick: None, chaff_until: Instant::now() }
    }

    /// When [`Obfuscator::tick`] must be called next, if a clock is running.
    pub fn deadline(&self) -> Option<Instant> {
        self.next_tick
    }

    fn take_chunk(&mut self) -> Vec<u8> {
        let n = self.pending.len().min(PAD_TO);
        self.pending.drain(..n).collect()
    }

    /// New input from the terminal; returns what must be sent right away.
    pub fn input(&mut self, now: Instant, data: &[u8]) -> Vec<ClientMsg> {
        self.pending.extend_from_slice(data);
        let jitter = rand::thread_rng().gen_range(CHAFF_MIN..=CHAFF_MAX);
        self.chaff_until = now + jitter;
        if self.pending.len() > BULK {
            return vec![ClientMsg::Stdin(std::mem::take(&mut self.pending))];
        }
        if self.next_tick.is_none() {
            // Idle: the first keystroke goes out at once and starts the clock.
            self.next_tick = Some(now + self.interval);
            return vec![typed(self.take_chunk())];
        }
        Vec::new()
    }

    /// Called at [`Obfuscator::deadline`]: the packet for this tick, if any.
    pub fn tick(&mut self, now: Instant) -> Option<ClientMsg> {
        let due = self.next_tick?;
        if self.pending.is_empty() && now >= self.chaff_until {
            self.next_tick = None;
            return None;
        }
        // Stay on the clock; if we fell far behind, restart it from now.
        let next = due + self.interval;
        self.next_tick = Some(if next < now { now + self.interval } else { next });
        Some(typed(self.take_chunk()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size(msg: &ClientMsg) -> usize {
        postcard::to_stdvec(msg).unwrap().len()
    }

    fn data(msg: &ClientMsg) -> &[u8] {
        match msg {
            ClientMsg::Typed { data, .. } | ClientMsg::Stdin(data) => data,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn keystrokes_leave_on_a_fixed_clock_with_equal_sizes() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut o = Obfuscator::new(DEFAULT_INTERVAL);
        // First key goes out at once.
        let first = o.input(t0, b"l");
        assert_eq!(first.len(), 1);
        assert_eq!(data(&first[0]), b"l");
        // Keys typed between ticks wait for the next tick.
        assert!(o.input(ms(5), b"s").is_empty());
        assert!(o.input(ms(9), b"\r").is_empty());
        assert_eq!(o.deadline(), Some(ms(20)));
        let tick = o.tick(ms(20)).unwrap();
        assert_eq!(data(&tick), b"s\r");
        // Then chaff, same size as real keystrokes, every 20 ms.
        let chaff = o.tick(ms(40)).unwrap();
        assert!(data(&chaff).is_empty());
        assert_eq!(size(&chaff), size(&tick));
        assert_eq!(size(&chaff), size(&first[0]));
        assert_eq!(o.deadline(), Some(ms(60)));
    }

    #[test]
    fn chaff_stops_one_to_two_seconds_after_typing() {
        let t0 = Instant::now();
        let mut o = Obfuscator::new(DEFAULT_INTERVAL);
        o.input(t0, b"x");
        let mut t = t0;
        let mut packets = 0;
        while let Some(deadline) = o.deadline() {
            t = deadline;
            if o.tick(t).is_some() {
                packets += 1;
            }
        }
        let quiet_after = t - t0;
        assert!(quiet_after >= CHAFF_MIN && quiet_after <= CHAFF_MAX + DEFAULT_INTERVAL, "{quiet_after:?}");
        assert!(packets >= 49, "{packets} chaff packets");
        // Idle again: the next key is sent immediately.
        assert_eq!(o.input(t + Duration::from_secs(5), b"y").len(), 1);
    }

    #[test]
    fn bulk_input_bypasses_obfuscation() {
        let t0 = Instant::now();
        let mut o = Obfuscator::new(DEFAULT_INTERVAL);
        o.input(t0, b"a");
        let paste = vec![b'p'; 1000];
        let out = o.input(t0 + Duration::from_millis(3), &paste);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], ClientMsg::Stdin(d) if d.len() == 1000));
    }
}
