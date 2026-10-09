//! Per-source penalties, like sshd's PerSourcePenalties (OpenSSH 9.8):
//! addresses whose connections fail to log in collect penalty time, and once
//! it passes a minimum, new connections from there are dropped until it runs
//! out. IPv4 addresses count singly, IPv6 ones per /64.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::Penalties as Settings;

/// How a connection ended, for the penalty it earns.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    /// Logged in: no penalty.
    LoggedIn,
    /// Tried to log in and was refused.
    AuthFailed,
    /// Went away (or timed out) without trying.
    NoAuth,
    /// Did not finish logging in within login_grace_time.
    GraceExceeded,
}

struct Entry {
    expires: Instant,
    /// The penalty has passed the minimum: connections are dropped.
    enforced: bool,
}

/// Sources and their penalties.
pub struct Penalties {
    settings: Settings,
    sources: Mutex<HashMap<IpAddr, Entry>>,
}

/// The address a penalty is kept for: IPv4 as is, IPv6 per /64.
fn source(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
        v4 => v4,
    }
}

impl Penalties {
    pub fn new(settings: Settings) -> Penalties {
        Penalties { settings, sources: Mutex::default() }
    }

    fn exempt(&self, ip: IpAddr) -> bool {
        !self.settings.exempt.is_empty() && crate::pattern::address_allowed(&self.settings.exempt.join(","), ip)
    }

    /// Whether connections from `ip` are dropped right now.
    pub fn refused(&self, ip: IpAddr) -> Option<Duration> {
        self.refused_at(ip, Instant::now())
    }

    fn refused_at(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        if !self.settings.enabled {
            return None;
        }
        let map = self.sources.lock().unwrap();
        map.get(&source(ip)).filter(|e| e.enforced && e.expires > now).map(|e| e.expires - now)
    }

    /// Adds the penalty for how a connection from `ip` ended. Returns true
    /// when this starts dropping the source's connections.
    pub fn record(&self, ip: IpAddr, outcome: Outcome) -> bool {
        self.record_at(ip, outcome, Instant::now())
    }

    fn record_at(&self, ip: IpAddr, outcome: Outcome, now: Instant) -> bool {
        let s = &self.settings;
        let add = match outcome {
            Outcome::LoggedIn => return false,
            Outcome::AuthFailed => s.authfail,
            Outcome::NoAuth => s.noauth,
            Outcome::GraceExceeded => s.grace_exceeded,
        };
        if !s.enabled || add.is_zero() || self.exempt(ip) {
            return false;
        }
        let mut map = self.sources.lock().unwrap();
        map.retain(|_, e| e.expires > now);
        let key = source(ip);
        // Like sshd with overflow "permissive": a full table adds nothing.
        if !map.contains_key(&key) && map.len() >= s.max_sources {
            return false;
        }
        let e = map.entry(key).or_insert(Entry { expires: now, enforced: false });
        e.expires = (e.expires.max(now) + add).min(now + s.max);
        let starts = !e.enforced && e.expires - now >= s.min;
        e.enforced |= starts;
        starts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn penalties_accrue_and_expire() {
        let p = Penalties::new(Settings::default());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t = Instant::now();
        assert!(!p.record_at(ip, Outcome::AuthFailed, t));
        assert!(!p.record_at(ip, Outcome::AuthFailed, t));
        assert!(p.refused_at(ip, t).is_none(), "below the minimum");
        assert!(p.record_at(ip, Outcome::AuthFailed, t), "15 s reached");
        assert!(p.refused_at(ip, t).is_some());
        assert!(p.refused_at("192.0.2.2".parse().unwrap(), t).is_none(), "other sources are fine");
        assert!(p.refused_at(ip, t + Duration::from_secs(16)).is_none(), "it runs out");
        assert!(!p.record_at(ip, Outcome::LoggedIn, t));
        for _ in 0..1000 {
            p.record_at(ip, Outcome::AuthFailed, t);
        }
        assert!(p.refused_at(ip, t + Duration::from_secs(599)).is_some());
        assert!(p.refused_at(ip, t + Duration::from_secs(601)).is_none(), "capped at max");
    }

    #[test]
    fn ipv6_counts_per_64_and_exemptions() {
        let p = Penalties::new(Settings { exempt: vec!["10.0.0.0/8".into()], ..Settings::default() });
        let t = Instant::now();
        for i in 1..=3 {
            p.record_at(format!("2001:db8::{i}").parse().unwrap(), Outcome::AuthFailed, t);
        }
        assert!(p.refused_at("2001:db8::ffff".parse().unwrap(), t).is_some());
        assert!(p.refused_at("2001:db8:0:1::1".parse().unwrap(), t).is_none());
        for _ in 0..10 {
            p.record_at("10.1.2.3".parse().unwrap(), Outcome::AuthFailed, t);
        }
        assert!(p.refused_at("10.1.2.3".parse().unwrap(), t).is_none(), "exempt");
        let off = Penalties::new(Settings { enabled: false, ..Settings::default() });
        for _ in 0..10 {
            off.record_at("192.0.2.9".parse().unwrap(), Outcome::AuthFailed, t);
        }
        assert!(off.refused_at("192.0.2.9".parse().unwrap(), t).is_none());
    }
}
