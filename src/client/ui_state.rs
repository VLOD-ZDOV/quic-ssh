//! What `qsh ui` remembers between runs (`~/.config/qsh/ui-state.toml`):
//! the last check of each host, the connection history, and per-host
//! connection preferences.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A host's last check is reused for this long before it is checked again.
pub const PROBE_TTL: u64 = 10 * 60;
/// Connections kept in the history.
const HISTORY_LEN: usize = 50;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CachedProbe {
    /// `host:port` that was checked; a different one makes the entry stale.
    pub endpoint: String,
    /// `quic`, `tcp` or `ssh` (no qshd).
    pub kind: String,
    pub port: u16,
    pub handshake_ms: u64,
    /// `known`, `unknown` or `changed`.
    pub key: Option<String>,
    /// Unix time of the check.
    pub at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HistoryEntry {
    /// What was connected to: an alias or `user@host[:port]`.
    pub dest: String,
    pub at: u64,
    pub ok: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Prefs {
    /// `auto`, `quic` or `tcp`.
    pub transport: String,
    /// Use plain ssh when the host has no qshd (`--full`).
    pub ssh_fallback: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { transport: "auto".into(), ssh_fallback: true }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct UiState {
    #[serde(default)]
    pub probes: BTreeMap<String, CachedProbe>,
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
    #[serde(default)]
    pub prefs: BTreeMap<String, Prefs>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn path(home: &Path) -> PathBuf {
    crate::keys::qsh_dir(home).join("ui-state.toml")
}

impl UiState {
    /// Loads the state; a missing or damaged file starts empty.
    pub fn load(home: &Path) -> UiState {
        std::fs::read_to_string(path(home)).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, home: &Path) -> anyhow::Result<()> {
        let file = path(home);
        crate::keys::create_private_dir(file.parent().expect("has a parent"))?;
        crate::platform::replace_file(&file, toml::to_string(self)?.as_bytes())?;
        Ok(())
    }

    /// The cached check for `alias`, if it is for `endpoint` and recent enough.
    pub fn fresh_probe(&self, alias: &str, endpoint: &str, now: u64) -> Option<&CachedProbe> {
        self.probes.get(alias).filter(|p| p.endpoint == endpoint && now.saturating_sub(p.at) < PROBE_TTL)
    }

    /// Records a connection attempt (newest first, one entry per destination).
    pub fn record(&mut self, dest: &str, ok: bool, at: u64) {
        self.history.retain(|h| h.dest != dest);
        self.history.insert(0, HistoryEntry { dest: dest.to_string(), at, ok });
        self.history.truncate(HISTORY_LEN);
    }

    /// When `dest` was last connected to.
    pub fn last_used(&self, dest: &str) -> Option<u64> {
        self.history.iter().find(|h| h.dest == dest).map(|h| h.at)
    }

    pub fn prefs(&self, alias: &str) -> Prefs {
        self.prefs.get(alias).cloned().unwrap_or_default()
    }
}

/// "5 min ago", "3 h ago"...
pub fn ago(at: u64, now: u64) -> String {
    let s = now.saturating_sub(at);
    match s {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", s / 60),
        3600..86400 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_and_cache() {
        let home = tempfile::tempdir().unwrap();
        let mut s = UiState::default();
        s.record("a", true, 100);
        s.record("b", false, 200);
        s.record("a", true, 300);
        assert_eq!(s.history.iter().map(|h| h.dest.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(s.last_used("a"), Some(300));
        s.probes.insert("a".into(), CachedProbe { endpoint: "h:1".into(), kind: "quic".into(), port: 1, handshake_ms: 5, key: None, at: 1000 });
        assert!(s.fresh_probe("a", "h:1", 1000 + PROBE_TTL - 1).is_some());
        assert!(s.fresh_probe("a", "h:1", 1000 + PROBE_TTL).is_none(), "too old");
        assert!(s.fresh_probe("a", "h:2", 1001).is_none(), "another endpoint");
        s.prefs.insert("a".into(), Prefs { transport: "tcp".into(), ssh_fallback: false });
        s.save(home.path()).unwrap();
        assert_eq!(UiState::load(home.path()), s);
        std::fs::write(path(home.path()), "garbage = [").unwrap();
        assert_eq!(UiState::load(home.path()), UiState::default());
        assert_eq!(ago(0, 7200), "2 h ago");
    }
}
