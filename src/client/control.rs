//! Settings for connection sharing (`ControlMaster`, `ControlPath`,
//! `ControlPersist`, `-M`, `-S`, `-O`); the sharing itself is in
//! [`crate::transport::shared`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// `ControlMaster`: whether this qsh offers its connection to later runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ControlMaster {
    /// Use a master if there is one, never become one (the default).
    #[default]
    No,
    /// Become the master (`-M`, `yes`, `ask`).
    Yes,
    /// Use a master if there is one, otherwise become it (`auto`, `autoask`).
    Auto,
}

/// `ControlPersist`: how long a master stays after its last session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Persist {
    /// The master is the qsh the user started, and ends with it.
    #[default]
    No,
    /// A master in the background, until `-O exit` or the connection ends.
    Forever,
    /// A master in the background, ending this long after its last session.
    For(Duration),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sharing {
    pub master: ControlMaster,
    /// The master's socket; `None` when sharing is off.
    pub path: Option<PathBuf>,
    pub persist: Persist,
}

impl Sharing {
    /// Whether this run should become a master in the background first.
    pub fn background_master(&self) -> bool {
        cfg!(unix) && self.master != ControlMaster::No && self.persist != Persist::No && self.path.is_some()
    }
}

pub fn parse_master(v: &str) -> ControlMaster {
    match v.to_ascii_lowercase().as_str() {
        "yes" | "ask" | "true" => ControlMaster::Yes,
        "auto" | "autoask" => ControlMaster::Auto,
        _ => ControlMaster::No,
    }
}

/// `yes`/`0` (forever), `no`, or a time: `600`, `10m`, `1h30m` (ssh's units s m h d w).
pub fn parse_persist(v: &str) -> Persist {
    match v.to_ascii_lowercase().as_str() {
        "yes" | "true" | "0" => Persist::Forever,
        "no" | "false" => Persist::No,
        t => parse_time(t).map(Persist::For).unwrap_or(Persist::No),
    }
}

fn parse_time(t: &str) -> Option<Duration> {
    let mut total = 0u64;
    let mut num = String::new();
    for c in t.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            'w' => 7 * 86400,
            _ => return None,
        };
        total = total.checked_add(num.parse::<u64>().ok()?.checked_mul(unit)?)?;
        num.clear();
    }
    if !num.is_empty() {
        total = total.checked_add(num.parse().ok()?)?;
    }
    (total > 0).then(|| Duration::from_secs(total))
}

/// `%C`: a short hash of the connection, so socket names stay short and
/// carry no host names.
pub fn connection_hash(host: &str, port: u16, user: &str) -> String {
    let digest = Sha256::digest(format!("{host}\0{port}\0{user}").as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// The default socket directory, `~/.config/qsh/ctl`.
pub fn default_dir(home: &Path) -> PathBuf {
    crate::keys::qsh_dir(home).join("ctl")
}

/// Works out the sharing settings for one destination from `ControlMaster`,
/// `ControlPath` and `ControlPersist`. `ControlPath` is only read from qsh's
/// own config and `-o`/`-S`: one from ssh's config names ssh's sockets,
/// which speak another protocol.
pub fn sharing([master, path, persist]: [Option<&str>; 3], home: &Path, host: &str, port: u16, user: &str, local_user: &str) -> Sharing {
    let master = master.map(parse_master).unwrap_or_default();
    let persist = persist.map(parse_persist).unwrap_or_default();
    let pattern = match path {
        Some(p) if p.eq_ignore_ascii_case("none") => None,
        Some(p) => Some(p.to_string()),
        // Like ssh, sharing needs a ControlPath; qsh has a default for masters.
        None if master != ControlMaster::No => Some(format!("{}/%C", default_dir(home).display())),
        None => None,
    };
    let path = pattern.map(|p| {
        // %C and %p here; the rest (%d %h %r %u, ~) as for other paths.
        let mut s = String::new();
        let mut chars = p.chars();
        while let Some(c) = chars.next() {
            match (c, c == '%') {
                (_, true) => match chars.next() {
                    Some('C') => s.push_str(&connection_hash(host, port, user)),
                    Some('p') => s.push_str(&port.to_string()),
                    Some(o) => {
                        s.push('%');
                        s.push(o);
                    }
                    None => s.push('%'),
                },
                (c, false) => s.push(c),
            }
        }
        super::config::expand_path(&s, home, host, user, local_user)
    });
    Sharing { master, path, persist }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings() {
        assert_eq!(parse_persist("10m"), Persist::For(Duration::from_secs(600)));
        assert_eq!(parse_persist("1h30m"), Persist::For(Duration::from_secs(5400)));
        assert_eq!(parse_persist("90"), Persist::For(Duration::from_secs(90)));
        assert_eq!(parse_persist("yes"), Persist::Forever);
        assert_eq!(parse_persist("0"), Persist::Forever);
        assert_eq!(parse_persist("no"), Persist::No);
        assert_eq!(parse_persist("5x"), Persist::No);
        assert_eq!(parse_master("autoask"), ControlMaster::Auto);
        assert_eq!(parse_master("ASK"), ControlMaster::Yes);

        let home = Path::new("/h");
        let off = sharing([None, None, None], home, "example.com", 4422, "bob", "me");
        assert_eq!(off.path, None, "off by default");
        let auto = sharing([Some("auto"), None, None], home, "example.com", 4422, "bob", "me");
        let p = auto.path.unwrap();
        assert!(p.starts_with("/h/.config/qsh/ctl"));
        assert_eq!(p.file_name().unwrap().len(), 16);
        let other = sharing([Some("auto"), None, None], home, "example.com", 4422, "alice", "me");
        assert_ne!(other.path.unwrap(), p, "one master per user@host:port");
        let custom = sharing([None, Some("~/s/%r@%h:%p%%p"), None], home, "example.com", 22, "bob", "me");
        assert_eq!(custom.path.unwrap(), Path::new("/h/s/bob@example.com:22%p"));
        assert_eq!(sharing([Some("yes"), Some("none"), None], home, "h", 1, "u", "me").path, None);
    }
}
