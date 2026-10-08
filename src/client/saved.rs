//! Connections saved from `qsh ui`, kept in `~/.config/qsh/ui-hosts` in
//! ssh_config syntax, so `qsh NAME` works from the command line too.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::config::UI_HOSTS;

/// One saved connection (a `Host` block).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Saved {
    pub name: String,
    pub host: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity: Option<String>,
}

pub fn path(home: &Path) -> PathBuf {
    crate::keys::qsh_dir(home).join(UI_HOSTS)
}

fn plain(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"')
}

impl Saved {
    /// Checks the fields before they go into a config file.
    pub fn validate(&self) -> Result<()> {
        if !plain(&self.name) || self.name.starts_with('-') || self.name.contains(['*', '?', '!', ',', '@', ':']) {
            bail!("name: one word, no spaces or * ? ! , @ :");
        }
        if !plain(&self.host) || self.host.starts_with('-') {
            bail!("host: a host name or address, no spaces");
        }
        if let Some(u) = &self.user {
            if !crate::proto::valid_user_name(u) {
                bail!("user: letters, digits, . _ - only");
            }
        }
        if let Some(i) = &self.identity {
            if i.chars().any(|c| c.is_control() || c == '"') {
                bail!("key file: no quotes or control characters");
            }
        }
        Ok(())
    }

    fn block(&self) -> String {
        let mut out = format!("Host {}\n    HostName {}\n", self.name, self.host);
        if let Some(u) = &self.user {
            out += &format!("    User {u}\n");
        }
        if let Some(p) = self.port {
            out += &format!("    Port {p}\n");
        }
        if let Some(i) = &self.identity {
            let quoted = if i.contains(char::is_whitespace) { format!("\"{i}\"") } else { i.clone() };
            out += &format!("    IdentityFile {quoted}\n");
        }
        out
    }
}

/// Parses the file written by [`save`] (simple `Host` blocks only).
pub fn parse(text: &str) -> Vec<Saved> {
    let mut out: Vec<Saved> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k.to_ascii_lowercase(), v.trim().trim_matches('"').to_string()),
            None => continue,
        };
        match key.as_str() {
            "host" => out.push(Saved { name: value, ..Default::default() }),
            _ => {
                let Some(s) = out.last_mut() else { continue };
                match key.as_str() {
                    "hostname" => s.host = value,
                    "user" => s.user = Some(value),
                    "port" => s.port = value.parse().ok(),
                    "identityfile" => s.identity = Some(value),
                    _ => {}
                }
            }
        }
    }
    out
}

pub fn load(home: &Path) -> Vec<Saved> {
    std::fs::read_to_string(path(home)).map(|t| parse(&t)).unwrap_or_default()
}

/// Writes all saved connections (replacing the file atomically).
pub fn save(home: &Path, all: &[Saved]) -> Result<()> {
    for s in all {
        s.validate().with_context(|| format!("connection {:?}", s.name))?;
    }
    let file = path(home);
    let dir = file.parent().context("bad path")?;
    crate::keys::create_private_dir(dir)?;
    let mut text = String::from("# Connections saved in `qsh ui` (n new, e edit, d delete), in ssh_config syntax.\n# Read after ~/.config/qsh/config and ~/.ssh/config; names here are not used there.\n");
    for s in all {
        text.push('\n');
        text += &s.block();
    }
    crate::platform::replace_file(&file, text.as_bytes()).with_context(|| format!("cannot write {}", file.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_lookup() {
        let home = tempfile::tempdir().unwrap();
        let a = Saved { name: "box".into(), host: "192.0.2.5".into(), user: Some("admin".into()), port: Some(2222), identity: Some("~/.ssh/my key".into()) };
        let b = Saved { name: "web".into(), host: "web.example.com".into(), ..Default::default() };
        save(home.path(), &[a.clone(), b.clone()]).unwrap();
        assert_eq!(load(home.path()), vec![a, b]);
        // qsh itself reads the file: `qsh box` resolves through it.
        let t = super::super::Target::parse_with("box", None, Some(home.path()), false).unwrap();
        assert_eq!((t.host.as_str(), t.user.as_str(), t.port), ("192.0.2.5", "admin", 2222));
        assert!(super::super::config::host_aliases(home.path()).contains(&"web".to_string()));
    }

    #[test]
    fn bad_fields_are_refused() {
        let ok = Saved { name: "box".into(), host: "example.com".into(), ..Default::default() };
        assert!(ok.validate().is_ok());
        for bad in [
            Saved { name: "two words".into(), ..ok.clone() },
            Saved { name: "*".into(), ..ok.clone() },
            Saved { host: "-oProxyCommand=x".into(), ..ok.clone() },
            Saved { host: "a\nHost *".into(), ..ok.clone() },
            Saved { user: Some("ro ot".into()), ..ok.clone() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }
}
