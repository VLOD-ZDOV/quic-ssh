//! `~/.config/qsh/known_hosts`: one `host ssh-ed25519 AAAA...` entry per line.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;

use crate::keys::{create_private_dir, PublicKey};

pub struct KnownHosts {
    path: PathBuf,
}

/// `host`, or `[host]:port` for a non-default port (same convention as OpenSSH).
pub fn host_id(host: &str, port: u16) -> String {
    if port == crate::DEFAULT_PORT {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

impl KnownHosts {
    pub fn new(path: PathBuf) -> KnownHosts {
        KnownHosts { path }
    }

    pub fn lookup(&self, id: &str) -> Result<Option<PublicKey>> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(text.lines().find_map(|line| {
            let (name, key) = line.trim().split_once(char::is_whitespace)?;
            if name == id { PublicKey::parse_openssh(key) } else { None }
        }))
    }

    /// All host ids in the file, in order.
    pub fn ids(&self) -> Vec<String> {
        std::fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().next().filter(|w| !w.starts_with(['@', '#'])).map(str::to_string))
            .collect()
    }

    /// Keys on `@cert-authority` (or `@revoked`) lines whose host patterns
    /// match one of `names` (OpenSSH syntax; hashed names are not matched).
    pub fn marked(&self, marker: &str, names: &[String]) -> Vec<ssh_key::public::KeyData> {
        let text = fs::read_to_string(&self.path).unwrap_or_default();
        text.lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                if words.next()? != marker {
                    return None;
                }
                let patterns: Vec<&str> = words.next()?.split(',').collect();
                let key = words.collect::<Vec<_>>().join(" ");
                if !names.iter().any(|n| crate::pattern::host_matches(&patterns, n)) {
                    return None;
                }
                ssh_key::PublicKey::from_openssh(&key).ok().map(|k| k.key_data().clone())
            })
            .collect()
    }

    /// Appends an entry in one write, so that entries added at the same time
    /// (`qsh multi` to new hosts) never mix; starts a new line if the file
    /// does not end with one.
    pub fn add(&self, id: &str, key: PublicKey) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            create_private_dir(dir)?;
        }
        let mut f = OpenOptions::new().read(true).append(true).create(true).open(&self.path)?;
        let mut line = format!("{id} {}\n", key.to_openssh(""));
        if !ends_with_newline(&mut f)? {
            line.insert(0, '\n');
        }
        f.write_all(line.as_bytes())?;
        Ok(())
    }
}

/// Whether the file is empty or ends with a newline.
fn ends_with_newline(f: &mut fs::File) -> Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    if f.metadata()?.len() == 0 {
        return Ok(true);
    }
    f.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    f.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Identity;

    #[test]
    fn add_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let kh = KnownHosts::new(dir.path().join("q").join("known_hosts"));
        let a = Identity::generate().public();
        let b = Identity::generate().public();
        assert_eq!(kh.lookup("example.com").unwrap(), None);
        kh.add("example.com", a).unwrap();
        kh.add(&host_id("example.com", 2222), b).unwrap();
        assert_eq!(kh.lookup("example.com").unwrap(), Some(a));
        assert_eq!(kh.lookup("[example.com]:2222").unwrap(), Some(b));
        assert_eq!(kh.lookup("example.org").unwrap(), None);
        // A hand-edited file without a final newline: the next entry still gets its own line.
        let path = dir.path().join("q").join("known_hosts");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.trim_end()).unwrap();
        let c = Identity::generate().public();
        kh.add("example.net", c).unwrap();
        assert_eq!(kh.lookup("[example.com]:2222").unwrap(), Some(b));
        assert_eq!(kh.lookup("example.net").unwrap(), Some(c));
    }

    #[test]
    fn markers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let ca = Identity::generate().public();
        let bad = Identity::generate().public();
        std::fs::write(
            &path,
            format!("@cert-authority *.example.com,!old.example.com {}\n@revoked * {}\n", ca.to_openssh("ca"), bad.to_openssh("")),
        )
        .unwrap();
        let kh = KnownHosts::new(path);
        let names = |n: &str| vec![n.to_string()];
        assert_eq!(kh.marked("@cert-authority", &names("web.example.com")).len(), 1);
        assert!(kh.marked("@cert-authority", &names("old.example.com")).is_empty());
        assert!(kh.marked("@cert-authority", &names("example.org")).is_empty());
        assert_eq!(kh.marked("@revoked", &names("anything")).len(), 1);
        assert_eq!(kh.lookup("web.example.com").unwrap(), None, "marker lines are not host keys");
    }
}
