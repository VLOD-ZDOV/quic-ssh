//! `~/.config/qsh/known_hosts`: one `host ssh-ed25519 AAAA...` entry per line.
//! Host names may be patterns (`*.example.com`, `!old.example.com`) or
//! hashed (`|1|salt|hash`, as with OpenSSH's HashKnownHosts).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine;

use crate::keys::{create_private_dir, PublicKey};

pub struct KnownHosts {
    /// The file new keys are added to (none: `UserKnownHostsFile none`).
    path: Option<PathBuf>,
    /// More files that are only read (more `UserKnownHostsFile`s,
    /// `GlobalKnownHostsFile`).
    read_also: Vec<PathBuf>,
    /// Output of `KnownHostsCommand`, read like a file.
    extra: Option<Arc<String>>,
    /// Add names hashed (`HashKnownHosts`).
    hash: bool,
}

/// `|1|salt|hash`: HMAC-SHA1 of the name keyed with the salt (base64).
fn hashed_matches(hashed: &str, name: &str) -> bool {
    use hmac::{Hmac, Mac};
    let b64 = base64::engine::general_purpose::STANDARD;
    let Some((salt, hash)) = hashed.split_once('|') else { return false };
    let (Ok(salt), Ok(hash)) = (b64.decode(salt), b64.decode(hash)) else { return false };
    let Ok(mut mac) = Hmac::<sha1::Sha1>::new_from_slice(&salt) else { return false };
    mac.update(name.as_bytes());
    mac.verify_slice(&hash).is_ok()
}

/// `name` hashed with a new salt, as OpenSSH writes it.
fn hash_name(name: &str) -> String {
    use hmac::{Hmac, Mac};
    let b64 = base64::engine::general_purpose::STANDARD;
    let salt: [u8; 20] = rand::random();
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&salt).expect("any key length");
    mac.update(name.as_bytes());
    format!("|1|{}|{}", b64.encode(salt), b64.encode(mac.finalize().into_bytes()))
}

/// Whether a line's host field (comma-separated names, patterns or hashes) names `id`.
fn names_match(field: &str, id: &str) -> bool {
    let mut plain = Vec::new();
    for n in field.split(',') {
        match n.strip_prefix("|1|") {
            Some(h) if hashed_matches(h, id) => return true,
            Some(_) => {}
            None => plain.push(n),
        }
    }
    crate::pattern::host_matches(&plain, id)
}

/// `host`, or `[host]:port` for a non-default port (same convention as
/// OpenSSH), in lower case like ssh's names (hashed names must match exactly).
pub fn host_id(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == crate::DEFAULT_PORT {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

impl KnownHosts {
    pub fn new(path: PathBuf) -> KnownHosts {
        KnownHosts { path: Some(path), read_also: Vec::new(), extra: None, hash: false }
    }

    /// Also reads `files` and `extra` (never written), and hashes names it adds.
    /// `path`: the user's file (`None`: `UserKnownHostsFile none`).
    pub fn with(path: Option<PathBuf>, files: Vec<PathBuf>, extra: Option<Arc<String>>, hash: bool) -> KnownHosts {
        KnownHosts { path, read_also: files, extra, hash }
    }

    /// The text of all sources (missing files are empty). Bytes that are not
    /// UTF-8 spoil only their own line, as with OpenSSH.
    fn text(&self) -> Result<String> {
        let mut text = String::new();
        let own = self.path.iter().map(|p| (p, true));
        for (path, is_own) in own.chain(self.read_also.iter().map(|p| (p, false))) {
            match fs::read(path) {
                Ok(b) => text.push_str(&String::from_utf8_lossy(&b)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                // Only the user's own file must be readable; others (the
                // system's, which may be closed to users) are skipped as by ssh.
                Err(e) if !is_own => tracing::debug!("skipping {}: {e}", path.display()),
                Err(e) => return Err(anyhow::Error::from(e).context(format!("cannot read {}", path.display()))),
            }
            text.push('\n');
        }
        if let Some(extra) = &self.extra {
            text.push_str(extra);
        }
        Ok(text)
    }

    /// Every key listed for `id` (lines naming it alone, in a list as
    /// OpenSSH writes `host,address`, by a pattern or hashed).
    pub fn keys(&self, id: &str) -> Result<Vec<PublicKey>> {
        Ok(self
            .text()?
            .lines()
            .filter_map(|line| {
                let (names, key) = line.trim().split_once(char::is_whitespace)?;
                if names.starts_with(['@', '#']) || !names_match(names, id) {
                    return None;
                }
                PublicKey::parse_openssh(key.trim())
            })
            .collect())
    }

    /// The first key for `id`.
    pub fn lookup(&self, id: &str) -> Result<Option<PublicKey>> {
        Ok(self.keys(id)?.into_iter().next())
    }

    /// All host ids in the file, in order.
    pub fn ids(&self) -> Vec<String> {
        self.text()
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().next().filter(|w| !w.starts_with(['@', '#'])))
            .flat_map(|names| names.split(',').map(str::to_string).collect::<Vec<_>>())
            // Hashed names and patterns are no destinations.
            .filter(|n| !n.starts_with('|') && !n.contains(['*', '?', '!']))
            .collect()
    }

    /// Keys on `@cert-authority` (or `@revoked`) lines whose host patterns
    /// match one of `names` (OpenSSH syntax).
    /// A file that exists but cannot be read is an error: its `@revoked`
    /// lines must not be skipped silently.
    pub fn marked(&self, marker: &str, names: &[String]) -> Result<Vec<ssh_key::public::KeyData>> {
        Ok(self
            .text()?
            .lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                if words.next()? != marker {
                    return None;
                }
                let field = words.next()?;
                let key = words.collect::<Vec<_>>().join(" ");
                if !names.iter().any(|n| names_match(field, n)) {
                    return None;
                }
                ssh_key::PublicKey::from_openssh(&key).ok().map(|k| k.key_data().clone())
            })
            .collect())
    }

    /// Appends an entry in one write, so that entries added at the same time
    /// (`qsh multi` to new hosts) never mix; starts a new line if the file
    /// does not end with one.
    pub fn add(&self, id: &str, key: PublicKey) -> Result<()> {
        let Some(path) = &self.path else { anyhow::bail!("UserKnownHostsFile is none: the key is not saved") };
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        let mut f = OpenOptions::new().read(true).append(true).create(true).open(path)?;
        let name = if self.hash { hash_name(id) } else { id.to_string() };
        let mut line = format!("{name} {}\n", key.to_openssh(""));
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
        // OpenSSH-style lists of names, and a line that is not UTF-8 elsewhere.
        let d = Identity::generate().public();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b"# caf\xe9\n");
        bytes.extend_from_slice(format!("alias.example,192.0.2.9 {}\n", d.to_openssh("")).as_bytes());
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(kh.lookup("192.0.2.9").unwrap(), Some(d));
        assert_eq!(kh.lookup("alias.example").unwrap(), Some(d));
        assert_eq!(kh.lookup("example.com").unwrap(), Some(a));
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
        assert_eq!(kh.marked("@cert-authority", &names("web.example.com")).unwrap().len(), 1);
        assert!(kh.marked("@cert-authority", &names("old.example.com")).unwrap().is_empty());
        assert!(kh.marked("@cert-authority", &names("example.org")).unwrap().is_empty());
        assert_eq!(kh.marked("@revoked", &names("anything")).unwrap().len(), 1);
        assert_eq!(kh.lookup("web.example.com").unwrap(), None, "marker lines are not host keys");
    }

    #[test]
    fn hashed_patterns_and_more_files() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, c) = (Identity::generate().public(), Identity::generate().public(), Identity::generate().public());
        let global = dir.path().join("global");
        std::fs::write(&global, format!("*.example.com,!bad.example.com {}\n", b.to_openssh(""))).unwrap();
        let kh = KnownHosts::with(Some(dir.path().join("own")), vec![global], Some(Arc::new(format!("from-command {}\n", c.to_openssh("")))), true);
        kh.add("[host.example]:2222", a).unwrap();
        let text = std::fs::read_to_string(dir.path().join("own")).unwrap();
        assert!(text.starts_with("|1|") && !text.contains("host.example"), "{text}");
        assert_eq!(kh.lookup("[host.example]:2222").unwrap(), Some(a));
        assert_eq!(kh.lookup("host.example").unwrap(), None);
        assert_eq!(kh.lookup("web.example.com").unwrap(), Some(b));
        assert_eq!(kh.lookup("bad.example.com").unwrap(), None);
        assert_eq!(kh.lookup("from-command").unwrap(), Some(c));
        assert_eq!(kh.ids(), vec!["from-command"], "hashed names and patterns are not listed");
        // Written by `ssh-keygen -H` for "example.com".
        assert!(hashed_matches("jLzX8/hLVkOJ2dIUr06/FZ3KJrM=|PBvM/gMzzlJiXMqdTsQaWGCbOmU=", "example.com"));
        assert!(!hashed_matches("jLzX8/hLVkOJ2dIUr06/FZ3KJrM=|PBvM/gMzzlJiXMqdTsQaWGCbOmU=", "example.org"));
        let h = hash_name("example.com");
        assert!(names_match(&h, "example.com") && !names_match(&h, "example.org"));
    }
}
