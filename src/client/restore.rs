//! `RestoreSession`: lets a terminal session outlive qsh itself. Its token
//! goes into a private file, and qsh holds a lock on that file for as long as
//! it runs: an unlocked file belongs to a session nobody is attached to, while
//! a locked one is another window's and is left alone. The lock also ends with
//! a killed process, which is the case this is for.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// A session's file, locked by this qsh.
pub struct Claim {
    file: File,
    path: PathBuf,
}

fn dir(home: &Path) -> PathBuf {
    crate::keys::qsh_dir(home).join("sessions")
}

fn private(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
}

impl Claim {
    /// A new, empty claim for a session to `key` (see `connection_hash`).
    pub fn new(home: &Path, key: &str) -> Result<Claim> {
        let dir = dir(home);
        crate::keys::create_private_dir(&dir)?;
        let path = dir.join(format!("{key}.{:016x}", rand::random::<u64>()));
        let file = private(OpenOptions::new().read(true).write(true).create_new(true)).open(&path).with_context(|| format!("cannot create {}", path.display()))?;
        file.try_lock().with_context(|| format!("cannot lock {}", path.display()))?;
        Ok(Claim { file, path })
    }

    pub fn save(&self, token: &[u8]) -> Result<()> {
        let mut file = &self.file;
        file.rewind()?;
        file.set_len(0)?;
        file.write_all(token)?;
        Ok(())
    }

    /// The session is over.
    pub fn forget(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Sessions to `key` that no running qsh holds, newest first, each with its token.
pub fn left_behind(home: &Path, key: &str) -> Vec<(Claim, Vec<u8>)> {
    let Ok(entries) = std::fs::read_dir(dir(home)) else { return Vec::new() };
    let mut found = Vec::new();
    for path in entries.flatten().map(|e| e.path()) {
        if !path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.strip_prefix(key).is_some_and(|rest| rest.starts_with('.'))) {
            continue;
        }
        let Ok(file) = private(OpenOptions::new().read(true).write(true)).open(&path) else { continue };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => continue,
            Err(TryLockError::Error(e)) => {
                tracing::debug!("cannot lock {}: {e}", path.display());
                continue;
            }
        }
        let mut token = Vec::new();
        let when = file.metadata().and_then(|m| m.modified()).ok();
        let claim = Claim { path, file };
        if (&claim.file).read_to_end(&mut token).is_err() || token.is_empty() {
            claim.forget();
            continue;
        }
        found.push((when, claim, token));
    }
    found.sort_by_key(|(when, ..)| std::cmp::Reverse(*when));
    found.into_iter().map(|(_, claim, token)| (claim, token)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_session_is_left_alone() {
        let home = tempfile::tempdir().unwrap();
        let claim = Claim::new(home.path(), "abc").unwrap();
        claim.save(b"token").unwrap();
        assert!(left_behind(home.path(), "abc").is_empty());
        drop(claim);
        assert!(left_behind(home.path(), "other").is_empty());
        let found = left_behind(home.path(), "abc");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, b"token");
    }

    #[test]
    fn a_forgotten_session_is_gone() {
        let home = tempfile::tempdir().unwrap();
        let claim = Claim::new(home.path(), "abc").unwrap();
        claim.save(b"token").unwrap();
        claim.forget();
        assert!(left_behind(home.path(), "abc").is_empty());
    }
}
