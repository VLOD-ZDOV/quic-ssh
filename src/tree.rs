//! Directory trees as tar streams for `qsh cp -r`, with defensive extraction.
//!
//! Extraction is where scp had its worst bugs (a malicious peer choosing
//! paths, CVE-2019-6111 and relatives), so the receiver accepts only regular
//! files and directories, only relative paths without `..`, never writes
//! through an existing symlink, and drops setuid/setgid/sticky bits.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

/// What a transfer moved and what it left out.
#[derive(Debug, Default, PartialEq)]
pub struct Stats {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Symlinks, devices, sockets and the like (not transferred).
    pub skipped: u64,
}

/// Writes the contents of `root` (not `root` itself) as a tar stream.
/// Symlinks and special files are skipped and counted.
pub fn write_tree(root: &Path, out: impl Write) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut tar = tar::Builder::new(out);
    tar.mode(tar::HeaderMode::Deterministic);
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let dir = root.join(&rel);
        let mut entries: Vec<_> = fs::read_dir(&dir)
            .with_context(|| format!("{}", dir.display()))?
            .collect::<io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = rel.join(entry.file_name());
            let meta = entry.path().symlink_metadata()?;
            let mut header = tar::Header::new_gnu();
            header.set_mode(meta.mode() & 0o777);
            header.set_mtime(meta.mtime().max(0) as u64);
            if meta.is_dir() {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                tar.append_data(&mut header, &path, io::empty())?;
                stats.dirs += 1;
                stack.push(path);
            } else if meta.is_file() {
                let file = fs::File::open(entry.path()).with_context(|| format!("{}", entry.path().display()))?;
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(meta.len());
                // A file that shrinks while being read must not desync the stream.
                let mut data = file.take(meta.len()).chain(io::repeat(0).take(meta.len()));
                tar.append_data(&mut header, &path, (&mut data).take(meta.len()))?;
                stats.files += 1;
                stats.bytes += meta.len();
            } else {
                stats.skipped += 1;
            }
        }
    }
    tar.into_inner()?.flush()?;
    Ok(stats)
}

/// Joins a tar entry path to `dest`, refusing anything but plain relative names.
fn safe_join(dest: &Path, entry: &Path) -> Result<PathBuf> {
    let mut out = dest.to_path_buf();
    let mut depth = 0;
    for c in entry.components() {
        match c {
            Component::Normal(name) => {
                out.push(name);
                depth += 1;
            }
            Component::CurDir => {}
            _ => bail!("refusing unsafe path {:?} in the archive", entry),
        }
    }
    if depth == 0 {
        bail!("refusing empty path in the archive");
    }
    Ok(out)
}

/// Fails if any existing component of `path` below `dest` is a symlink.
fn no_symlinks_below(dest: &Path, path: &Path) -> Result<()> {
    let rel = path.strip_prefix(dest).expect("path is inside dest");
    let mut cur = dest.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        match cur.symlink_metadata() {
            Ok(m) if m.file_type().is_symlink() => bail!("refusing to write through symlink {}", cur.display()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Extracts a tar stream into the existing directory `dest`.
pub fn extract_tree(input: impl Read, dest: &Path) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut archive = tar::Archive::new(input);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let rel = entry.path()?.into_owned();
        let target = safe_join(dest, &rel)?;
        no_symlinks_below(dest, &target)?;
        let mode = entry.header().mode().unwrap_or(0o644) & 0o777;
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                match fs::create_dir(&target) {
                    Ok(()) => fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(mode | 0o700))?,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists && target.is_dir() => {}
                    Err(e) => return Err(e).with_context(|| format!("{}", target.display())),
                }
                stats.dirs += 1;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(mode)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&target)
                    .with_context(|| format!("{}", target.display()))?;
                stats.bytes += io::copy(&mut entry, &mut f)?;
                stats.files += 1;
            }
            _ => stats.skipped += 1,
        }
    }
    Ok(stats)
}

/// Where a file or tree named `name` lands: inside `dest` if that is an
/// existing directory, otherwise at `dest` itself (like `cp -r` and `scp -r`).
/// Only the last component of `name` counts, and `.`/`..` are refused.
pub fn tree_target(dest: &Path, name: &str) -> Result<PathBuf> {
    let name = Path::new(name).file_name().context("invalid name")?;
    if name == ".." || name == "." {
        bail!("invalid name");
    }
    Ok(if dest.is_dir() { dest.join(name) } else { dest.to_path_buf() })
}

/// Reads the chunked framing of a tree download: chunks of a big-endian u32
/// length and that many bytes, ended by a zero length. A final status follows
/// it on the stream, after [`Unchunk::finish`].
pub struct Unchunk<R> {
    inner: R,
    left: usize,
    done: bool,
}

impl<R: Read> Unchunk<R> {
    pub fn new(inner: R) -> Unchunk<R> {
        Unchunk { inner, left: 0, done: false }
    }

    /// Skips whatever the reader did not consume (e.g. tar padding) up to the
    /// end marker and returns the underlying stream.
    pub fn finish(mut self) -> io::Result<R> {
        io::copy(&mut self, &mut io::sink())?;
        Ok(self.inner)
    }
}

impl<R: Read> Read for Unchunk<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut len = [0u8; 4];
            self.inner.read_exact(&mut len)?;
            self.left = u32::from_be_bytes(len) as usize;
            if self.left == 0 {
                self.done = true;
                return Ok(0);
            }
        }
        let want = buf.len().min(self.left);
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.left -= n;
        Ok(n)
    }
}

/// Creates the target directory of a tree transfer (it may already exist).
pub fn create_target(target: &Path) -> Result<()> {
    match fs::create_dir(target) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && target.symlink_metadata()?.is_dir() => Ok(()),
        Err(e) => Err(e).with_context(|| format!("{}", target.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sample(root: &Path) {
        fs::create_dir_all(root.join("sub/deeper")).unwrap();
        fs::write(root.join("a.txt"), "alpha").unwrap();
        fs::write(root.join("sub/b.bin"), vec![7u8; 100_000]).unwrap();
        fs::write(root.join("sub/deeper/c"), "").unwrap();
        fs::set_permissions(root.join("a.txt"), fs::Permissions::from_mode(0o4755)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("link")).unwrap();
    }

    #[test]
    fn roundtrip_skips_symlinks_and_setuid() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        sample(src.path());
        let mut buf = Vec::new();
        let sent = write_tree(src.path(), &mut buf).unwrap();
        assert_eq!(sent, Stats { files: 3, dirs: 2, bytes: 100_005, skipped: 1 });
        let got = extract_tree(&buf[..], dst.path()).unwrap();
        assert_eq!((got.files, got.dirs, got.bytes), (3, 2, 100_005));
        assert_eq!(fs::read(dst.path().join("sub/b.bin")).unwrap().len(), 100_000);
        assert!(!dst.path().join("link").exists());
        let mode = fs::metadata(dst.path().join("a.txt")).unwrap().mode();
        assert_eq!(mode & 0o7000, 0, "setuid bit survived");
    }

    /// Builds a tar with one raw entry, bypassing the builder's own path checks.
    fn evil_tar(path: &str, kind: tar::EntryType, link: Option<&str>) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(if kind == tar::EntryType::Regular { 5 } else { 0 });
        header.set_mode(0o644);
        {
            let gnu = header.as_gnu_mut().unwrap();
            gnu.name[..path.len()].copy_from_slice(path.as_bytes());
        }
        if let Some(l) = link {
            header.set_link_name(l).unwrap();
        }
        header.set_cksum();
        let mut out = header.as_bytes().to_vec();
        if kind == tar::EntryType::Regular {
            let mut block = b"pwned".to_vec();
            block.resize(512, 0);
            out.extend(block);
        }
        out.extend([0u8; 1024]);
        out
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        let dst = tempfile::tempdir().unwrap();
        for p in ["../escape", "a/../../escape", "/tmp/qsh-abs-test"] {
            let r = extract_tree(&evil_tar(p, tar::EntryType::Regular, None)[..], dst.path());
            assert!(r.is_err(), "{p} was accepted");
        }
        assert!(!dst.path().parent().unwrap().join("escape").exists());
    }

    #[test]
    fn never_writes_through_symlinks() {
        let dst = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        // A symlink entry is skipped, not created.
        let s = extract_tree(&evil_tar("ln", tar::EntryType::Symlink, Some(outside.path().to_str().unwrap()))[..], dst.path()).unwrap();
        assert_eq!(s.skipped, 1);
        assert!(!dst.path().join("ln").exists());
        // A pre-existing symlink in the destination is not followed.
        std::os::unix::fs::symlink(outside.path(), dst.path().join("ln")).unwrap();
        assert!(extract_tree(&evil_tar("ln/x", tar::EntryType::Regular, None)[..], dst.path()).is_err());
        assert!(extract_tree(&evil_tar("ln", tar::EntryType::Regular, None)[..], dst.path()).is_err());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn target_naming() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(tree_target(d.path(), "proj").unwrap(), d.path().join("proj"));
        assert_eq!(tree_target(&d.path().join("new"), "proj").unwrap(), d.path().join("new"));
        assert!(tree_target(d.path(), "..").is_err());
    }
}
