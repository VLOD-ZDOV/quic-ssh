//! Directory trees as tar streams for `qsh cp -r`, with defensive extraction.
//!
//! Extraction is where scp had its worst bugs (a malicious peer choosing
//! paths, CVE-2019-6111 and relatives), so the receiver accepts only regular
//! files and directories, only relative paths without `..`, never writes
//! through an existing symlink, and drops setuid/setgid/sticky bits.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
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
            header.set_mode(crate::platform::mode(&meta) & 0o777);
            let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
            header.set_mtime(mtime.map(|d| d.as_secs()).unwrap_or(0));
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
            // On Windows a later `C:x` would replace the whole path, and
            // `name:stream` writes to an alternate data stream.
            Component::Normal(name) if cfg!(windows) && name.to_string_lossy().contains(':') => {
                bail!("refusing unsafe path {:?} in the archive", entry)
            }
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

/// Largest long name (GNU `L`/`K`) or PAX header accepted. The tar crate
/// reads these whole into memory, at whatever size the sender declares.
const MAX_META: u64 = 64 * 1024;

/// Watches the tar stream on its way to the tar crate and refuses oversized
/// metadata entries before they are read. It follows the archive layout
/// itself: 512-byte headers, then data padded to 512 bytes, its size from
/// the header or from a preceding PAX `size=` record. Sparse and
/// multi-volume entries, whose extra blocks it does not follow, are refused
/// (qsh never sends them).
struct MetaLimit<R> {
    inner: R,
    header: Vec<u8>,
    /// Data bytes still to pass before the padding.
    data: u64,
    /// Padding bytes after the data.
    pad: u64,
    /// The data of a PAX header being passed, kept to find `size=`.
    pax: Option<Vec<u8>>,
    /// Size from a PAX header, for the entry after it.
    next_size: Option<u64>,
}

impl<R> MetaLimit<R> {
    fn new(inner: R) -> MetaLimit<R> {
        MetaLimit { inner, header: Vec::with_capacity(512), data: 0, pad: 0, pax: None, next_size: None }
    }

    fn header_done(&mut self) -> io::Result<()> {
        let h = std::mem::take(&mut self.header);
        let kind = h[156];
        let size = self.next_size.take().unwrap_or_else(|| header_size(&h[124..136]));
        let refuse = |what: String| Err(io::Error::new(io::ErrorKind::InvalidData, what));
        match kind {
            b'S' | b'M' => return refuse("refusing a sparse or multi-volume entry in the archive".into()),
            b'L' | b'K' | b'x' | b'g' if size > MAX_META => return refuse(format!("refusing an archive header entry of {size} bytes")),
            _ => {}
        }
        self.pax = (kind == b'x').then(Vec::new);
        self.data = size;
        // Padding up to the next 512 bytes (no overflow for absurd sizes).
        self.pad = (512 - size % 512) % 512;
        if size == 0 {
            self.data_done();
        }
        Ok(())
    }

    fn data_done(&mut self) {
        if let Some(pax) = self.pax.take() {
            self.next_size = pax_value(&pax, b"size").and_then(|v| std::str::from_utf8(v).ok()?.parse().ok());
        }
    }
}

impl<R: Read> Read for MetaLimit<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let mut rest = &buf[..n];
        while !rest.is_empty() {
            let take = |want: u64, rest: &mut &[u8]| {
                let (now, later) = rest.split_at(want.min(rest.len() as u64) as usize);
                *rest = later;
                now.len()
            };
            if self.data > 0 {
                let before = rest;
                let k = take(self.data, &mut rest);
                if let Some(pax) = &mut self.pax {
                    pax.extend_from_slice(&before[..k]);
                }
                self.data -= k as u64;
                if self.data == 0 {
                    self.data_done();
                }
            } else if self.pad > 0 {
                self.pad -= take(self.pad, &mut rest) as u64;
            } else {
                let before = rest;
                let k = take(512 - self.header.len() as u64, &mut rest);
                self.header.extend_from_slice(&before[..k]);
                if self.header.len() == 512 {
                    self.header_done()?;
                }
            }
        }
        Ok(n)
    }
}

/// A header's size field: octal digits, or base-256 when the top bit is set.
fn header_size(field: &[u8]) -> u64 {
    if field[0] & 0x80 != 0 {
        return field[1..].iter().fold(0u64, |n, &b| n.saturating_mul(256).saturating_add(b as u64));
    }
    let text: String = field.iter().map(|&b| b as char).filter(|c| c.is_ascii_digit()).collect();
    u64::from_str_radix(&text, 8).unwrap_or(0)
}

/// The value of `key` in PAX records (`LEN key=value\n`).
fn pax_value<'a>(mut data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    while !data.is_empty() {
        let space = data.iter().position(|&b| b == b' ')?;
        let len: usize = std::str::from_utf8(&data[..space]).ok()?.parse().ok()?;
        if len <= space || len > data.len() {
            return None;
        }
        let record = &data[space + 1..len];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(value) = record.strip_prefix(key).and_then(|r| r.strip_prefix(b"=")) {
            return Some(value);
        }
        data = &data[len..];
    }
    None
}

/// Extracts a tar stream into the existing directory `dest`.
pub fn extract_tree(input: impl Read, dest: &Path) -> Result<Stats> {
    let mut stats = Stats::default();
    let mut archive = tar::Archive::new(MetaLimit::new(input));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let rel = entry.path()?.into_owned();
        let target = safe_join(dest, &rel)?;
        no_symlinks_below(dest, &target)?;
        let mode = entry.header().mode().unwrap_or(0o644) & 0o777;
        #[cfg(not(unix))]
        let _ = mode;
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                // The mode goes through the umask, as with files and `cp -r`.
                #[cfg(unix)]
                let created = {
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new().mode(mode | 0o700).create(&target)
                };
                #[cfg(not(unix))]
                let created = fs::create_dir(&target);
                match created {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists && target.is_dir() => {}
                    Err(e) => return Err(e).with_context(|| format!("{}", target.display())),
                }
                stats.dirs += 1;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                // Besides the symlink check above, never follow one that appears meanwhile.
                #[cfg(unix)]
                opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
                let mut f = opts.open(&target).with_context(|| format!("{}", target.display()))?;
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

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

#[cfg(test)]
mod meta_tests {
    use super::*;

    fn header(kind: u8, name: &str, size: u64) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
        h.set_size(size);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::new(kind));
        h.set_cksum();
        h
    }

    #[test]
    fn long_names_still_work() {
        let dir = tempfile::tempdir().unwrap();
        let long = format!("{}/{}", "d".repeat(80), "f".repeat(90));
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(3);
        h.set_mode(0o644);
        b.append_data(&mut h, &long, &b"abc"[..]).unwrap();
        let data = b.into_inner().unwrap();
        fs::create_dir(dir.path().join("d".repeat(80))).unwrap();
        let stats = extract_tree(data.as_slice(), dir.path()).unwrap();
        assert_eq!(stats.files, 1);
        assert_eq!(fs::read(dir.path().join(&long)).unwrap(), b"abc");
    }

    /// A long-name entry declaring gigabytes is refused at its header,
    /// before the tar crate would read it into memory.
    #[test]
    fn huge_metadata_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut data = header(b'L', "././@LongLink", 8 << 30).as_bytes().to_vec();
        data.extend(std::iter::repeat_n(b'a', 4096));
        let err = extract_tree(data.as_slice(), dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("refusing an archive header entry"), "{err:#}");
    }

    /// The layout is followed through a PAX size, so a long name hidden
    /// behind it is still seen.
    #[test]
    fn pax_size_is_followed() {
        let record = |k: &str, v: &str| {
            let body = format!(" {k}={v}\n");
            let mut len = body.len() + 1;
            while len.to_string().len() + body.len() != len {
                len += 1;
            }
            format!("{len}{body}")
        };
        let pax = record("size", "1024");
        let mut data = header(b'x', "pax", pax.len() as u64).as_bytes().to_vec();
        data.extend_from_slice(pax.as_bytes());
        data.resize(data.len().div_ceil(512) * 512, 0);
        // The entry's own header says 0 bytes; its real data (1024) holds
        // what would look like headers to a reader that ignored the PAX size.
        data.extend_from_slice(header(b'0', "file", 0).as_bytes());
        data.extend_from_slice(header(b'L', "fake", 8 << 30).as_bytes());
        data.extend(std::iter::repeat_n(0u8, 512));
        let mut guard = MetaLimit::new(data.as_slice());
        assert!(io::copy(&mut guard, &mut io::sink()).is_ok(), "the fake header inside data was taken for a header");
        let mut data = header(b'0', "file", 0).as_bytes().to_vec();
        data.extend_from_slice(header(b'L', "real", 8 << 30).as_bytes());
        assert!(io::copy(&mut MetaLimit::new(data.as_slice()), &mut io::sink()).is_err());
    }

    /// A size near u64::MAX (base-256) is not a reason to panic.
    #[test]
    fn absurd_sizes() {
        let mut h = header(b'0', "file", 0);
        h.as_mut_bytes()[124..136].copy_from_slice(&[0xff; 12]);
        let mut guard = MetaLimit::new(&h.as_bytes()[..]);
        let _ = io::copy(&mut guard, &mut io::sink());
    }
}
