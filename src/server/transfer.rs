//! The file-transfer helpers (`qshd internal-recv`, `internal-send`...):
//! run as the user, with the protocol on stdin and stdout (see `files`).

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::keys::{create_private_dir, home_dir, parse_key_list, qsh_dir, PublicKey};

/// Copies `r` to `w` with plain reads and writes. Not `io::copy`: between a
/// socket or file and a pipe it uses `splice()`, which keeps the pipe locked
/// while it waits for data, and qshd's own (non-blocking) access to the other
/// end of that pipe then sleeps in the kernel until data comes, which stalls
/// the whole server: a forwarded connection that stays quiet was enough.
pub(super) fn pump(mut r: impl Read, mut w: impl Write) -> io::Result<u64> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        w.write_all(&buf[..n])?;
        w.flush()?;
        total += n as u64;
    }
}

/// Where an upload goes: `path`, or `path/name` if `path` is a directory.
fn upload_target(path: &str, name: &str) -> Result<PathBuf> {
    crate::tree::tree_target(Path::new(if path.is_empty() { "." } else { path }), name)
}

/// Receives exactly `size` bytes from stdin into the target file.
pub fn recv(path: &str, name: &str, size: u64, mode: &str) -> Result<()> {
    // No setuid/setgid/sticky bits from the network (compare OpenSSH 10.3's scp fix).
    let mode = u32::from_str_radix(mode, 8).context("invalid mode")? & 0o777;
    let target = upload_target(path, name)?;
    let mut f = with_mode(OpenOptions::new().write(true).create(true).truncate(true), mode)
        .open(&target)
        .with_context(|| format!("{}", target.display()))?;
    let mut out = io::stdout();
    writeln!(out, "ok")?;
    out.flush()?;
    let n = pump(io::stdin().lock().take(size), &mut f)
        .with_context(|| format!("{}", target.display()))?;
    if n != size {
        bail!("{}: transfer interrupted ({n} of {size} bytes)", target.display());
    }
    Ok(())
}

/// Like [`recv`], but keeps what a target no larger than `size` already
/// holds if the client has the same beginning: writes "ok", the target's
/// size (8 bytes) and the SHA-256 of it (32 bytes, zeros when empty), reads
/// where to go on (8 bytes: that size or 0) and then the rest.
pub fn recv_resume(path: &str, name: &str, size: u64, mode: &str) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    let mode = u32::from_str_radix(mode, 8).context("invalid mode")? & 0o777;
    let target = upload_target(path, name)?;
    let mut f = with_mode(OpenOptions::new().read(true).write(true).create(true), mode)
        .open(&target)
        .with_context(|| format!("{}", target.display()))?;
    let meta = f.metadata()?;
    let have = if meta.is_file() && meta.len() <= size { meta.len() } else { 0 };
    let prefix = if have > 0 { crate::proto::prefix_sha256(&mut f, have)? } else { vec![0; 32] };
    let mut out = io::stdout();
    writeln!(out, "ok")?;
    out.write_all(&have.to_be_bytes())?;
    out.write_all(&prefix)?;
    out.flush()?;
    let mut stdin = io::stdin().lock();
    let mut offset = [0u8; 8];
    stdin.read_exact(&mut offset)?;
    let offset = u64::from_be_bytes(offset);
    if offset != 0 && offset != have {
        bail!("{}: cannot go on at byte {offset}", target.display());
    }
    // Not for a device or FIFO, which cannot be cut (as `recv`'s truncate).
    if meta.is_file() {
        f.set_len(offset)?;
        f.seek(SeekFrom::Start(offset))?;
    }
    let left = size - offset;
    let n = pump(stdin.take(left), &mut f).with_context(|| format!("{}", target.display()))?;
    if n != left {
        bail!("{}: transfer interrupted ({} of {size} bytes)", target.display(), offset + n);
    }
    Ok(())
}

/// Like [`send`], from byte `offset` on if the file's first `offset` bytes
/// have the SHA-256 `prefix` (hex), else from the start; the header gets the
/// start (8 bytes) after size and mode.
pub fn send_from(path: &str, offset: &str, prefix: &str) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    let offset: u64 = offset.parse().context("invalid offset")?;
    let mut f = fs::File::open(path).with_context(|| path.to_string())?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        bail!("{path}: not a regular file");
    }
    let same = offset > 0 && offset <= meta.len() && Some(crate::proto::prefix_sha256(&mut f, offset)?) == crate::proto::unhex(prefix);
    let start = if same { offset } else { 0 };
    f.seek(SeekFrom::Start(start))?;
    let mut out = io::stdout().lock();
    writeln!(out, "ok")?;
    out.write_all(&meta.len().to_be_bytes())?;
    out.write_all(&mode_of(&meta).to_be_bytes())?;
    out.write_all(&start.to_be_bytes())?;
    pump(Read::take(&mut f, meta.len() - start), &mut out)?;
    out.flush()?;
    Ok(())
}

/// Writes "ok", a 12-byte header (size, mode) and then the file contents to stdout.
pub fn send(path: &str) -> Result<()> {
    let mut f = fs::File::open(path).with_context(|| path.to_string())?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        bail!("{path}: not a regular file");
    }
    let mut out = io::stdout().lock();
    writeln!(out, "ok")?;
    out.write_all(&meta.len().to_be_bytes())?;
    out.write_all(&mode_of(&meta).to_be_bytes())?;
    pump(Read::take(&mut f, meta.len()), &mut out)?;
    out.flush()?;
    Ok(())
}

/// Receives a tar stream on stdin into `path` (or `path/name` if `path` is a
/// directory). Prints "ok" once the target directory exists.
pub fn untar(path: &str, name: &str) -> Result<()> {
    let target = upload_target(path, name)?;
    crate::tree::create_target(&target)?;
    let mut out = io::stdout();
    writeln!(out, "ok")?;
    out.flush()?;
    let stats = crate::tree::extract_tree(io::stdin().lock(), &target)?;
    if stats.skipped > 0 {
        eprintln!("{} entries skipped (only files and directories are copied)", stats.skipped);
    }
    Ok(())
}

/// Writes "ok" and then the contents of directory `path` as a tar stream.
pub fn tar(path: &str) -> Result<()> {
    let dir = Path::new(if path.is_empty() { "." } else { path });
    if !dir.is_dir() {
        bail!("{path}: not a directory");
    }
    let mut out = io::stdout().lock();
    writeln!(out, "ok")?;
    let stats = crate::tree::write_tree(dir, &mut out)?;
    out.flush()?;
    stats.check()
}


/// New files get `mode` (through the umask) on Unix; Windows has no modes.
#[cfg(unix)]
fn with_mode(o: &mut OpenOptions, mode: u32) -> &mut OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    o.mode(mode)
}

#[cfg(not(unix))]
fn with_mode(o: &mut OpenOptions, _mode: u32) -> &mut OpenOptions {
    o
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o777
}

/// What Unix would show for a file of Windows: read-only or not.
#[cfg(not(unix))]
fn mode_of(meta: &fs::Metadata) -> u32 {
    if meta.permissions().readonly() { 0o444 } else { 0o644 }
}

/// Prints and consumes the pending pairing code.
pub fn pair_take() -> Result<()> {
    let code = crate::pair::take_pending(&home_dir()?)?;
    println!("{code}");
    Ok(())
}

/// Appends a key to `~/.config/qsh/authorized_keys` unless already present
/// (after a pairing, whose code is then used up).
pub fn add_key(line: &str) -> Result<()> {
    let key = PublicKey::parse_openssh(line).context("invalid public key")?;
    let home = home_dir()?;
    crate::pair::discard_used(&home);
    let dir = qsh_dir(&home);
    create_private_dir(&dir)?;
    let path = dir.join("authorized_keys");
    let existing = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    if parse_key_list(&existing).contains(&key) {
        return Ok(());
    }
    let mut o = OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = o.open(&path)?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(f)?;
    }
    writeln!(f, "{}", line.trim())?;
    Ok(())
}
