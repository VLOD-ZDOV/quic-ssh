//! `qshd internal-*` subcommands. They run as the target user (spawned via
//! [`super::users::User::helper`]) and use plain blocking I/O.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::keys::{create_private_dir, home_dir, parse_key_list, qsh_dir, PublicKey};

/// Where an upload goes: `path`, or `path/name` if `path` is a directory.
fn upload_target(path: &str, name: &str) -> Result<PathBuf> {
    let base = if path.is_empty() { Path::new(".") } else { Path::new(path) };
    if base.is_dir() {
        let file = Path::new(name).file_name().context("invalid file name")?;
        if file == ".." || file == "." {
            bail!("invalid file name");
        }
        Ok(base.join(file))
    } else {
        Ok(base.to_path_buf())
    }
}

/// Receives exactly `size` bytes from stdin into the target file.
pub fn recv(path: &str, name: &str, size: u64, mode: &str) -> Result<()> {
    let mode = u32::from_str_radix(mode, 8).context("invalid mode")? & 0o7777;
    let target = upload_target(path, name)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&target)
        .with_context(|| format!("{}", target.display()))?;
    let mut out = io::stdout();
    writeln!(out, "ok")?;
    out.flush()?;
    let n = io::copy(&mut io::stdin().lock().take(size), &mut f)
        .with_context(|| format!("{}", target.display()))?;
    if n != size {
        bail!("{}: transfer interrupted ({n} of {size} bytes)", target.display());
    }
    Ok(())
}

/// Writes a 12-byte header (size, mode) and then the file contents to stdout.
pub fn send(path: &str) -> Result<()> {
    let mut f = fs::File::open(path).with_context(|| path.to_string())?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        bail!("{path}: not a regular file");
    }
    let mut out = io::stdout().lock();
    out.write_all(&meta.len().to_be_bytes())?;
    out.write_all(&(meta.mode() & 0o7777).to_be_bytes())?;
    io::copy(&mut Read::take(&mut f, meta.len()), &mut out)?;
    out.flush()?;
    Ok(())
}

/// Prints and consumes the pending pairing code.
pub fn pair_take() -> Result<()> {
    let code = crate::pair::take_pending(&home_dir()?)?;
    println!("{code}");
    Ok(())
}

/// Appends a key to `~/.config/qsh/authorized_keys` unless already present.
pub fn add_key(line: &str) -> Result<()> {
    let key = PublicKey::parse_openssh(line).context("invalid public key")?;
    let dir = qsh_dir(&home_dir()?);
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
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(f)?;
    }
    writeln!(f, "{}", line.trim())?;
    Ok(())
}
