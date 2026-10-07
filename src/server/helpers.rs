//! `qshd internal-*` subcommands. They run as the target user (spawned via
//! [`super::users::User::helper`]) and use plain blocking I/O.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::keys::{create_private_dir, home_dir, parse_key_list, qsh_dir, PublicKey};
pub use super::users::{decode_args, HELPER_ARGS, HELPER_FROM_ENV};

/// Where an upload goes: `path`, or `path/name` if `path` is a directory.
fn upload_target(path: &str, name: &str) -> Result<PathBuf> {
    crate::tree::tree_target(Path::new(if path.is_empty() { "." } else { path }), name)
}

/// Receives exactly `size` bytes from stdin into the target file.
pub fn recv(path: &str, name: &str, size: u64, mode: &str) -> Result<()> {
    // No setuid/setgid/sticky bits from the network (compare OpenSSH 10.3's scp fix).
    let mode = u32::from_str_radix(mode, 8).context("invalid mode")? & 0o777;
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
    out.write_all(&(meta.mode() & 0o7777).to_be_bytes())?;
    io::copy(&mut Read::take(&mut f, meta.len()), &mut out)?;
    out.flush()?;
    Ok(())
}

/// Connects to `host:port` and relays stdin/stdout to the socket (port
/// forwarding as the user). Prints "ok" first, or an error on stderr.
pub fn connect(host: &str, port: u16) -> Result<()> {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    let mut last = None;
    let mut sock = None;
    for addr in (host, port).to_socket_addrs().with_context(|| format!("connect {host}:{port}"))? {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let sock = match (sock, last) {
        (Some(s), _) => s,
        (None, Some(e)) => bail!("connect {host}:{port}: {e}"),
        (None, None) => bail!("connect {host}:{port}: no addresses"),
    };
    let _ = sock.set_nodelay(true);
    let mut out = io::stdout();
    writeln!(out, "ok")?;
    out.flush()?;
    let mut to_sock = sock.try_clone()?;
    let upstream = std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut to_sock);
        let _ = to_sock.shutdown(std::net::Shutdown::Write);
    });
    let mut from_sock = sock;
    let _ = io::copy(&mut from_sock, &mut io::stdout().lock());
    let _ = upstream.join();
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
    crate::tree::write_tree(dir, &mut out)?;
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
