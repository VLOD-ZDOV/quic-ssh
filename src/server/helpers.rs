//! `qshd internal-*` subcommands. They run as the target user (spawned via
//! [`super::users::User::helper`]) and use plain blocking I/O.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::keys::{create_private_dir, home_dir, parse_key_list, qsh_dir, PublicKey};
pub use super::users::{decode_args, BECOME, HELPER_ARGS, HELPER_FROM_ENV};

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

/// `qshd internal-become UID GID GROUPS HOME TTY ARG0 -- PROGRAM [ARGS...]`,
/// run as root (see `User::launch`): hands the terminal on stdin to the user
/// if TTY is `tty` (group `tty`, mode 0620, like sshd), switches to the
/// user's groups, group and user, changes to HOME (or `/`), and runs PROGRAM
/// with ARG0 (if not empty) as its argv[0]. Nothing here can raise
/// privileges: as anyone but root, switching users fails.
pub fn become_user(args: &[String]) -> Result<std::convert::Infallible> {
    use nix::sys::stat::{fchmod, Mode};
    use nix::unistd::{fchown, Gid, Group, Uid};
    use std::os::unix::process::CommandExt;
    let [uid, gid, groups, home, tty, arg0, dashes, program, rest @ ..] = args else {
        bail!("usage: internal-become UID GID GROUPS HOME TTY ARG0 -- PROGRAM [ARGS...]")
    };
    if dashes != "--" {
        bail!("bad arguments");
    }
    let (uid, gid) = (Uid::from_raw(uid.parse()?), Gid::from_raw(gid.parse()?));
    if tty == "tty" {
        let (group, mode) = match Group::from_name("tty") {
            Ok(Some(g)) => (Some(g.gid), 0o620),
            _ => (None, 0o600),
        };
        // Best effort: a terminal of another user namespace cannot be
        // chowned; it then stays root's, which is stricter.
        if fchown(io::stdin(), Some(uid), group).is_ok() {
            let _ = fchmod(io::stdin(), Mode::from_bits_truncate(mode));
        }
    }
    let mut cmd = std::process::Command::new(program);
    cmd.args(rest);
    if !arg0.is_empty() {
        cmd.arg0(arg0);
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let groups: Vec<Gid> = match groups.as_str() {
            "-" => Vec::new(),
            list => list.split(',').map(|g| g.parse().map(Gid::from_raw)).collect::<Result<_, _>>()?,
        };
        nix::unistd::setgroups(&groups)?;
        nix::unistd::setgid(gid)?;
        nix::unistd::setuid(uid)?;
        // Refuse to go on if root privileges could be regained.
        if !uid.is_root() && nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
            bail!("failed to drop privileges");
        }
        if std::env::set_current_dir(home).is_err() {
            std::env::set_current_dir("/")?;
        }
    }
    // macOS: the system drops root's supplementary groups when it switches
    // the user (membership is looked up dynamically there).
    #[cfg(target_vendor = "apple")]
    {
        let _ = groups;
        cmd.uid(uid.as_raw()).gid(gid.as_raw());
        cmd.current_dir(if std::path::Path::new(home).is_dir() { home.as_str() } else { "/" });
    }
    Err(anyhow::Error::from(cmd.exec()).context(format!("cannot run {program}")))
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
