//! `qshd internal-*` subcommands. They run as the target user (spawned via
//! [`super::users::User::helper`]) and use plain blocking I/O.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::keys::{create_private_dir, home_dir, parse_key_list, qsh_dir, PublicKey};
pub use super::users::{decode_args, Prelude, BECOME, HELPER_ARGS, HELPER_FROM_ENV};

/// Copies `r` to `w` with plain reads and writes. Not `io::copy`: between a
/// socket or file and a pipe it uses `splice()`, which keeps the pipe locked
/// while it waits for data, and qshd's own (non-blocking) access to the other
/// end of that pipe then sleeps in the kernel until data comes, which stalls
/// the whole server: a forwarded connection that stays quiet was enough.
fn pump(mut r: impl Read, mut w: impl Write) -> io::Result<u64> {
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
    let n = pump(io::stdin().lock().take(size), &mut f)
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
    out.write_all(&(meta.mode() & 0o777).to_be_bytes())?;
    pump(Read::take(&mut f, meta.len()), &mut out)?;
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
        let _ = pump(io::stdin().lock(), &mut to_sock);
        let _ = to_sock.shutdown(std::net::Shutdown::Write);
    });
    let mut from_sock = sock;
    let _ = pump(&mut from_sock, io::stdout().lock());
    let _ = upstream.join();
    Ok(())
}

/// Connects to the Unix socket `path` and relays stdin/stdout to it (`-L`
/// to a socket, as the user). Prints "ok" first, or an error on stderr.
pub fn connect_unix(path: &str) -> Result<()> {
    use std::os::unix::net::UnixStream;
    let sock = UnixStream::connect(path).with_context(|| format!("connect {path}"))?;
    let mut out = io::stdout();
    writeln!(out, "ok")?;
    out.flush()?;
    let mut to_sock = sock.try_clone()?;
    let upstream = std::thread::spawn(move || {
        let _ = pump(io::stdin().lock(), &mut to_sock);
        let _ = to_sock.shutdown(std::net::Shutdown::Write);
    });
    let mut from_sock = sock;
    let _ = pump(&mut from_sock, io::stdout().lock());
    let _ = upstream.join();
    Ok(())
}

/// Listens on the Unix socket `path` as the user (`-R` from a socket) and
/// hands the listening socket to qshd over stdout, which is a Unix socket:
/// qshd accepts the connections, but the file is the user's. `mask` (octal)
/// is taken away from the socket's permissions; with `unlink` = "yes", a
/// stale socket file is removed first.
pub fn listen_unix(path: &str, mask: &str, unlink: &str) -> Result<()> {
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileTypeExt;
    let mask = u32::from_str_radix(mask, 8).context("bad mask")? & 0o777;
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(mask as libc::mode_t));
    if unlink == "yes" && fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
        let _ = fs::remove_file(path);
    }
    let listener = std::os::unix::net::UnixListener::bind(path).with_context(|| format!("cannot listen on {path}"))?;
    let fds = [listener.as_fd()];
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    control.push(SendAncillaryMessage::ScmRights(&fds));
    sendmsg(io::stdout().as_fd(), &[io::IoSlice::new(b"L")], &mut control, SendFlags::empty()).context("cannot hand the socket to qshd")?;
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

/// `qshd internal-become UID GID GROUPS HOME TTY ARG0 PRELUDE -- PROGRAM [ARGS...]`
/// (see `User::launch`). As root: hands the terminal on stdin to the user
/// if TTY is `tty` (group `tty`, mode 0620, like sshd), switches to the
/// user's groups, group and user. Then changes to HOME (or `/`), does what
/// PRELUDE asks for (see [`Prelude`]) and runs PROGRAM with ARG0 (if not
/// empty) as its argv[0]. Nothing here can raise privileges: as anyone but
/// root, it only runs as the user it already is.
pub fn become_user(args: &[String]) -> Result<std::convert::Infallible> {
    use nix::sys::stat::{fchmod, Mode};
    use nix::unistd::{fchown, Gid, Group, Uid};
    use std::os::unix::process::CommandExt;
    let [uid, gid, groups, home, tty, arg0, prelude, dashes, program, rest @ ..] = args else {
        bail!("usage: internal-become UID GID GROUPS HOME TTY ARG0 PRELUDE -- PROGRAM [ARGS...]")
    };
    if dashes != "--" {
        bail!("bad arguments");
    }
    let prelude = Prelude::decode(prelude).context("bad prelude")?;
    crate::platform::close_inherited_fds();
    let (uid, gid) = (Uid::from_raw(uid.parse()?), Gid::from_raw(gid.parse()?));
    // Without root, only for the user qshd runs as (sessions with a prelude).
    let switch = nix::unistd::geteuid().is_root();
    if !switch && uid != nix::unistd::geteuid() {
        bail!("cannot switch users without root");
    }
    if switch && tty == "tty" {
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
    if let Some(root) = &prelude.chroot {
        if !switch {
            bail!("chroot_directory needs qshd to run as root");
        }
        enter_chroot(root)?;
    }
    #[cfg(not(target_vendor = "apple"))]
    if switch {
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
    }
    // macOS: the system drops root's supplementary groups when it switches
    // the user (membership is looked up dynamically there); the rc file
    // below runs as the user the same way.
    #[cfg(target_vendor = "apple")]
    let as_user = |c: &mut std::process::Command| {
        if switch {
            c.uid(uid.as_raw()).gid(gid.as_raw());
        }
    };
    #[cfg(target_vendor = "apple")]
    {
        let _ = groups;
        as_user(&mut cmd);
    }
    #[cfg(not(target_vendor = "apple"))]
    let as_user = |_: &mut std::process::Command| {};
    let home = Path::new(home);
    if std::env::set_current_dir(home).is_err() {
        std::env::set_current_dir("/")?;
    }
    run_prelude(&prelude, home, as_user);
    // qshd's own programs run right here: inside a chroot neither a shell
    // nor qshd's binary need to exist.
    #[cfg(not(target_vendor = "apple"))]
    if program.starts_with("internal-") {
        let code = match run_internal(program, rest) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("qshd: {e:#}");
                1
            }
        };
        let _ = io::stdout().flush();
        std::process::exit(code);
    }
    #[cfg(target_vendor = "apple")]
    if program.starts_with("internal-") {
        // Switched by exec (see above): run qshd itself.
        let mut own = std::process::Command::new(super::users::exe_path()?);
        own.arg(program).args(rest);
        as_user(&mut own);
        return Err(anyhow::Error::from(own.exec()).context(format!("cannot run {program}")));
    }
    Err(anyhow::Error::from(cmd.exec()).context(format!("cannot run {program}")))
}

/// qshd's helpers that can run inside `internal-become` (sessions and
/// file transfers of confined users); `args` as `helper_argv` makes them.
pub fn run_internal(program: &str, args: &[String]) -> Result<()> {
    let args: Vec<&str> = args.iter().map(String::as_str).skip_while(|a| *a == "--").collect();
    match (program, args.as_slice()) {
        (super::users::INTERNAL_SFTP, opts) => {
            let opts: Vec<String> = opts.iter().map(|s| s.to_string()).collect();
            let user = std::env::var("USER").unwrap_or_default();
            let home = std::env::var("HOME").unwrap_or_default();
            super::sftp::serve(super::sftp::Options::parse(&opts, &user, &home)?)
        }
        ("internal-recv", [path, name, size, mode]) => recv(path, name, size.parse()?, mode),
        ("internal-send", [path]) => send(path),
        ("internal-untar", [path, name]) => untar(path, name),
        ("internal-tar", [path]) => tar(path),
        _ => bail!("{program} cannot run here"),
    }
}

/// Like sshd's ChrootDirectory: the directory and every one above it must
/// belong to root and be writable by nobody else, or the user could plant
/// files (a fake /etc/passwd, a setuid binary's libraries) that root-run
/// code inside would trust.
fn enter_chroot(root: &Path) -> Result<()> {
    if !root.is_absolute() {
        bail!("chroot_directory {} is not an absolute path", root.display());
    }
    let mut path = PathBuf::from("/");
    for part in std::iter::once(None).chain(root.components().skip(1).map(Some)) {
        if let Some(part) = part {
            path.push(part);
        }
        let meta = fs::metadata(&path).with_context(|| format!("chroot_directory {}", path.display()))?;
        if !meta.is_dir() {
            bail!("chroot_directory: {} is not a directory", path.display());
        }
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            bail!("bad ownership or modes for chroot directory component {}", path.display());
        }
    }
    nix::unistd::chroot(root).with_context(|| format!("chroot to {}", root.display()))?;
    std::env::set_current_dir("/")?;
    Ok(())
}

/// What sshd does before a session's program: the last login and the
/// message of the day for a login shell (both skipped with `~/.hushlogin`),
/// then the user's `~/.ssh/rc`, or else the system's `/etc/ssh/sshrc`,
/// through `/bin/sh` and with the session's output.
fn run_prelude(prelude: &Prelude, home: &Path, as_user: impl Fn(&mut std::process::Command)) {
    if (prelude.motd || prelude.last_login.is_some()) && !home.join(".hushlogin").exists() {
        let mut out = io::stdout();
        if let Some(last) = &prelude.last_login {
            let _ = writeln!(out, "{last}");
        }
        if prelude.motd {
            if let Ok(f) = fs::File::open("/etc/motd") {
                let _ = pump(f.take(64 * 1024), &mut out);
            }
        }
        let _ = out.flush();
    }
    if prelude.rc {
        let user_rc = home.join(".ssh/rc");
        let rc = if user_rc.is_file() { Some(user_rc) } else { Some(PathBuf::from("/etc/ssh/sshrc")).filter(|p| p.is_file()) };
        if let Some(rc) = rc {
            let mut sh = std::process::Command::new("/bin/sh");
            sh.arg(&rc).stdin(std::process::Stdio::null());
            as_user(&mut sh);
            if let Err(e) = sh.status() {
                eprintln!("qshd: {}: {e}", rc.display());
            }
        }
    }
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
