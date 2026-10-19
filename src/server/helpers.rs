//! `qshd internal-*` subcommands. They run as the target user (spawned via
//! [`super::users::User::helper`]) and use plain blocking I/O.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::transfer::pump;
pub use super::transfer::{add_key, pair_take, recv, recv_resume, send, send_from, tar, untar};
pub use super::users::{decode_args, Prelude, BECOME, HELPER_ARGS, HELPER_FROM_ENV, PRELUDE_ENV, SESSION_ENV};

/// Connects to `host:port` (as the user the helper runs as).
fn connect_tcp(host: &str, port: u16) -> Result<std::net::TcpStream> {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    let mut last = None;
    for addr in (host, port).to_socket_addrs().with_context(|| format!("connect {host}:{port}"))? {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    match last {
        Some(e) => bail!("connect {host}:{port}: {e}"),
        None => bail!("connect {host}:{port}: no addresses"),
    }
}

/// Connects to `host:port` as the user and hands the socket to qshd (`-L`
/// in system mode): uid-based firewall rules apply to it, and no process
/// stays to relay the data.
pub fn connect_fd(host: &str, port: u16) -> Result<()> {
    hand_over(connect_tcp(host, port)?)
}

/// Like [`connect_fd`], to the Unix socket `path`.
pub fn connect_unix_fd(path: &str) -> Result<()> {
    hand_over(std::os::unix::net::UnixStream::connect(path).with_context(|| format!("connect {path}"))?)
}

/// Opens tunnel device `kind` (`tun`, `tap`) number `unit` (or `any`) as
/// the user and hands it to qshd (`-w` for a user other than root).
pub fn tun_fd(kind: &str, unit: &str) -> Result<()> {
    let ethernet = match kind {
        "tun" => false,
        "tap" => true,
        _ => bail!("unknown tunnel device kind {kind}"),
    };
    let unit = match unit {
        "any" => None,
        n => Some(n.parse::<u32>().context("bad tunnel device number")?),
    };
    #[cfg(target_os = "linux")]
    return hand_over(crate::tunnel::open_as_user(ethernet, unit)?);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ethernet, unit);
        bail!("tunnel devices are not supported on this system")
    }
}

/// Sends `fd` to qshd over stdout, which is a Unix socket.
fn hand_over(fd: impl std::os::fd::AsFd) -> Result<()> {
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::os::fd::AsFd;
    let fds = [fd.as_fd()];
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    control.push(SendAncillaryMessage::ScmRights(&fds));
    let out = io::stdout();
    sendmsg(out.as_fd(), &[io::IoSlice::new(b"S")], &mut control, SendFlags::empty()).context("cannot hand the socket to qshd")?;
    // Stay until qshd has it (it closes its end then): on macOS, a socket
    // still on its way when the sender exits was sometimes lost. Not long,
    // for a qshd from before this change, which waits for us first.
    let sock = std::os::unix::net::UnixStream::from(out.as_fd().try_clone_to_owned()?);
    sock.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
    let _ = io::Read::read(&mut &sock, &mut [0u8; 1]);
    Ok(())
}

/// Connects to `host:port` and relays stdin/stdout to the socket. Prints
/// "ok" first, or an error on stderr. Kept for a qshd started before an
/// update, which may run this binary's helpers (see [`connect_fd`]).
pub fn connect(host: &str, port: u16) -> Result<()> {
    let sock = connect_tcp(host, port)?;
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

/// Connects to the Unix socket `path` and relays stdin/stdout to it. Prints
/// "ok" first, or an error on stderr. Kept like [`connect`].
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
    use std::os::unix::fs::FileTypeExt;
    let mask = u32::from_str_radix(mask, 8).context("bad mask")? & 0o777;
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(mask as libc::mode_t));
    if unlink == "yes" && fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
        let _ = fs::remove_file(path);
    }
    let listener = std::os::unix::net::UnixListener::bind(path).with_context(|| format!("cannot listen on {path}"))?;
    hand_over(listener)
}

/// `qshd internal-become UID GID GROUPS HOME TTY ARG0 -- PROGRAM [ARGS...]`
/// (see `User::launch`), with the prelude in [`PRELUDE_ENV`]. As root: hands the terminal on stdin to the user
/// if TTY is `tty` (group `tty`, mode 0620, like sshd), switches to the
/// user's groups, group and user. Then changes to HOME (or `/`), does what
/// PRELUDE asks for (see [`Prelude`]) and runs PROGRAM with ARG0 (if not
/// empty) as its argv[0]. Nothing here can raise privileges: as anyone but
/// root, it only runs as the user it already is.
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
    let prelude = std::env::var(PRELUDE_ENV).unwrap_or_else(|_| "-".into());
    std::env::remove_var(PRELUDE_ENV);
    let prelude = Prelude::decode(&prelude).context("bad prelude")?;
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
    // The session's variables, now that they cannot act as root (see `User::launch_env`).
    if let Ok(encoded) = std::env::var(SESSION_ENV) {
        std::env::remove_var(SESSION_ENV);
        for pair in decode_args(&encoded).context("bad session environment")? {
            if let Some((k, v)) = pair.split_once('=').filter(|(k, _)| !k.is_empty()) {
                std::env::set_var(k, v);
            }
        }
    }
    let home = Path::new(home);
    let in_home = std::env::set_current_dir(home).is_ok();
    if !in_home {
        std::env::set_current_dir("/")?;
    }
    run_prelude(&prelude, in_home, as_user);
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
    // Only the one "--" that `helper_argv` puts in front: a "--" after it is an argument.
    let args: Vec<&str> = match args.split_first() {
        Some((first, rest)) if first == "--" => rest.iter().map(String::as_str).collect(),
        _ => args.iter().map(String::as_str).collect(),
    };
    match (program, args.as_slice()) {
        (super::users::INTERNAL_SFTP, opts) => {
            let opts: Vec<String> = opts.iter().map(|s| s.to_string()).collect();
            let user = std::env::var("USER").unwrap_or_default();
            let home = std::env::var("HOME").unwrap_or_default();
            super::sftp::serve(super::sftp::Options::parse(&opts, &user, &home)?)
        }
        ("internal-recv", [path, name, size, mode]) => recv(path, name, size.parse()?, mode),
        ("internal-send", [path]) => send(path),
        ("internal-recv-resume", [path, name, size, mode]) => recv_resume(path, name, size.parse()?, mode),
        ("internal-send-from", [path, offset, prefix]) => send_from(path, offset, prefix),
        ("internal-untar", [path, name]) => untar(path, name),
        ("internal-tar", [path]) => tar(path),
        ("internal-connect-unix", [path]) => connect_unix(path),
        ("internal-connect-unix-fd", [path]) => connect_unix_fd(path),
        ("internal-listen-unix", [path, mask, unlink]) => listen_unix(path, mask, unlink),
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
    // The real path is what is checked and entered (a symlink on the way
    // would otherwise lead past directories nobody checked).
    let root = &fs::canonicalize(root).with_context(|| format!("chroot_directory {}", root.display()))?;
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
/// then the user's `~/.ssh/rc` (through the user's shell, as `$SHELL -c
/// '/bin/sh .ssh/rc'`), or else the system's `/etc/ssh/sshrc` (`/bin/sh`),
/// with the session's output. Runs in the home directory if `in_home`.
fn run_prelude(prelude: &Prelude, in_home: bool, as_user: impl Fn(&mut std::process::Command)) {
    if (prelude.motd || prelude.last_login.is_some()) && !(in_home && Path::new(".hushlogin").exists()) {
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
    // The X11 data goes to the rc file on stdin; without one, to xauth.
    let x11_line = prelude.x11.as_ref().map(|(_, proto, cookie)| format!("{proto} {cookie}\n"));
    let rc = if !prelude.rc {
        None
    } else if let Some(shell) = prelude.user_rc.as_ref().filter(|_| in_home && Path::new(".ssh/rc").is_file()) {
        let mut cmd = std::process::Command::new(shell);
        cmd.args(["-c", "/bin/sh .ssh/rc"]);
        Some((cmd, ".ssh/rc"))
    } else {
        Path::new("/etc/ssh/sshrc").is_file().then(|| {
            let mut cmd = std::process::Command::new("/bin/sh");
            cmd.arg("/etc/ssh/sshrc");
            (cmd, "/etc/ssh/sshrc")
        })
    };
    let feed = |mut cmd: std::process::Command, input: Option<String>| {
        cmd.stdin(if input.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() });
        as_user(&mut cmd);
        let mut child = cmd.spawn()?;
        if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
            let _ = stdin.write_all(text.as_bytes());
        }
        child.wait()
    };
    if let Some((cmd, name)) = rc {
        if let Err(e) = feed(cmd, x11_line) {
            eprintln!("qshd: {name}: {e}");
        }
    } else if let (Some((display, proto, cookie)), Some(xauth)) = (&prelude.x11, &prelude.xauth) {
        let mut cmd = std::process::Command::new(xauth);
        cmd.args(["-q", "-"]).stdout(std::process::Stdio::null());
        let script = format!("remove {display}\nadd {display} {proto} {cookie}\n");
        if let Err(e) = feed(cmd, Some(script)) {
            eprintln!("qshd: {xauth}: {e}");
        }
    }
}

