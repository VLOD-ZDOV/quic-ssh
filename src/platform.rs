//! The few places where Unix and Windows differ for the client: file modes,
//! the local user name, and the terminal.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Creates a new file readable only by the owner (0600 on Unix). Fails if it exists.
pub fn create_private(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)
}

/// Sets Unix permission bits; Windows has no equivalent, so nothing happens there.
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    return std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode));
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// Unix permission bits of a file (on Windows: 0644, or 0444 if read-only, and 0755 for directories).
pub fn mode(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    return std::os::unix::fs::MetadataExt::mode(meta);
    #[cfg(not(unix))]
    match (meta.is_dir(), meta.permissions().readonly()) {
        (true, _) => 0o755,
        (false, true) => 0o444,
        (false, false) => 0o644,
    }
}

/// The local login name.
/// This machine's host name (for `%l`/`%L`).
pub fn hostname() -> String {
    #[cfg(unix)]
    {
        nix::unistd::gethostname().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default()
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
}

/// The real user id (`%i`); 0 where there is none (Windows).
pub fn uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::getuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

pub fn local_user() -> anyhow::Result<String> {
    #[cfg(unix)]
    {
        use anyhow::Context;
        let uid = nix::unistd::getuid();
        Ok(nix::unistd::User::from_uid(uid)?.context("cannot determine local user name")?.name)
    }
    #[cfg(not(unix))]
    std::env::var("USERNAME").map_err(|_| anyhow::anyhow!("cannot determine local user name (USERNAME is not set)"))
}

/// The controlling terminal for questions, as (input, output), even when
/// stdin/stdout are redirected.
pub fn terminal() -> io::Result<(File, File)> {
    #[cfg(unix)]
    {
        let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        Ok((tty.try_clone()?, tty))
    }
    #[cfg(not(unix))]
    {
        let input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
        let output = OpenOptions::new().read(true).write(true).open("CONOUT$")?;
        Ok((input, output))
    }
}

/// Listens on `addr` like `TcpListener::bind`, but an IPv6 address listens
/// for IPv6 only: `[::]` next to `0.0.0.0` on the same port would otherwise
/// clash with it (Linux makes `[::]` take IPv4 too) and be left out.
pub fn listen_tcp(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    listen_tcp_v6only(addr, addr.is_ipv6())
}

/// Listens on `addr`; `[::]` takes IPv4 too, as QUIC's UDP socket does.
/// Windows makes IPv6 sockets IPv6-only by default, so this must be explicit.
pub fn listen_tcp_dual(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    listen_tcp_v6only(addr, false)
}

fn listen_tcp_v6only(addr: std::net::SocketAddr, v6only: bool) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    if addr.is_ipv6() {
        sock.set_only_v6(v6only)?;
    }
    // As tokio's bind does: a port in TIME_WAIT can be listened on again.
    #[cfg(unix)]
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    tokio::net::TcpListener::from_std(sock.into())
}

/// For `127.0.0.1` the other loopback `::1`, and back: both mean "this
/// machine", but a service often listens on only one (an IPv6 `[::]`
/// socket on Windows takes no IPv4). Trying the other one is opt-in
/// (`LoopbackFallback`, `loopback_fallback`): while the service is down,
/// another local user may listen there.
pub fn other_loopback(host: &str) -> Option<&'static str> {
    match host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(ip) if ip.is_loopback() => Some("::1"),
        std::net::IpAddr::V6(ip) if ip.is_loopback() => Some("127.0.0.1"),
        _ => None,
    }
}

/// Connects to `host:port` within `timeout`; if that is refused, to
/// `fallback` (see [`other_loopback`]). The error is the first one: it names
/// what was asked for.
pub async fn connect_tcp(host: &str, port: u16, timeout: std::time::Duration, fallback: Option<&str>) -> io::Result<tokio::net::TcpStream> {
    let once = |host: &str| {
        let connect = tokio::net::TcpStream::connect((host.to_string(), port));
        async move {
            match tokio::time::timeout(timeout, connect).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out")),
            }
        }
    };
    match once(host).await {
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => match fallback {
            Some(other) => once(other).await.map_err(|_| e),
            None => Err(e),
        },
        r => r,
    }
}

/// Where writing `path` should go: the file a symlink points to, also one
/// that does not exist yet (canonicalize fails for those).
pub fn link_target(path: &Path) -> std::path::PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    match std::fs::read_link(path) {
        Ok(to) => path.parent().map_or(to.clone(), |dir| dir.join(&to)),
        Err(_) => path.to_path_buf(),
    }
}

/// Replaces `path` with `contents` in one step: written to a temporary file
/// of a unique name next to it, then renamed over it, so a reader never sees
/// half a file and two writers never write into the same temporary file.
/// A symlink is followed (dotfile managers): the file it points to is
/// replaced.
pub fn replace_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let file = link_target(path);
    let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let tmp = file.with_file_name(format!(".{name}.{}.{}.{nanos}.tmp", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
    // The file keeps its permissions (a private one stays private).
    let keep = |()| match std::fs::metadata(&file) {
        Ok(m) => std::fs::set_permissions(&tmp, m.permissions()),
        Err(_) => Ok(()),
    };
    let written = std::fs::write(&tmp, contents).and_then(keep).and_then(|()| std::fs::rename(&tmp, &file));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Closes every descriptor above stderr, like OpenSSH's `closefrom(3)`:
/// a program started for another user must not inherit anything of ours
/// (a terminal master opened by another thread is close-on-exec only a
/// moment after it is opened), and a background qsh must not keep its
/// caller's pipes open.
pub fn close_inherited_fds() {
    #[cfg(unix)]
    {
        let dir = if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" };
        let fds: Vec<std::os::fd::RawFd> = match std::fs::read_dir(dir) {
            Ok(entries) => entries.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).filter(|&fd| fd > 2).collect(),
            // No /proc (a chroot, a container): every possible descriptor.
            Err(_) => {
                let (soft, _) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap_or((1024, 1024));
                (3..soft.min(65536) as std::os::fd::RawFd).collect()
            }
        };
        // The listing's own descriptor is closed by now; closing it again fails harmlessly.
        for fd in fds {
            let _ = nix::unistd::close(fd);
        }
    }
}

/// Makes stdin, stdout and stderr blocking. qsh reads and writes them from
/// blocking threads, but a parent may hand over non-blocking descriptors
/// (openrsync does, with its socket pair), and a read would then fail at once
/// with "would block" instead of waiting for data.
pub fn blocking_stdio() {
    #[cfg(unix)]
    {
        use nix::fcntl::{fcntl, FcntlArg, OFlag};
        use std::os::fd::AsFd;
        let (stdin, stdout, stderr) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
        for fd in [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()] {
            if let Ok(flags) = fcntl(fd, FcntlArg::F_GETFL) {
                let flags = OFlag::from_bits_truncate(flags);
                if flags.contains(OFlag::O_NONBLOCK) {
                    let _ = fcntl(fd, FcntlArg::F_SETFL(flags - OFlag::O_NONBLOCK));
                }
            }
        }
    }
}

/// Lifts the soft limit on open files (often 1024) towards the hard one:
/// every connection, forwarded connection and helper holds descriptors.
/// Capped so that programs started from here, which inherit it, see a usual value.
pub fn raise_fd_limit() {
    #[cfg(unix)]
    {
        use nix::sys::resource::{getrlimit, setrlimit, Resource};
        const WANT: u64 = 8192;
        if let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) {
            let new = hard.min(WANT);
            if soft < new {
                let _ = setrlimit(Resource::RLIMIT_NOFILE, new, hard);
            }
        }
    }
}

/// The program's arguments. They go into a protocol of UTF-8 strings, and a
/// lossy conversion could name another file: one that is not UTF-8 is
/// refused with a message (std would panic).
pub fn args_or_exit(program: &str) -> Vec<String> {
    match std::env::args_os().map(std::ffi::OsString::into_string).collect() {
        Ok(args) => args,
        Err(bad) => {
            eprintln!("{program}: argument {:?} is not valid UTF-8", bad);
            std::process::exit(255);
        }
    }
}

/// Whether a panic is std's for printing to a closed pipe (`qshd pair |
/// head -1`), which should end the program quietly, as it does C tools.
pub fn is_broken_pipe_print(info: &std::panic::PanicHookInfo<'_>) -> bool {
    let payload = info.payload();
    let msg = payload.downcast_ref::<String>().map(String::as_str).or_else(|| payload.downcast_ref::<&str>().copied()).unwrap_or("");
    // EPIPE is 32 on every Unix qsh runs on; the text is not localized.
    msg.starts_with("failed printing to std") && msg.contains("os error 32")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn replaced_file_keeps_its_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("private");
        std::fs::write(&file, b"old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        super::replace_file(&file, b"new").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn dual_listener_takes_ipv4() {
        let Ok(l) = super::listen_tcp_dual((std::net::Ipv6Addr::UNSPECIFIED, 0).into()) else { return }; // no IPv6
        let port = l.local_addr().unwrap().port();
        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
    }

    #[test]
    fn other_loopback_pairs_v4_and_v6() {
        assert_eq!(super::other_loopback("127.0.0.1"), Some("::1"));
        assert_eq!(super::other_loopback("[::1]"), Some("127.0.0.1"));
        assert_eq!(super::other_loopback("localhost"), None); // resolves to both already
        assert_eq!(super::other_loopback("192.0.2.1"), None);
    }

    #[tokio::test]
    async fn refused_loopback_tries_the_other() {
        let Ok(l) = super::listen_tcp((std::net::Ipv6Addr::LOCALHOST, 0).into()) else { return }; // no IPv6
        let port = l.local_addr().unwrap().port();
        let timeout = std::time::Duration::from_secs(5);
        assert!(super::connect_tcp("127.0.0.1", port, timeout, None).await.is_err());
        super::connect_tcp("127.0.0.1", port, timeout, Some("::1")).await.unwrap();
    }
}
