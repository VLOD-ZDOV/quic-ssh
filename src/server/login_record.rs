//! Login records for terminal sessions in system mode, like sshd's: `who`
//! and `w` (utmp), `last` (wtmp) and `lastlog` show qsh logins.
//!
//! On Linux the files are written directly in glibc's format (static musl
//! builds have no working utmp functions). Only files that already exist are
//! written: distributions that dropped utmp/wtmp keep it that way. On macOS
//! the system's utmpx functions are used.

use std::net::IpAddr;

use tracing::debug;

/// A terminal session's login record; the logout is recorded on drop.
pub struct LoginRecord {
    line: String,
    pid: i32,
}

/// `/dev/pts/3` → `pts/3`.
fn line_of(tty: &str) -> String {
    tty.strip_prefix("/dev/").unwrap_or(tty).to_string()
}

/// Records a login of `user` on terminal `tty` (a device path) by process
/// `pid`, from `host`.
pub fn login(user: &str, tty: &str, pid: u32, host: IpAddr) -> LoginRecord {
    let record = LoginRecord { line: line_of(tty), pid: pid as i32 };
    if let Err(e) = imp::write(&record, Some((user, host))) {
        debug!("login record for {}: {e}", record.line);
    }
    record
}

impl Drop for LoginRecord {
    fn drop(&mut self) {
        if let Err(e) = imp::write(self, None) {
            debug!("logout record for {}: {e}", self.line);
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::net::IpAddr;
    use std::os::fd::AsRawFd;

    use super::LoginRecord;

    const UTMP: &str = "/var/run/utmp";
    const WTMP: &str = "/var/log/wtmp";
    const LASTLOG: &str = "/var/log/lastlog";

    /// glibc's `struct utmp` on 64-bit Linux (x86_64 and aarch64 alike).
    pub(super) const SIZE: usize = 384;
    const USER_PROCESS: i16 = 7;
    const DEAD_PROCESS: i16 = 8;
    const LINE: std::ops::Range<usize> = 8..40;
    const ID: std::ops::Range<usize> = 40..44;
    const USER: std::ops::Range<usize> = 44..76;
    const HOST: std::ops::Range<usize> = 76..332;
    /// `struct lastlog`: time (i32), line (32), host (256).
    const LASTLOG_SIZE: u64 = 292;

    fn put(buf: &mut [u8], at: std::ops::Range<usize>, text: &str) {
        let field = &mut buf[at];
        let n = text.len().min(field.len());
        field[..n].copy_from_slice(&text.as_bytes()[..n]);
    }

    /// One utmp/wtmp entry; `who` is `None` for a logout.
    pub(super) fn entry(line: &str, pid: i32, who: Option<(&str, IpAddr)>, now: std::time::Duration) -> [u8; SIZE] {
        let mut b = [0u8; SIZE];
        let kind = if who.is_some() { USER_PROCESS } else { DEAD_PROCESS };
        b[0..2].copy_from_slice(&kind.to_ne_bytes());
        b[4..8].copy_from_slice(&pid.to_ne_bytes());
        put(&mut b, LINE, line);
        // Like sshd: the last four bytes of the line name the entry.
        put(&mut b, ID, &line[line.len().saturating_sub(4)..]);
        if let Some((user, host)) = who {
            put(&mut b, USER, user);
            put(&mut b, HOST, &host.to_string());
            match host {
                IpAddr::V4(a) => b[348..352].copy_from_slice(&a.octets()),
                IpAddr::V6(a) => b[348..364].copy_from_slice(&a.octets()),
            }
        }
        b[340..344].copy_from_slice(&(now.as_secs() as i32).to_ne_bytes());
        b[344..348].copy_from_slice(&(now.subsec_micros() as i32).to_ne_bytes());
        b
    }

    /// Exclusive lock for the duration of an update, as glibc takes it.
    fn lock(f: &File) -> io::Result<()> {
        // SAFETY: a plain fcntl call with a valid descriptor and lock struct.
        let mut fl: libc::flock = unsafe { std::mem::zeroed() };
        fl.l_type = libc::F_WRLCK as _;
        fl.l_whence = libc::SEEK_SET as _;
        if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLKW, &fl) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Replaces the entry for the same line in a utmp file, or appends one.
    pub(super) fn update_utmp(path: &str, rec: &[u8; SIZE]) -> io::Result<()> {
        let mut f = OpenOptions::new().read(true).write(true).open(path)?;
        lock(&f)?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        let line = &rec[LINE];
        let slot = data.chunks_exact(SIZE).position(|e| {
            let kind = i16::from_ne_bytes([e[0], e[1]]);
            (kind == USER_PROCESS || kind == DEAD_PROCESS) && &e[LINE] == line
        });
        let at = slot.map_or(data.len() - data.len() % SIZE, |i| i * SIZE);
        f.seek(SeekFrom::Start(at as u64))?;
        f.write_all(rec)
    }

    pub(super) fn append(path: &str, rec: &[u8]) -> io::Result<()> {
        let mut f = OpenOptions::new().append(true).open(path)?;
        lock(&f)?;
        f.write_all(rec)
    }

    fn lastlog(uid: u32, line: &str, host: IpAddr, now: std::time::Duration) -> io::Result<()> {
        let mut f = OpenOptions::new().write(true).open(LASTLOG)?;
        let mut rec = [0u8; LASTLOG_SIZE as usize];
        rec[0..4].copy_from_slice(&(now.as_secs() as i32).to_ne_bytes());
        put(&mut rec, 4..36, line);
        put(&mut rec, 36..292, &host.to_string());
        f.seek(SeekFrom::Start(uid as u64 * LASTLOG_SIZE))?;
        f.write_all(&rec)
    }

    pub(super) fn write(r: &LoginRecord, who: Option<(&str, IpAddr)>) -> io::Result<()> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let rec = entry(&r.line, r.pid, who, now);
        let utmp = update_utmp(UTMP, &rec);
        let wtmp = append(WTMP, &rec);
        if let Some((user, host)) = who {
            if let Ok(Some(u)) = nix::unistd::User::from_name(user) {
                let _ = lastlog(u.uid.as_raw(), &r.line, host, now);
            }
        }
        utmp.and(wtmp)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::net::IpAddr;

    use super::LoginRecord;

    fn put(field: &mut [libc::c_char], text: &str) {
        for (d, s) in field.iter_mut().zip(text.bytes().take(field.len().saturating_sub(1))) {
            *d = s as libc::c_char;
        }
    }

    pub(super) fn write(r: &LoginRecord, who: Option<(&str, IpAddr)>) -> std::io::Result<()> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        // SAFETY: a zeroed utmpx is valid; the libc calls get a valid pointer.
        unsafe {
            let mut u: libc::utmpx = std::mem::zeroed();
            u.ut_type = if who.is_some() { libc::USER_PROCESS } else { libc::DEAD_PROCESS };
            u.ut_pid = r.pid;
            put(&mut u.ut_line, &r.line);
            put(&mut u.ut_id, &r.line[r.line.len().saturating_sub(4)..]);
            if let Some((user, host)) = who {
                put(&mut u.ut_user, user);
                put(&mut u.ut_host, &host.to_string());
            }
            u.ut_tv.tv_sec = now.as_secs() as _;
            u.ut_tv.tv_usec = now.subsec_micros() as _;
            libc::setutxent();
            let ok = !libc::pututxline(&u).is_null();
            libc::endutxent();
            if ok { Ok(()) } else { Err(std::io::Error::last_os_error()) }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    pub(super) fn write(_: &super::LoginRecord, _: Option<(&str, std::net::IpAddr)>) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::imp::*;

    #[test]
    fn utmp_entries() {
        let host: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let now = std::time::Duration::from_secs(1_700_000_000);
        let login = entry("pts/12", 4242, Some(("alice", host)), now);
        assert_eq!(&login[0..2], &7i16.to_ne_bytes());
        assert_eq!(&login[8..14], b"pts/12");
        assert_eq!(&login[40..44], b"s/12");
        assert_eq!(&login[44..49], b"alice");
        assert_eq!(&login[76..85], b"192.0.2.7");
        assert_eq!(&login[348..352], &[192, 0, 2, 7]);
        let dir = tempfile::tempdir().unwrap();
        let utmp = dir.path().join("utmp");
        let other = entry("pts/3", 1, Some(("bob", host)), now);
        std::fs::write(&utmp, other).unwrap();
        let path = utmp.to_str().unwrap();
        update_utmp(path, &login).unwrap();
        let logout = entry("pts/12", 4242, None, now);
        update_utmp(path, &logout).unwrap();
        let data = std::fs::read(&utmp).unwrap();
        assert_eq!(data.len(), 2 * SIZE, "the logout replaces the login");
        assert_eq!(&data[SIZE..SIZE + 2], &8i16.to_ne_bytes());
        assert_eq!(&data[..SIZE], &other[..]);
        append(path, &login).unwrap();
        assert_eq!(std::fs::read(&utmp).unwrap().len(), 3 * SIZE);
        assert!(update_utmp(dir.path().join("missing").to_str().unwrap(), &login).is_err(), "never created");
    }
}
