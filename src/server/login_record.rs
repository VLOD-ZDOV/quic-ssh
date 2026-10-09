//! Login records for terminal sessions in system mode, like sshd's: `who`
//! and `w` (utmp), `last` (wtmp) and `lastlog` show qsh logins.
//!
//! Linux only. The files are written directly in glibc's format (static
//! musl builds have no working utmp functions), for the layouts of x86_64
//! and aarch64; on other architectures nothing is written. Only files that
//! already exist are written: distributions that dropped utmp/wtmp keep it
//! that way. Records are written by one background thread, in order, and a
//! file locked by someone else for too long is skipped, so a local user
//! holding a lock cannot stall the server.

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

struct Job {
    line: String,
    pid: i32,
    /// `None` for a logout.
    who: Option<(String, IpAddr)>,
    at: std::time::Duration,
}

fn send(job: Job) {
    use std::sync::mpsc::{channel, Sender};
    use std::sync::{Mutex, OnceLock};
    static WRITER: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();
    let tx = WRITER.get_or_init(|| {
        let (tx, rx) = channel::<Job>();
        std::thread::spawn(move || {
            for job in rx {
                if let Err(e) = imp::write(&job) {
                    debug!("login record for {}: {e}", job.line);
                }
            }
        });
        Mutex::new(tx)
    });
    let _ = tx.lock().unwrap().send(job);
}

fn now() -> std::time::Duration {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
}

/// Records a login of `user` on terminal `tty` (a device path) by process
/// `pid`, from `host`.
pub fn login(user: &str, tty: &str, pid: u32, host: IpAddr) -> LoginRecord {
    let record = LoginRecord { line: line_of(tty), pid: pid as i32 };
    send(Job { line: record.line.clone(), pid: record.pid, who: Some((user.to_string(), host)), at: now() });
    record
}

/// "Last login: Thu Oct  9 12:00:00 2026 from 192.0.2.1", as sshd shows
/// it, from lastlog or else wtmp; `None` without an earlier login there.
pub fn last_login(uid: u32, user: &str) -> Option<String> {
    let (secs, host) = imp::last(uid, user)?;
    let zone = jiff::tz::TimeZone::try_system().unwrap_or(jiff::tz::TimeZone::UTC);
    let when = jiff::Timestamp::from_second(secs).ok()?.to_zoned(zone).strftime("%a %b %e %H:%M:%S %Y").to_string();
    Some(if host.is_empty() { format!("Last login: {when}") } else { format!("Last login: {when} from {host}") })
}

impl Drop for LoginRecord {
    fn drop(&mut self) {
        send(Job { line: std::mem::take(&mut self.line), pid: self.pid, who: None, at: now() });
    }
}

/// glibc's `struct utmp` and `struct lastlog` differ between architectures:
/// x86_64 keeps 32-bit times for compatibility with i386, aarch64 does not.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod layout {
    pub const SIZE: usize = 384;
    /// `ut_tv`: seconds and microseconds, each this many bytes.
    pub const TV: usize = 340;
    pub const TV_FIELD: usize = 4;
    pub const ADDR: usize = 348;
    pub const LASTLOG_SIZE: usize = 292;
    pub const LASTLOG_TIME: usize = 4;
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod layout {
    pub const SIZE: usize = 400;
    pub const TV: usize = 344;
    pub const TV_FIELD: usize = 8;
    pub const ADDR: usize = 360;
    pub const LASTLOG_SIZE: usize = 296;
    pub const LASTLOG_TIME: usize = 8;
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::net::IpAddr;
    use std::time::Duration;

    pub(super) use super::layout::SIZE;
    use super::layout::*;
    use super::Job;

    const UTMP: &str = "/var/run/utmp";
    const WTMP: &str = "/var/log/wtmp";
    const LASTLOG: &str = "/var/log/lastlog";

    const USER_PROCESS: i16 = 7;
    const DEAD_PROCESS: i16 = 8;
    const LINE: std::ops::Range<usize> = 8..40;
    const ID: std::ops::Range<usize> = 40..44;
    const USER: std::ops::Range<usize> = 44..76;
    const HOST: std::ops::Range<usize> = 76..332;
    /// How long to wait for a lock someone else holds before skipping.
    const LOCK_WAIT: Duration = Duration::from_secs(2);

    fn put(buf: &mut [u8], at: std::ops::Range<usize>, text: &str) {
        let field = &mut buf[at];
        let n = text.len().min(field.len());
        field[..n].copy_from_slice(&text.as_bytes()[..n]);
    }

    /// Writes `value` into a field of `width` bytes (4 or 8).
    fn put_int(buf: &mut [u8], at: usize, width: usize, value: i64) {
        if width == 8 {
            buf[at..at + 8].copy_from_slice(&value.to_ne_bytes());
        } else {
            buf[at..at + 4].copy_from_slice(&(value as i32).to_ne_bytes());
        }
    }

    /// One utmp/wtmp entry; `who` is `None` for a logout.
    pub(super) fn entry(line: &str, pid: i32, who: Option<(&str, IpAddr)>, now: Duration) -> [u8; SIZE] {
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
                IpAddr::V4(a) => b[ADDR..ADDR + 4].copy_from_slice(&a.octets()),
                IpAddr::V6(a) => b[ADDR..ADDR + 16].copy_from_slice(&a.octets()),
            }
        }
        put_int(&mut b, TV, TV_FIELD, now.as_secs() as i64);
        put_int(&mut b, TV + TV_FIELD, TV_FIELD, now.subsec_micros() as i64);
        b
    }

    /// An exclusive lock as glibc takes it, waiting a little at most.
    fn lock(f: &File) -> io::Result<()> {
        use nix::fcntl::{fcntl, FcntlArg};
        let fl = libc::flock { l_type: libc::F_WRLCK as _, l_whence: libc::SEEK_SET as _, l_start: 0, l_len: 0, l_pid: 0 };
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            match fcntl(f, FcntlArg::F_SETLK(&fl)) {
                Ok(_) => return Ok(()),
                Err(_) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(io::Error::other(format!("locked by another process ({e})"))),
            }
        }
    }

    /// Replaces the entry for the same line in a utmp file, or appends one.
    pub(super) fn update_utmp(path: &str, rec: &[u8; SIZE]) -> io::Result<()> {
        let mut f = OpenOptions::new().read(true).write(true).open(path)?;
        lock(&f)?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        let line = &rec[LINE];
        let slot = data.as_chunks::<SIZE>().0.iter().position(|e| {
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

    fn lastlog(uid: u32, line: &str, host: IpAddr, now: Duration) -> io::Result<()> {
        let mut f = OpenOptions::new().write(true).open(LASTLOG)?;
        let mut rec = [0u8; LASTLOG_SIZE];
        put_int(&mut rec, 0, LASTLOG_TIME, now.as_secs() as i64);
        put(&mut rec, LASTLOG_TIME..LASTLOG_TIME + 32, line);
        put(&mut rec, LASTLOG_TIME + 32..LASTLOG_SIZE, &host.to_string());
        f.seek(SeekFrom::Start(uid as u64 * LASTLOG_SIZE as u64))?;
        f.write_all(&rec)
    }

    /// Reads a NUL-padded text field.
    fn text(field: &[u8]) -> String {
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        String::from_utf8_lossy(&field[..end]).chars().filter(|c| !c.is_control()).collect()
    }

    fn get_int(buf: &[u8], at: usize, width: usize) -> i64 {
        if width == 8 {
            i64::from_ne_bytes(buf[at..at + 8].try_into().unwrap())
        } else {
            i32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as i64
        }
    }

    /// How much of wtmp's end is searched for a login.
    const WTMP_TAIL: u64 = 4 << 20;

    /// The user's last login (time, host): lastlog's entry, or else the
    /// newest login of theirs in the end of wtmp.
    pub(super) fn last(uid: u32, user: &str) -> Option<(i64, String)> {
        let from_lastlog = || -> io::Result<Option<(i64, String)>> {
            let mut f = File::open(LASTLOG)?;
            let mut rec = [0u8; LASTLOG_SIZE];
            f.seek(SeekFrom::Start(uid as u64 * LASTLOG_SIZE as u64))?;
            f.read_exact(&mut rec)?;
            let t = get_int(&rec, 0, LASTLOG_TIME);
            Ok((t > 0).then(|| (t, text(&rec[LASTLOG_TIME + 32..]))))
        };
        if let Ok(Some(found)) = from_lastlog() {
            return Some(found);
        }
        let mut f = File::open(WTMP).ok()?;
        let len = f.metadata().ok()?.len();
        let start = len.saturating_sub(WTMP_TAIL) / SIZE as u64 * SIZE as u64;
        f.seek(SeekFrom::Start(start)).ok()?;
        let mut data = Vec::new();
        f.read_to_end(&mut data).ok()?;
        data.as_chunks::<SIZE>().0.iter().rev().find_map(|e| {
            let kind = i16::from_ne_bytes([e[0], e[1]]);
            (kind == USER_PROCESS && text(&e[USER]) == user).then(|| (get_int(e, TV, TV_FIELD), text(&e[HOST])))
        })
    }

    pub(super) fn write(job: &Job) -> io::Result<()> {
        let who = job.who.as_ref().map(|(u, h)| (u.as_str(), *h));
        let rec = entry(&job.line, job.pid, who, job.at);
        let utmp = update_utmp(UTMP, &rec);
        let wtmp = append(WTMP, &rec);
        if let Some((user, host)) = who {
            if let Ok(Some(u)) = nix::unistd::User::from_name(user) {
                let _ = lastlog(u.uid.as_raw(), &job.line, host, job.at);
            }
        }
        utmp.and(wtmp)
    }
}

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
mod imp {
    /// Nothing is written here (no known layout).
    pub(super) fn write(job: &super::Job) -> std::io::Result<()> {
        let _ = (job.pid, &job.who, job.at);
        Ok(())
    }

    pub(super) fn last(_uid: u32, _user: &str) -> Option<(i64, String)> {
        None
    }
}

#[cfg(all(test, target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::imp::*;

    #[test]
    fn utmp_entries() {
        let host: std::net::IpAddr = "192.0.2.7".parse().unwrap();
        let now = std::time::Duration::from_secs(1_700_000_000);
        let login = entry("pts/12", 4242, Some(("alice", host)), now);
        // glibc's sizeof(struct utmp) on this architecture.
        assert_eq!(login.len(), if cfg!(target_arch = "x86_64") { 384 } else { 400 });
        assert_eq!(&login[0..2], &7i16.to_ne_bytes());
        assert_eq!(&login[8..14], b"pts/12");
        assert_eq!(&login[40..44], b"s/12");
        assert_eq!(&login[44..49], b"alice");
        assert_eq!(&login[76..85], b"192.0.2.7");
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

    /// The layout matches the libc crate's `utmpx`, which mirrors glibc's struct.
    #[cfg(target_env = "gnu")]
    #[test]
    fn layout_matches_libc() {
        assert_eq!(SIZE, std::mem::size_of::<libc::utmpx>());
    }
}
