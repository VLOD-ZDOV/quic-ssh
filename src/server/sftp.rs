//! `internal-sftp`: an SFTP server (protocol version 3, with OpenSSH's
//! extensions) built into qshd, like sshd's. It needs no sftp-server
//! binary and no shell, so it also serves accounts whose shell is nologin
//! and works inside `chroot_directory`.
//!
//! It runs as the user, in the process that switched to them, and reads
//! requests from stdin and answers on stdout with plain blocking I/O.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

const VERSION: u32 = 3;

const INIT: u8 = 1;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const READ: u8 = 5;
const WRITE: u8 = 6;
const LSTAT: u8 = 7;
const FSTAT: u8 = 8;
const SETSTAT: u8 = 9;
const FSETSTAT: u8 = 10;
const OPENDIR: u8 = 11;
const READDIR: u8 = 12;
const REMOVE: u8 = 13;
const MKDIR: u8 = 14;
const RMDIR: u8 = 15;
const REALPATH: u8 = 16;
const STAT: u8 = 17;
const RENAME: u8 = 18;
const READLINK: u8 = 19;
const SYMLINK: u8 = 20;
const EXTENDED: u8 = 200;

const R_VERSION: u8 = 2;
const R_STATUS: u8 = 101;
const R_HANDLE: u8 = 102;
const R_DATA: u8 = 103;
const R_NAME: u8 = 104;
const R_ATTRS: u8 = 105;
const R_EXTENDED: u8 = 201;

const OK: u32 = 0;
const EOF: u32 = 1;
const NO_SUCH_FILE: u32 = 2;
const PERMISSION_DENIED: u32 = 3;
const FAILURE: u32 = 4;
const BAD_MESSAGE: u32 = 5;
const OP_UNSUPPORTED: u32 = 8;

const ATTR_SIZE: u32 = 0x1;
const ATTR_UIDGID: u32 = 0x2;
const ATTR_PERMISSIONS: u32 = 0x4;
const ATTR_ACMODTIME: u32 = 0x8;
const ATTR_EXTENDED: u32 = 0x8000_0000;

const FXF_READ: u32 = 0x1;
const FXF_WRITE: u32 = 0x2;
const FXF_APPEND: u32 = 0x4;
const FXF_CREAT: u32 = 0x8;
const FXF_TRUNC: u32 = 0x10;
const FXF_EXCL: u32 = 0x20;

/// Largest request accepted, and the limits announced (as OpenSSH's).
const MAX_PACKET: u32 = 256 * 1024;
const MAX_READ: u32 = MAX_PACKET - 1024;
const MAX_HANDLES: usize = 512;
/// Directory entries per READDIR answer.
const DIR_BATCH: usize = 100;

/// Options of `internal-sftp` (a subset of sftp-server's).
#[derive(Default, Debug, PartialEq)]
pub struct Options {
    /// `-R`: refuse everything that changes files.
    pub read_only: bool,
    /// `-u`: umask for created files.
    pub umask: Option<u32>,
    /// `-d`: start directory instead of the home.
    pub start_dir: Option<String>,
}

impl Options {
    /// Parses `internal-sftp`'s arguments; `-d` may use `%u` (user), `%d`
    /// (home) and `%%`. Logging options (`-e`, `-f`, `-l`) are accepted and
    /// do nothing.
    pub fn parse(args: &[String], user: &str, home: &str) -> Result<Options> {
        let mut o = Options::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "-R" => o.read_only = true,
                "-e" => {}
                "-u" => {
                    let v = it.next().map(String::as_str).unwrap_or("");
                    o.umask = Some(u32::from_str_radix(v, 8).map_err(|_| anyhow::anyhow!("bad umask {v:?}"))? & 0o777);
                }
                "-d" => {
                    let v = it.next().map(String::as_str).unwrap_or("");
                    o.start_dir = Some(expand(v, user, home)?);
                }
                "-f" | "-l" => {
                    it.next();
                }
                other => bail!("internal-sftp: unsupported option {other:?}"),
            }
        }
        Ok(o)
    }
}

fn expand(s: &str, user: &str, home: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('u') => out.push_str(user),
            Some('d') => out.push_str(home),
            Some('%') => out.push('%'),
            other => bail!("unknown token %{} in {s:?}", other.map(String::from).unwrap_or_default()),
        }
    }
    Ok(out)
}

/// Runs the server until the client closes stdin.
pub fn serve(opts: Options) -> Result<()> {
    if let Some(mask) = opts.umask {
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(mask as libc::mode_t));
    }
    if let Some(dir) = &opts.start_dir {
        std::env::set_current_dir(dir).map_err(|e| anyhow::anyhow!("start directory {dir}: {e}"))?;
    }
    let mut input = BufReader::with_capacity(MAX_PACKET as usize, io::stdin().lock());
    let mut output = BufWriter::with_capacity(MAX_PACKET as usize, io::stdout().lock());
    let mut server = Server { opts, handles: HashMap::new(), next_handle: 0 };
    loop {
        let mut len = [0u8; 4];
        match input.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len);
        if len == 0 || len > MAX_PACKET {
            bail!("bad packet length {len}");
        }
        let mut packet = vec![0u8; len as usize];
        input.read_exact(&mut packet)?;
        let reply = server.handle(&packet);
        output.write_all(&(reply.len() as u32).to_be_bytes())?;
        output.write_all(&reply)?;
        output.flush()?;
    }
}

enum Handle {
    File(File),
    Dir { path: PathBuf, entries: Option<fs::ReadDir>, dots: bool },
}

struct Server {
    opts: Options,
    handles: HashMap<u32, Handle>,
    next_handle: u32,
}

/// Reads fields of a request.
struct Msg<'a>(&'a [u8]);

impl<'a> Msg<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes(b.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| u64::from_be_bytes(b.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn string(&mut self) -> Option<String> {
        self.bytes().map(|b| String::from_utf8_lossy(b).into_owned())
    }
    fn path(&mut self) -> Option<PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        let b = self.bytes()?;
        // NUL bytes cannot be in paths; refuse instead of cutting the name.
        if b.contains(&0) {
            return None;
        }
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(if b.is_empty() { b"." } else { b })))
    }
    fn attrs(&mut self) -> Option<Attrs> {
        let flags = self.u32()?;
        let mut a = Attrs::default();
        if flags & ATTR_SIZE != 0 {
            a.size = Some(self.u64()?);
        }
        if flags & ATTR_UIDGID != 0 {
            a.ids = Some((self.u32()?, self.u32()?));
        }
        if flags & ATTR_PERMISSIONS != 0 {
            a.perm = Some(self.u32()?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            a.times = Some((self.u32()?, self.u32()?));
        }
        if flags & ATTR_EXTENDED != 0 {
            for _ in 0..self.u32()? {
                self.bytes()?;
                self.bytes()?;
            }
        }
        Some(a)
    }
}

/// Builds an answer.
struct Out(Vec<u8>);

impl Out {
    fn new(kind: u8, id: u32) -> Out {
        let mut v = vec![kind];
        v.extend_from_slice(&id.to_be_bytes());
        Out(v)
    }
    fn u32(mut self, v: u32) -> Out {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(mut self, v: u64) -> Out {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn bytes(mut self, b: &[u8]) -> Out {
        self = self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
        self
    }
    fn str(self, s: &str) -> Out {
        self.bytes(s.as_bytes())
    }
    fn attrs(mut self, m: &fs::Metadata) -> Out {
        self = self.u32(ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME);
        self = self.u64(m.size()).u32(m.uid()).u32(m.gid()).u32(m.mode());
        self.u32(m.atime() as u32).u32(m.mtime() as u32)
    }
}

#[derive(Default)]
struct Attrs {
    size: Option<u64>,
    ids: Option<(u32, u32)>,
    perm: Option<u32>,
    times: Option<(u32, u32)>,
}

fn status(id: u32, code: u32, text: &str) -> Vec<u8> {
    Out::new(R_STATUS, id).u32(code).str(text).str("").0
}

fn io_status(id: u32, e: &io::Error) -> Vec<u8> {
    let code = match e.kind() {
        io::ErrorKind::NotFound => NO_SUCH_FILE,
        io::ErrorKind::PermissionDenied => PERMISSION_DENIED,
        _ => FAILURE,
    };
    status(id, code, &e.to_string())
}

fn ok(id: u32) -> Vec<u8> {
    status(id, OK, "Success")
}

/// `-rw-r--r--    1 alice    staff        1234 Oct  9 12:00 name`, as `ls -l` (for sftp's `ls`).
fn long_name(name: &str, m: &fs::Metadata) -> String {
    use std::os::unix::fs::FileTypeExt;
    let mode = m.mode();
    let t = m.file_type();
    let kind = if t.is_dir() {
        'd'
    } else if t.is_symlink() {
        'l'
    } else if t.is_char_device() {
        'c'
    } else if t.is_block_device() {
        'b'
    } else if t.is_fifo() {
        'p'
    } else if t.is_socket() {
        's'
    } else {
        '-'
    };
    let mut perms = String::from(kind);
    for (i, c) in "rwxrwxrwx".chars().enumerate() {
        let bit = 0o400 >> i;
        perms.push(if mode & bit != 0 { c } else { '-' });
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(m.uid())).ok().flatten().map(|u| u.name);
    let group = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(m.gid())).ok().flatten().map(|g| g.name);
    let when = jiff::Timestamp::from_second(m.mtime())
        .map(|t| t.to_zoned(jiff::tz::TimeZone::try_system().unwrap_or(jiff::tz::TimeZone::UTC)))
        .map(|z| {
            let recent = (jiff::Timestamp::now().as_second() - m.mtime()).abs() < 182 * 86400;
            z.strftime(if recent { "%b %e %H:%M" } else { "%b %e  %Y" }).to_string()
        })
        .unwrap_or_default();
    format!(
        "{perms} {:>4} {:<8} {:<8} {:>8} {when} {name}",
        m.nlink(),
        user.unwrap_or_else(|| m.uid().to_string()),
        group.unwrap_or_else(|| m.gid().to_string()),
        m.size()
    )
}

fn apply_attrs(path: &Path, a: &Attrs, follow: bool) -> io::Result<()> {
    use nix::sys::stat::{utimensat, UtimensatFlags};
    use nix::sys::time::TimeSpec;
    if let Some(size) = a.size {
        OpenOptions::new().write(true).open(path)?.set_len(size)?;
    }
    if let Some(perm) = a.perm {
        if follow || !fs::symlink_metadata(path)?.file_type().is_symlink() {
            fs::set_permissions(path, fs::Permissions::from_mode(perm & 0o7777))?;
        }
    }
    if let Some((uid, gid)) = a.ids {
        let chown = if follow { std::os::unix::fs::chown } else { std::os::unix::fs::lchown };
        chown(path, Some(uid), Some(gid))?;
    }
    if let Some((atime, mtime)) = a.times {
        let flag = if follow { UtimensatFlags::FollowSymlink } else { UtimensatFlags::NoFollowSymlink };
        let t = |s: u32| TimeSpec::new(s as i64, 0);
        utimensat(nix::fcntl::AT_FDCWD, path, &t(atime), &t(mtime), flag).map_err(io::Error::from)?;
    }
    Ok(())
}

impl Server {
    fn handle(&mut self, packet: &[u8]) -> Vec<u8> {
        let mut m = Msg(packet);
        let Some(kind) = m.u8() else { return status(0, BAD_MESSAGE, "empty packet") };
        if kind == INIT {
            let mut out = Out::new(R_VERSION, VERSION);
            for (name, version) in [
                ("posix-rename@openssh.com", "1"),
                ("statvfs@openssh.com", "2"),
                ("fstatvfs@openssh.com", "2"),
                ("hardlink@openssh.com", "1"),
                ("fsync@openssh.com", "1"),
                ("lsetstat@openssh.com", "1"),
                ("limits@openssh.com", "1"),
                ("expand-path@openssh.com", "1"),
                ("home-directory", "1"),
            ] {
                out = out.str(name).str(version);
            }
            return out.0;
        }
        let Some(id) = m.u32() else { return status(0, BAD_MESSAGE, "no request id") };
        self.request(kind, id, &mut m).unwrap_or_else(|| status(id, BAD_MESSAGE, "malformed request"))
    }

    fn writable(&self, id: u32) -> Option<Vec<u8>> {
        self.opts.read_only.then(|| status(id, PERMISSION_DENIED, "read-only server"))
    }

    fn new_handle(&mut self, id: u32, h: Handle) -> Vec<u8> {
        if self.handles.len() >= MAX_HANDLES {
            return status(id, FAILURE, "too many open handles");
        }
        let n = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        self.handles.insert(n, h);
        Out::new(R_HANDLE, id).bytes(&n.to_be_bytes()).0
    }

    fn handle_id(m: &mut Msg) -> Option<u32> {
        let b = m.bytes()?;
        Some(u32::from_be_bytes(b.try_into().ok().unwrap_or([0xff; 4])))
    }

    fn file(&mut self, h: u32) -> Option<&mut File> {
        match self.handles.get_mut(&h) {
            Some(Handle::File(f)) => Some(f),
            _ => None,
        }
    }

    fn request(&mut self, kind: u8, id: u32, m: &mut Msg) -> Option<Vec<u8>> {
        Some(match kind {
            OPEN => {
                let path = m.path()?;
                let flags = m.u32()?;
                let attrs = m.attrs()?;
                if flags & (FXF_WRITE | FXF_APPEND | FXF_CREAT | FXF_TRUNC) != 0 {
                    if let Some(denied) = self.writable(id) {
                        return Some(denied);
                    }
                }
                let mut o = OpenOptions::new();
                o.read(flags & FXF_READ != 0).write(flags & FXF_WRITE != 0).append(flags & FXF_APPEND != 0);
                if flags & FXF_CREAT != 0 {
                    if flags & FXF_EXCL != 0 {
                        o.create_new(true);
                    } else {
                        o.create(true);
                    }
                }
                o.truncate(flags & FXF_TRUNC != 0);
                o.mode(attrs.perm.unwrap_or(0o666) & 0o777);
                match o.open(&path) {
                    Ok(f) if f.metadata().is_ok_and(|md| md.is_dir()) => status(id, FAILURE, "is a directory"),
                    Ok(f) => self.new_handle(id, Handle::File(f)),
                    Err(e) => io_status(id, &e),
                }
            }
            CLOSE => {
                let h = Self::handle_id(m)?;
                match self.handles.remove(&h) {
                    Some(_) => ok(id),
                    None => status(id, FAILURE, "invalid handle"),
                }
            }
            READ => {
                let h = Self::handle_id(m)?;
                let offset = m.u64()?;
                let len = m.u32()?.min(MAX_READ);
                let Some(f) = self.file(h) else { return Some(status(id, FAILURE, "invalid handle")) };
                let mut buf = vec![0u8; len as usize];
                let result = f.seek(SeekFrom::Start(offset)).and_then(|_| {
                    let mut filled = 0;
                    while filled < buf.len() {
                        match f.read(&mut buf[filled..]) {
                            Ok(0) => break,
                            Ok(n) => filled += n,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(e) => return Err(e),
                        }
                    }
                    Ok(filled)
                });
                match result {
                    Ok(0) if len > 0 => status(id, EOF, "End of file"),
                    Ok(n) => Out::new(R_DATA, id).bytes(&buf[..n]).0,
                    Err(e) => io_status(id, &e),
                }
            }
            WRITE => {
                let h = Self::handle_id(m)?;
                let offset = m.u64()?;
                let data = m.bytes()?;
                if let Some(denied) = self.writable(id) {
                    return Some(denied);
                }
                let Some(f) = self.file(h) else { return Some(status(id, FAILURE, "invalid handle")) };
                // Appending files ignore the offset (O_APPEND).
                match f.seek(SeekFrom::Start(offset)).and_then(|_| f.write_all(data)) {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            LSTAT | STAT => {
                let path = m.path()?;
                let meta = if kind == STAT { fs::metadata(&path) } else { fs::symlink_metadata(&path) };
                match meta {
                    Ok(md) => Out::new(R_ATTRS, id).attrs(&md).0,
                    Err(e) => io_status(id, &e),
                }
            }
            FSTAT => {
                let h = Self::handle_id(m)?;
                let meta = match self.handles.get(&h) {
                    Some(Handle::File(f)) => f.metadata(),
                    Some(Handle::Dir { path, .. }) => fs::metadata(path),
                    None => return Some(status(id, FAILURE, "invalid handle")),
                };
                match meta {
                    Ok(md) => Out::new(R_ATTRS, id).attrs(&md).0,
                    Err(e) => io_status(id, &e),
                }
            }
            SETSTAT => {
                let path = m.path()?;
                let attrs = m.attrs()?;
                if let Some(denied) = self.writable(id) {
                    return Some(denied);
                }
                match apply_attrs(&path, &attrs, true) {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            FSETSTAT => {
                let h = Self::handle_id(m)?;
                let attrs = m.attrs()?;
                if let Some(denied) = self.writable(id) {
                    return Some(denied);
                }
                let result = match self.handles.get(&h) {
                    Some(Handle::File(f)) => fsetstat(f, &attrs),
                    Some(Handle::Dir { path, .. }) => apply_attrs(path, &attrs, true),
                    None => return Some(status(id, FAILURE, "invalid handle")),
                };
                match result {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            OPENDIR => {
                let path = m.path()?;
                match fs::read_dir(&path) {
                    Ok(entries) => self.new_handle(id, Handle::Dir { path, entries: Some(entries), dots: true }),
                    Err(e) => io_status(id, &e),
                }
            }
            READDIR => {
                let h = Self::handle_id(m)?;
                let Some(Handle::Dir { path, entries, dots }) = self.handles.get_mut(&h) else {
                    return Some(status(id, FAILURE, "invalid handle"));
                };
                let mut names: Vec<(String, String, fs::Metadata)> = Vec::new();
                if std::mem::take(dots) {
                    for dot in [".", ".."] {
                        if let Ok(md) = fs::symlink_metadata(path.join(dot)) {
                            names.push((dot.into(), long_name(dot, &md), md));
                        }
                    }
                }
                if let Some(it) = entries {
                    for entry in it.by_ref() {
                        let Ok(entry) = entry else { continue };
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if let Ok(md) = fs::symlink_metadata(entry.path()) {
                            names.push((name.clone(), long_name(&name, &md), md));
                        }
                        if names.len() >= DIR_BATCH {
                            break;
                        }
                    }
                    if names.len() < DIR_BATCH {
                        *entries = None;
                    }
                }
                if names.is_empty() {
                    return Some(status(id, EOF, "End of directory"));
                }
                let mut out = Out::new(R_NAME, id).u32(names.len() as u32);
                for (name, long, md) in &names {
                    out = out.str(name).str(long).attrs(md);
                }
                out.0
            }
            REMOVE => {
                let path = m.path()?;
                if let Some(denied) = self.writable(id) {
                    return Some(denied);
                }
                match fs::remove_file(&path) {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            MKDIR => {
                let path = m.path()?;
                let attrs = m.attrs()?;
                if let Some(denied) = self.writable(id) {
                    return Some(denied);
                }
                match fs::DirBuilder::new().mode(attrs.perm.unwrap_or(0o777) & 0o777).create(&path) {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            RMDIR => {
                let path = m.path()?;
                if let Some(denied) = self.writable(id) {
                    return Some(denied);
                }
                match fs::remove_dir(&path) {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            REALPATH => {
                let path = m.path()?;
                match fs::canonicalize(&path) {
                    Ok(p) => name_reply(id, &p),
                    Err(e) => io_status(id, &e),
                }
            }
            RENAME => {
                let (from, to) = (m.path()?, m.path()?);
                if let Some(denied) = self.writable(id) {
                    return Some(denied);
                }
                // SFTP v3 rename does not replace an existing target: as in
                // sftp-server, a new link and then away with the old name
                // (which fails if the target exists, with no window between
                // a check and the rename), else a check and a rename.
                match fs::hard_link(&from, &to) {
                    Ok(()) => match fs::remove_file(&from) {
                        Ok(()) => ok(id),
                        Err(e) => {
                            let _ = fs::remove_file(&to);
                            io_status(id, &e)
                        }
                    },
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => status(id, FAILURE, "target exists"),
                    // Directories, file systems without links...
                    Err(_) if fs::symlink_metadata(&to).is_ok() => status(id, FAILURE, "target exists"),
                    Err(_) => match fs::rename(&from, &to) {
                        Ok(()) => ok(id),
                        Err(e) => io_status(id, &e),
                    },
                }
            }
            READLINK => {
                let path = m.path()?;
                match fs::read_link(&path) {
                    Ok(target) => {
                        use std::os::unix::ffi::OsStrExt;
                        Out::new(R_NAME, id).u32(1).bytes(target.as_os_str().as_bytes()).str("").u32(0).0
                    }
                    Err(e) => io_status(id, &e),
                }
            }
            SYMLINK => {
                // OpenSSH sends the target first (the reverse of the draft).
                let (target, link) = (m.path()?, m.path()?);
                if let Some(denied) = self.writable(id) {
                    return Some(denied);
                }
                match std::os::unix::fs::symlink(&target, &link) {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            EXTENDED => {
                let name = m.string()?;
                self.extended(&name, id, m)?
            }
            _ => status(id, OP_UNSUPPORTED, "operation not supported"),
        })
    }

    fn extended(&mut self, name: &str, id: u32, m: &mut Msg) -> Option<Vec<u8>> {
        let changes = matches!(name, "posix-rename@openssh.com" | "hardlink@openssh.com" | "lsetstat@openssh.com");
        if changes {
            if let Some(denied) = self.writable(id) {
                return Some(denied);
            }
        }
        Some(match name {
            "posix-rename@openssh.com" => {
                let (from, to) = (m.path()?, m.path()?);
                match fs::rename(&from, &to) {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            "hardlink@openssh.com" => {
                let (from, to) = (m.path()?, m.path()?);
                match fs::hard_link(&from, &to) {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            "lsetstat@openssh.com" => {
                let path = m.path()?;
                let attrs = m.attrs()?;
                // As in sftp-server: truncating would go through a symlink.
                if attrs.size.is_some() {
                    return Some(status(id, BAD_MESSAGE, "lsetstat cannot change the size"));
                }
                match apply_attrs(&path, &attrs, false) {
                    Ok(()) => ok(id),
                    Err(e) => io_status(id, &e),
                }
            }
            "fsync@openssh.com" => {
                let h = Self::handle_id(m)?;
                match self.file(h) {
                    Some(f) => match f.sync_all() {
                        Ok(()) => ok(id),
                        Err(e) => io_status(id, &e),
                    },
                    None => status(id, FAILURE, "invalid handle"),
                }
            }
            "statvfs@openssh.com" => {
                let path = m.path()?;
                match nix::sys::statvfs::statvfs(&path) {
                    Ok(v) => statvfs_reply(id, &v),
                    Err(e) => io_status(id, &e.into()),
                }
            }
            "fstatvfs@openssh.com" => {
                let h = Self::handle_id(m)?;
                match self.file(h) {
                    Some(f) => match nix::sys::statvfs::fstatvfs(&*f) {
                        Ok(v) => statvfs_reply(id, &v),
                        Err(e) => io_status(id, &e.into()),
                    },
                    None => status(id, FAILURE, "invalid handle"),
                }
            }
            "limits@openssh.com" => Out::new(R_EXTENDED, id)
                .u64(MAX_PACKET as u64)
                .u64(MAX_READ as u64)
                .u64(MAX_READ as u64)
                .u64(MAX_HANDLES as u64)
                .0,
            "expand-path@openssh.com" => {
                let path = m.string()?;
                let expanded = match expand_tilde(&path) {
                    Some(p) => p,
                    None => return Some(status(id, NO_SUCH_FILE, "no such user")),
                };
                match fs::canonicalize(&expanded) {
                    Ok(p) => name_reply(id, &p),
                    Err(e) => io_status(id, &e),
                }
            }
            "home-directory" => {
                let user = m.string()?;
                match nix::unistd::User::from_name(&user).ok().flatten() {
                    Some(u) => name_reply(id, &u.dir),
                    None => status(id, NO_SUCH_FILE, "no such user"),
                }
            }
            _ => status(id, OP_UNSUPPORTED, "extension not supported"),
        })
    }
}

fn fsetstat(f: &File, a: &Attrs) -> io::Result<()> {
    use nix::sys::stat::futimens;
    use nix::sys::time::TimeSpec;
    if let Some(size) = a.size {
        f.set_len(size)?;
    }
    if let Some(perm) = a.perm {
        f.set_permissions(fs::Permissions::from_mode(perm & 0o7777))?;
    }
    if let Some((uid, gid)) = a.ids {
        std::os::unix::fs::fchown(f, Some(uid), Some(gid))?;
    }
    if let Some((atime, mtime)) = a.times {
        let t = |s: u32| TimeSpec::new(s as i64, 0);
        futimens(f, &t(atime), &t(mtime)).map_err(io::Error::from)?;
    }
    Ok(())
}

/// `~`, `~/x` and `~user/x` as the shell would expand them.
fn expand_tilde(path: &str) -> Option<PathBuf> {
    let Some(rest) = path.strip_prefix('~') else { return Some(PathBuf::from(if path.is_empty() { "." } else { path })) };
    let (user, tail) = rest.split_once('/').unwrap_or((rest, ""));
    let home = if user.is_empty() {
        std::env::var_os("HOME").map(PathBuf::from).or_else(|| nix::unistd::User::from_uid(nix::unistd::getuid()).ok().flatten().map(|u| u.dir))?
    } else {
        nix::unistd::User::from_name(user).ok().flatten()?.dir
    };
    Some(home.join(tail))
}

fn name_reply(id: u32, path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    let attrs_none = 0u32;
    Out::new(R_NAME, id).u32(1).bytes(path.as_os_str().as_bytes()).bytes(path.as_os_str().as_bytes()).u32(attrs_none).0
}

// The field types differ between systems (32 or 64 bits).
#[allow(clippy::unnecessary_cast)]
fn statvfs_reply(id: u32, v: &nix::sys::statvfs::Statvfs) -> Vec<u8> {
    use nix::sys::statvfs::FsFlags;
    let mut flags = 0u64;
    if v.flags().contains(FsFlags::ST_RDONLY) {
        flags |= 1;
    }
    if v.flags().contains(FsFlags::ST_NOSUID) {
        flags |= 2;
    }
    Out::new(R_EXTENDED, id)
        .u64(v.block_size() as u64)
        .u64(v.fragment_size() as u64)
        .u64(v.blocks() as u64)
        .u64(v.blocks_free() as u64)
        .u64(v.blocks_available() as u64)
        .u64(v.files() as u64)
        .u64(v.files_free() as u64)
        .u64(v.files_available() as u64)
        .u64(v.filesystem_id() as u64)
        .u64(flags)
        .u64(v.name_max() as u64)
        .0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(kind: u8, id: u32, fields: &[&[u8]]) -> Vec<u8> {
        let mut v = vec![kind];
        v.extend_from_slice(&id.to_be_bytes());
        for f in fields {
            v.extend_from_slice(f);
        }
        v
    }

    fn s(text: &str) -> Vec<u8> {
        let mut v = (text.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(text.as_bytes());
        v
    }

    fn code(reply: &[u8]) -> u32 {
        assert_eq!(reply[0], R_STATUS, "{reply:?}");
        u32::from_be_bytes(reply[5..9].try_into().unwrap())
    }

    #[test]
    fn file_roundtrip_and_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let p = path.to_str().unwrap();
        let mut srv = Server { opts: Options::default(), handles: HashMap::new(), next_handle: 0 };
        let flags = (FXF_WRITE | FXF_CREAT | FXF_TRUNC).to_be_bytes();
        let reply = srv.handle(&packet(OPEN, 1, &[&s(p), &flags, &0u32.to_be_bytes()]));
        assert_eq!(reply[0], R_HANDLE);
        let handle = &reply[5..];
        let reply = srv.handle(&packet(WRITE, 2, &[handle, &0u64.to_be_bytes(), &s("hello")]));
        assert_eq!(code(&reply), OK);
        assert_eq!(code(&srv.handle(&packet(CLOSE, 3, &[handle]))), OK);
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");

        let reply = srv.handle(&packet(OPEN, 4, &[&s(p), &FXF_READ.to_be_bytes(), &0u32.to_be_bytes()]));
        let handle = reply[5..].to_vec();
        let reply = srv.handle(&packet(READ, 5, &[&handle, &1u64.to_be_bytes(), &100u32.to_be_bytes()]));
        assert_eq!(reply[0], R_DATA);
        assert_eq!(&reply[9..], b"ello");
        let reply = srv.handle(&packet(READ, 6, &[&handle, &5u64.to_be_bytes(), &100u32.to_be_bytes()]));
        assert_eq!(code(&reply), EOF);

        srv.opts.read_only = true;
        assert_eq!(code(&srv.handle(&packet(REMOVE, 7, &[&s(p)]))), PERMISSION_DENIED);
        let reply = srv.handle(&packet(OPEN, 8, &[&s(p), &flags, &0u32.to_be_bytes()]));
        assert_eq!(code(&reply), PERMISSION_DENIED);
        assert!(path.exists());
    }

    #[test]
    fn malformed_requests_get_an_error() {
        let mut srv = Server { opts: Options::default(), handles: HashMap::new(), next_handle: 0 };
        assert_eq!(code(&srv.handle(&packet(OPEN, 1, &[&[0, 0, 0, 9, b'x']]))), BAD_MESSAGE);
        assert_eq!(code(&srv.handle(&packet(STAT, 2, &[&s("a\0b")]))), BAD_MESSAGE);
        assert_eq!(code(&srv.handle(&packet(99, 3, &[]))), OP_UNSUPPORTED);
        assert_eq!(code(&srv.handle(&packet(CLOSE, 4, &[&s("zzzz")]))), FAILURE);
    }

    #[test]
    fn options() {
        let o = Options::parse(&["-R".into(), "-u".into(), "027".into(), "-d".into(), "/srv/%u".into(), "-l".into(), "INFO".into()], "alice", "/home/alice")
            .unwrap();
        assert_eq!(o, Options { read_only: true, umask: Some(0o27), start_dir: Some("/srv/alice".into()) });
        assert!(Options::parse(&["-x".into()], "a", "/").is_err());
    }
}
