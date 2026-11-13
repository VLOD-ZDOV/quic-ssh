//! `qsh cp`: scp-style single-file copies.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{expect_ok, prefix_sha256, write_msg, Reply, Request, ResumeFrom, Transfer};
use crate::transport::{compress, decompress, Conn, RecvHalf, SendHalf};

/// Opens a stream for a transfer request, compressed if asked for and the
/// server can (protocol version 5); returns whether it is compressed.
async fn open(conn: &Conn, request: Transfer, compressed: bool) -> Result<(SendHalf, RecvHalf, bool)> {
    let compressed = compressed && conn.server_version() >= 5;
    if !compressed {
        tracing::debug!("copying without compression");
    }
    let (mut send, recv) = conn.open_bi().await?;
    let request = if compressed { Request::Compressed(request) } else { Request::from(request) };
    write_msg(&mut send, &request).await?;
    Ok((send, recv, compressed))
}

#[derive(Debug, PartialEq)]
pub enum Location {
    Local(PathBuf),
    /// `[user@]host:path`; `dest` is `[user@]host`.
    Remote { dest: String, path: String },
}

impl Location {
    /// Like scp: `host:path` is remote unless a '/' comes before the first ':'.
    pub fn parse(s: &str) -> Location {
        // `C:\dir` and `C:/dir` on Windows are local, as with scp there.
        let b = s.as_bytes();
        if cfg!(windows) && b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/') {
            return Location::Local(crate::platform::local_path(s));
        }
        let colon = if let Some(close) = s.find("]:").filter(|_| s.contains('[')) {
            Some(close + 1)
        } else {
            s.find(':')
        };
        match colon {
            Some(i) if i > 0 && !s[..i].contains('/') => {
                // Remote paths start in the home directory: `~` and `~/` mean
                // it, as with scp (whose remote shell expands them).
                let path = match &s[i + 1..] {
                    "~" => "",
                    p => p.strip_prefix("~/").unwrap_or(p),
                };
                Location::Remote { dest: s[..i].to_string(), path: path.to_string() }
            }
            _ => Location::Local(crate::platform::local_path(s)),
        }
    }
}

/// What the wildcards in remote path `pattern` name on the server, and
/// whether each is a directory. `None` for a path without wildcards, and
/// for an older server, which gets the path as it is.
pub async fn glob(conn: &Conn, pattern: &str) -> Result<Option<Vec<(String, bool)>>> {
    if !crate::pattern::has_wildcard(pattern) || conn.server_version() < crate::proto::GLOB {
        return Ok(None);
    }
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::Glob { pattern: pattern.to_string() }).await?;
    match expect_ok(&mut recv).await? {
        Reply::Matches(found) if found.is_empty() => bail!("{pattern}: no match"),
        Reply::Matches(found) => match found.iter().find(|(path, _)| !named_by(pattern, path)) {
            Some((path, _)) => bail!("the server answered {pattern} with {path:?}, which it does not name"),
            None => Ok(Some(found)),
        },
        other => bail!("unexpected reply {other:?}"),
    }
}

/// Whether `pattern` can name `path`. The names of the files a download
/// writes must be ones the user asked for, never the server's choice: it
/// could send a `.bashrc` for `*.log` (scp's CVE-2019-6111). Case is
/// ignored, as a Windows server does.
fn named_by(pattern: &str, path: &str) -> bool {
    let parts = |s: &str| s.split(['/', '\\']).filter(|p| !p.is_empty()).map(str::to_string).collect::<Vec<_>>();
    let (pattern, path) = (parts(pattern), parts(path));
    pattern.len() == path.len()
        && pattern.iter().zip(&path).all(|(part, name)| {
            let wild = crate::pattern::has_wildcard(part);
            (!wild || !matches!(name.as_str(), "." | "..")) && crate::pattern::part_matches(part, name, true, wild)
        })
}

/// A path without the single quotes around it: cmd.exe hands them on as
/// they are, so a command line written for a Unix shell works there too.
pub fn unquote(path: &str) -> &str {
    path.strip_prefix('\'').and_then(|p| p.strip_suffix('\'')).unwrap_or(path)
}

/// Local sources with their wildcards expanded, for Windows, whose shells
/// leave that to the program. A pattern that matches nothing stays as it is.
pub fn expand_local(sources: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for s in sources {
        let found = match Location::parse(s) {
            Location::Local(path) if crate::pattern::has_wildcard(s) => {
                // `*.*` is every file there, with a dot in its name or not.
                let all = path.file_name().is_some_and(|n| n == "*.*");
                let path = if all { path.with_file_name("*") } else { path };
                crate::pattern::glob(&path.to_string_lossy(), false).unwrap_or_default()
            }
            _ => Vec::new(),
        };
        if found.is_empty() {
            out.push(s.clone());
        } else {
            out.extend(found);
        }
    }
    out
}

/// The SHA-256 of a file's first `n` bytes (`None` if it cannot be read).
async fn prefix_of(path: &Path, n: u64) -> Option<Vec<u8>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || prefix_sha256(std::fs::File::open(path).ok()?, n).ok()).await.ok().flatten()
}

/// Copies `total` bytes, drawing a progress line on stderr when it is a terminal.
async fn transfer<R, W>(r: &mut R, w: &mut W, total: u64, label: &str) -> Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let show = std::io::stderr().is_terminal();
    let start = Instant::now();
    let mut last = start;
    let mut done = 0u64;
    let mut buf = vec![0u8; 256 * 1024];
    let draw = |done: u64, final_line: bool| {
        let secs = start.elapsed().as_secs_f64().max(0.001);
        let pct = (done * 100).checked_div(total).unwrap_or(100);
        eprint!(
            "\r{label}  {pct:3}%  {:>10}  {:>10}/s{}",
            human(done),
            human((done as f64 / secs) as u64),
            if final_line { "\n" } else { "" }
        );
    };
    while done < total {
        let want = buf.len().min((total - done) as usize);
        let n = r.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        done += n as u64;
        if show && last.elapsed() > Duration::from_millis(200) {
            last = Instant::now();
            draw(done, false);
        }
    }
    w.flush().await?;
    if show {
        draw(done, true);
    }
    Ok(done)
}

fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

pub async fn upload(conn: &Conn, local: &Path, remote: &str, compressed: bool) -> Result<()> {
    let mut file = tokio::fs::File::open(local)
        .await
        .with_context(|| format!("cannot open {}", local.display()))?;
    let meta = file.metadata().await?;
    if !meta.is_file() {
        bail!("{} is not a regular file", local.display());
    }
    let name = local.file_name().context("source has no file name")?.to_string_lossy().into_owned();
    let size = meta.len();
    let mode = crate::platform::mode(&meta) & 0o777;
    // A partial copy there from before goes on where it stopped, if its
    // beginning is ours; otherwise the whole file goes again.
    let resume = conn.server_version() >= 8;
    let req = if resume {
        Transfer::UploadResume { path: remote.to_string(), name: name.clone(), size, mode }
    } else {
        Transfer::Upload { path: remote.to_string(), name: name.clone(), size, mode }
    };
    let (mut send, mut recv, compressed) = open(conn, req, compressed).await?;
    let mut offset = 0;
    if resume {
        let Reply::Partial { have, prefix } = expect_ok(&mut recv).await? else { bail!("unexpected reply to an upload") };
        if have > 0 && have <= size && prefix_of(local, have).await.as_deref() == Some(prefix.as_slice()) {
            offset = have;
        }
        write_msg(&mut send, &ResumeFrom { offset }).await?;
        if offset > 0 {
            resuming(&name, offset, size);
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(offset)).await?;
        }
    }
    expect_ok(&mut recv).await?;
    let left = size - offset;
    let mut send = if compressed { compress(send) } else { send };
    let mut answer = answer(recv);
    let sending = async {
        let sent = transfer(&mut file, &mut send, left, &name).await?;
        send.shutdown().await?;
        anyhow::Ok(sent)
    };
    tokio::pin!(sending);
    let changed = || anyhow::anyhow!("{} changed size during the copy", local.display());
    tokio::select! {
        sent = &mut sending => match sent {
            Ok(n) if n != left => Err(changed()),
            Ok(_) => answer.await?,
            Err(e) => Err(server_reason(&mut answer, e).await),
        },
        // The server took it all; only our end of the stream was left to send.
        early = &mut answer => {
            early??;
            if sending.await? != left { Err(changed()) } else { Ok(()) }
        }
    }
}

/// The server's final answer to an upload, read while we send: a server
/// that gives up half-way (a full disk) answers without reading the rest,
/// and over TCP our writes would then wait forever for flow-control credit.
fn answer(mut recv: RecvHalf) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move { expect_ok(&mut recv).await.map(drop) })
}

/// Why sending failed: the server's reason if it gave one, which says more
/// than our write error ("stopped by peer").
async fn server_reason(answer: &mut tokio::task::JoinHandle<Result<()>>, write: anyhow::Error) -> anyhow::Error {
    match tokio::time::timeout(Duration::from_secs(2), answer).await {
        Ok(Ok(Err(server))) => server,
        _ => write,
    }
}

pub async fn download(conn: &Conn, remote: &str, local: &Path, compressed: bool) -> Result<()> {
    let name = Path::new(remote).file_name().context("remote path has no file name")?;
    let target = if local.is_dir() { local.join(name) } else { local.to_path_buf() };
    // A partial copy here from before: the server sends the rest if its
    // beginning matches (and everything otherwise).
    let partial = match std::fs::metadata(&target) {
        Ok(m) if m.is_file() && m.len() > 0 && conn.server_version() >= 8 => prefix_of(&target, m.len()).await.map(|p| (m.len(), p)),
        _ => None,
    };
    let have = partial.as_ref().map(|(o, _)| *o);
    let request = match partial {
        Some((offset, prefix)) => Transfer::DownloadFrom { path: remote.to_string(), offset, prefix },
        None => Transfer::Download { path: remote.to_string() },
    };
    let (_send, mut recv, compressed) = open(conn, request, compressed).await?;
    let (size, mode, start) = match expect_ok(&mut recv).await? {
        Reply::File { size, mode } => (size, mode, 0),
        Reply::FileFrom { size, mode, start } if start <= size && (start == 0 || have == Some(start)) => (size, mode, start),
        other => bail!("unexpected reply {other:?}"),
    };
    if start > 0 {
        resuming(&name.to_string_lossy(), start, size);
    }
    let existed = target.exists();
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(start == 0);
    // Writable by its owner until complete, so an interrupted copy of a
    // read-only file can go on; the mode is set at the end.
    #[cfg(unix)]
    opts.mode(mode & 0o777 | 0o200);
    #[cfg(not(unix))]
    let _ = (mode, existed);
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut opened = opts.open(&target).await;
    // A partial copy left read-only (by an older qsh).
    #[cfg(unix)]
    if start > 0 && opened.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = std::fs::metadata(&target) {
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(m.permissions().mode() | 0o200));
            opened = opts.open(&target).await;
        }
    }
    let mut file = opened.with_context(|| format!("cannot create {}", target.display()))?;
    if start > 0 {
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    let mut recv = if compressed { decompress(recv) } else { recv };
    let got = transfer(&mut recv, &mut file, size - start, &name.to_string_lossy()).await?;
    if got != size - start {
        bail!("transfer interrupted ({} of {size} bytes; run the same copy again to go on)", start + got);
    }
    // A file this copy made: read-only now if it is so on the server.
    #[cfg(unix)]
    if mode & 0o200 == 0 && (!existed || start > 0) {
        use std::os::unix::fs::PermissionsExt;
        let m = file.metadata().await?.permissions().mode();
        file.set_permissions(std::fs::Permissions::from_mode(m & !0o200)).await?;
    }
    Ok(())
}

fn resuming(name: &str, offset: u64, size: u64) {
    tracing::debug!("{name}: going on from byte {offset} of {size}");
    if offset == size {
        eprintln!("{name}: already complete");
    } else if std::io::stderr().is_terminal() {
        eprintln!("{name}: going on from {} of {}", human(offset), human(size));
    }
}

/// `qsh cp -r` upload: sends the contents of `local` as a tar stream.
pub async fn upload_tree(conn: &Conn, local: &Path, remote: &str, compressed: bool) -> Result<()> {
    if !local.is_dir() {
        return upload(conn, local, remote, compressed).await;
    }
    let name = local
        .canonicalize()?
        .file_name()
        .context("source has no directory name")?
        .to_string_lossy()
        .into_owned();
    let (send, mut recv, compressed) = open(conn, Transfer::UploadTree { path: remote.to_string(), name }, compressed).await?;
    expect_ok(&mut recv).await?;
    let send = if compressed { compress(send) } else { send };
    let root = local.to_path_buf();
    let mut answer = answer(recv);
    let mut sending = tokio::task::spawn_blocking(move || -> Result<(crate::tree::Stats, SendHalf)> {
        let mut w = tokio_util::io::SyncIoBridge::new(send);
        let stats = crate::tree::write_tree(&root, &mut w)?;
        w.shutdown()?;
        Ok((stats, w.into_inner()))
    });
    let stats = tokio::select! {
        sent = &mut sending => match sent? {
            Ok((stats, _send)) => {
                answer.await??;
                stats
            }
            Err(e) => return Err(server_reason(&mut answer, e).await),
        },
        // An error stops us here (a blocked writer stays behind until the
        // connection closes); success means only the end was left to send.
        early = &mut answer => {
            early??;
            sending.await??.0
        }
    };
    report(&stats);
    stats.check()
}

/// `qsh cp -r` download: receives the contents of remote directory `remote`.
pub async fn download_tree(conn: &Conn, remote: &str, local: &Path, compressed: bool) -> Result<()> {
    let (send, mut recv, compressed) = open(conn, Transfer::DownloadTree { path: remote.to_string() }, compressed).await?;
    expect_ok(&mut recv).await?;
    drop(send);
    // The rest of the stream, the final status included, is compressed.
    let recv = if compressed { decompress(recv) } else { recv };
    // The name comes from what we asked for, never from the server. Without
    // one (`host:`, `host:.`), the contents go straight into `local`.
    let target = match Path::new(remote.trim_end_matches('/')).file_name() {
        Some(name) => crate::tree::tree_target(local, &name.to_string_lossy())?,
        None => local.to_path_buf(),
    };
    crate::tree::create_target(&target)?;
    let (stats, mut recv) = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut input = crate::tree::Unchunk::new(tokio_util::io::SyncIoBridge::new(recv));
        let stats = crate::tree::extract_tree(&mut input, &target)?;
        Ok((stats, input.finish()?.into_inner()))
    })
    .await??;
    // The server's verdict: the tar stream ends cleanly even if it gave up half-way.
    expect_ok(&mut recv).await.context("copy incomplete")?;
    report(&stats);
    Ok(())
}

fn report(stats: &crate::tree::Stats) {
    if std::io::stderr().is_terminal() {
        eprintln!("{} files, {} directories, {}", stats.files, stats.dirs, human(stats.bytes));
    }
    if stats.skipped > 0 {
        eprintln!("qsh: {} symlinks or special files were skipped", stats.skipped);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_names_only_what_was_asked() {
        assert!(named_by("logs/*.log", "logs/a.log"));
        assert!(named_by("/var/*/app?.log", "/var/x/app1.log"));
        assert!(named_by("Logs\\*.LOG", "Logs\\a.log"));
        assert!(named_by(".*rc", ".bashrc"));
        for bad in [".bashrc", "logs/.bashrc", "logs/a.txt", "other/a.log", "logs/x/a.log", "a.log", "logs/../a.log"] {
            assert!(!named_by("logs/*.log", bad), "{bad}");
        }
        assert!(!named_by("*", ".bashrc") && !named_by("*", "..") && !named_by("*/a", "../a"));
    }

    #[test]
    fn unquoted() {
        assert_eq!(unquote("'host:logs/*.log'"), "host:logs/*.log");
        assert_eq!(unquote("it's"), "it's");
        assert_eq!(unquote("'"), "'");
    }

    #[test]
    fn parse_locations() {
        let remote = |d: &str, p: &str| Location::Remote { dest: d.into(), path: p.into() };
        assert_eq!(Location::parse("alice@example.com:docs/a.txt"), remote("alice@example.com", "docs/a.txt"));
        assert_eq!(Location::parse("example.com:"), remote("example.com", ""));
        assert_eq!(Location::parse("u@[::1]:/tmp/x"), remote("u@[::1]", "/tmp/x"));
        assert_eq!(Location::parse("./a:b"), Location::Local("./a:b".into()));
        assert_eq!(Location::parse("/abs/path"), Location::Local("/abs/path".into()));
        assert_eq!(Location::parse("file.txt"), Location::Local("file.txt".into()));
        if cfg!(windows) {
            assert_eq!(Location::parse(r"C:\Users\a.txt"), Location::Local(r"C:\Users\a.txt".into()));
            assert_eq!(Location::parse("d:/x"), Location::Local("d:/x".into()));
        }
    }
}
