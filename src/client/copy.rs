//! `qsh cp`: scp-style single-file copies.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{expect_ok, write_msg, Reply, Request};
use crate::transport::{compress, decompress, Conn, RecvHalf, SendHalf};

/// Opens a stream for a transfer request, compressed if asked for and the
/// server can (protocol version 5); returns whether it is compressed.
async fn open(conn: &Conn, request: Request, compressed: bool) -> Result<(SendHalf, RecvHalf, bool)> {
    let compressed = compressed && conn.server_version() >= 5;
    if !compressed {
        tracing::debug!("copying without compression");
    }
    let (mut send, recv) = conn.open_bi().await?;
    let request = if compressed { Request::Compressed(Box::new(request)) } else { request };
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
        let colon = if let Some(close) = s.find("]:").filter(|_| s.contains('[')) {
            Some(close + 1)
        } else {
            s.find(':')
        };
        match colon {
            Some(i) if i > 0 && !s[..i].contains('/') => {
                Location::Remote { dest: s[..i].to_string(), path: s[i + 1..].to_string() }
            }
            _ => Location::Local(PathBuf::from(s)),
        }
    }
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
    let req = Request::Upload { path: remote.to_string(), name: name.clone(), size, mode: crate::platform::mode(&meta) & 0o777 };
    let (send, mut recv, compressed) = open(conn, req, compressed).await?;
    expect_ok(&mut recv).await?;
    let mut send = if compressed { compress(send) } else { send };
    let sent = transfer(&mut file, &mut send, size, &name).await?;
    send.shutdown().await?;
    if sent != size {
        bail!("{} changed size during the copy", local.display());
    }
    expect_ok(&mut recv).await?;
    Ok(())
}

pub async fn download(conn: &Conn, remote: &str, local: &Path, compressed: bool) -> Result<()> {
    let (_send, mut recv, compressed) = open(conn, Request::Download { path: remote.to_string() }, compressed).await?;
    let (size, mode) = match expect_ok(&mut recv).await? {
        Reply::File { size, mode } => (size, mode),
        other => bail!("unexpected reply {other:?}"),
    };
    let name = Path::new(remote).file_name().context("remote path has no file name")?;
    let target = if local.is_dir() { local.join(name) } else { local.to_path_buf() };
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(mode & 0o777);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = opts.open(&target).await.with_context(|| format!("cannot create {}", target.display()))?;
    let mut recv = if compressed { decompress(recv) } else { recv };
    let got = transfer(&mut recv, &mut file, size, &name.to_string_lossy()).await?;
    if got != size {
        bail!("transfer interrupted ({got} of {size} bytes)");
    }
    Ok(())
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
    let (send, mut recv, compressed) = open(conn, Request::UploadTree { path: remote.to_string(), name }, compressed).await?;
    expect_ok(&mut recv).await?;
    let send = if compressed { compress(send) } else { send };
    let root = local.to_path_buf();
    let sent = tokio::task::spawn_blocking(move || -> Result<(crate::tree::Stats, SendHalf)> {
        let mut w = tokio_util::io::SyncIoBridge::new(send);
        let stats = crate::tree::write_tree(&root, &mut w)?;
        w.shutdown()?;
        Ok((stats, w.into_inner()))
    })
    .await?;
    match sent {
        Ok((stats, _send)) => {
            expect_ok(&mut recv).await?;
            report(&stats);
            Ok(())
        }
        // If the server gave up, its reason is more useful than our write error.
        Err(e) => match tokio::time::timeout(std::time::Duration::from_secs(2), expect_ok(&mut recv)).await {
            Ok(Err(server)) => Err(server),
            _ => Err(e),
        },
    }
}

/// `qsh cp -r` download: receives the contents of remote directory `remote`.
pub async fn download_tree(conn: &Conn, remote: &str, local: &Path, compressed: bool) -> Result<()> {
    let (send, mut recv, compressed) = open(conn, Request::DownloadTree { path: remote.to_string() }, compressed).await?;
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
    fn parse_locations() {
        let remote = |d: &str, p: &str| Location::Remote { dest: d.into(), path: p.into() };
        assert_eq!(Location::parse("alice@example.com:docs/a.txt"), remote("alice@example.com", "docs/a.txt"));
        assert_eq!(Location::parse("example.com:"), remote("example.com", ""));
        assert_eq!(Location::parse("u@[::1]:/tmp/x"), remote("u@[::1]", "/tmp/x"));
        assert_eq!(Location::parse("./a:b"), Location::Local("./a:b".into()));
        assert_eq!(Location::parse("/abs/path"), Location::Local("/abs/path".into()));
        assert_eq!(Location::parse("file.txt"), Location::Local("file.txt".into()));
    }
}
