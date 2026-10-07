//! `qsh cp`: scp-style single-file copies.

use std::io::IsTerminal;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{expect_ok, write_msg, Reply, Request};
use crate::transport::Conn;

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

pub async fn upload(conn: &Conn, local: &Path, remote: &str) -> Result<()> {
    let mut file = tokio::fs::File::open(local)
        .await
        .with_context(|| format!("cannot open {}", local.display()))?;
    let meta = file.metadata().await?;
    if !meta.is_file() {
        bail!("{} is not a regular file", local.display());
    }
    let name = local.file_name().context("source has no file name")?.to_string_lossy().into_owned();
    let size = meta.len();
    let (mut send, mut recv) = conn.open_bi().await?;
    let req = Request::Upload { path: remote.to_string(), name: name.clone(), size, mode: meta.mode() & 0o777 };
    write_msg(&mut send, &req).await?;
    expect_ok(&mut recv).await?;
    let sent = transfer(&mut file, &mut send, size, &name).await?;
    send.shutdown().await?;
    if sent != size {
        bail!("{} changed size during the copy", local.display());
    }
    expect_ok(&mut recv).await?;
    Ok(())
}

pub async fn download(conn: &Conn, remote: &str, local: &Path) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::Download { path: remote.to_string() }).await?;
    let (size, mode) = match expect_ok(&mut recv).await? {
        Reply::File { size, mode } => (size, mode),
        other => bail!("unexpected reply {other:?}"),
    };
    let name = Path::new(remote).file_name().context("remote path has no file name")?;
    let target = if local.is_dir() { local.join(name) } else { local.to_path_buf() };
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode & 0o777)
        .open(&target)
        .await
        .with_context(|| format!("cannot create {}", target.display()))?;
    let got = transfer(&mut recv, &mut file, size, &name.to_string_lossy()).await?;
    if got != size {
        bail!("transfer interrupted ({got} of {size} bytes)");
    }
    Ok(())
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
