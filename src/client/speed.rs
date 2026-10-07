//! Latency and throughput measurements over an open connection.

use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::proto::{expect_ok, write_msg, Reply, Request};
use crate::transport::Conn;

/// Upper bound on what one test asks the server to send or receive.
const MAX_BYTES: u64 = 4 << 30;
const CHUNK: usize = 256 * 1024;
const REPORT_EVERY: Duration = Duration::from_millis(100);

/// One round trip on a fresh stream (what a new command or forward costs).
pub async fn ping(conn: &Conn) -> Result<Duration> {
    let start = Instant::now();
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::Ping).await?;
    expect_ok(&mut recv).await?;
    Ok(start.elapsed())
}

/// Megabits per second for `bytes` in `elapsed`.
pub fn mbps(bytes: u64, elapsed: Duration) -> f64 {
    bytes as f64 * 8.0 / 1e6 / elapsed.as_secs_f64().max(1e-6)
}

/// Downloads from the server for about `duration`. `progress(bytes, elapsed)`
/// is called every 100 ms. Returns the total bytes and time.
pub async fn download(conn: &Conn, duration: Duration, mut progress: impl FnMut(u64, Duration)) -> Result<(u64, Duration)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::SpeedDown { bytes: MAX_BYTES }).await?;
    expect_ok(&mut recv).await?;
    let start = Instant::now();
    let mut last = start;
    let mut total = 0u64;
    let mut buf = vec![0u8; CHUNK];
    while start.elapsed() < duration {
        let n = recv.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if last.elapsed() >= REPORT_EVERY {
            last = Instant::now();
            progress(total, start.elapsed());
        }
    }
    // Dropping the stream tells the server to stop sending.
    Ok((total, start.elapsed()))
}

/// Uploads to the server for about `duration`; the result counts only bytes
/// the server confirmed receiving.
pub async fn upload(conn: &Conn, duration: Duration, mut progress: impl FnMut(u64, Duration)) -> Result<(u64, Duration)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::SpeedUp { bytes: MAX_BYTES }).await?;
    expect_ok(&mut recv).await?;
    let start = Instant::now();
    let mut last = start;
    let mut sent = 0u64;
    let buf = vec![0u8; CHUNK];
    while start.elapsed() < duration {
        send.write_all(&buf).await?;
        sent += buf.len() as u64;
        if last.elapsed() >= REPORT_EVERY {
            last = Instant::now();
            progress(sent, start.elapsed());
        }
    }
    send.shutdown().await?;
    match expect_ok(&mut recv).await? {
        Reply::File { size, .. } => Ok((size, start.elapsed())),
        other => bail!("unexpected reply {other:?}"),
    }
}
