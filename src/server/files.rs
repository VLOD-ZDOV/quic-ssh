//! File transfer. The actual file access happens in a helper process running
//! as the user (`qshd internal-recv` / `internal-send`, see `helpers`).

use std::process::Stdio;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::users::User;
use crate::proto::{write_msg, Reply};
use crate::transport::{RecvHalf, SendHalf};

async fn stderr_text(child: &mut tokio::process::Child) -> String {
    let mut text = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = (&mut e).take(4096).read_to_string(&mut text).await;
    }
    let text = text.trim().to_string();
    if text.is_empty() { "helper failed".into() } else { text }
}

pub async fn upload(
    mut send: SendHalf,
    mut recv: RecvHalf,
    user: &User,
    path: &str,
    name: &str,
    size: u64,
    mode: u32,
) -> Result<()> {
    let mut child = user
        .helper(&["internal-recv", path, name, &size.to_string(), &format!("{:o}", mode & 0o777)])?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // The helper prints "ok" once the destination is open.
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("piped")).read_line(&mut ready).await?;
    if ready.trim() != "ok" {
        let err = stderr_text(&mut child).await;
        write_msg(&mut send, &Reply::Err(err)).await?;
        return Ok(());
    }
    write_msg(&mut send, &Reply::Ok).await?;

    let mut stdin = child.stdin.take().expect("piped");
    let copied = tokio::io::copy(&mut (&mut recv).take(size), &mut stdin).await;
    drop(stdin);
    let status = child.wait().await?;
    let reply = match copied {
        Ok(n) if n == size && status.success() => Reply::Ok,
        Ok(n) if n != size => Reply::Err(format!("transfer interrupted after {n} of {size} bytes")),
        _ => Reply::Err(stderr_text(&mut child).await),
    };
    write_msg(&mut send, &reply).await?;
    send.shutdown().await?;
    Ok(())
}

pub async fn download(mut send: SendHalf, user: &User, path: &str) -> Result<()> {
    let mut child = user
        .helper(&["internal-send", path])?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().expect("piped");
    // Header from the helper: size (u64 BE) + mode (u32 BE).
    let mut header = [0u8; 12];
    if stdout.read_exact(&mut header).await.is_err() {
        let err = stderr_text(&mut child).await;
        write_msg(&mut send, &Reply::Err(err)).await?;
        return Ok(());
    }
    let size = u64::from_be_bytes(header[..8].try_into().unwrap());
    let mode = u32::from_be_bytes(header[8..].try_into().unwrap());
    write_msg(&mut send, &Reply::File { size, mode }).await?;
    tokio::io::copy(&mut stdout.take(size), &mut send).await?;
    send.shutdown().await?;
    let _ = child.wait().await;
    Ok(())
}
