//! File transfer. The actual file access happens in a helper process running
//! as the user (`qshd internal-recv` / `internal-send`, see `helpers`),
//! started through the user's shell like sshd starts scp and sftp-server.

use std::process::Stdio;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdout};

use super::users::User;
use crate::proto::{write_msg, Reply};
use crate::transport::{RecvHalf, SendHalf};

/// Size of the chunks a tree download is framed in (see [`crate::tree::Unchunk`]).
const CHUNK: usize = 64 * 1024;

fn spawn(user: &User, args: &[&str], stdin: bool) -> Result<Child> {
    Ok(user
        .shell_helper(args)?
        .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

async fn stderr_text(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = (&mut e).take(4096).read_to_string(&mut text).await;
    }
    let text = text.trim().to_string();
    if text.is_empty() { "helper failed".into() } else { text }
}

/// Waits for the helper's "ok" line. Otherwise returns what went wrong: its
/// stderr, or what it printed instead (e.g. nologin's "account not available").
async fn ready(child: &mut Child) -> Result<BufReader<ChildStdout>, String> {
    let mut out = BufReader::new(child.stdout.take().expect("piped"));
    let mut line = String::new();
    let _ = (&mut out).take(4096).read_line(&mut line).await;
    if line.trim() == "ok" {
        return Ok(out);
    }
    let err = stderr_text(child).await;
    let _ = child.wait().await;
    Err(match line.trim() {
        "" => err,
        printed if err == "helper failed" => printed.to_string(),
        printed => format!("{printed}: {err}"),
    })
}

/// Starts a helper and answers the request: `Reply::Ok` once it is ready, or its error.
async fn start(send: &mut SendHalf, user: &User, args: &[&str], stdin: bool) -> Result<Option<(Child, BufReader<ChildStdout>)>> {
    let mut child = match spawn(user, args, stdin) {
        Ok(c) => c,
        Err(e) => {
            write_msg(send, &Reply::Err(format!("cannot start helper: {e:#}"))).await?;
            return Ok(None);
        }
    };
    match ready(&mut child).await {
        Ok(out) => Ok(Some((child, out))),
        Err(e) => {
            write_msg(send, &Reply::Err(e)).await?;
            Ok(None)
        }
    }
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
    let args = ["internal-recv", path, name, &size.to_string(), &format!("{:o}", mode & 0o777)];
    let Some((mut child, _)) = start(&mut send, user, &args, true).await? else { return Ok(()) };
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
    let Some((mut child, mut out)) = start(&mut send, user, &["internal-send", path], false).await? else {
        return Ok(());
    };
    // Header from the helper: size (u64 BE) + mode (u32 BE).
    let mut header = [0u8; 12];
    if out.read_exact(&mut header).await.is_err() {
        let err = stderr_text(&mut child).await;
        write_msg(&mut send, &Reply::Err(err)).await?;
        return Ok(());
    }
    let size = u64::from_be_bytes(header[..8].try_into().unwrap());
    let mode = u32::from_be_bytes(header[8..].try_into().unwrap());
    write_msg(&mut send, &Reply::File { size, mode }).await?;
    tokio::io::copy(&mut out.take(size), &mut send).await?;
    send.shutdown().await?;
    let _ = child.wait().await;
    Ok(())
}

pub async fn upload_tree(mut send: SendHalf, mut recv: RecvHalf, user: &User, path: &str, name: &str) -> Result<()> {
    let Some((mut child, _)) = start(&mut send, user, &["internal-untar", path, name], true).await? else {
        return Ok(());
    };
    write_msg(&mut send, &Reply::Ok).await?;
    let mut stdin = child.stdin.take().expect("piped");
    // The helper may exit right after the end-of-archive marker, before the
    // rest of the trailer arrives, so a failed write alone is not an error:
    // its exit status decides.
    let _ = tokio::io::copy(&mut recv, &mut stdin).await;
    drop(stdin);
    let status = child.wait().await?;
    let reply = if status.success() {
        // Only the rest of the trailer can be left; let the client finish sending it.
        let _ = tokio::io::copy(&mut recv, &mut tokio::io::sink()).await;
        Reply::Ok
    } else {
        Reply::Err(stderr_text(&mut child).await)
    };
    write_msg(&mut send, &reply).await?;
    send.shutdown().await?;
    Ok(())
}

/// Sends the helper's tar stream in chunks, then a final status: a tar stream
/// alone ends cleanly even if the helper failed half-way (unreadable files).
pub async fn download_tree(mut send: SendHalf, user: &User, path: &str) -> Result<()> {
    let Some((mut child, mut out)) = start(&mut send, user, &["internal-tar", path], false).await? else {
        return Ok(());
    };
    write_msg(&mut send, &Reply::Ok).await?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = out.read(&mut buf).await?;
        send.write_all(&(n as u32).to_be_bytes()).await?;
        if n == 0 {
            break;
        }
        send.write_all(&buf[..n]).await?;
    }
    let status = child.wait().await?;
    let reply = if status.success() { Reply::Ok } else { Reply::Err(stderr_text(&mut child).await) };
    write_msg(&mut send, &reply).await?;
    send.shutdown().await?;
    Ok(())
}
