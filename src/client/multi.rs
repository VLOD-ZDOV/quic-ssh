//! `qsh multi`: one command on several hosts at once. Each host runs in its
//! own `qsh` (so `--full`, the configs and shared connections apply), with
//! `BatchMode`: nothing can ask questions in parallel. Output lines are
//! prefixed with the host name; a summary of failures comes last.

use std::io::IsTerminal;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::sync::{mpsc, Semaphore};

const COLORS: [u8; 6] = [36, 33, 32, 35, 34, 31];

/// The hosts for `-g` groups and explicit names, without duplicates.
pub fn destinations(groups: &super::groups::Groups, names: &[String], hosts: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for g in names {
        match groups.get(g) {
            Some(members) => out.extend(members.iter().cloned()),
            None => bail!("no group {g:?} (groups are set in `qsh ui` with g, or in ~/.config/qsh/groups)"),
        }
    }
    out.extend(hosts.iter().cloned());
    let mut seen = std::collections::HashSet::new();
    out.retain(|h| seen.insert(h.clone()));
    if out.is_empty() {
        bail!("no hosts given");
    }
    Ok(out)
}

enum Line {
    Out(usize, String),
    Err(usize, String),
}

async fn pump<R: AsyncRead + Unpin>(r: R, i: usize, err: bool, tx: mpsc::UnboundedSender<Line>) {
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                let text = String::from_utf8_lossy(&buf).trim_end_matches(['\n', '\r']).to_string();
                let _ = tx.send(if err { Line::Err(i, text) } else { Line::Out(i, text) });
            }
        }
    }
}

/// Runs `command` on every host in `dests`, at most `parallel` at a time;
/// `flags` go to each `qsh`. Returns 0 if it succeeded everywhere, 255 if a
/// host could not be reached, else 1.
pub async fn run(dests: &[String], command: &[String], parallel: usize, flags: &[String]) -> Result<i32> {
    if command.is_empty() {
        bail!("no command given (qsh multi HOSTS -- COMMAND)");
    }
    let exe = std::env::current_exe()?;
    let width = dests.iter().map(|d| d.chars().count()).max().unwrap_or(0);
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let limit = Arc::new(Semaphore::new(parallel.max(1)));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut tasks = Vec::new();
    for (i, dest) in dests.iter().enumerate() {
        let mut cmd = tokio::process::Command::new(&exe);
        cmd.args(flags)
            .args(["-T", "-n", "-o", "BatchMode=yes", "--", dest])
            .args(command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let (limit, tx) = (limit.clone(), tx.clone());
        tasks.push(tokio::spawn(async move {
            let _permit = limit.acquire_owned().await;
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Line::Err(i, format!("cannot start qsh: {e}")));
                    return 255;
                }
            };
            let out = tokio::spawn(pump(child.stdout.take().expect("piped"), i, false, tx.clone()));
            let err = tokio::spawn(pump(child.stderr.take().expect("piped"), i, true, tx));
            let status = child.wait().await;
            let _ = tokio::join!(out, err);
            status.ok().and_then(|s| s.code()).unwrap_or(255)
        }));
    }
    drop(tx);
    let prefix = |i: usize| {
        let name = format!("{:<width$}", dests[i]);
        if color {
            format!("\x1b[{}m{name}\x1b[0m │ ", COLORS[i % COLORS.len()])
        } else {
            format!("{name} | ")
        }
    };
    while let Some(line) = rx.recv().await {
        match line {
            Line::Out(i, text) => println!("{}{text}", prefix(i)),
            Line::Err(i, text) => eprintln!("{}{text}", prefix(i)),
        }
    }
    let mut codes = Vec::new();
    for t in tasks {
        codes.push(t.await.unwrap_or(255));
    }
    let failed: Vec<(usize, i32)> = codes.iter().copied().enumerate().filter(|&(_, c)| c != 0).collect();
    if failed.is_empty() {
        if dests.len() > 1 {
            eprintln!("ok on all {} hosts", dests.len());
        }
        return Ok(0);
    }
    eprintln!("\nfailed on {} of {} hosts:", failed.len(), dests.len());
    for &(i, code) in &failed {
        let what = if code == 255 { "could not connect or log in".to_string() } else { format!("exit code {code}") };
        eprintln!("  {}: {what}", dests[i]);
    }
    Ok(if failed.iter().any(|&(_, c)| c == 255) { 255 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_from_groups_and_names() {
        let mut g = crate::client::groups::Groups::new();
        g.insert("web".into(), vec!["w1".into(), "w2".into()]);
        g.insert("db".into(), vec!["d1".into(), "w1".into()]);
        let d = destinations(&g, &["web".into(), "db".into()], &["extra".into(), "w2".into()]).unwrap();
        assert_eq!(d, ["w1", "w2", "d1", "extra"]);
        assert!(destinations(&g, &["nope".into()], &[]).is_err());
        assert!(destinations(&g, &[], &[]).is_err());
    }
}
