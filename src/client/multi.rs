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
            None => {
                let known: Vec<&str> = groups.keys().map(String::as_str).collect();
                let have = if known.is_empty() { "there are none yet".to_string() } else { format!("there are: {}", known.join(", ")) };
                bail!("no group {g:?}; {have} (set them in `qsh ui` with e, or in ~/.config/qsh/groups)")
            }
        }
    }
    out.extend(hosts.iter().cloned());
    let mut seen = std::collections::HashSet::new();
    out.retain(|h| seen.insert(h.clone()));
    if out.is_empty() {
        bail!("no hosts given (qsh multi [-g GROUP] [HOST...] -- COMMAND)");
    }
    Ok(out)
}

enum Line {
    Out(usize, String),
    Err(usize, String),
}

/// How one host's run ended.
#[derive(Clone, Copy, PartialEq)]
enum End {
    Code(i32),
    Signal,
    /// qsh could not even be started.
    NotStarted,
}

async fn pump<R: AsyncRead + Unpin>(r: R, i: usize, err: bool, tx: mpsc::UnboundedSender<Line>) {
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                // No control characters (tabs aside): a `\r` or an escape
                // sequence could overwrite the prefix, posing as another host.
                let text: String = String::from_utf8_lossy(&buf)
                    .trim_end_matches(['\n', '\r'])
                    .chars()
                    .filter(|&c| c == '\t' || !c.is_control())
                    .collect();
                let _ = tx.send(if err { Line::Err(i, text) } else { Line::Out(i, text) });
            }
        }
    }
}

/// Runs `command` on every host in `dests`, at most `parallel` at a time;
/// `flags` go to each `qsh`. Returns 0 if it succeeded everywhere, 255 if a
/// host could not be reached, else 1.
pub async fn run(dests: &[String], command: &[String], parallel: usize, flags: &[String]) -> Result<i32> {
    let jobs: Vec<(String, Vec<String>)> = dests.iter().map(|d| (d.clone(), flags.to_vec())).collect();
    run_each(&jobs, command, parallel).await
}

/// Like [`run`], with flags of its own for each host (`qsh ui` passes each
/// host's preferences).
pub async fn run_each(jobs: &[(String, Vec<String>)], command: &[String], parallel: usize) -> Result<i32> {
    let dests: Vec<String> = jobs.iter().map(|(d, _)| d.clone()).collect();
    let dests = dests.as_slice();
    if command.is_empty() {
        bail!("no command given (qsh multi HOSTS -- COMMAND)");
    }
    let exe = std::env::current_exe()?;
    let width = dests.iter().map(|d| d.chars().count()).max().unwrap_or(0);
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    // Bounded: tokio's semaphore panics above its maximum.
    let limit = Arc::new(Semaphore::new(parallel.clamp(1, 256)));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut tasks = Vec::new();
    for (i, (dest, flags)) in jobs.iter().enumerate() {
        let mut cmd = tokio::process::Command::new(&exe);
        cmd.args(flags)
            .args(["-T", "-n", "-o", "BatchMode=yes", "--", dest])
            // One hint in the summary instead of one per host.
            .env("QSH_NO_DOCTOR_HINT", "1")
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
                    return End::NotStarted;
                }
            };
            let out = tokio::spawn(pump(child.stdout.take().expect("piped"), i, false, tx.clone()));
            let err = tokio::spawn(pump(child.stderr.take().expect("piped"), i, true, tx));
            let status = child.wait().await;
            let _ = tokio::join!(out, err);
            match status.ok().map(|s| s.code()) {
                Some(Some(code)) => End::Code(code),
                Some(None) => End::Signal,
                None => End::NotStarted,
            }
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
    {
        use std::io::Write;
        let (mut out, mut err) = (std::io::stdout().lock(), std::io::stderr().lock());
        while let Some(line) = rx.recv().await {
            let written = match line {
                Line::Out(i, text) => writeln!(out, "{}{text}", prefix(i)),
                Line::Err(i, text) => writeln!(err, "{}{text}", prefix(i)),
            };
            // The reader went away (`| head`): stop; the children end with us.
            if written.is_err() {
                return Ok(1);
            }
        }
    }
    let mut ends = Vec::new();
    for t in tasks {
        ends.push(t.await.unwrap_or(End::NotStarted));
    }
    let failed: Vec<(usize, End)> = ends.iter().copied().enumerate().filter(|&(_, e)| e != End::Code(0)).collect();
    if failed.is_empty() {
        if dests.len() > 1 {
            eprintln!("ok on all {} hosts", dests.len());
        }
        return Ok(0);
    }
    eprintln!("\nfailed on {} of {} hosts:", failed.len(), dests.len());
    for &(i, end) in &failed {
        let what = match end {
            End::Code(255) => "exit code 255: could not connect or log in (or the command itself exited 255)".to_string(),
            End::Code(code) => format!("exit code {code}"),
            End::Signal => "qsh was killed by a signal".to_string(),
            End::NotStarted => "qsh could not be started".to_string(),
        };
        eprintln!("  {}: {what}", dests[i]);
    }
    // Not the command failing, but qsh: the host may not be reachable.
    let broken = |e: End| matches!(e, End::Code(255) | End::Signal | End::NotStarted);
    if let Some(&(i, _)) = failed.iter().find(|&&(_, e)| broken(e)) {
        eprintln!("`qsh doctor {}` shows why a host cannot be reached", dests[i]);
    }
    Ok(if failed.iter().any(|&(_, e)| broken(e)) { 255 } else { 1 })
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
