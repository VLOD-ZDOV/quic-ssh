//! `qsh doctor [host]`: checks the local setup and, for a host, each step of
//! connecting (name, QUIC, TCP, host key, login), with a hint for whatever
//! does not work.

use std::io::IsTerminal;
use std::time::{Duration, Instant};

use anyhow::Result;

use super::{ConnectOptions, Target};
use crate::keys::{home_dir, qsh_dir, Identity};
use crate::transport::{self, Mode};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq)]
enum Level {
    Ok,
    Note,
    Bad,
}

struct Report {
    color: bool,
    failed: bool,
}

impl Report {
    fn line(&mut self, level: Level, what: &str, detail: impl AsRef<str>) {
        let (mark, code) = match level {
            Level::Ok => ("✓", "32"),
            Level::Note => ("!", "33"),
            Level::Bad => ("✗", "31"),
        };
        self.failed |= level == Level::Bad;
        if self.color {
            println!("  \x1b[{code}m{mark}\x1b[0m {what:<12} {}", detail.as_ref());
        } else {
            println!("  {mark} {what:<12} {}", detail.as_ref());
        }
    }

    fn hint(&self, text: impl AsRef<str>) {
        if self.color {
            println!("                 \x1b[2m→ {}\x1b[0m", text.as_ref());
        } else {
            println!("                 → {}", text.as_ref());
        }
    }
}

fn ms(d: Duration) -> String {
    format!("{:.0} ms", d.as_secs_f64() * 1000.0)
}

async fn local(r: &mut Report) -> Result<()> {
    let home = home_dir()?;
    println!("This computer");
    let candidates = [home.join(".ssh/id_ed25519"), qsh_dir(&home).join("id_ed25519")];
    match candidates.iter().find(|p| p.exists()) {
        Some(p) if Identity::is_ed25519_file(p) => r.line(Level::Ok, "key", p.display().to_string()),
        Some(p) => r.line(Level::Note, "key", format!("{} is not an Ed25519 key qsh can use for TLS", p.display())),
        None => {
            r.line(Level::Note, "key", "no ~/.ssh/id_ed25519 or ~/.config/qsh/id_ed25519");
            r.hint("keys from ssh-agent and other key files still work; `qsh keygen` creates one");
        }
    }
    match crate::agent::Agent::from_env().await {
        Some(mut agent) => match agent.keys().await {
            Ok(keys) => r.line(Level::Ok, "ssh-agent", format!("{} key(s)", keys.len())),
            Err(e) => r.line(Level::Note, "ssh-agent", format!("not usable: {e:#}")),
        },
        None => r.line(Level::Note, "ssh-agent", "none (SSH_AUTH_SOCK is not set)"),
    }
    let aliases = super::config::host_aliases(&home);
    let files: Vec<String> = [qsh_dir(&home).join("config"), home.join(".ssh/config"), qsh_dir(&home).join(super::config::UI_HOSTS)]
        .iter()
        .filter(|p| p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if files.is_empty() {
        r.line(Level::Ok, "config", "no config files (not needed)");
    } else {
        r.line(Level::Ok, "config", format!("{} host(s) in {}", aliases.len(), files.join(", ")));
    }
    Ok(())
}

async fn host(r: &mut Report, dest: &str, port: Option<u16>, opts: &ConnectOptions) -> Result<()> {
    println!();
    let target = match Target::parse(dest, port, opts.full) {
        Ok(t) => t,
        Err(e) => {
            r.line(Level::Bad, "destination", format!("{e:#}"));
            return Ok(());
        }
    };
    println!("{} → {}@{}:{}", dest, target.user, target.host, target.port);
    if target.needs_proxy {
        r.line(Level::Note, "proxy", "~/.ssh/config sends this host through ProxyJump/ProxyCommand");
        r.hint("qsh does not connect directly; `qsh --full` hands it to ssh, or set ProxyJump in ~/.config/qsh/config");
        return Ok(());
    }
    let addrs = match tokio::time::timeout(STEP_TIMEOUT, tokio::net::lookup_host((target.host.as_str(), target.port))).await {
        Ok(Ok(a)) => a.map(|a| a.ip().to_string()).collect::<Vec<_>>(),
        Ok(Err(e)) => {
            r.line(Level::Bad, "name", format!("{}: {e}", target.host));
            r.hint("check the host name (and HostName in your config)");
            return Ok(());
        }
        Err(_) => {
            r.line(Level::Bad, "name", "DNS does not answer");
            return Ok(());
        }
    };
    let mut unique = addrs.clone();
    unique.dedup();
    r.line(Level::Ok, "name", unique.join(", "));

    // Handshakes with a throwaway key: is qshd there, over which transport?
    let tls = crate::tls::client_config(&Identity::generate())?;
    let mut peer = None;
    let mut reachable = Vec::new();
    for (mode, name) in [(Mode::Quic, "quic"), (Mode::Tcp, "tcp")] {
        let start = Instant::now();
        match tokio::time::timeout(STEP_TIMEOUT, transport::connect(&target.host, target.port, mode, target.family, tls.clone())).await {
            Ok(Ok(conn)) => {
                r.line(Level::Ok, name, format!("qshd answers on {} {} ({})", if mode == Mode::Quic { "udp" } else { "tcp" }, target.port, ms(start.elapsed())));
                peer = Some(conn.peer_key());
                reachable.push(mode);
                conn.close().await;
            }
            Ok(Err(e)) => r.line(Level::Bad, name, format!("{e:#}").lines().last().unwrap_or_default().trim()),
            Err(_) => r.line(Level::Bad, name, "no answer"),
        }
    }
    match reachable.as_slice() {
        [] => {
            r.hint(format!("is qshd running there (`systemctl status qshd`), listening on {}, and let through the firewall?", target.port));
            r.hint("a host with only sshd: `qsh --full` uses ssh there");
            return Ok(());
        }
        [Mode::Tcp] => r.hint(format!("UDP {} is blocked on the way: qsh works over TCP (slower on lossy links); open UDP {} for QUIC", target.port, target.port)),
        [Mode::Quic] => r.hint("TCP fallback is off or blocked; fine while UDP gets through"),
        _ => {}
    }
    let Some(key) = peer else { return Ok(()) };
    match super::known_host_key(&target.host, target.port) {
        Ok(Some(k)) if k == key => r.line(Level::Ok, "host key", format!("known ({})", key.fingerprint())),
        Ok(Some(k)) => {
            r.line(Level::Bad, "host key", format!("CHANGED: now {}, known as {}", key.fingerprint(), k.fingerprint()));
            r.hint("if the server was reinstalled, remove its line from ~/.config/qsh/known_hosts; otherwise do not connect");
            return Ok(());
        }
        _ => {
            r.line(Level::Note, "host key", format!("not known yet ({})", key.fingerprint()));
            r.hint(format!("`qsh pair {dest} CODE` (code from `qshd pair` there) confirms it, or connect once and compare"));
            return Ok(());
        }
    }
    let quiet = Target { batch_mode: true, quiet: true, ..target.clone() };
    let start = Instant::now();
    let login = tokio::time::timeout(STEP_TIMEOUT * 4, super::connect(&quiet, &ConnectOptions { share: false, ..opts.clone() })).await;
    match login {
        Ok(Ok(conn)) => {
            let took = start.elapsed();
            let ping = super::speed::ping(&conn).await.map(ms).unwrap_or_else(|e| format!("{e:#}"));
            r.line(Level::Ok, "login", format!("as {} over {} in {} (round trip {ping})", target.user, conn.transport_name(), ms(took)));
            if conn.server_version() < crate::proto::VERSION {
                r.line(Level::Note, "qshd", format!("older protocol ({}); update qshd for every feature", conn.server_version()));
            }
            conn.close().await;
        }
        Ok(Err(e)) => {
            let text = format!("{e:#}");
            r.line(Level::Bad, "login", text.lines().next().unwrap_or_default());
            if e.is::<super::LoginRefused>() || text.contains("access denied") {
                r.hint(format!("add your key there: `qshd pair` on the server, then `qsh pair {dest} CODE`, or ssh-copy-id"));
            } else if text.contains("one-time code") || text.contains("passphrase") || text.contains("terminal") {
                r.hint("the login asks a question; that is fine when you connect yourself");
            }
        }
        Err(_) => r.line(Level::Bad, "login", "took too long"),
    }
    Ok(())
}

/// Runs the checks; the exit code is 1 if something is broken.
pub async fn run(dest: Option<&str>, port: Option<u16>, opts: &ConnectOptions) -> Result<i32> {
    let mut r = Report { color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(), failed: false };
    local(&mut r).await?;
    if let Some(d) = dest {
        host(&mut r, d, port, opts).await?;
    }
    Ok(if r.failed { 1 } else { 0 })
}
