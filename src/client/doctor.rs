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

/// `host:port`, with IPv6 addresses in brackets.
fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
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
    println!("{} → {}@{}", dest, target.user, endpoint(&target.host, target.port));
    if target.needs_proxy {
        r.line(Level::Note, "proxy", "~/.ssh/config sends this host through ProxyJump/ProxyCommand");
        r.hint("qsh does not connect directly; `qsh --full` hands it to ssh, or set ProxyJump in ~/.config/qsh/config");
        return Ok(());
    }
    let mut fingerprint = None;
    match &target.proxy_jump {
        // Only reachable through the jump hosts: the login step follows them.
        Some(jumps) => r.line(Level::Note, "route", format!("through {jumps} (checked by the login below)")),
        None => match reachability(r, &target).await {
            Some(f) => fingerprint = Some(f),
            None => return Ok(()),
        },
    }
    // The login decides about the host key exactly as `qsh` does (known
    // hosts, certificates, revocations), and never saves a new key.
    let quiet = Target { batch_mode: true, quiet: true, ..target.clone() };
    let opts = ConnectOptions { share: false, accept_new_host: false, ..opts.clone() };
    let start = Instant::now();
    match tokio::time::timeout(STEP_TIMEOUT * 4, super::connect(&quiet, &opts)).await {
        Ok(Ok(conn)) => {
            let took = start.elapsed();
            r.line(Level::Ok, "host key", format!("trusted ({})", conn.peer_key().fingerprint()));
            let ping = super::speed::ping(&conn).await.map(ms).unwrap_or_else(|e| format!("{e:#}"));
            r.line(Level::Ok, "login", format!("as {} over {} in {} (round trip {ping})", target.user, conn.transport_name(), ms(took)));
            if conn.server_version() < crate::proto::VERSION {
                r.line(Level::Note, "qshd", format!("older protocol ({}); update qshd for every feature", conn.server_version()));
            }
            conn.close().await;
        }
        Ok(Err(e)) => {
            let text = format!("{e:#}");
            let first = text.lines().next().unwrap_or_default().to_string();
            if text.contains("host key verification failed") {
                let f = fingerprint.map(|f| format!(" ({f})")).unwrap_or_default();
                r.line(Level::Note, "host key", format!("not known yet{f}; the login was not tried"));
                r.hint(format!("`qsh pair {dest} CODE` (code from `qshd pair` there) confirms it, or connect once and compare"));
            } else if text.contains("HAS CHANGED") || text.contains("revoked") {
                r.line(Level::Bad, "host key", text.lines().find(|l| l.contains("now presents") || l.contains("revoked")).unwrap_or(&first));
                r.hint("if the server was reinstalled, remove its old line from known_hosts; otherwise do not connect");
            } else if e.is::<super::LoginRefused>() || text.contains("access denied") {
                r.line(Level::Bad, "login", first);
                r.hint(format!("add your key there: `qshd pair` on the server, then `qsh pair {dest} CODE`, or ssh-copy-id"));
            } else if text.contains("one-time code") || text.contains("passphrase") || text.contains("terminal") {
                r.line(Level::Note, "login", first);
                r.hint("the login asks a question; that is fine when you connect yourself");
            } else {
                r.line(Level::Bad, "login", first);
            }
        }
        Err(_) => r.line(Level::Bad, "login", "took too long"),
    }
    Ok(())
}

/// Name, QUIC and TCP checks (handshakes with a throwaway key, no login).
/// Returns the host key's fingerprint, or `None` if qshd is not reachable.
async fn reachability(r: &mut Report, target: &Target) -> Option<String> {
    let addrs = match tokio::time::timeout(STEP_TIMEOUT, tokio::net::lookup_host((target.host.as_str(), target.port))).await {
        Ok(Ok(a)) => a.map(|a| a.ip().to_string()).collect::<Vec<_>>(),
        Ok(Err(e)) => {
            r.line(Level::Bad, "name", format!("{}: {e}", target.host));
            r.hint("check the host name (and HostName in your config)");
            return None;
        }
        Err(_) => {
            r.line(Level::Bad, "name", "DNS does not answer");
            return None;
        }
    };
    let mut unique = addrs;
    unique.dedup();
    r.line(Level::Ok, "name", unique.join(", "));
    let tls = crate::tls::client_config(&Identity::generate()).ok()?;
    // With --full, qshd may answer on the ssh port or on its own.
    let ports: Vec<u16> = std::iter::once(target.port).chain(target.alt_ports.iter().copied()).collect();
    let tcp_port = target.alt_ports.first().copied().unwrap_or(target.port);
    let mut found = Vec::new();
    let start = Instant::now();
    let quic = tokio::time::timeout(STEP_TIMEOUT, transport::connect_probe(&target.host, &ports, target.family, &target.bind, |_| tls.clone())).await;
    let quic = match quic {
        Ok(Ok(conn)) => {
            found.push(("quic", format!("qshd answers on udp {} ({})", conn.remote_addr().port(), ms(start.elapsed())), conn.peer_key()));
            conn.close().await;
            None
        }
        Ok(Err(e)) => Some(format!("{e:#}").lines().last().unwrap_or_default().trim().to_string()),
        Err(_) => Some("no answer".to_string()),
    };
    let start = Instant::now();
    let tcp = match tokio::time::timeout(STEP_TIMEOUT, transport::connect(&target.host, tcp_port, Mode::Tcp, target.family, &target.bind, tls)).await {
        Ok(Ok(conn)) => {
            found.push(("tcp", format!("qshd answers on tcp {tcp_port} ({})", ms(start.elapsed())), conn.peer_key()));
            conn.close().await;
            None
        }
        Ok(Err(e)) => Some(format!("{e:#}").lines().last().unwrap_or_default().trim().to_string()),
        Err(_) => Some("no answer".to_string()),
    };
    // One transport is enough: the other one failing is only a note.
    let level = if found.is_empty() { Level::Bad } else { Level::Note };
    for (name, ok, _) in &found {
        r.line(Level::Ok, name, ok);
    }
    if let Some(e) = &quic {
        r.line(level, "quic", e);
    }
    if let Some(e) = &tcp {
        r.line(level, "tcp", e);
    }
    match (quic.is_none(), tcp.is_none()) {
        (false, false) => {
            r.hint(format!("is qshd running there (`systemctl status qshd`), listening on {}, and let through the firewall?", target.port));
            r.hint("a host with only sshd: `qsh --full` uses ssh there");
            return None;
        }
        (false, true) => r.hint(format!("UDP {} is blocked on the way: qsh works over TCP (slower on lossy links); open UDP {} for QUIC", target.port, target.port)),
        (true, false) => r.hint("the TCP fallback is off or blocked; fine while UDP gets through"),
        _ => {}
    }
    found.first().map(|(_, _, key)| key.fingerprint())
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
