//! Port forwarding: local (`-L`), remote (`-R`), dynamic SOCKS (`-D`) and
//! stdio (`-W`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::proto::{expect_ok, read_msg, write_msg, Opened, Reply, Request};
use crate::transport::{Conn, RecvHalf, SendHalf};

#[derive(Debug, Clone, PartialEq)]
pub struct Forward {
    /// Listen address; `None` means the default (loopback, or all with `-g`).
    pub bind: Option<String>,
    pub port: u16,
    pub host: String,
    pub host_port: u16,
}

/// Splits on ':' while keeping `[v6:addr]` together and unbracketed.
fn split_spec(s: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('[') {
            let (inner, after) = r.split_once(']').context("unclosed '['")?;
            parts.push(inner.to_string());
            rest = after.strip_prefix(':').unwrap_or(after);
        } else {
            let (p, after) = rest.split_once(':').unwrap_or((rest, ""));
            parts.push(p.to_string());
            rest = after;
        }
    }
    Ok(parts)
}

fn parse_port(p: &str, spec: &str) -> Result<u16> {
    p.parse::<u16>().with_context(|| format!("invalid port {p:?} in {spec:?}"))
}

impl Forward {
    /// `[bind:]port:host:hostport` (`-L` and `-R`).
    pub fn parse(s: &str) -> Result<Forward> {
        let parts = split_spec(s)?;
        let (bind, rest) = match parts.len() {
            3 => (None, &parts[..]),
            4 => (Some(parts[0].clone()), &parts[1..]),
            _ => bail!("expected [bind_address:]port:host:hostport, got {s:?}"),
        };
        Ok(Forward { bind, port: parse_port(&rest[0], s)?, host: rest[1].clone(), host_port: parse_port(&rest[2], s)? })
    }

    pub fn describe(&self) -> String {
        format!("{}:{}:{}", self.port, self.host, self.host_port)
    }
}

/// `[bind:]port` (`-D`).
pub fn parse_dynamic(s: &str) -> Result<(Option<String>, u16)> {
    let parts = split_spec(s)?;
    match parts.as_slice() {
        [p] => Ok((None, parse_port(p, s)?)),
        [b, p] => Ok((Some(b.clone()), parse_port(p, s)?)),
        _ => bail!("expected [bind_address:]port, got {s:?}"),
    }
}

/// Binds local listeners. The default (and `localhost`) means loopback, both
/// IPv4 and IPv6; `-g`, `*` or an empty address mean every interface.
async fn bind_local(bind: Option<&str>, port: u16, gateway: bool) -> Result<Vec<TcpListener>> {
    let any = || vec![SocketAddr::from(([0u8; 4], port)), SocketAddr::from(([0u16; 8], port))];
    let addrs: Vec<SocketAddr> = match bind {
        None if gateway => any(),
        None => vec![SocketAddr::from(([127, 0, 0, 1], port)), SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], port))],
        Some("" | "*") => any(),
        Some(b) => tokio::net::lookup_host((b, port)).await.with_context(|| format!("cannot resolve {b}"))?.collect(),
    };
    let mut listeners = Vec::new();
    let mut last_err = None;
    for addr in addrs {
        match TcpListener::bind(addr).await {
            Ok(l) => listeners.push(l),
            Err(e) => last_err = Some(e),
        }
    }
    match (listeners.is_empty(), last_err) {
        (true, Some(e)) => Err(e).with_context(|| format!("cannot listen on port {port}")),
        (true, None) => bail!("no address to listen on for port {port}"),
        _ => Ok(listeners),
    }
}

/// Opens a `DirectTcp` stream through the server.
pub async fn open_direct(conn: &Conn, host: &str, port: u16) -> Result<(SendHalf, RecvHalf)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Request::DirectTcp { host: host.to_string(), port }).await?;
    expect_ok(&mut recv).await?;
    Ok((send, recv))
}

/// `-L`: listens locally and forwards each connection through the server.
pub async fn start_local(conn: Arc<Conn>, fwd: Forward, gateway: bool) -> Result<()> {
    for listener in bind_local(fwd.bind.as_deref(), fwd.port, gateway).await? {
        let (conn, fwd) = (conn.clone(), fwd.clone());
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = listener.accept().await {
                let _ = tcp.set_nodelay(true);
                let (conn, fwd) = (conn.clone(), fwd.clone());
                tokio::spawn(async move {
                    let result = async {
                        let (send, recv) = open_direct(&conn, &fwd.host, fwd.host_port).await?;
                        crate::transport::splice(tcp, send, recv).await
                    }
                    .await;
                    match result {
                        Ok(()) => debug!("forward from {peer} closed"),
                        Err(e) => warn!("forward {}:{} failed: {e:#}", fwd.host, fwd.host_port),
                    }
                });
            }
        });
    }
    Ok(())
}

/// `-D`: a local SOCKS4/4a/5 proxy whose connections go out from the server.
pub async fn start_dynamic(conn: Arc<Conn>, spec: &str, gateway: bool) -> Result<()> {
    let (bind, port) = parse_dynamic(spec)?;
    for listener in bind_local(bind.as_deref(), port, gateway).await? {
        let conn = conn.clone();
        tokio::spawn(async move {
            while let Ok((mut tcp, peer)) = listener.accept().await {
                let _ = tcp.set_nodelay(true);
                let conn = conn.clone();
                tokio::spawn(async move {
                    let result = async {
                        let req = super::socks::accept(&mut tcp).await?;
                        match open_direct(&conn, &req.host, req.port).await {
                            Ok((send, recv)) => {
                                req.reply(&mut tcp, true).await?;
                                crate::transport::splice(tcp, send, recv).await
                            }
                            Err(e) => {
                                let _ = req.reply(&mut tcp, false).await;
                                Err(e.context(format!("{}:{}", req.host, req.port)))
                            }
                        }
                    }
                    .await;
                    if let Err(e) = result {
                        debug!("SOCKS client {peer}: {e:#}");
                    }
                });
            }
        });
    }
    Ok(())
}

/// Active `-R` forwards and agent forwarding; dropping this cancels them.
pub struct RemoteForwards {
    _requests: Vec<(SendHalf, RecvHalf)>,
}

/// `-A`: asks the server to offer the local agent at `agent` to its sessions.
/// Problems are warnings, as in ssh: the session works without the agent.
async fn request_agent(conn: &Conn, quiet: bool) -> Option<(SendHalf, RecvHalf)> {
    if conn.server_version() < 4 {
        if !quiet {
            eprintln!("qsh: warning: the server's qshd is too old for agent forwarding (-A)");
        }
        return None;
    }
    let attempt = async {
        let (mut send, mut recv) = conn.open_bi().await?;
        write_msg(&mut send, &Request::AgentForward).await?;
        expect_ok(&mut recv).await?;
        anyhow::Ok((send, recv))
    };
    match attempt.await {
        Ok(streams) => Some(streams),
        Err(e) => {
            if !quiet {
                eprintln!("qsh: warning: agent forwarding refused: {e:#}");
            }
            None
        }
    }
}

/// `-R`: asks the server to listen and serves the connections it hands back.
/// With `agent` (`-A`), also forwards that ssh-agent socket.
pub async fn start_remote(conn: &Arc<Conn>, forwards: &[Forward], agent: Option<PathBuf>, quiet: bool) -> Result<RemoteForwards> {
    let mut routes = HashMap::new();
    let mut requests = Vec::new();
    for f in forwards {
        let (mut send, mut recv) = conn.open_bi().await?;
        write_msg(&mut send, &Request::RemoteForward { bind: f.bind.clone().unwrap_or_default(), port: f.port }).await?;
        match expect_ok(&mut recv).await.with_context(|| format!("remote forward {}", f.describe()))? {
            Reply::Bound { port } => {
                if f.port == 0 && !quiet {
                    eprintln!("Allocated port {port} for remote forward to {}:{}", f.host, f.host_port);
                }
                routes.insert(port, (f.host.clone(), f.host_port));
            }
            other => bail!("unexpected reply {other:?}"),
        }
        requests.push((send, recv));
    }
    let agent = match agent {
        Some(path) => match request_agent(conn, quiet).await {
            Some(streams) => {
                requests.push(streams);
                Some(Arc::new(path))
            }
            None => None,
        },
        None => None,
    };
    if routes.is_empty() && agent.is_none() {
        return Ok(RemoteForwards { _requests: requests });
    }
    let routes = Arc::new(routes);
    let conn = conn.clone();
    tokio::spawn(async move {
        while let Some((send, mut recv)) = conn.accept_bi().await {
            let (routes, agent) = (routes.clone(), agent.clone());
            tokio::spawn(async move {
                let (port, origin) = match read_msg(&mut recv).await {
                    Ok(Opened::Forwarded { port, origin }) => (port, origin),
                    // Only if we asked for it: a server cannot reach our agent on its own.
                    Ok(Opened::Agent) => {
                        let Some(path) = agent else { return };
                        match crate::agent::connect_raw(path.as_path()).await {
                            Ok(sock) => {
                                let (r, w) = tokio::io::split(sock);
                                let _ = crate::transport::bridge(r, w, send, recv).await;
                            }
                            Err(e) => warn!("forwarded agent: {e}"),
                        }
                        return;
                    }
                    Err(_) => return,
                };
                let Some((host, host_port)) = routes.get(&port) else { return };
                match TcpStream::connect((host.as_str(), *host_port)).await {
                    Ok(tcp) => {
                        let _ = tcp.set_nodelay(true);
                        if let Err(e) = crate::transport::splice(tcp, send, recv).await {
                            debug!("remote forward from {origin}: {e:#}");
                        }
                    }
                    Err(e) => warn!("remote forward to {host}:{host_port} failed: {e}"),
                }
            });
        }
    });
    Ok(RemoteForwards { _requests: requests })
}

/// `-W host:port`: connects stdin/stdout to `host:port` through the server.
pub async fn stdio(conn: &Conn, spec: &str) -> Result<()> {
    let parts = split_spec(spec)?;
    let [host, port] = parts.as_slice() else { bail!("-W expects host:port, got {spec:?}") };
    let (send, recv) = open_direct(conn, host, parse_port(port, spec)?).await?;
    crate::transport::bridge(tokio::io::stdin(), tokio::io::stdout(), send, recv).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_specs() {
        let f = Forward::parse("8080:localhost:80").unwrap();
        assert_eq!(f, Forward { bind: None, port: 8080, host: "localhost".into(), host_port: 80 });
        let f = Forward::parse("0.0.0.0:8080:db.internal:5432").unwrap();
        assert_eq!((f.bind.as_deref(), f.host.as_str(), f.host_port), (Some("0.0.0.0"), "db.internal", 5432));
        let f = Forward::parse("[::1]:8080:[fe80::1]:22").unwrap();
        assert_eq!((f.bind.as_deref(), f.host.as_str()), (Some("::1"), "fe80::1"));
        assert!(Forward::parse("8080:host").is_err());
        assert!(Forward::parse("x:host:80").is_err());
        assert_eq!(parse_dynamic("1080").unwrap(), (None, 1080));
        assert_eq!(parse_dynamic("*:1080").unwrap(), (Some("*".into()), 1080));
        assert!(parse_dynamic("a:b:c").is_err());
    }

    #[tokio::test]
    async fn default_bind_is_loopback_only() {
        let ls = bind_local(None, 0, false).await.unwrap();
        assert!(ls.iter().all(|l| l.local_addr().unwrap().ip().is_loopback()));
        let ls = bind_local(None, 0, true).await.unwrap();
        assert!(ls.iter().all(|l| l.local_addr().unwrap().ip().is_unspecified()));
    }
}
