//! Local port forwarding (`-L [bind:]port:host:hostport`).

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use crate::proto::{expect_ok, write_msg, Request};
use crate::transport::Conn;

#[derive(Debug, Clone, PartialEq)]
pub struct Forward {
    pub bind: String,
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

impl Forward {
    pub fn parse(s: &str) -> Result<Forward> {
        let parts = split_spec(s)?;
        let port = |p: &str| p.parse::<u16>().with_context(|| format!("invalid port {p:?} in -L {s}"));
        let (bind, rest) = match parts.len() {
            3 => ("localhost".to_string(), &parts[..]),
            4 => (parts[0].clone(), &parts[1..]),
            _ => bail!("-L expects [bind_address:]port:host:hostport, got {s:?}"),
        };
        Ok(Forward { bind, port: port(&rest[0])?, host: rest[1].clone(), host_port: port(&rest[2])? })
    }
}

/// Binds the local listener(s) and serves them in the background. A name like
/// `localhost` binds every address it resolves to (127.0.0.1 and ::1).
pub async fn start(conn: Arc<Conn>, fwd: Forward) -> Result<()> {
    let addrs: Vec<_> = tokio::net::lookup_host((fwd.bind.as_str(), fwd.port))
        .await
        .with_context(|| format!("cannot resolve {}", fwd.bind))?
        .collect();
    let mut bound = 0;
    let mut last_err = None;
    for addr in addrs {
        match TcpListener::bind(addr).await {
            Ok(l) => {
                bound += 1;
                tokio::spawn(serve(l, conn.clone(), fwd.clone()));
            }
            Err(e) => last_err = Some(e),
        }
    }
    match (bound, last_err) {
        (0, Some(e)) => Err(e).with_context(|| format!("cannot listen on {}:{}", fwd.bind, fwd.port)),
        (0, None) => bail!("{} has no addresses", fwd.bind),
        _ => Ok(()),
    }
}

async fn serve(listener: TcpListener, conn: Arc<Conn>, fwd: Forward) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("forward accept failed: {e}");
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let (conn, fwd) = (conn.clone(), fwd.clone());
        tokio::spawn(async move {
            let result = async {
                let (mut send, mut recv) = conn.open_bi().await?;
                write_msg(&mut send, &Request::DirectTcp { host: fwd.host.clone(), port: fwd.host_port }).await?;
                expect_ok(&mut recv).await?;
                crate::transport::splice(tcp, send, recv).await
            }
            .await;
            match result {
                Ok(()) => debug!("forward from {peer} closed"),
                Err(e) => warn!("forward {}:{} failed: {e:#}", fwd.host, fwd.host_port),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_specs() {
        let f = Forward::parse("8080:localhost:80").unwrap();
        assert_eq!(f, Forward { bind: "localhost".into(), port: 8080, host: "localhost".into(), host_port: 80 });
        let f = Forward::parse("0.0.0.0:8080:db.internal:5432").unwrap();
        assert_eq!((f.bind.as_str(), f.host.as_str(), f.host_port), ("0.0.0.0", "db.internal", 5432));
        let f = Forward::parse("[::1]:8080:[fe80::1]:22").unwrap();
        assert_eq!((f.bind.as_str(), f.host.as_str()), ("::1", "fe80::1"));
        assert!(Forward::parse("8080:host").is_err());
        assert!(Forward::parse("x:host:80").is_err());
    }
}
