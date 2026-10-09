//! X11 forwarding (`qsh -X`/`-Y`), like sshd's: a display on the server
//! (`localhost:10` and up) whose connections go to the client, which checks
//! the fake cookie the server side uses and puts the real one in its place.
//! Sessions get `DISPLAY` and an xauth entry for the fake cookie.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tracing::{debug, info};

use crate::config::ServerConfig;
use crate::proto::{write_msg, Opened, Reply};
use crate::transport::{Conn, RecvHalf, SendHalf};

/// How many display numbers above `x11_display_offset` are tried.
const DISPLAYS: u32 = 1000;

/// The forwarded display of a connection.
#[derive(Clone, Debug)]
pub struct Display {
    /// `DISPLAY` for sessions.
    pub display: String,
    /// The name of the display in xauth (`unix:10.0`).
    pub auth_display: String,
    pub proto: String,
    /// The fake cookie (hex) sessions authenticate with.
    pub cookie: String,
}

/// The display of a connection, while X11 forwarding is on.
#[derive(Default)]
pub struct X11 {
    display: Mutex<Option<Display>>,
}

impl X11 {
    pub fn display(&self) -> Option<Display> {
        self.display.lock().unwrap().clone()
    }
}

/// Clears the display when forwarding ends.
struct Clear<'a>(&'a X11);

impl Drop for Clear<'_> {
    fn drop(&mut self) {
        *self.0.display.lock().unwrap() = None;
    }
}

/// Valid authentication data from a client: a protocol name and a hex cookie.
fn plausible(proto: &str, cookie: &str) -> bool {
    !proto.is_empty()
        && proto.len() <= 64
        && proto.bytes().all(|b| b.is_ascii_graphic())
        && !cookie.is_empty()
        && cookie.len() <= 1024
        && cookie.len().is_multiple_of(2)
        && cookie.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What a client asks for: the fake authentication and the screen.
pub struct Request {
    pub proto: String,
    pub cookie: String,
    pub screen: u32,
}

/// `Request::X11Forward`: listens on the first free display and hands its
/// connections to the client until the request stream closes.
pub async fn forward(mut send: SendHalf, mut recv: RecvHalf, conn: Arc<Conn>, cfg: &ServerConfig, x11: &X11, req: Request) -> Result<()> {
    let Request { proto, cookie, screen } = req;
    if !plausible(&proto, &cookie) {
        return write_msg(&mut send, &Reply::Err("bad X11 authentication data".into())).await;
    }
    if x11.display().is_some() {
        return write_msg(&mut send, &Reply::Err("X11 forwarding is already on for this connection".into())).await;
    }
    let ips: Vec<IpAddr> = if cfg.x11_use_localhost {
        vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()]
    } else {
        vec![Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()]
    };
    let mut found = None;
    for n in cfg.x11_display_offset..cfg.x11_display_offset.saturating_add(DISPLAYS) {
        let Ok(port) = u16::try_from(6000 + n) else { break };
        // The display is taken if its IPv4 port is; IPv6 is a bonus.
        let Ok(first) = tokio::net::TcpListener::bind(SocketAddr::new(ips[0], port)).await else { continue };
        let mut listeners = vec![first];
        if let Ok(l) = tokio::net::TcpListener::bind(SocketAddr::new(ips[1], port)).await {
            listeners.push(l);
        }
        found = Some((n, listeners));
        break;
    }
    let Some((number, listeners)) = found else {
        return write_msg(&mut send, &Reply::Err("no free X11 display".into())).await;
    };
    let host = nix::unistd::gethostname().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default();
    let display = if cfg.x11_use_localhost {
        Display {
            display: format!("localhost:{number}.{screen}"),
            auth_display: format!("unix:{number}.{screen}"),
            proto,
            cookie,
        }
    } else {
        Display { display: format!("{host}:{number}.{screen}"), auth_display: format!("{host}/unix:{number}.{screen}"), proto, cookie }
    };
    *x11.display.lock().unwrap() = Some(display);
    let _clear = Clear(x11);
    write_msg(&mut send, &Reply::Ok).await?;
    info!("{}: X11 forwarding on display {number}", conn.remote_addr());
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let acceptors: Vec<_> = listeners
        .into_iter()
        .map(|l| {
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Ok(accepted) = l.accept().await {
                    if tx.send(accepted).await.is_err() {
                        break;
                    }
                }
            })
        })
        .collect();
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            Some((tcp, origin)) = rx.recv() => {
                let conn = conn.clone();
                tokio::spawn(async move {
                    let _ = tcp.set_nodelay(true);
                    let result = async {
                        let (mut s, r) = conn.open_bi().await?;
                        write_msg(&mut s, &Opened::X11 { origin: origin.to_string() }).await?;
                        crate::transport::splice(tcp, s, r).await
                    }
                    .await;
                    if let Err(e) = result {
                        debug!("X11 connection from {origin}: {e:#}");
                    }
                });
            }
            // The client closed the request stream (or the connection is gone).
            _ = recv.read(&mut probe) => break,
        }
    }
    for a in acceptors {
        a.abort();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn auth_data_checks() {
        assert!(super::plausible("MIT-MAGIC-COOKIE-1", "00112233445566778899aabbccddeeff"));
        assert!(!super::plausible("MIT MAGIC", "00"));
        assert!(!super::plausible("MIT-MAGIC-COOKIE-1", "0g"));
        assert!(!super::plausible("MIT-MAGIC-COOKIE-1", "abc"));
        assert!(!super::plausible("MIT-MAGIC-COOKIE-1", "00\nadd :0 x 00"));
    }
}
