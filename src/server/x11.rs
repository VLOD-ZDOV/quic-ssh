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

/// A listener for a display on `addr`: IPv6 only on IPv6 addresses, so `[::]`
/// does not clash with the display's own `0.0.0.0`.
fn listen(addr: SocketAddr, reuse: bool) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    // Like sshd: only for loopback displays.
    sock.set_reuse_address(reuse)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    tokio::net::TcpListener::from_std(sock.into())
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
    'displays: for n in cfg.x11_display_offset..cfg.x11_display_offset.saturating_add(DISPLAYS) {
        let Ok(port) = u16::try_from(6000 + n) else { break };
        let mut listeners = Vec::new();
        for ip in &ips {
            match listen(SocketAddr::new(*ip, port), cfg.x11_use_localhost) {
                Ok(l) => listeners.push(l),
                // Someone holding the display on either address is taken: with
                // half of it, they would get the connections (and cookies) of
                // programs that reach the other address (CVE-2008-1483).
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue 'displays,
                // No IPv6 (or IPv4) here.
                Err(e) => debug!("X11 display {n} on {ip}: {e}"),
            }
        }
        if !listeners.is_empty() {
            found = Some((n, listeners));
            break;
        }
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
    // Checked again with the display taken: two requests at once must not
    // both get one (the first to end would clear the other's).
    let taken = {
        let mut slot = x11.display.lock().unwrap();
        let taken = slot.is_some();
        if !taken {
            *slot = Some(display);
        }
        taken
    };
    if taken {
        return write_msg(&mut send, &Reply::Err("X11 forwarding is already on for this connection".into())).await;
    }
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
    /// A display whose IPv6 port someone else holds is skipped as a whole.
    #[tokio::test]
    async fn half_taken_display_is_skipped() {
        use std::net::{Ipv6Addr, SocketAddr};
        let Ok(squat) = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else { return }; // no IPv6
        let port = squat.local_addr().unwrap().port();
        let err = super::listen(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port), true).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[test]
    fn auth_data_checks() {
        assert!(super::plausible("MIT-MAGIC-COOKIE-1", "00112233445566778899aabbccddeeff"));
        assert!(!super::plausible("MIT MAGIC", "00"));
        assert!(!super::plausible("MIT-MAGIC-COOKIE-1", "0g"));
        assert!(!super::plausible("MIT-MAGIC-COOKIE-1", "abc"));
        assert!(!super::plausible("MIT-MAGIC-COOKIE-1", "00\nadd :0 x 00"));
    }
}
