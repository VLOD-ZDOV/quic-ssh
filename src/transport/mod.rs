//! Transport abstraction: QUIC (preferred) or TLS-over-TCP with yamux multiplexing.

mod quic;
mod tcp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::keys::PublicKey;

pub type SendHalf = Box<dyn AsyncWrite + Send + Unpin>;
pub type RecvHalf = Box<dyn AsyncRead + Send + Unpin>;

/// TLS exporter label used to bind pairing to this exact connection.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-qsh-pair-v1";

/// How long the client waits for QUIC before falling back to TCP.
const QUIC_TIMEOUT: Duration = Duration::from_millis(2500);
/// How long `--full` waits for qshd before handing over to ssh.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);
const TCP_TIMEOUT: Duration = Duration::from_secs(10);
/// Server-side limit for completing the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum concurrent streams (sessions, forwards, copies) per connection.
const MAX_STREAMS: u32 = 128;
const KEEPALIVE: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

enum Inner {
    Quic(quic::QuicConn),
    Tcp(tcp::TcpConn),
}

/// An authenticated, encrypted, multiplexed connection.
pub struct Conn {
    inner: Inner,
    peer_key: PublicKey,
    exporter: [u8; 32],
    remote: SocketAddr,
}

impl Conn {
    pub async fn open_bi(&self) -> Result<(SendHalf, RecvHalf)> {
        match &self.inner {
            Inner::Quic(c) => c.open_bi().await,
            Inner::Tcp(c) => c.open_bi().await,
        }
    }

    /// Next stream opened by the peer; `None` once the connection is closed.
    pub async fn accept_bi(&self) -> Option<(SendHalf, RecvHalf)> {
        match &self.inner {
            Inner::Quic(c) => c.accept_bi().await,
            Inner::Tcp(c) => c.accept_bi().await,
        }
    }

    /// Key from the peer's TLS certificate (signature already verified).
    pub fn peer_key(&self) -> PublicKey {
        self.peer_key
    }

    /// Connection-unique secret derived from the TLS session.
    pub fn exporter(&self) -> [u8; 32] {
        self.exporter
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    pub fn transport_name(&self) -> &'static str {
        match &self.inner {
            Inner::Quic(_) => "quic",
            Inner::Tcp(_) => "tcp",
        }
    }

    /// Resolves when the connection is gone.
    pub async fn closed(&self) {
        match &self.inner {
            Inner::Quic(c) => c.closed().await,
            Inner::Tcp(c) => c.closed().await,
        }
    }

    /// Gracefully closes the connection, flushing pending data.
    pub async fn close(&self) {
        match &self.inner {
            Inner::Quic(c) => c.close().await,
            Inner::Tcp(c) => c.close().await,
        }
    }
}

fn single_peer_cert(certs: Option<&[rustls::pki_types::CertificateDer<'_>]>) -> Result<PublicKey> {
    match certs {
        Some([cert]) => crate::tls::cert_key(cert),
        _ => bail!("peer did not present exactly one certificate"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    /// QUIC first, TCP if UDP does not get through.
    Auto,
    Quic,
    Tcp,
}

/// Connects to `host:port` using the given transport mode.
pub async fn connect(host: &str, port: u16, mode: Mode, tls: rustls::ClientConfig) -> Result<Conn> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("cannot resolve {host}"))?
        .collect();
    if addrs.is_empty() {
        bail!("{host} has no addresses");
    }
    let tls = Arc::new(tls);
    let mut errors = Vec::new();

    if mode != Mode::Tcp {
        for &addr in &addrs {
            let timeout = if mode == Mode::Quic { TCP_TIMEOUT } else { QUIC_TIMEOUT };
            match tokio::time::timeout(timeout, quic::connect(tls.clone(), addr)).await {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => errors.push(format!("quic {addr}: {e:#}")),
                Err(_) => errors.push(format!("quic {addr}: timed out")),
            }
            debug!("{}", errors.last().unwrap());
        }
    }
    if mode != Mode::Quic {
        for &addr in &addrs {
            match tokio::time::timeout(TCP_TIMEOUT, tcp::connect(tls.clone(), addr)).await {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => errors.push(format!("tcp {addr}: {e:#}")),
                Err(_) => errors.push(format!("tcp {addr}: timed out")),
            }
            debug!("{}", errors.last().unwrap());
        }
    }
    Err(Unreachable(format!("cannot connect to {host}:{port}\n  {}", errors.join("\n  "))).into())
}

/// No qshd answered (as opposed to an authentication or host key failure).
#[derive(Debug)]
pub struct Unreachable(pub String);

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unreachable {}

/// QUIC-only connect for `qsh --full`, where the TCP port belongs to sshd.
/// Tries every address and port in parallel and takes the first qshd that
/// answers; gives up after [`PROBE_TIMEOUT`], or as soon as every UDP port
/// turned out to be closed.
pub async fn connect_probe(host: &str, ports: &[u16], tls: rustls::ClientConfig) -> Result<Conn> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let mut candidates = Vec::new();
    for &port in ports {
        let addrs = tokio::net::lookup_host((host, port)).await.with_context(|| format!("cannot resolve {host}"))?;
        candidates.extend(addrs);
    }
    let tls = Arc::new(tls);
    let mut attempts: FuturesUnordered<_> = candidates
        .into_iter()
        .map(|addr| {
            let tls = tls.clone();
            async move {
                tokio::select! {
                    r = tokio::time::timeout(PROBE_TIMEOUT, quic::connect(tls, addr)) => match r {
                        Ok(Ok(conn)) => Ok(conn),
                        Ok(Err(e)) => Err(format!("quic {addr}: {e:#}")),
                        Err(_) => Err(format!("quic {addr}: no answer")),
                    },
                    () = udp_port_closed(addr) => Err(format!("quic {addr}: udp port closed")),
                }
            }
        })
        .collect();
    let mut errors = Vec::new();
    while let Some(result) = attempts.next().await {
        match result {
            Ok(conn) => return Ok(conn),
            Err(e) => errors.push(e),
        }
    }
    let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
    Err(Unreachable(format!("no qshd at {host} (udp {})\n  {}", ports.join(", "), errors.join("\n  "))).into())
}

/// Resolves only if the host answers a datagram with ICMP port unreachable.
async fn udp_port_closed(addr: SocketAddr) {
    let bind: SocketAddr = if addr.is_ipv4() { ([0u8; 4], 0).into() } else { ([0u16; 8], 0).into() };
    let probe = async {
        let sock = tokio::net::UdpSocket::bind(bind).await?;
        sock.connect(addr).await?;
        // A single byte is ignored by a QUIC server (too short to be a packet).
        sock.send(&[0]).await?;
        let mut buf = [0u8; 1];
        loop {
            if let Err(e) = sock.recv(&mut buf).await {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    return std::io::Result::Ok(());
                }
                return Err(e);
            }
        }
    };
    if probe.await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Server listener bound to the same port on UDP (QUIC) and, optionally, TCP.
pub struct Listener {
    quic: quinn::Endpoint,
    tcp: Option<tokio::net::TcpListener>,
    tls: Arc<rustls::ServerConfig>,
}

/// A connection attempt whose handshake has not completed yet.
pub enum Incoming {
    Quic(Box<quinn::Incoming>),
    Tcp(tokio::net::TcpStream, SocketAddr, Arc<rustls::ServerConfig>),
}

impl Listener {
    pub async fn bind(addr: SocketAddr, tls: rustls::ServerConfig, tcp: bool) -> Result<Listener> {
        let tls = Arc::new(tls);
        let quic = quic::server_endpoint(tls.clone(), addr)
            .with_context(|| format!("cannot listen on udp {addr}"))?;
        let tcp = if tcp {
            // Port 0: put TCP on whatever port UDP got so both share one number.
            let tcp_addr = SocketAddr::new(addr.ip(), quic.local_addr()?.port());
            Some(
                tokio::net::TcpListener::bind(tcp_addr)
                    .await
                    .with_context(|| format!("cannot listen on tcp {tcp_addr}"))?,
            )
        } else {
            None
        };
        Ok(Listener { quic, tcp, tls })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.quic.local_addr()?)
    }

    /// Human-readable list of the active transports.
    pub fn transports(&self) -> &'static str {
        if self.tcp.is_some() { "quic + tcp" } else { "quic only" }
    }

    pub async fn accept(&self) -> Result<Incoming> {
        let tcp_accept = async {
            match &self.tcp {
                Some(l) => l.accept().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            inc = self.quic.accept() => inc.map(|i| Incoming::Quic(Box::new(i))).context("quic endpoint closed"),
            res = tcp_accept => {
                let (sock, addr) = res?;
                Ok(Incoming::Tcp(sock, addr, self.tls.clone()))
            }
        }
    }
}

impl Incoming {
    /// Drops the attempt without doing any handshake work.
    pub fn reject(self) {
        match self {
            Incoming::Quic(i) => i.ignore(),
            Incoming::Tcp(..) => {}
        }
    }

    pub fn remote_addr(&self) -> SocketAddr {
        match self {
            Incoming::Quic(i) => i.remote_address(),
            Incoming::Tcp(_, addr, _) => *addr,
        }
    }

    /// Completes the TLS handshake (bounded by [`HANDSHAKE_TIMEOUT`]).
    pub async fn handshake(self) -> Result<Conn> {
        let fut = async move {
            match self {
                Incoming::Quic(i) => quic::accept(*i).await,
                Incoming::Tcp(sock, addr, tls) => tcp::accept(tls, sock, addr).await,
            }
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await.context("handshake timed out")?
    }
}

/// Copies bytes both ways between a TCP socket and a stream, propagating half-closes.
pub async fn splice(tcp: tokio::net::TcpStream, send: SendHalf, recv: RecvHalf) -> Result<()> {
    let (tr, tw) = tcp.into_split();
    bridge(tr, tw, send, recv).await
}

/// Copies `r` → `send` and `recv` → `w` concurrently, shutting each writer down at EOF.
pub async fn bridge<R, W>(mut r: R, mut w: W, mut send: SendHalf, mut recv: RecvHalf) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let up = async {
        tokio::io::copy(&mut r, &mut send).await?;
        send.shutdown().await
    };
    let down = async {
        tokio::io::copy(&mut recv, &mut w).await?;
        w.shutdown().await
    };
    tokio::try_join!(up, down)?;
    Ok(())
}
