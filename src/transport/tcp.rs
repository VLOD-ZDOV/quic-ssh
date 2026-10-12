//! Fallback transport: TLS 1.3 over TCP, streams multiplexed with yamux.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, Mode};

use super::{Conn, Inner, RecvHalf, SendHalf, EXPORTER_LABEL};
use crate::keys::PublicKey;

enum Cmd {
    Open(oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>),
    Close,
}

pub struct TcpConn {
    cmds: mpsc::Sender<Cmd>,
    incoming: Mutex<mpsc::Receiver<yamux::Stream>>,
    alive: watch::Receiver<bool>,
    /// How many streams opened by the peer may wait to be accepted; more are
    /// reset (few before login, see [`super::PREAUTH_STREAMS`]).
    queue: Arc<AtomicUsize>,
    /// Streams we may still open. yamux ends the whole connection when the
    /// peer has more streams than it allows, so opens beyond this wait, as
    /// in QUIC.
    opens: Arc<Semaphore>,
    raised: AtomicBool,
}

/// What yamux allows, counting streams both ways: room for [`MAX_STREAMS`]
/// from each side and for closed streams that are not gone yet.
///
/// [`MAX_STREAMS`]: super::MAX_STREAMS
const YAMUX_STREAMS: usize = 4 * super::MAX_STREAMS as usize;
/// Streams we open to a peer older than protocol version 7, whose yamux
/// allowed 128 for both sides together.
const OLD_PEER_STREAMS: usize = 96;

fn yamux_config(mode: Mode) -> Config {
    let mut cfg = Config::default();
    cfg.set_max_num_streams(YAMUX_STREAMS);
    // yamux gives every stream a 256 KiB window it cannot take back; beyond
    // that, per-stream windows auto-tune up to this much more in total.
    let more = if matches!(mode, Mode::Server) { super::server_buffer() as usize } else { 128 << 20 };
    cfg.set_max_connection_receive_window(Some(YAMUX_STREAMS * (256 << 10) + more));
    cfg
}

fn split(s: yamux::Stream) -> (SendHalf, RecvHalf) {
    split_io(s.compat())
}

fn split_io<S: AsyncRead + AsyncWrite + Send + 'static>(s: S) -> (SendHalf, RecvHalf) {
    let (r, w) = tokio::io::split(s);
    (Box::new(w), Box::new(r))
}

/// A stream we opened; its permit goes back when both halves are dropped.
struct Opened {
    stream: tokio_util::compat::Compat<yamux::Stream>,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for Opened {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Opened {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Runs the yamux connection in a background task. All stream I/O (including
/// window updates) is driven here, so streams may write without reading.
/// The connection closes on `Cmd::Close` or when the `TcpConn` is dropped.
fn start<T>(socket: T, mode: Mode, queue: Arc<AtomicUsize>) -> (mpsc::Sender<Cmd>, mpsc::Receiver<yamux::Stream>, watch::Receiver<bool>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = Connection::new(socket.compat(), yamux_config(mode), mode);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(32);
    let (in_tx, in_rx) = mpsc::channel(super::MAX_STREAMS as usize);
    let (alive_tx, alive_rx) = watch::channel(true);
    tokio::spawn(async move {
        let mut opens: VecDeque<oneshot::Sender<_>> = VecDeque::new();
        let mut closing = false;
        futures::future::poll_fn(|cx| {
            while !closing {
                match cmd_rx.poll_recv(cx) {
                    Poll::Ready(Some(Cmd::Open(tx))) => opens.push_back(tx),
                    Poll::Ready(Some(Cmd::Close)) | Poll::Ready(None) => closing = true,
                    Poll::Pending => break,
                }
            }
            if closing {
                return conn.poll_close(cx).map(|_| ());
            }
            while !opens.is_empty() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(res) => {
                        let _ = opens.pop_front().expect("non-empty").send(res);
                    }
                    Poll::Pending => break,
                }
            }
            loop {
                match conn.poll_next_inbound(cx) {
                    // A full queue means the peer opens streams faster than we
                    // serve them; dropping the stream resets it.
                    Poll::Ready(Some(Ok(stream))) => {
                        let waiting = in_tx.max_capacity() - in_tx.capacity();
                        if waiting < queue.load(Ordering::Relaxed) {
                            drop(in_tx.try_send(stream));
                        }
                    }
                    Poll::Ready(Some(Err(e))) => {
                        tracing::debug!("yamux connection error: {e}");
                        return Poll::Ready(());
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
        let _ = alive_tx.send(false);
    });
    (cmd_tx, in_rx, alive_rx)
}

/// Peer key and exporter secret of a completed TLS handshake.
type TlsInfo = (PublicKey, Option<Vec<u8>>, [u8; 32]);

fn tls_info<D>(c: &rustls::ConnectionCommon<D>) -> Result<TlsInfo> {
    let (peer_key, host_cert) = super::peer_identity(c.peer_certificates())?;
    let exporter = c
        .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(b""))
        .context("TLS exporter failed")?;
    Ok((peer_key, host_cert, exporter))
}

fn finish<T>(socket: T, mode: Mode, info: TlsInfo, remote: SocketAddr, local_ip: Option<std::net::IpAddr>) -> Conn
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (peer_key, host_cert, exporter) = info;
    let limit = if matches!(mode, Mode::Server) { super::PREAUTH_STREAMS } else { super::MAX_STREAMS };
    let queue = Arc::new(AtomicUsize::new(limit as usize));
    let (cmds, incoming, alive) = start(socket, mode, queue.clone());
    Conn {
        inner: Inner::Tcp(TcpConn {
            cmds,
            incoming: Mutex::new(incoming),
            alive,
            queue,
            opens: Arc::new(Semaphore::new(OLD_PEER_STREAMS)),
            raised: AtomicBool::new(false),
        }),
        peer_key,
        exporter,
        remote,
        local_ip,
        hops: Vec::new(),
        server_version: 3,
        host_cert,
    }
}

/// TCP keepalive (QUIC has its own): a peer that vanished without a word
/// (sleep, a changed network, a NAT that forgot the connection) is noticed
/// after about a minute instead of never, on both sides.
/// `alive`: the server's own probe interval and count instead.
fn keep_alive(sock: &TcpStream, alive: Option<super::Alive>) {
    use std::time::Duration;
    let (time, interval, retries) = match alive {
        Some(a) => (a.interval, a.interval, a.count.max(1)),
        None => (Duration::from_secs(30), Duration::from_secs(10), 3),
    };
    let ka = socket2::TcpKeepalive::new().with_time(time);
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "windows"))]
    let ka = ka.with_interval(interval);
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let ka = ka.with_retries(retries);
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    let _ = retries;
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "windows")))]
    let _ = interval;
    if let Err(e) = socket2::SockRef::from(sock).set_tcp_keepalive(&ka) {
        tracing::debug!("TCP keepalive: {e}");
    }
}

/// `local`: the address to connect from (`-b`/`-B`); any if `None`.
pub async fn connect(tls: Arc<rustls::ClientConfig>, addr: SocketAddr, local: Option<SocketAddr>) -> Result<Conn> {
    let sock = match local {
        None => TcpStream::connect(addr).await?,
        Some(local) => {
            let s = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
            s.bind(local).with_context(|| format!("cannot bind to {}", local.ip()))?;
            s.connect(addr).await?
        }
    };
    sock.set_nodelay(true)?;
    keep_alive(&sock, None);
    let name = ServerName::try_from(crate::tls::SERVER_NAME)?;
    let stream = tokio_rustls::TlsConnector::from(tls).connect(name, sock).await?;
    let info = tls_info(stream.get_ref().1)?;
    Ok(finish(stream, Mode::Client, info, addr, None))
}

/// TLS + yamux over an already open byte stream (e.g. a stream forwarded
/// through a jump host). `remote` is only used for display.
pub async fn connect_stream<S>(tls: Arc<rustls::ClientConfig>, stream: S, remote: SocketAddr) -> Result<Conn>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let name = ServerName::try_from(crate::tls::SERVER_NAME)?;
    let stream = tokio_rustls::TlsConnector::from(tls).connect(name, stream).await?;
    let info = tls_info(stream.get_ref().1)?;
    Ok(finish(stream, Mode::Client, info, remote, None))
}

pub async fn accept(tls: Arc<rustls::ServerConfig>, sock: TcpStream, addr: SocketAddr, alive: Option<super::Alive>) -> Result<Conn> {
    sock.set_nodelay(true)?;
    keep_alive(&sock, alive);
    let local_ip = sock.local_addr().ok().map(|a| a.ip());
    let stream = tokio_rustls::TlsAcceptor::from(tls).accept(sock).await?;
    let info = tls_info(stream.get_ref().1)?;
    Ok(finish(stream, Mode::Server, info, addr, local_ip))
}

impl TcpConn {
    pub async fn open_bi(&self) -> Result<(SendHalf, RecvHalf)> {
        let permit = tokio::select! {
            p = self.opens.clone().acquire_owned() => p.map_err(|_| anyhow!("connection closed"))?,
            () = self.closed() => bail!("connection closed"),
        };
        let (tx, rx) = oneshot::channel();
        self.cmds.send(Cmd::Open(tx)).await.map_err(|_| anyhow!("connection closed"))?;
        let stream = rx.await.map_err(|_| anyhow!("connection closed"))??;
        Ok(split_io(Opened { stream: stream.compat(), _permit: permit }))
    }

    /// The peer's protocol version is known: from 7 on, its yamux allows
    /// [`YAMUX_STREAMS`], so we may open [`super::MAX_STREAMS`].
    pub fn peer_version(&self, version: u32) {
        if version >= 7 && !self.raised.swap(true, Ordering::Relaxed) {
            self.opens.add_permits(super::MAX_STREAMS as usize - OLD_PEER_STREAMS);
        }
    }

    pub async fn accept_bi(&self) -> Option<(SendHalf, RecvHalf)> {
        self.incoming.lock().await.recv().await.map(split)
    }

    pub fn logged_in(&self) {
        self.queue.store(super::MAX_STREAMS as usize, Ordering::Relaxed);
    }

    pub async fn closed(&self) {
        let mut alive = self.alive.clone();
        let _ = alive.wait_for(|a| !*a).await;
    }

    pub async fn close(&self) {
        let _ = self.cmds.send(Cmd::Close).await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), self.closed()).await;
    }
}
