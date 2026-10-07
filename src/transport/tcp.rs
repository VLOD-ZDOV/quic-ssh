//! Fallback transport: TLS 1.3 over TCP, streams multiplexed with yamux.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
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
}

fn yamux_config() -> Config {
    let mut cfg = Config::default();
    cfg.set_max_num_streams(super::MAX_STREAMS as usize);
    // Per-stream windows auto-tune up to this total.
    cfg.set_max_connection_receive_window(Some(128 << 20));
    cfg
}

fn split(s: yamux::Stream) -> (SendHalf, RecvHalf) {
    let (r, w) = tokio::io::split(s.compat());
    (Box::new(w), Box::new(r))
}

/// Runs the yamux connection in a background task. All stream I/O (including
/// window updates) is driven here, so streams may write without reading.
/// The connection closes on `Cmd::Close` or when the `TcpConn` is dropped.
fn start<T>(socket: T, mode: Mode) -> (mpsc::Sender<Cmd>, mpsc::Receiver<yamux::Stream>, watch::Receiver<bool>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = Connection::new(socket.compat(), yamux_config(), mode);
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
                    Poll::Ready(Some(Ok(stream))) => drop(in_tx.try_send(stream)),
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
fn tls_info<D>(c: &rustls::ConnectionCommon<D>) -> Result<(PublicKey, [u8; 32])> {
    let peer_key = super::single_peer_cert(c.peer_certificates())?;
    let exporter = c
        .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(b""))
        .context("TLS exporter failed")?;
    Ok((peer_key, exporter))
}

fn finish<T>(socket: T, mode: Mode, info: (PublicKey, [u8; 32]), remote: SocketAddr) -> Conn
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (peer_key, exporter) = info;
    let (cmds, incoming, alive) = start(socket, mode);
    Conn {
        inner: Inner::Tcp(TcpConn { cmds, incoming: Mutex::new(incoming), alive }),
        peer_key,
        exporter,
        remote,
        hops: Vec::new(),
        server_version: 3,
    }
}

pub async fn connect(tls: Arc<rustls::ClientConfig>, addr: SocketAddr) -> Result<Conn> {
    let sock = TcpStream::connect(addr).await?;
    sock.set_nodelay(true)?;
    let name = ServerName::try_from(crate::tls::SERVER_NAME)?;
    let stream = tokio_rustls::TlsConnector::from(tls).connect(name, sock).await?;
    let info = tls_info(stream.get_ref().1)?;
    Ok(finish(stream, Mode::Client, info, addr))
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
    Ok(finish(stream, Mode::Client, info, remote))
}

pub async fn accept(tls: Arc<rustls::ServerConfig>, sock: TcpStream, addr: SocketAddr) -> Result<Conn> {
    sock.set_nodelay(true)?;
    let stream = tokio_rustls::TlsAcceptor::from(tls).accept(sock).await?;
    let info = tls_info(stream.get_ref().1)?;
    Ok(finish(stream, Mode::Server, info, addr))
}

impl TcpConn {
    pub async fn open_bi(&self) -> Result<(SendHalf, RecvHalf)> {
        let (tx, rx) = oneshot::channel();
        self.cmds.send(Cmd::Open(tx)).await.map_err(|_| anyhow!("connection closed"))?;
        let stream = rx.await.map_err(|_| anyhow!("connection closed"))??;
        Ok(split(stream))
    }

    pub async fn accept_bi(&self) -> Option<(SendHalf, RecvHalf)> {
        self.incoming.lock().await.recv().await.map(split)
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
