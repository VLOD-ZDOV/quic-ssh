use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, TransportConfig, VarInt};
use rustls::pki_types::CertificateDer;

use super::{Conn, Inner, RecvHalf, SendHalf, EXPORTER_LABEL};

pub struct QuicConn {
    /// Client-owned endpoint; `None` on the server, where the listener owns it.
    endpoint: Option<Endpoint>,
    conn: quinn::Connection,
}

/// Connection-wide receive window once logged in.
const RECEIVE_WINDOW: u32 = 32 << 20;

/// `server`: start with the limits for a client that has not logged in
/// yet (see [`QuicConn::logged_in`]). `alive`: the server's probe
/// interval and how many probes may go unanswered.
fn transport_config(server: bool, alive: Option<super::Alive>) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    let (streams, window) = if server { (super::PREAUTH_STREAMS, super::PREAUTH_WINDOW) } else { (super::MAX_STREAMS, RECEIVE_WINDOW) };
    t.max_concurrent_bidi_streams(VarInt::from_u32(streams));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    let (keepalive, idle) = match alive {
        Some(a) => (a.interval, a.interval.saturating_mul(a.count.max(1))),
        None => (super::KEEPALIVE, super::IDLE_TIMEOUT),
    };
    t.keep_alive_interval(Some(keepalive));
    // QUIC allows idle timeouts up to 2^62 ms; ours are far below.
    t.max_idle_timeout(idle.try_into().ok());
    // Larger windows than the defaults so bulk copies are not window-limited on long links.
    t.stream_receive_window(VarInt::from_u32(8 << 20));
    t.receive_window(VarInt::from_u32(window));
    t.send_window(32 << 20);
    // BBR instead of the default Cubic: it does not treat random loss (Wi-Fi,
    // mobile) as congestion; with 1% loss it keeps ~2x the throughput of Cubic.
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(t)
}

pub fn server_endpoint(tls: Arc<rustls::ServerConfig>, addr: SocketAddr, alive: Option<super::Alive>) -> Result<Endpoint> {
    let crypto = QuicServerConfig::try_from(tls)?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport_config(true, alive));
    Ok(Endpoint::server(cfg, addr)?)
}

fn finish(endpoint: Option<Endpoint>, conn: quinn::Connection) -> Result<Conn> {
    let certs = conn
        .peer_identity()
        .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok());
    let (peer_key, host_cert) = super::peer_identity(certs.as_deref().map(Vec::as_slice))?;
    let mut exporter = [0u8; 32];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|_| anyhow::anyhow!("TLS exporter failed"))?;
    let remote = conn.remote_address();
    let local_ip = conn.local_ip();
    Ok(Conn { inner: Inner::Quic(QuicConn { endpoint, conn }), peer_key, exporter, remote, local_ip, hops: Vec::new(), server_version: 3, host_cert })
}

/// `local`: the address to send from (`-b`/`-B`); any if `None`.
pub async fn connect(tls: Arc<rustls::ClientConfig>, addr: SocketAddr, local: Option<SocketAddr>) -> Result<Conn> {
    let any: SocketAddr = if addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let bind = local.unwrap_or(any);
    let endpoint = Endpoint::client(bind)?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    cfg.transport_config(transport_config(false, None));
    let conn = endpoint.connect_with(cfg, addr, crate::tls::SERVER_NAME)?.await?;
    finish(Some(endpoint), conn)
}

pub async fn accept(incoming: quinn::Incoming) -> Result<Conn> {
    let conn = incoming.await.context("quic handshake failed")?;
    finish(None, conn)
}

impl QuicConn {
    pub async fn open_bi(&self) -> Result<(SendHalf, RecvHalf)> {
        let (s, r) = self.conn.open_bi().await?;
        Ok((Box::new(s), Box::new(r)))
    }

    pub async fn accept_bi(&self) -> Option<(SendHalf, RecvHalf)> {
        match self.conn.accept_bi().await {
            Ok((s, r)) => Some((Box::new(s), Box::new(r))),
            Err(e) => {
                tracing::debug!("quic connection ended: {e}");
                None
            }
        }
    }

    pub async fn closed(&self) {
        self.conn.closed().await;
    }

    pub fn logged_in(&self) {
        self.conn.set_receive_window(VarInt::from_u32(RECEIVE_WINDOW));
        self.conn.set_max_concurrent_bi_streams(VarInt::from_u32(super::MAX_STREAMS));
    }

    pub async fn close(&self) {
        self.conn.close(VarInt::from_u32(0), b"bye");
        if let Some(endpoint) = &self.endpoint {
            // Give the endpoint driver a moment to transmit CONNECTION_CLOSE. Waiting
            // for full idle would sit out the draining period (3×PTO, ~200 ms) for nothing.
            let _ = tokio::time::timeout(std::time::Duration::from_millis(20), endpoint.wait_idle()).await;
        }
    }
}
