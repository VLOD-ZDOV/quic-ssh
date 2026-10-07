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

fn transport_config() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(super::MAX_STREAMS));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.keep_alive_interval(Some(super::KEEPALIVE));
    t.max_idle_timeout(Some(super::IDLE_TIMEOUT.try_into().expect("valid idle timeout")));
    // Larger windows than the defaults so bulk copies are not window-limited on long links.
    t.stream_receive_window(VarInt::from_u32(8 << 20));
    t.receive_window(VarInt::from_u32(32 << 20));
    t.send_window(32 << 20);
    // BBR instead of the default Cubic: it does not treat random loss (Wi-Fi,
    // mobile) as congestion; with 1% loss it keeps ~2x the throughput of Cubic.
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(t)
}

pub fn server_endpoint(tls: Arc<rustls::ServerConfig>, addr: SocketAddr) -> Result<Endpoint> {
    let crypto = QuicServerConfig::try_from(tls)?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport_config());
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
    Ok(Conn { inner: Inner::Quic(QuicConn { endpoint, conn }), peer_key, exporter, remote, hops: Vec::new(), server_version: 3, host_cert })
}

pub async fn connect(tls: Arc<rustls::ClientConfig>, addr: SocketAddr) -> Result<Conn> {
    let bind: SocketAddr = if addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let endpoint = Endpoint::client(bind)?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    cfg.transport_config(transport_config());
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

    pub async fn close(&self) {
        self.conn.close(VarInt::from_u32(0), b"bye");
        if let Some(endpoint) = &self.endpoint {
            // Give the endpoint driver a moment to transmit CONNECTION_CLOSE. Waiting
            // for full idle would sit out the draining period (3×PTO, ~200 ms) for nothing.
            let _ = tokio::time::timeout(std::time::Duration::from_millis(20), endpoint.wait_idle()).await;
        }
    }
}
