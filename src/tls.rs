//! TLS 1.3 configuration with raw Ed25519 key pinning instead of a PKI.
//!
//! Both sides present a self-signed certificate wrapping their Ed25519 key.
//! The handshake signature is always verified against that certificate; who
//! the key belongs to is decided right after the handshake, before any
//! application data is sent: by known_hosts on the client and by
//! authorized_keys on the server.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use x509_parser::oid_registry::OID_SIG_ED25519;

use crate::keys::{Identity, PublicKey};
use crate::proto::{ALPN, ALPN_HOST_CERT};

/// Server name sent in SNI; certificates are pinned by key, so it is not checked.
pub const SERVER_NAME: &str = "qsh";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Self-signed certificate carrying the identity's public key.
pub fn self_signed(id: &Identity) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let der = id.pkcs8_der();
    let key_pair = rcgen::KeyPair::try_from(der.as_slice()).context("cannot load key into rcgen")?;
    let mut params = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, SERVER_NAME);
    let cert = params.self_signed(&key_pair)?;
    Ok((
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
    ))
}

/// Extracts the Ed25519 key from a certificate's SubjectPublicKeyInfo.
pub fn cert_key(cert: &CertificateDer<'_>) -> Result<PublicKey> {
    let (rest, parsed) =
        x509_parser::parse_x509_certificate(cert.as_ref()).context("malformed certificate")?;
    if !rest.is_empty() {
        bail!("trailing data after certificate");
    }
    let spki = parsed.public_key();
    if spki.algorithm.algorithm != OID_SIG_ED25519 {
        bail!("certificate key is not ed25519");
    }
    let bytes: [u8; 32] = spki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .context("bad ed25519 key length")?;
    Ok(PublicKey(bytes))
}

fn verify13(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError> {
    if dss.scheme != SignatureScheme::ED25519 {
        return Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::NoSignatureSchemesInCommon,
        ));
    }
    verify_tls13_signature(message, cert, dss, &provider.signature_verification_algorithms)
}

fn bad_cert(e: anyhow::Error) -> TlsError {
    TlsError::General(format!("{e:#}"))
}

/// Judges the server's key (and SSH host certificate, if it sent one)
/// during the handshake; `Err` ends the handshake with that reason.
pub type HostCheck = Arc<dyn Fn(PublicKey, Option<&[u8]>) -> Result<(), String> + Send + Sync>;

/// Client-side check of the server certificate: a well-formed Ed25519
/// certificate whose handshake signature verifies, and, with a `check`, a key
/// the client already trusts or does not know yet. A rejected server never
/// sees the client's certificate: the client sends it only after this check.
struct HostKeyVerifier {
    provider: Arc<CryptoProvider>,
    check: Option<HostCheck>,
}

impl std::fmt::Debug for HostKeyVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostKeyVerifier").field("check", &self.check.is_some()).finish()
    }
}

impl ServerCertVerifier for HostKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // At most the SSH host certificate, checked after the handshake.
        if intermediates.len() > 1 {
            return Err(TlsError::General("unexpected certificate chain".into()));
        }
        let key = cert_key(end_entity).map_err(bad_cert)?;
        if let Some(check) = &self.check {
            check(key, intermediates.first().map(|c| c.as_ref())).map_err(TlsError::General)?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify13(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Server-side check of the client certificate. Any well-formed Ed25519
/// certificate whose handshake signature verifies is accepted; authorization
/// against authorized_keys happens afterwards.
#[derive(Debug)]
struct ClientKeyVerifier {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for ClientKeyVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if !intermediates.is_empty() {
            return Err(TlsError::General("unexpected certificate chain".into()));
        }
        cert_key(end_entity).map_err(bad_cert)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify13(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Presents the host certificate (SSH format, as a second chain entry) only
/// to clients that ask for it with [`ALPN_HOST_CERT`]; older clients accept
/// exactly one certificate.
#[derive(Debug)]
struct HostCertResolver {
    plain: Arc<rustls::sign::CertifiedKey>,
    with_cert: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for HostCertResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let wants = hello.alpn().is_some_and(|mut a| a.any(|p| p == ALPN_HOST_CERT));
        Some(if wants { self.with_cert.clone() } else { self.plain.clone() })
    }
}

/// `host_cert`: an OpenSSH host certificate for `host`'s key, in wire format.
pub fn server_config(host: &Identity, host_cert: Option<Vec<u8>>) -> Result<rustls::ServerConfig> {
    let provider = provider();
    let (cert, key) = self_signed(host)?;
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(ClientKeyVerifier { provider: provider.clone() }));
    let mut cfg = match host_cert {
        None => builder.with_single_cert(vec![cert], key)?,
        Some(ssh_cert) => {
            let signer = provider.key_provider.load_private_key(key)?;
            let plain = rustls::sign::CertifiedKey::new(vec![cert.clone()], signer.clone());
            let with_cert = rustls::sign::CertifiedKey::new(vec![cert, CertificateDer::from(ssh_cert)], signer);
            builder.with_cert_resolver(Arc::new(HostCertResolver { plain: Arc::new(plain), with_cert: Arc::new(with_cert) }))
        }
    };
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(cfg)
}

/// A client config without a host check (probes that do not log in).
pub fn client_config(id: &Identity) -> Result<rustls::ClientConfig> {
    checked_client_config(id, None)
}

/// A client config whose handshake fails unless `check` accepts the server.
pub fn checked_client_config(id: &Identity, check: Option<HostCheck>) -> Result<rustls::ClientConfig> {
    let provider = provider();
    let (cert, key) = self_signed(id)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(HostKeyVerifier { provider, check }))
        .with_client_auth_cert(vec![cert], key)?;
    // The second entry is never selected; it asks for the host certificate.
    cfg.alpn_protocols = vec![ALPN.to_vec(), ALPN_HOST_CERT.to_vec()];
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_carries_key() {
        let id = Identity::generate();
        let (cert, _) = self_signed(&id).unwrap();
        assert_eq!(cert_key(&cert).unwrap(), id.public());
    }

    #[test]
    fn verifier_requires_ed25519() {
        let name = ServerName::try_from(SERVER_NAME).unwrap();
        let verify = |cert: &CertificateDer<'_>| {
            HostKeyVerifier { provider: provider(), check: None }
                .verify_server_cert(cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        };
        let (cert, _) = self_signed(&Identity::generate()).unwrap();
        assert!(verify(&cert));
        let ecdsa = rcgen::generate_simple_self_signed(vec!["x".into()]).unwrap();
        assert!(!verify(ecdsa.cert.der()));
    }

    #[test]
    fn verifier_runs_the_host_check() {
        let name = ServerName::try_from(SERVER_NAME).unwrap();
        let (trusted, other) = (Identity::generate(), Identity::generate());
        let pin = trusted.public();
        let check: HostCheck = Arc::new(move |key, _| if key == pin { Ok(()) } else { Err("changed".into()) });
        let verifier = HostKeyVerifier { provider: provider(), check: Some(check) };
        let verify = |id: &Identity| verifier.verify_server_cert(&self_signed(id).unwrap().0, &[], &name, &[], UnixTime::now()).is_ok();
        assert!(verify(&trusted));
        assert!(!verify(&other));
    }

    /// The client's certificate goes out only after the host check: a
    /// refused server never learns the client's key.
    #[test]
    fn refused_server_never_sees_the_client_key() {
        let server_cfg = Arc::new(server_config(&Identity::generate(), None).unwrap());
        let refuse: HostCheck = Arc::new(|_, _| Err("refused".into()));
        for (check, accepted) in [(None, true), (Some(refuse), false)] {
            let client_cfg = Arc::new(checked_client_config(&Identity::generate(), check).unwrap());
            let mut client = rustls::ClientConnection::new(client_cfg, ServerName::try_from(SERVER_NAME).unwrap()).unwrap();
            let mut server = rustls::ServerConnection::new(server_cfg.clone()).unwrap();
            for _ in 0..10 {
                let mut buf = Vec::new();
                client.write_tls(&mut buf).unwrap();
                server.read_tls(&mut buf.as_slice()).unwrap();
                let server_ok = server.process_new_packets().is_ok();
                let mut buf = Vec::new();
                server.write_tls(&mut buf).unwrap();
                client.read_tls(&mut buf.as_slice()).unwrap();
                let client_ok = client.process_new_packets().is_ok();
                if !server_ok || !client_ok || (!client.is_handshaking() && !server.is_handshaking()) {
                    break;
                }
            }
            assert_eq!(server.peer_certificates().is_some(), accepted);
            assert_eq!(client.is_handshaking(), !accepted);
        }
    }
}
