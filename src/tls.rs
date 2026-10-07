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
use crate::proto::ALPN;

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

/// Client-side check of the server certificate: a well-formed Ed25519
/// certificate whose handshake signature verifies. The key itself is checked
/// against known_hosts by the caller.
#[derive(Debug)]
struct HostKeyVerifier {
    provider: Arc<CryptoProvider>,
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
        if !intermediates.is_empty() {
            return Err(TlsError::General("unexpected certificate chain".into()));
        }
        cert_key(end_entity).map_err(bad_cert)?;
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

pub fn server_config(host: &Identity) -> Result<rustls::ServerConfig> {
    let provider = provider();
    let (cert, key) = self_signed(host)?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(ClientKeyVerifier { provider }))
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(cfg)
}

pub fn client_config(id: &Identity) -> Result<rustls::ClientConfig> {
    let provider = provider();
    let (cert, key) = self_signed(id)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(HostKeyVerifier { provider }))
        .with_client_auth_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
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
            HostKeyVerifier { provider: provider() }
                .verify_server_cert(cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        };
        let (cert, _) = self_signed(&Identity::generate()).unwrap();
        assert!(verify(&cert));
        let ecdsa = rcgen::generate_simple_self_signed(vec!["x".into()]).unwrap();
        assert!(!verify(ecdsa.cert.der()));
    }
}
