//! Post-quantum key exchange for TLS 1.3: X25519MLKEM768
//! (draft-ietf-tls-ecdhe-mlkem), X25519 and ML-KEM-768 (FIPS 203) together.
//! The session key comes from both secrets, so traffic recorded today stays
//! private unless both are broken. A peer without it (qsh before 2.0) gets
//! plain X25519. Logging in still uses Ed25519 signatures.
//!
//! X25519 is ring's, ML-KEM is libcrux's (Rust).

use std::sync::atomic::{AtomicU64, Ordering};

use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768KeyPair, MlKem768PublicKey};
use rand::RngCore;
use rustls::crypto::ring::kx_group::X25519;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use zeroize::Zeroizing;

/// The group, for a `CryptoProvider`'s `kx_groups` (first, to be preferred).
pub static X25519_MLKEM768: &dyn SupportedKxGroup = &Hybrid;

const X25519_LEN: usize = 32;
/// The client's ML-KEM share: an encapsulation key.
const ENCAPSULATION_KEY_LEN: usize = 1184;
/// The server's ML-KEM share: a ciphertext.
const CIPHERTEXT_LEN: usize = 1088;

static COMPLETED: AtomicU64 = AtomicU64::new(0);

/// How many hybrid key exchanges this process has finished; a connection
/// made in between two readings that differ had one (`qsh -v` says so).
pub fn completed() -> u64 {
    COMPLETED.load(Ordering::Relaxed)
}

fn random<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut bytes = Zeroizing::new([0u8; N]);
    rand::rngs::OsRng.fill_bytes(&mut bytes[..]);
    bytes
}

const INVALID_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// Both secrets in the order the group defines: ML-KEM's, then X25519's.
fn combine(post_quantum: &[u8], classical: &[u8]) -> SharedSecret {
    let secret = Zeroizing::new([post_quantum, classical].concat());
    COMPLETED.fetch_add(1, Ordering::Relaxed);
    SharedSecret::from(&secret[..])
}

#[derive(Debug)]
struct Hybrid;

impl SupportedKxGroup for Hybrid {
    /// The client's side: a fresh key of each kind.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = X25519.start()?;
        let post_quantum = mlkem768::generate_key_pair(*random());
        let share = [post_quantum.pk().as_slice(), classical.pub_key()].concat();
        Ok(Box::new(Active { classical, post_quantum, share }))
    }

    /// The server's side, from the client's share.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != ENCAPSULATION_KEY_LEN + X25519_LEN {
            return Err(INVALID_SHARE);
        }
        let (key, classical_share) = client_share.split_at(ENCAPSULATION_KEY_LEN);
        let key = MlKem768PublicKey::try_from(key).map_err(|_| INVALID_SHARE)?;
        // FIPS 203's check of an encapsulation key received from someone else.
        if !mlkem768::validate_public_key(&key) {
            return Err(INVALID_SHARE);
        }
        let (ciphertext, post_quantum) = mlkem768::encapsulate(&key, *random());
        let post_quantum = Zeroizing::new(post_quantum);
        let classical = X25519.start_and_complete(classical_share)?;
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: [ciphertext.as_slice().as_slice(), &classical.pub_key].concat(),
            secret: combine(&post_quantum[..], classical.secret.secret_bytes()),
        })
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct Active {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: MlKem768KeyPair,
    share: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        if server_share.len() != CIPHERTEXT_LEN + X25519_LEN {
            return Err(INVALID_SHARE);
        }
        let (ciphertext, classical_share) = server_share.split_at(CIPHERTEXT_LEN);
        let ciphertext = MlKem768Ciphertext::try_from(ciphertext).map_err(|_| INVALID_SHARE)?;
        let post_quantum = Zeroizing::new(mlkem768::decapsulate(self.post_quantum.private_key(), &ciphertext));
        let classical = self.classical.complete(classical_share)?;
        Ok(combine(&post_quantum[..], classical.secret_bytes()))
    }

    /// The X25519 key doubles as a plain X25519 share, so a server without
    /// the hybrid group answers at once instead of asking again.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_get_the_same_secret() {
        let client = X25519_MLKEM768.start().unwrap();
        assert_eq!(client.pub_key().len(), ENCAPSULATION_KEY_LEN + X25519_LEN);
        let server = X25519_MLKEM768.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(server.pub_key.len(), CIPHERTEXT_LEN + X25519_LEN);
        assert_eq!(server.group, NamedGroup::X25519MLKEM768);
        let secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(secret.secret_bytes().len(), 64);
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }

    /// The second half is exactly what X25519 alone gives, the first is ML-KEM's.
    #[test]
    fn secret_is_ml_kem_then_x25519() {
        let pq = mlkem768::generate_key_pair(*random());
        let x = X25519.start().unwrap();
        let share = [pq.pk().as_slice(), x.pub_key()].concat();
        let server = X25519_MLKEM768.start_and_complete(&share).unwrap();
        let (ciphertext, x_share) = server.pub_key.split_at(CIPHERTEXT_LEN);
        let ml_kem = mlkem768::decapsulate(pq.private_key(), &MlKem768Ciphertext::try_from(ciphertext).unwrap());
        let x25519 = x.complete(x_share).unwrap();
        assert_eq!(server.secret.secret_bytes(), [&ml_kem[..], x25519.secret_bytes()].concat());
    }

    #[test]
    fn bad_shares_are_refused() {
        let client = X25519_MLKEM768.start().unwrap();
        let share = client.pub_key().to_vec();
        assert!(X25519_MLKEM768.start_and_complete(&share[1..]).is_err(), "short");
        assert!(X25519_MLKEM768.start_and_complete(&[&share[..], &[0]].concat()).is_err(), "long");
        // A coefficient out of range (above the modulus): not a valid key.
        let mut out_of_range = share.clone();
        out_of_range[..2].copy_from_slice(&[0xff, 0xff]);
        assert!(X25519_MLKEM768.start_and_complete(&out_of_range).is_err(), "not reduced");
        let server = X25519_MLKEM768.start_and_complete(&share).unwrap();
        assert!(client.complete(&server.pub_key[1..]).is_err(), "short answer");
    }

    /// ML-KEM rejects implicitly: a changed ciphertext gives another secret,
    /// not an error, and the handshake then fails on its keys.
    #[test]
    fn changed_ciphertext_gives_another_secret() {
        let client = X25519_MLKEM768.start().unwrap();
        let mut server = X25519_MLKEM768.start_and_complete(client.pub_key()).unwrap();
        server.pub_key[0] ^= 1;
        let secret = client.complete(&server.pub_key).unwrap();
        assert_ne!(secret.secret_bytes(), server.secret.secret_bytes());
    }

    #[test]
    fn x25519_alone_from_the_same_key() {
        let client = X25519_MLKEM768.start().unwrap();
        let (group, share) = client.hybrid_component().unwrap();
        assert_eq!((group, share.len()), (NamedGroup::X25519, X25519_LEN));
        let server = X25519.start_and_complete(share).unwrap();
        let secret = client.complete_hybrid_component(&server.pub_key).unwrap();
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
    }
}
