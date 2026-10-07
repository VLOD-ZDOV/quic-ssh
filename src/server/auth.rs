//! Logging in: the key from the TLS handshake, then (protocol version 4)
//! further keys and certificates proven with signatures.

use std::time::Duration;

use anyhow::{bail, Result};
use signature::Verifier;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use tracing::{debug, warn};

use super::users::User;
use crate::authkeys::{self, AuthorizedKey, Grant, Login, Offered};
use crate::config::ServerConfig;
use crate::keys::{qsh_dir, read_strict, PublicKey};
use crate::proto::{auth_data, read_msg, write_msg, Auth, Reply};
use crate::transport::{RecvHalf, SendHalf};

/// Time for the whole key exchange after the hello (security keys need a touch).
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(120);
/// Keys a client may ask about before giving up (agents can hold many).
const MAX_QUERIES: u32 = 32;
/// Smallest accepted RSA modulus.
const MIN_RSA_BITS: usize = 2048;

/// The user's authorized_keys entries (`~/.config/qsh/authorized_keys`, and
/// `~/.ssh/authorized_keys` if enabled), read with StrictModes checks.
pub fn authorized_entries(cfg: &ServerConfig, user: &User) -> Vec<AuthorizedKey> {
    let mut files = vec![qsh_dir(&user.home).join("authorized_keys")];
    if cfg.use_ssh_authorized_keys {
        files.push(user.home.join(".ssh").join("authorized_keys"));
    }
    let mut entries = Vec::new();
    for path in files {
        match read_strict(&path, &user.home, user.uid) {
            Ok(text) => entries.extend(authkeys::parse_list(&text, |line, e| {
                warn!("{}:{line}: line ignored: {e:#}", path.display());
            })),
            Err(e) => warn!("ignoring {}: {e:#}", path.display()),
        }
    }
    entries
}

/// CA keys from `trusted_user_ca_keys`, trusted to sign certificates for any user.
pub fn trusted_cas(cfg: &ServerConfig) -> Vec<KeyData> {
    let Some(path) = &cfg.trusted_user_ca_keys else { return Vec::new() };
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| match ssh_key::PublicKey::from_openssh(l) {
                Ok(k) => Some(k.key_data().clone()),
                Err(e) => {
                    warn!("{}: bad CA key: {e}", path.display());
                    None
                }
            })
            .collect(),
        Err(e) => {
            warn!("cannot read {}: {e}", path.display());
            Vec::new()
        }
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The TLS handshake key as an offered key.
pub fn tls_key(key: PublicKey) -> Offered {
    Offered::Key(KeyData::Ed25519(Ed25519PublicKey(key.0)))
}

fn key_allowed(key: &KeyData) -> Result<()> {
    if let KeyData::Rsa(rsa) = key {
        let bits = rsa.n.as_positive_bytes().map(|b| b.len() * 8).unwrap_or(0);
        if bits < MIN_RSA_BITS {
            bail!("RSA key too small ({bits} bits, at least {MIN_RSA_BITS} needed)");
        }
    }
    if matches!(key, KeyData::Dsa(_)) {
        bail!("DSA keys are not accepted");
    }
    Ok(())
}

/// What the server knows while checking keys.
pub struct Checker<'a> {
    pub entries: &'a [AuthorizedKey],
    pub cas: &'a [KeyData],
    pub login: Login<'a>,
    pub exporter: [u8; 32],
}

impl Checker<'_> {
    pub fn check(&self, offered: &Offered) -> Result<Grant, String> {
        key_allowed(offered.signing_key()).map_err(|e| format!("{e:#}"))?;
        authkeys::check(offered, self.entries, self.cas, &self.login)
    }

    /// Checks a proof: the key is authorized and `signature` signs this login.
    fn verify(&self, key: &[u8], signature: &[u8]) -> Result<(Grant, Offered), String> {
        let offered = Offered::from_bytes(key).map_err(|e| format!("{e:#}"))?;
        let grant = self.check(&offered)?;
        let sig = ssh_key::Signature::try_from(signature).map_err(|e| format!("bad signature encoding: {e}"))?;
        let data = auth_data(&self.exporter, self.login.user, key);
        offered.signing_key().verify(&data, &sig).map_err(|_| "signature does not verify".to_string())?;
        if let Some(flags) = authkeys::security_key_flags(&sig) {
            if grant.require_presence && flags & 0x01 == 0 {
                return Err("security key was not touched (user presence required)".into());
            }
            if grant.require_verified && flags & 0x04 == 0 {
                return Err("security key did not verify the user (verify-required)".into());
            }
        }
        Ok((grant, offered))
    }
}

/// Key login after the handshake: the client asks which keys would be
/// accepted, then proves one with a signature. `Ok(None)` = denied (the
/// caller sends the final "access denied").
pub async fn key_auth(send: &mut SendHalf, recv: &mut RecvHalf, checker: &Checker<'_>, max_tries: u32) -> Result<Option<(Grant, String)>> {
    write_msg(send, &Reply::AuthKey).await?;
    let (mut queries, mut failures) = (0u32, 0u32);
    loop {
        match read_msg::<_, Auth>(recv).await? {
            Auth::Query { key } => {
                queries += 1;
                if queries > MAX_QUERIES {
                    debug!("too many keys offered");
                    return Ok(None);
                }
                let ok = Offered::from_bytes(&key).is_ok_and(|o| checker.check(&o).is_ok());
                write_msg(send, if ok { &Reply::Ok } else { &Reply::AuthKey }).await?;
            }
            Auth::PublicKey { key, signature } => match checker.verify(&key, &signature) {
                Ok((grant, offered)) => return Ok(Some((grant, offered.describe()))),
                Err(reason) => {
                    warn!("{}: {} rejected: {reason}", checker.login.ip, checker.login.user);
                    failures += 1;
                    if failures >= max_tries {
                        return Ok(None);
                    }
                    write_msg(send, &Reply::AuthKey).await?;
                }
            },
            Auth::Done => return Ok(None),
            Auth::Response(_) => bail!("unexpected answer while checking keys"),
        }
    }
}

