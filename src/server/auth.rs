//! Logging in: the key from the TLS handshake, then (protocol version 4)
//! further keys and certificates proven with signatures.

use std::time::Duration;

use anyhow::{bail, Result};
use signature::Verifier;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use tracing::warn;

use super::users::User;
use crate::authkeys::{self, AuthorizedKey, Grant, Login, Offered};
use crate::config::{ServerConfig, Totp};
use crate::keys::{qsh_dir, read_strict, read_strict_private, PublicKey};
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

/// Exact bit length of a big-endian unsigned integer (leading zero bits do not count).
fn bit_length(bytes: &[u8]) -> usize {
    match bytes.iter().position(|&b| b != 0) {
        Some(i) => (bytes.len() - i) * 8 - bytes[i].leading_zeros() as usize,
        None => 0,
    }
}

fn key_allowed(key: &KeyData) -> Result<()> {
    if let KeyData::Rsa(rsa) = key {
        let bits = rsa.n.as_positive_bytes().map(bit_length).unwrap_or(0);
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
    pub revoked: &'a super::revoked::Revocation,
    pub login: Login<'a>,
    pub exporter: [u8; 32],
}

impl Checker<'_> {
    pub fn check(&self, offered: &Offered) -> Result<Grant, String> {
        key_allowed(offered.signing_key()).map_err(|e| format!("{e:#}"))?;
        self.revoked.check(offered)?;
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
                    warn!("{}: {} offered more than {MAX_QUERIES} keys; giving up", checker.login.ip, checker.login.user);
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


/// Wrong one-time codes allowed per connection.
const TOTP_TRIES: u32 = 3;

/// The last accepted time step per user, so a code works only once.
/// Wrong one-time codes per user allowed within [`TOTP_WINDOW`], over all
/// connections (one connection only allows [`TOTP_TRIES`]).
const TOTP_MAX_FAILURES: usize = 10;
const TOTP_WINDOW: Duration = Duration::from_secs(15 * 60);

/// One-time code bookkeeping per uid: the last accepted time step (so a code
/// works once) and recent failures (so codes cannot be guessed by reconnecting).
#[derive(Default)]
pub struct TotpState {
    used: std::collections::HashMap<u32, u64>,
    failures: std::collections::HashMap<u32, std::collections::VecDeque<std::time::Instant>>,
}

impl TotpState {
    /// Recent failures of `uid`, forgetting those older than the window.
    fn recent_failures(&mut self, uid: u32) -> usize {
        let Some(list) = self.failures.get_mut(&uid) else { return 0 };
        while list.front().is_some_and(|t| t.elapsed() > TOTP_WINDOW) {
            list.pop_front();
        }
        if list.is_empty() {
            self.failures.remove(&uid);
            return 0;
        }
        list.len()
    }
}

pub type UsedCodes = std::sync::Mutex<TotpState>;

/// Second factor after a key: asks for a one-time code if the user has set
/// one up (or if the server requires it). `Err(message)` = deny with that answer.
pub async fn second_factor(
    send: &mut SendHalf,
    recv: &mut RecvHalf,
    user: &User,
    mode: Totp,
    version: u32,
    used: &UsedCodes,
) -> Result<Result<(), String>> {
    if mode == Totp::Off {
        return Ok(Ok(()));
    }
    let path = crate::totp::secret_path(&user.home);
    let secret = match read_strict_private(&path, &user.home, user.uid) {
        Ok(Some(text)) => match crate::totp::base32_decode(text.trim()) {
            Ok(s) if s.len() >= 10 => s,
            _ => {
                warn!("{}: unusable secret, login refused", path.display());
                return Ok(Err("access denied".into()));
            }
        },
        Ok(None) if mode == Totp::Required => {
            return Ok(Err("this server requires a one-time code, but none is set up for the account (`qshd totp`)".into()));
        }
        Ok(None) => return Ok(Ok(())),
        // A secret that cannot be read safely must not turn 2FA off.
        Err(e) => {
            warn!("{e:#}; login refused");
            return Ok(Err("access denied".into()));
        }
    };
    if version < 4 {
        return Ok(Err("this account needs a one-time code; update qsh to 0.5 or newer".into()));
    }
    for _ in 0..TOTP_TRIES {
        if used.lock().unwrap().recent_failures(user.uid) >= TOTP_MAX_FAILURES {
            warn!("{}: too many wrong one-time codes recently; refusing for now", user.name);
            return Ok(Err("too many wrong one-time codes; try again later".into()));
        }
        write_msg(send, &Reply::Prompt { text: "One-time code: ".into(), echo: false }).await?;
        let answer = match read_msg::<_, Auth>(recv).await? {
            Auth::Response(a) => a,
            Auth::Done => break,
            _ => bail!("unexpected message while asking for a one-time code"),
        };
        {
            let mut state = used.lock().unwrap();
            let last = state.used.get(&user.uid).copied();
            if let Some(step) = crate::totp::verify(&secret, &answer, now(), last) {
                state.used.insert(user.uid, step);
                state.failures.remove(&user.uid);
                return Ok(Ok(()));
            }
            state.failures.entry(user.uid).or_default().push_back(std::time::Instant::now());
        }
        warn!("{}: wrong one-time code", user.name);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(Err("access denied".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rsa_with_modulus(n: &[u8]) -> KeyData {
        KeyData::Rsa(ssh_key::public::RsaPublicKey {
            e: ssh_key::Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(),
            n: ssh_key::Mpint::from_positive_bytes(n).unwrap(),
        })
    }

    #[test]
    fn rsa_size_counts_real_bits() {
        assert_eq!(bit_length(&[0x01, 0xff]), 9);
        assert_eq!(bit_length(&[0x80, 0x00]), 16);
        assert_eq!(bit_length(&[0, 0]), 0);
        for (first, bits, ok) in [(0x01u8, 2041, false), (0x7f, 2047, false), (0x80, 2048, true)] {
            let mut n = vec![0xffu8; 256];
            n[0] = first;
            assert_eq!(bit_length(&n), bits);
            assert_eq!(key_allowed(&rsa_with_modulus(&n)).is_ok(), ok, "{bits} bits");
        }
    }

    #[test]
    fn totp_failures_are_counted_per_user_and_expire() {
        let mut state = TotpState::default();
        let old = std::time::Instant::now() - TOTP_WINDOW - Duration::from_secs(1);
        state.failures.entry(7).or_default().extend([old, old, std::time::Instant::now()]);
        assert_eq!(state.recent_failures(7), 1, "old failures are forgotten");
        assert_eq!(state.recent_failures(8), 0);
    }
}
