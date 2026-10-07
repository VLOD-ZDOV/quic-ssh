//! One-time-code pairing: adds a client key on the server and pins the host
//! key on the client, authenticated with SPAKE2 so a short code is enough.
//!
//! Flow on a fresh connection (after `Hello::Pair`):
//! 1. both sides exchange SPAKE2 messages derived from the code;
//! 2. the client sends `HMAC(K, "client" || T)`, the server checks it;
//! 3. the server stores the client key and answers `Reply::Ok` + `HMAC(K, "server" || T)`.
//!
//! `T` = TLS exporter || client key || server key, so the proof is bound to
//! this exact TLS session and both certificates; a man in the middle cannot
//! relay it. The code is deleted after the first attempt, so it allows one guess.

#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use anyhow::Context;
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity as SpakeId, Password, Spake2};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
use crate::keys::{create_private_dir, qsh_dir};
use crate::keys::PublicKey;
use crate::proto::{read_msg, write_msg, Reply};

pub const CODE_TTL: Duration = Duration::from_secs(600);
const ALPHABET: &[u8] = b"23456789abcdefghjkmnpqrstuvwxyz";
const SPAKE_ID: &[u8] = b"qsh-pair-v1";

/// Random code like `k7f3-9qxm` (~40 bits; one guess per code).
pub fn generate_code() -> String {
    let mut rng = rand::rngs::OsRng;
    let chars: String = (0..8)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// Lowercases and drops separators so `K7F3 9QXM` matches `k7f3-9qxm`.
pub fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(unix)]
fn pending_path(home: &Path) -> PathBuf {
    qsh_dir(home).join("pending_pair")
}

#[cfg(unix)]
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Creates a new pending code for the user owning `home`, replacing any older one.
#[cfg(unix)]
pub fn create_pending(home: &Path) -> Result<String> {
    let code = generate_code();
    let path = pending_path(home);
    create_private_dir(path.parent().unwrap())?;
    let _ = std::fs::remove_file(&path);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    writeln!(f, "{} {}", normalize(&code), now() + CODE_TTL.as_secs())?;
    Ok(code)
}

/// Reads and deletes the pending code. Runs as the target user.
#[cfg(unix)]
pub fn take_pending(home: &Path) -> Result<String> {
    let path = pending_path(home);
    let mut f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("no pairing code is active; run `qshd pair` on the server first")
        }
        Err(e) => return Err(e).context("cannot open pairing file"),
    };
    // Single use: remove before anything else can fail.
    std::fs::remove_file(&path).context("cannot remove pairing file")?;
    let meta = f.metadata()?;
    if !meta.is_file() || meta.uid() != nix::unistd::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
        bail!("pairing file has unsafe owner or permissions");
    }
    let mut text = String::new();
    Read::take(&mut f, 256).read_to_string(&mut text)?;
    let mut parts = text.split_whitespace();
    let code = parts.next().context("malformed pairing file")?.to_string();
    let expires: u64 = parts.next().and_then(|s| s.parse().ok()).context("malformed pairing file")?;
    if now() > expires {
        bail!("pairing code expired; run `qshd pair` again");
    }
    Ok(code)
}

fn transcript(exporter: &[u8; 32], client: PublicKey, server: PublicKey) -> Vec<u8> {
    [exporter.as_slice(), &client.0, &server.0].concat()
}

fn mac(key: &[u8], role: &[u8], transcript: &[u8]) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(role);
    m.update(transcript);
    m
}

async fn spake<S, R>(send: &mut S, recv: &mut R, code: &str) -> Result<Vec<u8>>
where
    S: AsyncWrite + Unpin + ?Sized,
    R: AsyncRead + Unpin + ?Sized,
{
    let (state, outbound) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(normalize(code).as_bytes()),
        &SpakeId::new(SPAKE_ID),
    );
    write_msg(send, &outbound).await?;
    let inbound: Vec<u8> = read_msg(recv).await?;
    state.finish(&inbound).map_err(|e| anyhow::anyhow!("pairing failed: {e:?}"))
}

/// Client side. On success the server has stored our key and proven it knows the code.
pub async fn client<S, R>(
    send: &mut S,
    recv: &mut R,
    code: &str,
    exporter: &[u8; 32],
    client_key: PublicKey,
    server_key: PublicKey,
) -> Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
    R: AsyncRead + Unpin + ?Sized,
{
    let t = transcript(exporter, client_key, server_key);
    let key = spake(send, recv, code).await?;
    write_msg(send, &mac(&key, b"client", &t).finalize().into_bytes().to_vec()).await?;
    match read_msg(recv).await? {
        Reply::Ok => {}
        Reply::Err(e) => bail!("{e}"),
        other => bail!("unexpected reply {other:?}"),
    }
    let server_mac: Vec<u8> = read_msg(recv).await?;
    mac(&key, b"server", &t)
        .verify_slice(&server_mac)
        .map_err(|_| anyhow::anyhow!("server failed to prove the pairing code (possible MITM)"))
}

/// Server side after the client proved the code; call [`Verified::confirm`] once the key is stored.
pub struct Verified {
    key: Vec<u8>,
    transcript: Vec<u8>,
}

/// Runs SPAKE2 and checks the client's proof. On failure an error reply is sent.
pub async fn server_verify<S, R>(
    send: &mut S,
    recv: &mut R,
    code: &str,
    exporter: &[u8; 32],
    client_key: PublicKey,
    server_key: PublicKey,
) -> Result<Verified>
where
    S: AsyncWrite + Unpin + ?Sized,
    R: AsyncRead + Unpin + ?Sized,
{
    let t = transcript(exporter, client_key, server_key);
    let key = spake(send, recv, code).await?;
    let client_mac: Vec<u8> = read_msg(recv).await?;
    if mac(&key, b"client", &t).verify_slice(&client_mac).is_err() {
        write_msg(send, &Reply::Err("wrong pairing code (the code is now used up)".into())).await?;
        bail!("wrong pairing code");
    }
    Ok(Verified { key, transcript: t })
}

impl Verified {
    pub async fn confirm<S: AsyncWrite + Unpin + ?Sized>(self, send: &mut S) -> Result<()> {
        write_msg(send, &Reply::Ok).await?;
        let m = mac(&self.key, b"server", &self.transcript).finalize().into_bytes().to_vec();
        write_msg(send, &m).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Identity;

    async fn run(client_code: &str, server_code: &str, server_exporter: [u8; 32]) -> (Result<()>, Result<()>) {
        let (mut c, mut s) = tokio::io::duplex(4096);
        let ck = Identity::generate().public();
        let sk = Identity::generate().public();
        let exporter = [9u8; 32];
        let server_code = server_code.to_string();
        let server = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut s);
            let v = server_verify(&mut w, &mut r, &server_code, &server_exporter, ck, sk).await?;
            v.confirm(&mut w).await
        });
        let (mut r, mut w) = tokio::io::split(&mut c);
        let res = client(&mut w, &mut r, client_code, &exporter, ck, sk).await;
        (res, server.await.unwrap())
    }

    #[tokio::test]
    async fn matching_codes_pair() {
        let (c, s) = run("K7F3 9QXM", "k7f3-9qxm", [9u8; 32]).await;
        c.unwrap();
        s.unwrap();
    }

    #[tokio::test]
    async fn wrong_code_fails_both_sides() {
        let (c, s) = run("aaaa-aaaa", "k7f3-9qxm", [9u8; 32]).await;
        assert!(c.is_err());
        assert!(s.is_err());
    }

    #[tokio::test]
    async fn different_sessions_fail() {
        // Same code but different TLS sessions (as with a relaying MITM).
        let (c, s) = run("k7f3-9qxm", "k7f3-9qxm", [1u8; 32]).await;
        assert!(c.is_err());
        assert!(s.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pending_file_single_use() {
        let home = tempfile::tempdir().unwrap();
        let code = create_pending(home.path()).unwrap();
        assert_eq!(take_pending(home.path()).unwrap(), normalize(&code));
        assert!(take_pending(home.path()).is_err());
    }
}
