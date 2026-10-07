//! Logging in beyond the TLS key (protocol version 4): keys from ssh-agent
//! and key files of any type, certificates, and prompts for a second factor.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ssh_key::{Algorithm, Certificate, PrivateKey};
use tracing::debug;

use super::Target;
use crate::agent::Agent;
use crate::keys::{home_dir, Identity};
use crate::proto::{auth_data, read_msg, write_msg, Auth, Reply};
use crate::transport::{Conn, RecvHalf, SendHalf};

/// Default key files, in OpenSSH's order (used when no IdentityFile is given).
const DEFAULT_KEYS: [&str; 5] = ["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk"];

enum Signer {
    /// The key from the TLS handshake (offered here with its certificate).
    Tls,
    Agent,
    File(PathBuf),
}

struct Candidate {
    /// SSH wire-format key or certificate.
    blob: Vec<u8>,
    /// For logs and errors.
    label: String,
    signer: Signer,
}

fn is_security_key(a: &Algorithm) -> bool {
    matches!(a, Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256)
}

/// The certificate for a key file: `<key>-cert.pub`, as OpenSSH looks for it.
fn cert_path(key: &Path) -> PathBuf {
    let mut p = key.as_os_str().to_owned();
    p.push("-cert.pub");
    PathBuf::from(p)
}

fn read_cert(path: &Path) -> Option<Certificate> {
    let text = std::fs::read_to_string(path).ok()?;
    match Certificate::from_openssh(text.trim()) {
        Ok(c) => Some(c),
        Err(e) => {
            debug!("ignoring certificate {}: {e}", path.display());
            None
        }
    }
}

/// Everything this client can offer, in order: certificates of the TLS key,
/// agent keys, then key files with their certificates.
pub struct Keyring {
    agent: Option<Agent>,
    candidates: Vec<Candidate>,
    next: usize,
}

impl Keyring {
    pub async fn new(target: &Target, explicit: &[PathBuf], tls: &Identity) -> Keyring {
        let mut files: Vec<PathBuf> = explicit.iter().chain(&target.identity_files).cloned().collect();
        if files.is_empty() {
            if let Ok(home) = home_dir() {
                files = DEFAULT_KEYS.iter().map(|k| home.join(".ssh").join(k)).collect();
            }
        }
        let tls_blob = tls.public().ssh_blob();
        let mut seen: HashSet<Vec<u8>> = HashSet::from([tls_blob.clone()]);
        let mut out = Vec::new();
        let mut add = |out: &mut Vec<Candidate>, blob: Vec<u8>, label: String, signer: Signer| {
            if seen.insert(blob.clone()) {
                out.push(Candidate { blob, label, signer });
            }
        };

        // Public halves of the key files (readable without a passphrase).
        let mut file_keys = Vec::new();
        for path in &files {
            let Ok(text) = std::fs::read_to_string(path) else { continue };
            match PrivateKey::from_openssh(&text) {
                Ok(k) => file_keys.push((path.clone(), k.public_key().key_data().clone())),
                Err(e) => debug!("skipping {}: {e}", path.display()),
            }
        }
        let wanted: HashSet<Vec<u8>> = file_keys.iter().filter_map(|(_, k)| ssh_key::PublicKey::from(k.clone()).to_bytes().ok()).collect();

        // Certificates: next to each key file, and from CertificateFile.
        let mut certs: Vec<(PathBuf, Certificate)> = Vec::new();
        for (path, _) in &file_keys {
            if let Some(c) = read_cert(&cert_path(path)) {
                certs.push((path.clone(), c));
            }
        }
        for path in &target.certificate_files {
            if let Some(c) = read_cert(path) {
                certs.push((path.clone(), c));
            }
        }
        for (path, cert) in &certs {
            let Ok(blob) = cert.to_bytes() else { continue };
            let label = format!("certificate {}", path.display());
            if cert.public_key() == &ssh_key::public::KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(tls.public().0)) {
                add(&mut out, blob, label, Signer::Tls);
            } else if let Some((key, _)) = file_keys.iter().find(|(_, k)| k == cert.public_key()) {
                if !is_security_key(&cert.public_key().algorithm()) {
                    add(&mut out, blob, label, Signer::File(key.clone()));
                }
            }
        }

        let agent = match &target.identity_agent {
            Some(None) => None,
            Some(Some(path)) => Agent::connect(path).await.map_err(|e| debug!("agent: {e:#}")).ok(),
            None => Agent::from_env().await,
        };
        let mut agent = agent;
        if let Some(a) = agent.as_mut() {
            match a.keys().await {
                Ok(keys) => {
                    for k in keys {
                        // With IdentitiesOnly, only agent keys that belong to an identity file.
                        let own_key = cert_key_blob(&k.blob).unwrap_or_else(|| k.blob.clone());
                        if target.identities_only && !wanted.contains(&own_key) {
                            continue;
                        }
                        add(&mut out, k.blob, format!("agent key {}", k.comment), Signer::Agent);
                    }
                }
                Err(e) => debug!("agent: {e:#}"),
            }
        }

        for (path, key) in &file_keys {
            if is_security_key(&key.algorithm()) {
                debug!("{}: security keys are used through ssh-agent (ssh-add)", path.display());
                continue;
            }
            if let Ok(blob) = ssh_key::PublicKey::from(key.clone()).to_bytes() {
                add(&mut out, blob, format!("{} {}", key.algorithm(), path.display()), Signer::File(path.clone()));
            }
        }
        Keyring { agent, candidates: out, next: 0 }
    }

    async fn sign(&mut self, index: usize, data: &[u8], tls: &Identity, batch: bool) -> Result<Vec<u8>> {
        let c = &self.candidates[index];
        match &c.signer {
            Signer::Tls => Ok(tls.ssh_sign(data)),
            Signer::Agent => self.agent.as_mut().context("agent went away")?.sign(&c.blob, data).await,
            Signer::File(path) => {
                let key = load_private(path, batch)?;
                let sig = sign_with(&key, data).with_context(|| format!("cannot sign with {}", path.display()))?;
                Ok(Vec::try_from(sig)?)
            }
        }
    }
}

/// Signs with a key file. RSA goes through the `rsa` crate directly, with
/// blinding: ssh-key 0.6 passes the first prime twice when it rebuilds the
/// private key, so its own RSA signing always fails.
fn sign_with(key: &PrivateKey, data: &[u8]) -> Result<ssh_key::Signature> {
    if let ssh_key::private::KeypairData::Rsa(kp) = key.key_data() {
        use signature::{RandomizedSigner, SignatureEncoding};
        let big = |m: &ssh_key::Mpint| rsa::BigUint::from_bytes_be(m.as_positive_bytes().unwrap_or_default());
        let private = rsa::RsaPrivateKey::from_components(
            big(&kp.public.n),
            big(&kp.public.e),
            big(&kp.private.d),
            vec![big(&kp.private.p), big(&kp.private.q)],
        )?;
        let signer = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha512>::new(private);
        let sig = signer.try_sign_with_rng(&mut rand::rngs::OsRng, data)?;
        return Ok(ssh_key::Signature::new(Algorithm::Rsa { hash: Some(ssh_key::HashAlg::Sha512) }, sig.to_vec())?);
    }
    Ok(signature::Signer::try_sign(key, data)?)
}

/// The key inside a certificate blob, as a key blob.
fn cert_key_blob(blob: &[u8]) -> Option<Vec<u8>> {
    let cert = Certificate::from_bytes(blob).ok()?;
    ssh_key::PublicKey::from(cert.public_key().clone()).to_bytes().ok()
}

fn load_private(path: &Path, batch: bool) -> Result<PrivateKey> {
    let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let key = PrivateKey::from_openssh(&text).with_context(|| format!("cannot parse {}", path.display()))?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    if batch {
        bail!("{} is encrypted and prompting is disabled (BatchMode)", path.display());
    }
    let pass = crate::prompt::secret(&format!("Enter passphrase for {}: ", path.display()))?;
    key.decrypt(pass.as_bytes()).context("wrong passphrase")
}

/// Answers a server question (a one-time code) on the terminal or through askpass.
fn ask(text: &str, echo: bool, batch: bool) -> Result<String> {
    if batch {
        bail!("the server asks {text:?}, but prompting is disabled (BatchMode)");
    }
    if echo { crate::prompt::line(text) } else { crate::prompt::secret(text) }
}

/// What the login ended with.
pub enum Outcome {
    /// Logged in; the server's protocol version.
    Welcome(u32),
    Denied(String),
}

/// Runs the login conversation after `Hello::Login` until the server lets us in or refuses.
pub async fn login(conn: &Conn, send: &mut SendHalf, recv: &mut RecvHalf, target: &Target, explicit: &[PathBuf], tls: &Identity) -> Result<Outcome> {
    let mut keyring: Option<Keyring> = None;
    let mut reply: Reply = read_msg(recv).await?;
    loop {
        reply = match reply {
            Reply::Ok => return Ok(Outcome::Welcome(3)),
            Reply::Welcome { version } => return Ok(Outcome::Welcome(version)),
            Reply::Err(e) => return Ok(Outcome::Denied(e)),
            Reply::Prompt { text, echo } => {
                let answer = ask(&text, echo, target.batch_mode)?;
                write_msg(send, &Auth::Response(answer)).await?;
                read_msg(recv).await?
            }
            Reply::AuthKey => {
                if keyring.is_none() {
                    keyring = Some(Keyring::new(target, explicit, tls).await);
                }
                let ring = keyring.as_mut().unwrap();
                offer_next(ring, conn, send, recv, target, tls).await?
            }
            other => bail!("unexpected reply {other:?} while logging in"),
        };
    }
}

/// Offers keys until the server accepts one, then proves it. Returns the
/// server's answer to the proof, or to `Auth::Done` if nothing was accepted.
async fn offer_next(ring: &mut Keyring, conn: &Conn, send: &mut SendHalf, recv: &mut RecvHalf, target: &Target, tls: &Identity) -> Result<Reply> {
    while ring.next < ring.candidates.len() {
        let index = ring.next;
        ring.next += 1;
        let blob = ring.candidates[index].blob.clone();
        write_msg(send, &Auth::Query { key: blob.clone() }).await?;
        match read_msg::<_, Reply>(recv).await? {
            Reply::Ok => {}
            Reply::AuthKey => continue,
            other => return Ok(other),
        }
        debug!("server accepts {}", ring.candidates[index].label);
        let data = auth_data(&conn.exporter(), &target.user, &blob);
        let signature = match ring.sign(index, &data, tls, target.batch_mode).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("qsh: {}: {e:#}", ring.candidates[index].label);
                continue;
            }
        };
        write_msg(send, &Auth::PublicKey { key: blob, signature }).await?;
        return read_msg(recv).await;
    }
    write_msg(send, &Auth::Done).await?;
    read_msg(recv).await
}
