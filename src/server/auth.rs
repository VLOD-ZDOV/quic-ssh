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
use crate::keys::{qsh_dir, read_strict, open_strict_private, PublicKey};
use crate::proto::{auth_data, read_msg, write_msg, Auth, Reply};
use crate::transport::{RecvHalf, SendHalf};

/// Keys a client may ask about before giving up (agents can hold many).
const MAX_QUERIES: u32 = 32;
/// Smallest accepted RSA modulus.
const MIN_RSA_BITS: usize = 2048;

/// The user's authorized_keys entries (`~/.config/qsh/authorized_keys` if
/// `use_qsh_authorized_keys`, and `authorized_keys_file` if
/// `use_ssh_authorized_keys`), read with StrictModes checks.
pub fn authorized_entries(cfg: &ServerConfig, user: &User) -> Vec<AuthorizedKey> {
    let mut files = Vec::new();
    if cfg.use_qsh_authorized_keys {
        files.push(qsh_dir(&user.home).join("authorized_keys"));
    }
    if cfg.use_ssh_authorized_keys {
        for f in cfg.authorized_keys_files(&user.name, user.uid, &user.home) {
            match f {
                Ok(path) => files.push(path),
                Err(e) => warn!("authorized_keys_file: {e:#}"),
            }
        }
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

/// The user's `authorized_principals_file`, if one is configured (an
/// unreadable one allows no principal, as in sshd).
pub fn authorized_principals(cfg: &ServerConfig, user: &User) -> Option<Vec<authkeys::AuthorizedPrincipal>> {
    let file = cfg.authorized_principals_file.as_ref()?;
    let path = match crate::config::expand_user_path(file, &user.name, user.uid, &user.home) {
        Ok(p) => user.home.join(p),
        Err(e) => {
            warn!("authorized_principals_file: {e:#}");
            return Some(Vec::new());
        }
    };
    match read_strict(&path, &user.home, user.uid) {
        Ok(text) => Some(authkeys::parse_principals(&text, |line, e| warn!("{}:{line}: line ignored: {e:#}", path.display()))),
        Err(e) => {
            warn!("ignoring {}: {e:#}", path.display());
            Some(Vec::new())
        }
    }
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
    /// `authorized_keys_command`, if configured.
    #[cfg(unix)]
    pub command: Option<&'a super::keys_command::KeysCommand<'a>>,
    /// Stands in for `authorized_keys_command` where it is not run.
    #[cfg(unix)]
    pub mimic: Option<&'a super::keys_command::Mimic>,
    pub login: Login<'a>,
    pub exporter: [u8; 32],
}

impl Checker<'_> {
    pub async fn check(&self, offered: &Offered) -> Result<Grant, String> {
        key_allowed(offered.signing_key()).map_err(|e| format!("{e:#}"))?;
        // The CA's key must meet the same minimum (no small RSA CAs).
        if let Offered::Cert(cert) = offered {
            key_allowed(cert.signature_key()).map_err(|e| format!("certificate authority: {e:#}"))?;
        }
        self.revoked.check(offered)?;
        let from_files = authkeys::check(offered, self.entries, self.cas, &self.login);
        #[cfg(not(unix))]
        return from_files;
        #[cfg(unix)]
        match (from_files, self.command, self.mimic) {
            (Err(_), Some(command), _) => authkeys::check(offered, &command.entries(offered).await, self.cas, &self.login),
            (Err(e), None, Some(mimic)) => {
                mimic.wait(offered).await;
                Err(e)
            }
            (result, _, _) => result,
        }
    }

    /// Checks a proof: the key is authorized and `signature` signs this login.
    async fn verify(&self, key: &[u8], signature: &[u8]) -> Result<(Grant, Offered), String> {
        let offered = Offered::from_bytes(key).map_err(|e| format!("{e:#}"))?;
        let grant = self.check(&offered).await?;
        let sig = ssh_key::Signature::try_from(signature).map_err(|e| format!("bad signature encoding: {e}"))?;
        if !authkeys::signature_fits(offered.signing_key(), &sig) {
            return Err(format!("{} signature for a {} key", sig.algorithm(), offered.signing_key().algorithm()));
        }
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
                    warn!("{}: {:?} offered more than {MAX_QUERIES} keys; giving up", checker.login.ip, checker.login.user);
                    return Ok(None);
                }
                let ok = match Offered::from_bytes(&key) {
                    Ok(o) => checker.check(&o).await.is_ok(),
                    Err(_) => false,
                };
                write_msg(send, if ok { &Reply::Ok } else { &Reply::AuthKey }).await?;
            }
            Auth::PublicKey { key, signature } => match checker.verify(&key, &signature).await {
                Ok((grant, offered)) => return Ok(Some((grant, offered.describe()))),
                Err(reason) => {
                    warn!("{}: {:?} rejected: {reason}", checker.login.ip, checker.login.user);
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


/// Passwords a client may try per connection (like sshd's default 3 prompts).
#[cfg(unix)]
const PASSWORD_TRIES: u32 = 3;

/// Whether `password` matches a crypt(3) hash: yescrypt (`$y$`) or
/// SHA-crypt (`$5$`, `$6$`). Locked (`!`, `*`) and other hashes never match;
/// an empty hash only for an empty password with `empty_ok`.
#[cfg(unix)]
pub fn password_matches(hash: &str, password: &str, empty_ok: bool) -> bool {
    use sha_crypt::PasswordVerifier as _;
    if hash.is_empty() {
        return empty_ok && password.is_empty();
    }
    if hash.starts_with("$y$") {
        yescrypt::Yescrypt::default().verify_password(password.as_bytes(), hash).is_ok()
    } else if hash.starts_with("$5$") || hash.starts_with("$6$") {
        sha_crypt::ShaCrypt::default().verify_password(password.as_bytes(), hash).is_ok()
    } else {
        false
    }
}

/// Longest password checked (as in sshd): hashing a huge one would let a
/// client keep the server busy (compare CVE-2016-6515).
#[cfg(unix)]
const MAX_PASSWORD: usize = 1024;

/// A hash qshd can check (yescrypt or SHA-crypt).
#[cfg(unix)]
fn usable_hash(h: &str) -> bool {
    h.starts_with("$y$") || h.starts_with("$5$") || h.starts_with("$6$")
}

/// The hash unknown users are checked against, so they take as long as
/// known ones (compare CVE-2016-6210): a real one from /etc/shadow (root's,
/// or else the first usable), so its scheme and cost are the system's; a
/// match against it never counts. Without one, a yescrypt hash of a random
/// password.
#[cfg(unix)]
fn dummy_hash() -> String {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        let from_shadow = super::users::shadow_hash("root").filter(|h| usable_hash(h)).or_else(|| {
            let text = std::fs::read_to_string("/etc/shadow").ok()?;
            text.lines().filter_map(|l| l.split(':').nth(1)).find(|h| usable_hash(h)).map(str::to_string)
        });
        from_shadow.unwrap_or_else(|| {
            use yescrypt::PasswordHasher as _;
            let (password, salt): ([u8; 16], [u8; 16]) = (rand::random(), rand::random());
            yescrypt::Yescrypt::default().hash_password_with_salt(&password, &salt).map(|h| h.to_string()).unwrap_or_default()
        })
    })
    .clone()
}

/// Password login after keys failed (`password_authentication`): asks up to
/// [`PASSWORD_TRIES`] times. `user` is `None` for an unknown or refused user,
/// who gets the same questions and the same work done.
/// Windows passwords are not checked by qshd: keys only.
#[cfg(windows)]
pub async fn password_auth(_send: &mut SendHalf, _recv: &mut RecvHalf, _user: Option<&User>, _empty_ok: bool, _login: &Login<'_>) -> Result<bool> {
    Ok(false)
}

#[cfg(unix)]
pub async fn password_auth(send: &mut SendHalf, recv: &mut RecvHalf, user: Option<&User>, empty_ok: bool, login: &Login<'_>) -> Result<bool> {
    // Only root reads /etc/shadow: without it no password can match. An
    // expired password (or one that must be changed first) does not either,
    // as qshd cannot have it changed; keys still work.
    let hash = match user.filter(|u| u.switches()) {
        Some(u) => {
            let name = u.name.clone();
            tokio::task::spawn_blocking(move || super::users::shadow_hash(&name).filter(|_| !super::users::password_expired(&name))).await?
        }
        None => None,
    };
    for _ in 0..PASSWORD_TRIES {
        write_msg(send, &Reply::Password).await?;
        let password = match read_msg::<_, Auth>(recv).await? {
            Auth::Response(p) => zeroize::Zeroizing::new(p),
            Auth::Done => return Ok(false),
            _ => bail!("unexpected message while asking for a password"),
        };
        // Locked accounts (`!`, `*`) take as long as others, too.
        let (hash, known) = match &hash {
            Some(h) if usable_hash(h) || (h.is_empty() && empty_ok) => (h.clone(), true),
            _ => (dummy_hash(), false),
        };
        // An empty password only with permit_empty_passwords, whatever the hash.
        let ok = password.len() <= MAX_PASSWORD
            && tokio::task::spawn_blocking(move || password_matches(&hash, &password, empty_ok) && (empty_ok || !password.is_empty())).await?
            && known;
        if ok {
            return Ok(true);
        }
        warn!("{}: wrong password for {:?}", login.ip, login.user);
        // Like a wrong one-time code: guessing takes time on every connection.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(false)
}

/// Questions and messages from PAM modules per login.
#[cfg(all(feature = "pam", target_os = "linux"))]
const PAM_MESSAGES: u32 = 32;

/// Password login through PAM (`use_pam`): `pam_authenticate`, up to
/// [`PASSWORD_TRIES`] times, then `pam_acct_mgmt`. The modules' questions go
/// to the client: one for a password as [`Reply::Password`] (so qsh asks
/// it as for a password of its own), others as [`Reply::Prompt`]; their
/// messages only to the log. `user` is `None` for an unknown or refused
/// user: PAM is asked for `NOUSER` with a wrong answer, like sshd, so it
/// takes the same steps and time. A login is refused if a module changed
/// `PAM_USER`. True when logged in.
#[cfg(all(feature = "pam", target_os = "linux"))]
pub async fn pam_password_auth(send: &mut SendHalf, recv: &mut RecvHalf, user: Option<&User>, cfg: &ServerConfig, login: &Login<'_>) -> Result<bool> {
    use super::pam::{Conversation, Message, Pam, PAM_DISALLOW_NULL_AUTHTOK, PAM_NEW_AUTHTOK_REQD};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::{mpsc, oneshot};

    struct Ask {
        text: String,
        echo: bool,
        answer: oneshot::Sender<Option<zeroize::Zeroizing<String>>>,
    }
    /// What an unknown user's answers become.
    const WRONG: &str = "\x08\n\r\x7fINCORRECT";
    let (tx, mut rx) = mpsc::channel::<Ask>(1);
    let gave_up = Arc::new(AtomicBool::new(false));
    let known = user.is_some();
    let name = user.map(|u| u.name.clone()).unwrap_or_else(|| "NOUSER".into());
    let (service, rhost) = (cfg.pam_service.clone(), login.ip.to_string());
    let flags = if cfg.permit_empty_passwords { 0 } else { PAM_DISALLOW_NULL_AUTHTOK };
    let stopped = gave_up.clone();
    let name_for_log = name.clone();
    let worker = tokio::task::spawn_blocking(move || -> Result<bool> {
        let mut asked = 0u32;
        let conv: Conversation = Box::new(move |m| {
            asked += 1;
            if asked > PAM_MESSAGES {
                return None;
            }
            match m {
                Message::Prompt { text, echo } => {
                    let (answer, answered) = oneshot::channel();
                    tx.blocking_send(Ask { text: text.to_string(), echo, answer }).ok()?;
                    let given = answered.blocking_recv().ok().flatten()?;
                    Some(if known && given.len() <= MAX_PASSWORD { given.to_string() } else { WRONG.to_string() })
                }
                // Not to the client before it is in: some (pam_faillock's
                // "account locked") tell whether an account exists.
                Message::Info { text, .. } => {
                    tracing::info!("PAM ({name_for_log}): {}", text.trim());
                    None
                }
            }
        });
        let mut pam = Pam::start(&service, &name, conv)?;
        pam.set_rhost(&rhost)?;
        pam.set_tty("ssh")?;
        for _ in 0..PASSWORD_TRIES {
            match pam.authenticate(flags) {
                // A module may have changed the user: then this is not their login.
                Ok(()) if known && pam.user().as_deref() != Some(name.as_str()) => {
                    warn!("{rhost}: PAM authenticated {:?} instead of {name:?}; refused", pam.user());
                    return Ok(false);
                }
                Ok(()) if known => {
                    return Ok(match pam.acct_mgmt(0) {
                        Ok(()) => true,
                        // It cannot be changed here; keys still work.
                        Err(e) if e.code == PAM_NEW_AUTHTOK_REQD => {
                            warn!("{rhost}: the password of {name:?} has expired");
                            false
                        }
                        Err(e) => {
                            warn!("{rhost}: PAM account check refused {name:?}: {e}");
                            false
                        }
                    });
                }
                Ok(()) => warn!("{rhost}: PAM accepted the wrong answer for {name:?}"),
                Err(e) => warn!("{rhost}: PAM authentication of {name:?} failed: {e}"),
            }
            if stopped.load(Ordering::Relaxed) {
                break;
            }
        }
        Ok(false)
    });
    // The worker drops its end of the channel when it is done with PAM.
    while let Some(Ask { text, echo, answer }) = rx.recv().await {
        let reply = if !echo && text.to_lowercase().contains("password") { Reply::Password } else { Reply::Prompt { text, echo } };
        write_msg(send, &reply).await?;
        match read_msg::<_, Auth>(recv).await? {
            Auth::Response(p) => {
                let _ = answer.send(Some(zeroize::Zeroizing::new(p)));
            }
            Auth::Done => {
                gave_up.store(true, Ordering::Relaxed);
                let _ = answer.send(None);
            }
            _ => bail!("unexpected message while asking for a password"),
        }
    }
    worker.await?
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
pub struct TotpState {
    used: std::collections::HashMap<u32, u64>,
    failures: std::collections::HashMap<u32, std::collections::VecDeque<std::time::Instant>>,
    /// Codes asked for and not answered yet, per uid: they count as possible
    /// failures, so parallel logins cannot get more guesses than the limit.
    pending: std::collections::HashMap<u32, usize>,
    /// The last time step an earlier qshd process could have accepted: the
    /// codes it used are not known, so none up to here are taken (a code
    /// seen before a restart cannot be replayed after it).
    floor: u64,
}

impl Default for TotpState {
    fn default() -> TotpState {
        // Tests log in right after starting a server (never in release builds).
        let testing = cfg!(debug_assertions) && std::env::var_os("QSHD_TEST_NO_TOTP_FLOOR").is_some();
        let floor = if testing { 0 } else { now() / crate::totp::STEP + crate::totp::WINDOW };
        TotpState { used: Default::default(), failures: Default::default(), pending: Default::default(), floor }
    }
}

impl TotpState {
    /// Steps up to this one are not accepted for `uid`.
    fn last_used(&self, uid: u32) -> u64 {
        self.used.get(&uid).copied().unwrap_or(0).max(self.floor)
    }

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

/// The last code step taken by any qshd, kept as the secret file's
/// modification time on a step boundary (a file written by hand is not on
/// one, to the nanosecond).
fn step_taken(file: &std::fs::File) -> u64 {
    let mtime = file.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
    match mtime {
        Some(t) if t.subsec_nanos() == 0 && t.as_secs() > 0 && t.as_secs().is_multiple_of(crate::totp::STEP) => t.as_secs() / crate::totp::STEP,
        _ => 0,
    }
}

/// Locks the secret file, waiting at most a few seconds.
async fn lock_briefly(file: &std::fs::File) -> std::io::Result<()> {
    for _ in 0..60 {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        }
    }
    Err(std::io::Error::other("held by another process"))
}

fn take_step(file: &std::fs::File, path: &std::path::Path, step: u64) {
    let mtime = std::time::UNIX_EPOCH + Duration::from_secs(step * crate::totp::STEP);
    // Windows sets times only through a handle opened to change attributes.
    #[cfg(windows)]
    let reopened = {
        const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
        std::os::windows::fs::OpenOptionsExt::access_mode(&mut std::fs::OpenOptions::new(), FILE_WRITE_ATTRIBUTES).open(path)
    };
    #[cfg(windows)]
    let file = reopened.as_ref().unwrap_or(file);
    #[cfg(not(windows))]
    let _ = path;
    if let Err(e) = file.set_modified(mtime) {
        warn!("cannot mark the one-time code as used for other qshd instances: {e}");
    }
}

/// Second factor after a key: asks for a one-time code if the user has set
/// one up (or if the server requires it). `Err(message)` = deny with that
/// answer; `Ok(true)`: a code was given.
pub async fn second_factor(
    send: &mut SendHalf,
    recv: &mut RecvHalf,
    user: &User,
    mode: Totp,
    version: u32,
    used: &UsedCodes,
) -> Result<Result<bool, String>> {
    if mode == Totp::Off {
        return Ok(Ok(false));
    }
    let path = crate::totp::secret_path(&user.home);
    let read = {
        let (path, home, uid) = (path.clone(), user.home.clone(), user.uid);
        tokio::task::spawn_blocking(move || open_strict_private(&path, &home, uid)).await?
    };
    let (secret, file) = match read {
        Ok(Some((text, file))) => match crate::totp::base32_decode(text.trim()) {
            Ok(s) if s.len() >= 10 => (s, file),
            _ => {
                warn!("{}: unusable secret, login refused", path.display());
                return Ok(Err("access denied".into()));
            }
        },
        Ok(None) if mode == Totp::Required => {
            return Ok(Err("this server requires a one-time code, but none is set up for the account (`qshd totp`)".into()));
        }
        Ok(None) => return Ok(Ok(false)),
        // A secret that cannot be read safely must not turn 2FA off.
        Err(e) => {
            warn!("{e:#}; login refused");
            return Ok(Err("access denied".into()));
        }
    };
    if version < 4 {
        return Ok(Err("this account needs a one-time code; update qsh to 0.5 or newer".into()));
    }
    /// Takes back a reserved guess when its answer is in (or the login ends).
    struct Reserved<'a>(&'a UsedCodes, u32);
    impl Drop for Reserved<'_> {
        fn drop(&mut self) {
            let mut state = self.0.lock().unwrap();
            if let Some(n) = state.pending.get_mut(&self.1) {
                *n -= 1;
                if *n == 0 {
                    state.pending.remove(&self.1);
                }
            }
        }
    }
    for _ in 0..TOTP_TRIES {
        let _reserved = {
            let mut state = used.lock().unwrap();
            let pending = state.pending.get(&user.uid).copied().unwrap_or(0);
            if state.recent_failures(user.uid) + pending >= TOTP_MAX_FAILURES {
                warn!("{}: too many wrong one-time codes recently; refusing for now", user.name);
                return Ok(Err("too many wrong one-time codes; try again later".into()));
            }
            *state.pending.entry(user.uid).or_default() += 1;
            Reserved(used, user.uid)
        };
        // Right after a start, the current code may be one that is not taken.
        let starting = now() / crate::totp::STEP <= used.lock().unwrap().floor;
        let text = if starting { "One-time code (qshd has just started: wait for the next code): " } else { "One-time code: " };
        write_msg(send, &Reply::Prompt { text: text.into(), echo: false }).await?;
        let answer = match read_msg::<_, Auth>(recv).await? {
            Auth::Response(a) => a,
            Auth::Done => break,
            _ => bail!("unexpected message while asking for a one-time code"),
        };
        // Another qshd of the user's (another port, a user-mode one) may
        // have taken a code: the lock makes check and mark one step.
        // Without the lock (a file system without locks, or the user holds
        // it), this qshd still takes each code once; tell why others might not.
        // The user owns the file and can hold the lock forever: never block
        // on it, least of all under `used`, which every login shares.
        if let Err(e) = lock_briefly(&file).await {
            warn!("{}: cannot lock the one-time code file ({e}); another qshd of the user could take the same code", user.name);
        }
        {
            let mut state = used.lock().unwrap();
            let last = state.last_used(user.uid).max(step_taken(&file));
            if let Some(step) = crate::totp::verify(&secret, &answer, now(), Some(last)) {
                state.used.insert(user.uid, step);
                state.failures.remove(&user.uid);
                take_step(&file, &path, step);
                return Ok(Ok(true));
            }
            let _ = file.unlock();
            state.failures.entry(user.uid).or_default().push_back(std::time::Instant::now());
        }
        warn!("{}: wrong one-time code", user.name);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(Err("access denied".into()))
}

#[cfg(test)]
mod tests {
    /// A lock the user holds on the secret file does not stall the login.
    #[tokio::test]
    async fn held_lock_is_given_up_on() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let held = std::fs::File::open(path.path()).unwrap();
        held.lock().unwrap();
        let mine = std::fs::File::open(path.path()).unwrap();
        let start = std::time::Instant::now();
        assert!(super::lock_briefly(&mine).await.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        drop(held);
        assert!(super::lock_briefly(&mine).await.is_ok());
    }

    /// The step taken is kept in the secret file for other qshd instances.
    #[test]
    fn taken_step_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "x").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert_eq!(super::step_taken(&file), 0, "a file written normally marks nothing");
        super::take_step(&file, &path, 59_000_000);
        assert_eq!(super::step_taken(&std::fs::File::open(&path).unwrap()), 59_000_000);
    }

    #[cfg(unix)]
    #[test]
    fn password_hashes() {
        use super::password_matches;
        // From `openssl passwd -6/-5` and yescrypt's reference test vectors.
        let sha512 = "$6$qshtestsalt$i8JXuslD6mAnfXAKKecnuL/2Qdw1eDYSbLuWYv2qWaDfHIJnDSi1MThwYfHW5kMeXgnGwYOgjCfj0KlYRGljP1";
        let sha256 = "$5$qshtestsalt$JdnCalLoja2O/VY64/yqVbHXNG0WEmGliMWddNSTwC4";
        let yes = "$y$j80$LdJMENpBABJJ3h2$ysXVVJwuaVlI1BWoEKt/Bz3WNDDmdOWz/8KTQaHL1cC";
        assert!(password_matches(sha512, "hunter2", false) && !password_matches(sha512, "hunter3", false));
        assert!(password_matches(sha256, "hunter2", false) && !password_matches(sha256, "", false));
        assert!(password_matches(yes, "pleaseletmein", false) && !password_matches(yes, "pleaseletmeout", false));
        for locked in ["!", "*", "!$6$qshtestsalt$x", "$1$abc$def", "x"] {
            assert!(!password_matches(locked, "hunter2", false), "{locked}");
        }
        assert!(!password_matches("", "", false));
        assert!(password_matches("", "", true) && !password_matches("", "x", true));
        assert!(!super::dummy_hash().is_empty());
    }

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

    #[test]
    fn totp_codes_from_before_a_start_are_not_taken() {
        let secret = [7u8; 20];
        let mut state = TotpState::default();
        let step = now() / crate::totp::STEP;
        // The current code (and the next one, within the window) may have been used before.
        let current = format!("{:06}", crate::totp::code(&secret, step));
        assert_eq!(crate::totp::verify(&secret, &current, now(), Some(state.last_used(1))), None);
        state.floor = step - 2;
        assert_eq!(crate::totp::verify(&secret, &current, now(), Some(state.last_used(1))), Some(step));
        state.used.insert(1, step);
        assert_eq!(state.last_used(1), step);
    }
}
