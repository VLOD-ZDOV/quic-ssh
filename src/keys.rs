//! Ed25519 identities, OpenSSH key formats and key-list files.

use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{HashAlg, LineEnding, PrivateKey};

/// Directory holding qsh state for a given home directory (`~/.config/qsh`).
pub fn qsh_dir(home: &Path) -> PathBuf {
    home.join(".config").join("qsh")
}

/// Home directory of the current process.
pub fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().context("cannot determine home directory")
}

/// Raw Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    fn ssh(&self) -> ssh_key::PublicKey {
        ssh_key::PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(self.0)))
    }

    /// OpenSSH-compatible fingerprint, e.g. `SHA256:abc...`.
    pub fn fingerprint(&self) -> String {
        self.ssh().fingerprint(HashAlg::Sha256).to_string()
    }

    /// `ssh-ed25519 AAAA... comment`
    pub fn to_openssh(&self, comment: &str) -> String {
        let mut key = self.ssh();
        key.set_comment(comment);
        key.to_openssh().expect("encoding an ed25519 public key cannot fail")
    }

    /// SSH wire-format public key blob.
    pub fn ssh_blob(&self) -> Vec<u8> {
        self.ssh().to_bytes().expect("encoding an ed25519 public key cannot fail")
    }

    /// Parses an `ssh-ed25519 AAAA... [comment]` line. Other key types yield `None`.
    pub fn parse_openssh(line: &str) -> Option<PublicKey> {
        let key = ssh_key::PublicKey::from_openssh(line.trim()).ok()?;
        match key.key_data() {
            KeyData::Ed25519(k) => Some(PublicKey(k.0)),
            _ => None,
        }
    }
}

/// An Ed25519 private key used for host or client authentication.
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Identity {
        Identity { signing: SigningKey::generate(&mut OsRng) }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key().to_bytes())
    }

    /// SSH wire-format signature over `data`.
    pub fn ssh_sign(&self, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sig = ssh_key::Signature::new(ssh_key::Algorithm::Ed25519, self.signing.sign(data).to_bytes().to_vec())
            .expect("valid ed25519 signature size");
        Vec::try_from(sig).expect("encoding a signature cannot fail")
    }

    pub fn pkcs8_der(&self) -> Vec<u8> {
        self.signing
            .to_pkcs8_der()
            .expect("encoding an ed25519 private key cannot fail")
            .as_bytes()
            .to_vec()
    }

    /// Whether `path` holds an OpenSSH Ed25519 private key (checked without decrypting).
    pub fn is_ed25519_file(path: &Path) -> bool {
        fs::read_to_string(path)
            .ok()
            .and_then(|t| PrivateKey::from_openssh(&t).ok())
            .is_some_and(|k| k.algorithm() == ssh_key::Algorithm::Ed25519)
    }

    /// Loads an OpenSSH private key, asking for a passphrase if it is encrypted.
    pub fn load(path: &Path) -> Result<Identity> {
        Self::load_with(path, true)
    }

    /// Like [`Identity::load`]; without `prompt`, an encrypted key is an error
    /// unless this process already decrypted it (reconnects never prompt).
    pub fn load_with(path: &Path, prompt: bool) -> Result<Identity> {
        if !Identity::is_ed25519_file(path) && path.exists() {
            bail!("{} is not an ed25519 key", path.display());
        }
        let key = load_private_key(path, prompt)?;
        match key.key_data() {
            KeypairData::Ed25519(kp) => Ok(Identity {
                signing: SigningKey::from_bytes(&kp.private.to_bytes()),
            }),
            _ => bail!("{} is not an ed25519 key (only ed25519 is supported)", path.display()),
        }
    }

    /// The key as an OpenSSH private key (for `ssh-add`-style use).
    pub fn to_private_key(&self, comment: &str) -> Result<PrivateKey> {
        Ok(PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from(&self.signing)), comment)?)
    }

    /// Writes the key in OpenSSH format (mode 0600) plus a `.pub` file next to it.
    pub fn save(&self, path: &Path, comment: &str) -> Result<()> {
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        let kp = Ed25519Keypair::from(&self.signing);
        let key = PrivateKey::new(KeypairData::Ed25519(kp), comment)?;
        let text = key.to_openssh(LineEnding::LF)?;
        let mut f = crate::platform::create_private(path).with_context(|| format!("cannot create {}", path.display()))?;
        f.write_all(text.as_bytes())?;
        let mut pub_path = path.as_os_str().to_owned();
        pub_path.push(".pub");
        fs::write(&pub_path, format!("{}\n", self.public().to_openssh(comment)))?;
        Ok(())
    }

    /// Loads the key at `path`, generating it first if it does not exist.
    pub fn load_or_generate(path: &Path, comment: &str) -> Result<(Identity, bool)> {
        if path.exists() {
            return Ok((Identity::load(path)?, false));
        }
        let id = Identity::generate();
        id.save(path, comment)?;
        Ok((id, true))
    }
}

/// Key files this process has decrypted, so a reconnect does not ask again.
fn decrypted_cache() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, PrivateKey>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<PathBuf, PrivateKey>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Loads an OpenSSH private key of any type, asking for the passphrase of an
/// encrypted one (unless `prompt` is false). Decrypted keys are remembered for
/// the life of the process.
pub fn load_private_key(path: &Path, prompt: bool) -> Result<PrivateKey> {
    if let Some(key) = decrypted_cache().lock().unwrap().get(path) {
        return Ok(key.clone());
    }
    #[cfg(unix)]
    check_private_mode(path)?;
    let text = fs::read_to_string(path).with_context(|| format!("cannot read key {}", path.display()))?;
    let key = PrivateKey::from_openssh(&text).with_context(|| format!("cannot parse key {}", path.display()))?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    if !prompt {
        bail!("{} is encrypted and prompting is disabled (BatchMode)", path.display());
    }
    let pass = crate::prompt::secret(&format!("Enter passphrase for {}: ", path.display()))?;
    let key = key.decrypt(pass.as_bytes()).context("wrong passphrase")?;
    decrypted_cache().lock().unwrap().insert(path.to_path_buf(), key.clone());
    Ok(key)
}

/// Refuses a private key of ours that other users can read, as OpenSSH
/// does: it may already be stolen, and the owner should know.
#[cfg(unix)]
fn check_private_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).with_context(|| format!("cannot read key {}", path.display()))?;
    if meta.uid() == nix::unistd::getuid().as_raw() && meta.mode() & 0o077 != 0 {
        let (mode, path) = (meta.mode() & 0o777, path.display());
        bail!(
            "permissions {mode:04o} for {path} are too open: a private key must not be accessible by others \
             (chmod 600 {path}; if others could read it, consider it compromised)"
        );
    }
    Ok(())
}

/// Creates a directory (and parents) with mode 0700 for the leaf.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        crate::platform::set_mode(dir, 0o700)?;
    }
    Ok(())
}

/// An SSH certificate. `ssh-keygen` without `-V` makes one valid forever,
/// ending at 2^64-1, which ssh-key refuses (it wants a 63-bit time): such a
/// one is read with the latest end ssh-key takes, and its signature is
/// checked over the bytes as signed.
#[derive(Clone, Debug)]
pub struct Cert {
    cert: ssh_key::Certificate,
    /// For a certificate valid forever: what the CA signed.
    forever_signed: Option<Vec<u8>>,
    /// As it was read (encoding `cert` again would change a forever one).
    raw: Vec<u8>,
}

impl std::ops::Deref for Cert {
    type Target = ssh_key::Certificate;
    fn deref(&self) -> &ssh_key::Certificate {
        &self.cert
    }
}

impl Cert {
    pub fn from_bytes(bytes: &[u8]) -> Result<Cert> {
        let err = match ssh_key::Certificate::from_bytes(bytes) {
            Ok(cert) => return Ok(Cert { cert, forever_signed: None, raw: bytes.to_vec() }),
            Err(e) => e,
        };
        // Which eight 0xff bytes are the end of validity is up to the parse.
        // A few tries at most: a client sends this before logging in.
        const LATEST: u64 = i64::MAX as u64;
        let mut patched = bytes.to_vec();
        for at in (0..bytes.len().saturating_sub(7)).filter(|&i| bytes[i..i + 8] == [0xff; 8]).take(64) {
            patched[at..at + 8].copy_from_slice(&LATEST.to_be_bytes());
            let parsed = ssh_key::Certificate::from_bytes(&patched);
            patched[at..at + 8].copy_from_slice(&[0xff; 8]);
            let Ok(cert) = parsed else { continue };
            if cert.valid_before() != LATEST {
                continue;
            }
            // The signature is the last field: everything before it was signed.
            let signature = 4 + ssh_encoding::Encode::encoded_len(cert.signature())?;
            let signed = bytes[..bytes.len().saturating_sub(signature)].to_vec();
            return Ok(Cert { cert, forever_signed: Some(signed), raw: patched });
        }
        Err(err.into())
    }

    /// The certificate as it was read.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.raw.clone())
    }

    /// The `type base64 [comment]` text of a `-cert.pub` file.
    pub fn from_openssh(text: &str) -> Result<Cert> {
        use base64::Engine;
        let data = text.split_whitespace().nth(1).context("not a certificate line")?;
        Cert::from_bytes(&base64::engine::general_purpose::STANDARD.decode(data)?)
    }

    /// Like [`ssh_key::Certificate::validate_at`].
    pub fn validate_at<'a>(&self, now: u64, ca_fingerprints: impl IntoIterator<Item = &'a ssh_key::Fingerprint>) -> Result<()> {
        let Some(signed) = &self.forever_signed else {
            return Ok(self.cert.validate_at(now, ca_fingerprints)?);
        };
        signature::Verifier::verify(self.cert.signature_key(), signed, self.cert.signature()).context("certificate signature")?;
        let ca = self.cert.signature_key().fingerprint(HashAlg::Sha256);
        if !ca_fingerprints.into_iter().any(|f| f == &ca) {
            bail!("certificate authority is not trusted");
        }
        if now < self.cert.valid_after() {
            bail!("certificate is not valid yet");
        }
        Ok(())
    }
}

/// Parses an authorized_keys-style text and returns all ed25519 keys in it.
pub fn parse_key_list(text: &str) -> Vec<PublicKey> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        // Lines with options (`from="..." ssh-ed25519 ...`, `command=...`) are skipped:
        // qsh cannot enforce those restrictions, so it must not grant access through them.
        .filter(|l| l.starts_with("ssh-ed25519 "))
        .filter_map(PublicKey::parse_openssh)
        .collect()
}

#[cfg(unix)]
/// Checks that `path` and every directory above its real location, up to
/// `top`, is owned by `uid` or root and not group/world writable (otherwise
/// someone else could swap the file). Like sshd, the real path counts: a
/// symlinked directory (`~/.ssh -> /elsewhere`) is checked where it really
/// is, all the way up to `/` if that is outside `top`, where the file itself
/// must belong to the user.
fn check_owner_chain(path: &Path, top: &Path, uid: u32, opened: &fs::Metadata) -> Result<()> {
    let real = fs::canonicalize(path).with_context(|| format!("cannot resolve {}", path.display()))?;
    // A path named outside the home directory (`/etc/ssh/keys/%u`) is the
    // administrator's: root may own its file, as with sshd.
    let named_outside = !path.starts_with(top);
    let top = fs::canonicalize(top).unwrap_or_else(|_| top.to_path_buf());
    let named_outside = named_outside && !path.starts_with(&top);
    // Reached from inside the home directory, outside it only the user's own
    // files count: root reads these, and a symlink must not make it read
    // someone else's (such as root's authorized_keys) as the user's.
    let meta = fs::metadata(&real)?;
    // A directory swapped back and forth around the checks must not make
    // them pass for one file while another one is open.
    if (meta.dev(), meta.ino()) != (opened.dev(), opened.ino()) {
        bail!("{} was replaced while being checked", path.display());
    }
    let owner = meta.uid();
    if uid != 0 && !real.starts_with(&top) && owner != uid && !(named_outside && owner == 0) {
        bail!("{} leads outside the home directory to a file the user does not own", path.display());
    }
    for p in real.ancestors() {
        let meta = fs::metadata(p).with_context(|| format!("cannot stat {}", p.display()))?;
        if meta.uid() != uid && meta.uid() != 0 {
            bail!("{} has wrong owner", p.display());
        }
        if meta.mode() & 0o022 != 0 {
            bail!("{} is group or world writable", p.display());
        }
        if p == top {
            break;
        }
    }
    Ok(())
}

#[cfg(unix)]
/// Opens a file the way sshd's StrictModes reads authorized_keys: no symlink
/// at the end, and the file and its directories up to `home` owned by `uid`
/// (or root) and not group/world writable. `Ok(None)` if it does not exist.
fn open_strict(path: &Path, home: &Path, uid: u32) -> Result<Option<fs::File>> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot open {}", path.display())),
    };
    let opened = f.metadata()?;
    if !opened.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    check_owner_chain(path, home, uid, &opened)?;
    // The checks went by name: the file open must be the one they saw.
    let checked = fs::metadata(path)?;
    if (checked.dev(), checked.ino()) != (opened.dev(), opened.ino()) {
        bail!("{} was replaced while being checked", path.display());
    }
    Ok(Some(f))
}

fn read_limited(f: fs::File) -> Result<String> {
    use std::io::Read;
    let mut text = String::new();
    Read::take(f, 1 << 20).read_to_string(&mut text)?;
    Ok(text)
}

/// Reads an authorized_keys-style file with StrictModes checks (see
/// [`open_strict`]). A missing file reads as empty.
pub fn read_strict(path: &Path, home: &Path, uid: u32) -> Result<String> {
    match open_strict(path, home, uid)? {
        Some(f) => read_limited(f),
        None => Ok(String::new()),
    }
}

/// Like [`read_strict`] for secrets: the file must also be private (no
/// permissions for group or others). `Ok(None)` if it does not exist.
pub fn read_strict_private(path: &Path, home: &Path, uid: u32) -> Result<Option<String>> {
    Ok(open_strict_private(path, home, uid)?.map(|(text, _)| text))
}

#[cfg(unix)]
/// Like [`read_strict_private`], also returning the open file.
pub fn open_strict_private(path: &Path, home: &Path, uid: u32) -> Result<Option<(String, fs::File)>> {
    let Some(f) = open_strict(path, home, uid)? else { return Ok(None) };
    if f.metadata()?.mode() & 0o077 != 0 {
        bail!("{} must be private (chmod 600)", path.display());
    }
    Ok(Some((read_limited(f.try_clone()?)?, f)))
}

#[cfg(windows)]
/// On Windows: the file must be a regular one (not a link or a device).
/// Who else may change it is up to the profile's permissions, which keep
/// other users out by default.
fn open_strict(path: &Path, _home: &Path, _uid: u32) -> Result<Option<fs::File>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::from(e).context(format!("cannot read {}", path.display()))),
        Ok(m) if !m.file_type().is_file() => bail!("{} is not a regular file", path.display()),
        Ok(_) => {}
    }
    Ok(Some(fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?))
}

#[cfg(windows)]
/// Like [`read_strict_private`], also returning the open file.
pub fn open_strict_private(path: &Path, home: &Path, uid: u32) -> Result<Option<(String, fs::File)>> {
    if open_strict(path, home, uid)?.is_none() {
        return Ok(None);
    }
    // Writable: marking a one-time code as used sets the file's time.
    let f = fs::OpenOptions::new().read(true).write(true).open(path).with_context(|| format!("cannot open {}", path.display()))?;
    Ok(Some((read_limited(f.try_clone()?)?, f)))
}

/// The Ed25519 keys of an authorized_keys-style file read with [`read_strict`].
pub fn read_key_list_strict(path: &Path, home: &Path, uid: u32) -> Result<Vec<PublicKey>> {
    Ok(parse_key_list(&read_strict(path, home, uid)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blob of 0xff bytes (each 8 of them could be a forever end) is
    /// turned down quickly.
    #[test]
    fn hostile_certificate_blob_is_cheap() {
        let started = std::time::Instant::now();
        assert!(Cert::from_bytes(&vec![0xff; 1 << 20]).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[test]
    fn openssh_roundtrip() {
        let id = Identity::generate();
        let line = id.public().to_openssh("test");
        assert!(line.starts_with("ssh-ed25519 "));
        assert_eq!(PublicKey::parse_openssh(&line), Some(id.public()));
        assert!(id.public().fingerprint().starts_with("SHA256:"));
    }

    #[test]
    fn key_list_parsing() {
        let a = Identity::generate().public();
        let b = Identity::generate().public();
        let text = format!(
            "# comment\n\n{}\nssh-rsa AAAAB3NzaC1yc2E bogus\nfrom=\"10.0.0.1\" {}\ngarbage\n",
            a.to_openssh("a"),
            b.to_openssh("b")
        );
        assert_eq!(parse_key_list(&text), vec![a]);
    }

    #[cfg(unix)]
    #[test]
    fn strict_read_rejects_writable_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let dir = home.path().join(".ssh");
        fs::create_dir(&dir).unwrap();
        let file = dir.join("authorized_keys");
        let key = Identity::generate().public();
        fs::write(&file, key.to_openssh("k")).unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_key_list_strict(&file, home.path(), uid).unwrap(), vec![key]);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_key_list_strict(&file, home.path(), uid).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_key_list_strict(&file, home.path(), uid).is_err());
        assert!(read_key_list_strict(&dir.join("missing"), home.path(), uid).unwrap().is_empty());
    }

    /// A symlinked directory is checked where it really is.
    #[cfg(unix)]
    #[test]
    fn strict_read_follows_symlinked_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let (home, elsewhere) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let uid = nix::unistd::getuid().as_raw();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let shared = elsewhere.path().join("shared");
        let real = shared.join("ssh");
        fs::create_dir_all(&real).unwrap();
        let key = Identity::generate().public();
        fs::write(real.join("authorized_keys"), key.to_openssh("k")).unwrap();
        std::os::unix::fs::symlink(&real, home.path().join(".ssh")).unwrap();
        let file = home.path().join(".ssh/authorized_keys");
        fs::set_permissions(elsewhere.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        // Outside home, the check goes up to `/`: a temporary directory may
        // sit in a world-writable one, so only the difference is asserted.
        let before = read_key_list_strict(&file, home.path(), uid).is_ok();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_key_list_strict(&file, home.path(), uid).is_err(), "world-writable directory behind a symlink");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(read_key_list_strict(&file, home.path(), uid).is_ok(), before);
    }

    /// A symlink out of the home directory to a file the user does not own
    /// (say, root's authorized_keys) is not read as the user's.
    #[cfg(unix)]
    #[test]
    fn strict_read_refuses_foreign_files_outside_home() {
        let home = tempfile::tempdir().unwrap();
        let me = nix::unistd::getuid().as_raw();
        std::os::unix::fs::symlink("/etc", home.path().join(".ssh")).unwrap();
        let err = read_strict(&home.path().join(".ssh/passwd"), home.path(), me.max(1)).unwrap_err();
        assert!(format!("{err:#}").contains("does not own"), "{err:#}");
        // Named outside the home directory, root's files count (`/etc/ssh/keys/%u`).
        assert!(read_strict(Path::new("/etc/passwd"), home.path(), me.max(1)).is_ok());
    }

    /// The checks must be about the file that is open: a directory swapped
    /// to another file for them, and back, must not pass.
    #[cfg(unix)]
    #[test]
    fn strict_checks_are_about_the_open_file() {
        let home = tempfile::tempdir().unwrap();
        let me = nix::unistd::getuid().as_raw();
        let (open, checked) = (home.path().join("a"), home.path().join("b"));
        std::fs::write(&open, "x").unwrap();
        std::fs::write(&checked, "y").unwrap();
        let opened = std::fs::metadata(&open).unwrap();
        let err = check_owner_chain(&checked, home.path(), me, &opened).unwrap_err();
        assert!(format!("{err:#}").contains("replaced"), "{err:#}");
        assert!(check_owner_chain(&open, home.path(), me, &opened).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn readable_private_keys_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        Identity::generate().save(&path, "c").unwrap();
        assert!(Identity::load(&path).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = Identity::load(&path).err().expect("a world-readable key is refused");
        assert!(format!("{err:#}").contains(&format!("0644 for {} are too open", path.display())), "{err:#}");
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("id_ed25519");
        let (id, created) = Identity::load_or_generate(&path, "c").unwrap();
        assert!(created);
        let (again, created) = Identity::load_or_generate(&path, "c").unwrap();
        assert!(!created);
        assert_eq!(id.public(), again.public());
        #[cfg(unix)]
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    }
}
