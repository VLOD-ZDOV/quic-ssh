//! Ed25519 identities, OpenSSH key formats and key-list files.

use std::fs::{self, OpenOptions};
use std::io::Write;
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
        let text = fs::read_to_string(path)
            .with_context(|| format!("cannot read key {}", path.display()))?;
        let mut key = PrivateKey::from_openssh(&text)
            .with_context(|| format!("cannot parse key {}", path.display()))?;
        if key.algorithm() != ssh_key::Algorithm::Ed25519 {
            bail!("{} is not an ed25519 key (only ed25519 is supported)", path.display());
        }
        if key.is_encrypted() {
            let pass = rpassword::prompt_password(format!(
                "Enter passphrase for {}: ",
                path.display()
            ))?;
            key = key.decrypt(pass.as_bytes()).context("wrong passphrase")?;
        }
        match key.key_data() {
            KeypairData::Ed25519(kp) => Ok(Identity {
                signing: SigningKey::from_bytes(&kp.private.to_bytes()),
            }),
            _ => bail!("{} is not an ed25519 key (only ed25519 is supported)", path.display()),
        }
    }

    /// Writes the key in OpenSSH format (mode 0600) plus a `.pub` file next to it.
    pub fn save(&self, path: &Path, comment: &str) -> Result<()> {
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        let kp = Ed25519Keypair::from(&self.signing);
        let key = PrivateKey::new(KeypairData::Ed25519(kp), comment)?;
        let text = key.to_openssh(LineEnding::LF)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("cannot create {}", path.display()))?;
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

/// Creates a directory (and parents) with mode 0700 for the leaf.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    }
    Ok(())
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

/// Checks that `path` and every directory from it up to `top` is owned by
/// `uid` or root and not group/world writable (otherwise someone else could
/// swap the file).
fn check_owner_chain(path: &Path, top: &Path, uid: u32) -> Result<()> {
    let mut cur = Some(path);
    while let Some(p) = cur {
        let meta = match fs::metadata(p) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                cur = p.parent().filter(|_| p != top);
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("cannot stat {}", p.display())),
        };
        if meta.uid() != uid && meta.uid() != 0 {
            bail!("{} has wrong owner", p.display());
        }
        if meta.mode() & 0o022 != 0 {
            bail!("{} is group or world writable", p.display());
        }
        if p == top {
            break;
        }
        cur = p.parent();
    }
    Ok(())
}

/// Reads a key-list file the way sshd's StrictModes does: no symlink at the
/// end, and the file and its directories up to `home` owned by `uid` (or
/// root) and not group/world writable. A missing file is an empty list.
pub fn read_key_list_strict(path: &Path, home: &Path, uid: u32) -> Result<Vec<PublicKey>> {
    use std::io::Read;
    let mut f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("cannot open {}", path.display())),
    };
    if !f.metadata()?.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    check_owner_chain(path, home, uid)?;
    let mut text = String::new();
    Read::take(&mut f, 1 << 20).read_to_string(&mut text)?;
    Ok(parse_key_list(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("id_ed25519");
        let (id, created) = Identity::load_or_generate(&path, "c").unwrap();
        assert!(created);
        let (again, created) = Identity::load_or_generate(&path, "c").unwrap();
        assert!(!created);
        assert_eq!(id.public(), again.public());
        let mode = fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
