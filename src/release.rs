//! Signed releases. `qsh update` runs an installer only if its hash is in a
//! `SHA256SUMS` signed by a release key built into qsh, so a release whose
//! files were swapped (a stolen upload token) is refused: the hashes it
//! lists cannot be signed without the release key, which never goes to CI.
//!
//! Signing (by the maintainer, see `scripts/sign-release.sh`):
//! `ssh-keygen -Y sign -f <key> -n qsh-release SHA256SUMS` → `SHA256SUMS.sig`.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use ssh_key::{PublicKey, SshSig};

/// Keeps a release signature from being taken for any other one the key makes.
pub const NAMESPACE: &str = "qsh-release";

/// Keys that sign releases (OpenSSH public key lines).
const KEYS: &[&str] = &["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHQ4oyJmM90t3HybPXmBHfzt9BHveCywN26+rKZJ3H1p"];

/// Checks `sig` (an armored SSH signature) over `sums` against the release keys.
pub fn verify(sums: &[u8], sig: &str) -> Result<()> {
    verify_with(KEYS, sums, sig)
}

fn verify_with(keys: &[&str], sums: &[u8], sig: &str) -> Result<()> {
    let sig: SshSig = sig.trim().parse().context("SHA256SUMS.sig is not an SSH signature")?;
    for key in keys {
        let key: PublicKey = key.parse().context("bad release key")?;
        if key.verify(NAMESPACE, sums, &sig).is_ok() {
            return Ok(());
        }
    }
    bail!("SHA256SUMS is not signed by a qsh release key")
}

/// The release a signed `SHA256SUMS` is for (its `# version vX.Y.Z` line).
pub fn version(sums: &str) -> Option<&str> {
    sums.lines().find_map(|l| l.strip_prefix("# version ")).map(str::trim)
}

/// The SHA-256 (hex) that `SHA256SUMS` lists for `name`.
pub fn listed<'a>(sums: &'a str, name: &str) -> Option<&'a str> {
    sums.lines().find_map(|l| {
        let (hash, file) = l.split_once(char::is_whitespace)?;
        let file = file.trim_start();
        (file == name || file.strip_prefix('*') == Some(name)).then_some(hash)
    })
}

pub fn sha256_hex(data: &[u8]) -> String {
    crate::proto::hex(&Sha256::digest(data))
}

/// Whether release `a` (`v1.9.1`) comes before `b`, comparing the numbers.
pub fn older(a: &str, b: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> { v.trim_start_matches('v').split(['.', '-']).map_while(|p| p.parse().ok()).collect() };
    parts(a) < parts(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(sums: &[u8], namespace: &str) -> (String, String) {
        let id = crate::keys::Identity::generate();
        let private = id.to_private_key("test").unwrap();
        let sig = private.sign(namespace, ssh_key::HashAlg::Sha512, sums).unwrap();
        (id.public().to_openssh(""), sig.to_pem(ssh_key::LineEnding::LF).unwrap())
    }

    #[test]
    fn signature_checks() {
        let sums = b"# version v2.0.0\nabc  install.sh\n";
        let (key, sig) = sign(sums, NAMESPACE);
        let key = key.trim();
        assert!(verify_with(&[key], sums, &sig).is_ok());
        // Changed list, another key, another namespace: refused.
        assert!(verify_with(&[key], b"# version v2.0.0\nabd  install.sh\n", &sig).is_err());
        let (other, _) = sign(sums, NAMESPACE);
        assert!(verify_with(&[other.trim()], sums, &sig).is_err());
        let (key2, sig2) = sign(sums, "git");
        assert!(verify_with(&[key2.trim()], sums, &sig2).is_err());
        assert!(verify_with(&[key], sums, "not a signature").is_err());
    }

    /// What `ssh-keygen -Y sign` writes is what `verify` reads.
    #[test]
    fn ssh_keygen_signature() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("k");
        let made = std::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-f"]).arg(&key).status();
        let Ok(s) = made else { return }; // no OpenSSH here
        assert!(s.success());
        let sums = dir.path().join("SHA256SUMS");
        std::fs::write(&sums, "# version v9.9.9\n00  install.sh\n").unwrap();
        let signed = std::process::Command::new("ssh-keygen").args(["-Y", "sign", "-n", NAMESPACE, "-f"]).arg(&key).arg(&sums).output().unwrap();
        assert!(signed.status.success(), "{}", String::from_utf8_lossy(&signed.stderr));
        let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        let public: String = public.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        let sig = std::fs::read_to_string(dir.path().join("SHA256SUMS.sig")).unwrap();
        let data = std::fs::read(&sums).unwrap();
        verify_with(&[&public], &data, &sig).unwrap();
        assert!(verify_with(&[&public], b"# version v9.9.9\n01  install.sh\n", &sig).is_err());
    }

    #[test]
    fn built_in_keys_parse() {
        for k in KEYS {
            k.parse::<PublicKey>().unwrap();
        }
    }

    #[test]
    fn sums_lines() {
        let sums = "# version v1.10.0\n0123  install.sh\nabcd *qsh-x86_64-linux.tar.gz\n";
        assert_eq!(version(sums), Some("v1.10.0"));
        assert_eq!(listed(sums, "install.sh"), Some("0123"));
        assert_eq!(listed(sums, "qsh-x86_64-linux.tar.gz"), Some("abcd"));
        assert_eq!(listed(sums, "install"), None);
        assert!(older("v1.9.1", "v1.10.0"));
        assert!(!older("v1.10.0", "v1.9.1"));
        assert!(!older("v1.9.1", "v1.9.1"));
    }
}
