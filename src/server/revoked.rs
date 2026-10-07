//! `revoked_keys`: keys and certificates that may not log in, like sshd's
//! `RevokedKeys`. The file is either a list of public keys (one per line) or
//! a binary KRL made with `ssh-keygen -k` (keys, SHA1/SHA256 fingerprints,
//! certificate serials and key IDs per CA).

use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::path::Path;

use anyhow::{bail, Context, Result};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use ssh_key::public::KeyData;

use crate::authkeys::Offered;

const KRL_MAGIC: &[u8; 8] = b"SSHKRL\n\0";

/// Certificates revoked for one CA (`None` = any CA).
#[derive(Debug, Default)]
struct CertRevocations {
    ca: Option<Vec<u8>>,
    serials: Vec<RangeInclusive<u64>>,
    key_ids: HashSet<String>,
}

#[derive(Debug, Default)]
pub struct Revoked {
    /// Key blobs (SSH wire format).
    keys: HashSet<Vec<u8>>,
    sha1: HashSet<Vec<u8>>,
    sha256: HashSet<Vec<u8>>,
    certs: Vec<CertRevocations>,
}

/// The revocation list for this login.
pub enum Revocation {
    /// No `revoked_keys` configured.
    None,
    List(Revoked),
    /// Configured but unreadable or damaged: no key is accepted (as in sshd).
    Broken,
}

impl Revocation {
    pub fn load(path: Option<&Path>) -> Revocation {
        let Some(path) = path else { return Revocation::None };
        match std::fs::read(path).map_err(anyhow::Error::from).and_then(|data| Revoked::parse(&data)) {
            Ok(list) => Revocation::List(list),
            Err(e) => {
                tracing::error!("revoked_keys {}: {e:#}; refusing all keys", path.display());
                Revocation::Broken
            }
        }
    }

    /// Why `offered` may not be used, if it may not.
    pub fn check(&self, offered: &Offered) -> Result<(), String> {
        match self {
            Revocation::None => Ok(()),
            Revocation::Broken => Err("the server's revoked keys list is unreadable".into()),
            Revocation::List(list) if list.revoked(offered) => Err("key is revoked".into()),
            Revocation::List(_) => Ok(()),
        }
    }
}

fn blob(key: &KeyData) -> Vec<u8> {
    ssh_key::PublicKey::from(key.clone()).to_bytes().unwrap_or_default()
}

impl Revoked {
    pub fn parse(data: &[u8]) -> Result<Revoked> {
        if data.starts_with(KRL_MAGIC) {
            return parse_krl(data).context("bad KRL");
        }
        let text = std::str::from_utf8(data).context("neither a KRL nor a text file")?;
        let mut out = Revoked::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let key = ssh_key::PublicKey::from_openssh(line).with_context(|| format!("line {}: not a public key", n + 1))?;
            out.keys.insert(blob(key.key_data()));
        }
        Ok(out)
    }

    fn key_revoked(&self, key: &KeyData) -> bool {
        let b = blob(key);
        self.keys.contains(&b) || self.sha1.contains(Sha1::digest(&b).as_slice()) || self.sha256.contains(Sha256::digest(&b).as_slice())
    }

    pub fn revoked(&self, offered: &Offered) -> bool {
        match offered {
            Offered::Key(k) => self.key_revoked(k),
            Offered::Cert(cert) => {
                // The certified key and the CA can be revoked as plain keys too.
                if self.key_revoked(cert.public_key()) || self.key_revoked(cert.signature_key()) {
                    return true;
                }
                let ca = blob(cert.signature_key());
                self.certs.iter().filter(|c| c.ca.as_ref().is_none_or(|k| *k == ca)).any(|c| {
                    c.serials.iter().any(|r| r.contains(&cert.serial())) || c.key_ids.contains(cert.key_id())
                })
            }
        }
    }
}

/// Reads SSH wire-format fields.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("truncated");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// Serials past this many bits of a bitmap are not expanded.
const MAX_BITMAP_BITS: usize = 1 << 24;

fn parse_krl(data: &[u8]) -> Result<Revoked> {
    let mut r = Reader(&data[KRL_MAGIC.len()..]);
    let format = r.u32()?;
    if format != 1 {
        bail!("unsupported KRL format version {format}");
    }
    let _krl_version = r.u64()?;
    let _generated = r.u64()?;
    let _flags = r.u64()?;
    let _reserved = r.string()?;
    let _comment = r.string()?;
    let mut out = Revoked::default();
    while !r.done() {
        let kind = r.u8()?;
        let mut s = Reader(r.string()?);
        match kind {
            // Certificates.
            1 => {
                let ca = s.string()?;
                let _reserved = s.string()?;
                let mut certs = CertRevocations { ca: (!ca.is_empty()).then(|| ca.to_vec()), ..Default::default() };
                while !s.done() {
                    let sub = s.u8()?;
                    let mut d = Reader(s.string()?);
                    match sub {
                        0x20 => {
                            while !d.done() {
                                let n = d.u64()?;
                                certs.serials.push(n..=n);
                            }
                        }
                        0x21 => {
                            let (lo, hi) = (d.u64()?, d.u64()?);
                            certs.serials.push(lo..=hi);
                        }
                        0x22 => {
                            let offset = d.u64()?;
                            // An mpint: big-endian, bit 0 is the last byte's lowest bit.
                            let bits = d.string()?;
                            if bits.len() * 8 > MAX_BITMAP_BITS {
                                bail!("serial bitmap too large");
                            }
                            for (i, byte) in bits.iter().rev().enumerate() {
                                for bit in 0..8 {
                                    if byte & (1 << bit) != 0 {
                                        let n = offset.checked_add((i * 8 + bit) as u64).context("serial overflow")?;
                                        certs.serials.push(n..=n);
                                    }
                                }
                            }
                        }
                        0x23 => {
                            while !d.done() {
                                certs.key_ids.insert(String::from_utf8_lossy(d.string()?).into_owned());
                            }
                        }
                        other => bail!("unknown certificate section {other:#x}"),
                    }
                }
                out.certs.push(certs);
            }
            2 => {
                while !s.done() {
                    out.keys.insert(s.string()?.to_vec());
                }
            }
            3 => {
                while !s.done() {
                    out.sha1.insert(s.string()?.to_vec());
                }
            }
            // Signatures over the KRL: not needed to apply it.
            4 => {}
            5 => {
                while !s.done() {
                    out.sha256.insert(s.string()?.to_vec());
                }
            }
            other => bail!("unknown section {other}"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> KeyData {
        let public = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
        KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(public))
    }

    fn string(v: &[u8]) -> Vec<u8> {
        let mut out = (v.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(v);
        out
    }

    fn section(kind: u8, data: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend(string(data));
        out
    }

    #[test]
    fn text_list() {
        let a = ssh_key::PublicKey::from(key(1)).to_openssh().unwrap();
        let list = Revoked::parse(format!("# revoked\n{a}\n").as_bytes()).unwrap();
        assert!(list.revoked(&Offered::Key(key(1))));
        assert!(!list.revoked(&Offered::Key(key(2))));
        assert!(Revoked::parse(b"not a key\n").is_err());
    }

    #[test]
    fn krl_sections() {
        let mut krl = KRL_MAGIC.to_vec();
        krl.extend(1u32.to_be_bytes());
        krl.extend([0u8; 24]);
        krl.extend(string(b""));
        krl.extend(string(b"test"));
        krl.extend(section(2, &string(&blob(&key(1)))));
        krl.extend(section(5, &string(&Sha256::digest(blob(&key(2))))));
        krl.extend(section(3, &string(&Sha1::digest(blob(&key(3))))));
        let mut certs = string(&blob(&key(9)));
        certs.extend(string(b""));
        certs.extend(section(0x20, &[7u64.to_be_bytes(), 100u64.to_be_bytes()].concat()));
        certs.extend(section(0x21, &[1000u64.to_be_bytes(), 2000u64.to_be_bytes()].concat()));
        certs.extend(section(0x22, &[50u64.to_be_bytes().to_vec(), string(&[0b0000_0101, 0])].concat()));
        certs.extend(section(0x23, &string(b"stolen laptop")));
        krl.extend(section(1, &certs));
        let list = Revoked::parse(&krl).unwrap();
        for k in 1..=3 {
            assert!(list.revoked(&Offered::Key(key(k))), "key {k}");
        }
        assert!(!list.revoked(&Offered::Key(key(4))));
        let c = &list.certs[0];
        let serial = |n: u64| c.serials.iter().any(|r| r.contains(&n));
        // Bitmap 0x0500 from offset 50: bits 8 and 10.
        for (n, revoked) in [(7, true), (100, true), (1500, true), (2001, false), (58, true), (60, true), (59, false), (50, false)] {
            assert_eq!(serial(n), revoked, "serial {n}");
        }
        assert!(c.key_ids.contains("stolen laptop"));
        // Damaged files are refused (and then no key is accepted at all).
        assert!(Revoked::parse(&krl[..krl.len() - 3]).is_err());
        assert!(matches!(Revocation::load(Some(Path::new("/nonexistent/krl"))), Revocation::Broken));
    }
}
