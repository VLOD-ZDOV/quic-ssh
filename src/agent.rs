//! A small ssh-agent client (draft-ietf-sshm-ssh-agent): list keys and sign.
//! Keys in an agent never leave it, which is also how security keys (FIDO)
//! and PKCS#11 tokens are used.

use std::path::Path;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
/// Ask for rsa-sha2-512 instead of SHA-1 signatures for RSA keys.
const RSA_SHA2_512: u32 = 4;
const MAX_REPLY: usize = 256 * 1024;

pub struct Agent {
    sock: UnixStream,
}

/// A key held by the agent: its SSH wire-format blob (a key or a certificate).
#[derive(Clone, Debug)]
pub struct AgentKey {
    pub blob: Vec<u8>,
    pub comment: String,
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn take_u32(buf: &mut &[u8]) -> Result<u32> {
    let (head, rest) = buf.split_at_checked(4).context("truncated agent reply")?;
    *buf = rest;
    Ok(u32::from_be_bytes(head.try_into().unwrap()))
}

fn take_string<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = take_u32(buf)? as usize;
    let (head, rest) = buf.split_at_checked(len).context("truncated agent reply")?;
    *buf = rest;
    Ok(head)
}

impl Agent {
    /// The agent from `SSH_AUTH_SOCK`, if there is one.
    pub async fn from_env() -> Option<Agent> {
        let path = std::env::var_os("SSH_AUTH_SOCK")?;
        match Agent::connect(Path::new(&path)).await {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::debug!("ssh-agent: {e:#}");
                None
            }
        }
    }

    pub async fn connect(path: &Path) -> Result<Agent> {
        let sock = UnixStream::connect(path).await.with_context(|| format!("cannot connect to {}", path.display()))?;
        Ok(Agent { sock })
    }

    async fn request(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let mut frame = Vec::with_capacity(body.len() + 4);
        put_string(&mut frame, body);
        self.sock.write_all(&frame).await?;
        let len = self.sock.read_u32().await? as usize;
        if len == 0 || len > MAX_REPLY {
            bail!("bad agent reply length {len}");
        }
        let mut reply = vec![0u8; len];
        self.sock.read_exact(&mut reply).await?;
        Ok(reply)
    }

    pub async fn keys(&mut self) -> Result<Vec<AgentKey>> {
        let reply = self.request(&[REQUEST_IDENTITIES]).await?;
        let (&kind, mut rest) = reply.split_first().context("empty agent reply")?;
        if kind != IDENTITIES_ANSWER {
            bail!("agent refused to list keys");
        }
        let n = take_u32(&mut rest)?;
        let mut keys = Vec::new();
        for _ in 0..n.min(1024) {
            let blob = take_string(&mut rest)?.to_vec();
            let comment = String::from_utf8_lossy(take_string(&mut rest)?).into_owned();
            keys.push(AgentKey { blob, comment });
        }
        Ok(keys)
    }

    /// Signs `data` with the key `blob`; returns an SSH signature blob.
    pub async fn sign(&mut self, blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut body = vec![SIGN_REQUEST];
        put_string(&mut body, blob);
        put_string(&mut body, data);
        body.extend_from_slice(&RSA_SHA2_512.to_be_bytes());
        let reply = self.request(&body).await?;
        match reply.split_first() {
            Some((&SIGN_RESPONSE, mut rest)) => Ok(take_string(&mut rest)?.to_vec()),
            Some((&FAILURE, _)) => bail!("the agent refused to sign (key locked, not confirmed, or no touch)"),
            _ => bail!("unexpected agent reply"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings() {
        let mut buf = Vec::new();
        put_string(&mut buf, b"abc");
        put_string(&mut buf, b"");
        let mut rest = buf.as_slice();
        assert_eq!(take_string(&mut rest).unwrap(), b"abc");
        assert_eq!(take_string(&mut rest).unwrap(), b"");
        assert!(take_string(&mut rest).is_err());
        let mut short: &[u8] = &[0, 0, 0, 9, 1];
        assert!(take_string(&mut short).is_err());
    }
}
