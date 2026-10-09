//! A small ssh-agent client (draft-ietf-sshm-ssh-agent): list keys and sign.
//! Keys in an agent never leave it, which is also how security keys (FIDO)
//! and PKCS#11 tokens are used.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const ADD_IDENTITY: u8 = 17;
const ADD_ID_CONSTRAINED: u8 = 25;
const CONSTRAIN_LIFETIME: u8 = 1;
const CONSTRAIN_CONFIRM: u8 = 2;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
/// Ask for rsa-sha2-512 instead of SHA-1 signatures for RSA keys.
const RSA_SHA2_512: u32 = 4;
const MAX_REPLY: usize = 256 * 1024;

/// A connection to an agent: a Unix socket, or a named pipe on Windows.
pub trait AgentStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AgentStream for T {}

/// Where the agent is: `SSH_AUTH_SOCK`, or on Windows the pipe of the
/// OpenSSH agent service.
pub fn default_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SSH_AUTH_SOCK").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    #[cfg(windows)]
    return Some(PathBuf::from(r"\\.\pipe\openssh-ssh-agent"));
    #[cfg(not(windows))]
    None
}

/// Opens a raw connection to the agent at `path`.
pub async fn connect_raw(path: &Path) -> std::io::Result<Box<dyn AgentStream>> {
    #[cfg(unix)]
    return Ok(Box::new(tokio::net::UnixStream::connect(path).await?));
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        // A busy pipe frees up quickly; try a few times.
        for _ in 0..20 {
            match ClientOptions::new().open(path) {
                Ok(pipe) => return Ok(Box::new(pipe)),
                Err(e) if e.raw_os_error() == Some(231) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("the agent's pipe stays busy"))
    }
}

pub struct Agent {
    sock: Box<dyn AgentStream>,
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
    /// The agent from `SSH_AUTH_SOCK` (or Windows' OpenSSH agent), if there is one.
    pub async fn from_env() -> Option<Agent> {
        let path = default_path()?;
        match Agent::connect(&path).await {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::debug!("ssh-agent: {e:#}");
                None
            }
        }
    }

    pub async fn connect(path: &Path) -> Result<Agent> {
        let sock = connect_raw(path).await.with_context(|| format!("cannot connect to {}", path.display()))?;
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

    /// Adds a private key, like `ssh-add` (`AddKeysToAgent`): with
    /// `confirm`, the agent asks before each use; with `lifetime`, it
    /// forgets the key after that many seconds.
    pub async fn add(&mut self, key: &ssh_key::PrivateKey, confirm: bool, lifetime: Option<u32>) -> Result<()> {
        use ssh_encoding::Encode;
        let constrained = confirm || lifetime.is_some();
        let mut body = vec![if constrained { ADD_ID_CONSTRAINED } else { ADD_IDENTITY }];
        key.key_data().encode(&mut body).map_err(|e| anyhow::anyhow!("cannot encode the key: {e}"))?;
        put_string(&mut body, key.comment().as_bytes());
        if let Some(seconds) = lifetime {
            body.push(CONSTRAIN_LIFETIME);
            body.extend_from_slice(&seconds.to_be_bytes());
        }
        if confirm {
            body.push(CONSTRAIN_CONFIRM);
        }
        let reply = self.request(&body).await;
        // The private key must not linger in memory longer than needed.
        body.iter_mut().for_each(|b| *b = 0);
        match reply?.first() {
            Some(&SUCCESS) => Ok(()),
            _ => bail!("the agent refused the key"),
        }
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
