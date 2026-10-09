//! X11 forwarding on the client (`-X`, `-Y`), as ssh does it: the server's
//! sessions get a fake cookie; a program there that connects to the
//! forwarded display must present it, and qsh replaces it with the real
//! cookie of the local display before passing the connection on. With `-X`
//! (untrusted) the real cookie is a new one that xauth generates with the
//! X SECURITY extension's untrusted access.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::transport::{RecvHalf, SendHalf};

/// The cookies of one forwarding.
#[derive(Clone, Debug)]
pub struct X11Auth {
    /// The local display (`$DISPLAY`).
    pub display: String,
    pub proto: String,
    /// What the server's programs present.
    pub fake: Vec<u8>,
    /// What the local X server wants.
    pub real: Vec<u8>,
    /// The screen number of the display (`:0.1` → 1).
    pub screen: u32,
    /// Untrusted forwarding: the generated cookie expires then
    /// (ForwardX11Timeout), and so do new connections, as in ssh.
    pub refuse_after: Option<std::time::Instant>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

impl X11Auth {
    pub fn fake_hex(&self) -> String {
        hex(&self.fake)
    }
}

/// The display name xauth knows a display under (ssh's rule: `localhost:N`
/// is `unix:N`).
fn xauth_name(display: &str) -> String {
    match display.strip_prefix("localhost:") {
        Some(rest) => format!("unix:{rest}"),
        None => display.to_string(),
    }
}

/// `xauth list DISPLAY`: the first entry's protocol and cookie.
fn list_cookie(xauth: &str, file: Option<&Path>, display: &str) -> Result<(String, Vec<u8>)> {
    let mut cmd = Command::new(xauth);
    if let Some(f) = file {
        cmd.arg("-f").arg(f);
    }
    let out = cmd.arg("list").arg(xauth_name(display)).stdin(std::process::Stdio::null()).output().with_context(|| format!("cannot run {xauth}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let [_, proto, cookie] = fields.as_slice() {
            if let Some(c) = unhex(cookie) {
                return Ok((proto.to_string(), c));
            }
        }
    }
    bail!("xauth has no cookie for display {display}")
}

/// The screen number in a display name (`host:0.1` → 1).
fn screen_of(display: &str) -> u32 {
    let tail = display.rsplit(':').next().unwrap_or("");
    tail.split_once('.').and_then(|(_, s)| s.parse().ok()).unwrap_or(0)
}

/// Gets the cookies for forwarding `display`: the local one (trusted), or
/// one xauth generates for untrusted access, valid for `timeout` seconds.
pub fn prepare(display: &str, trusted: bool, xauth: &str, timeout: u32) -> Result<X11Auth> {
    let (proto, real) = if trusted {
        match list_cookie(xauth, None, display) {
            Ok(c) => c,
            // Like ssh: a display without access control may still work.
            Err(e) => {
                tracing::warn!("{e:#}; using fake authentication data for X11 forwarding");
                ("MIT-MAGIC-COOKIE-1".to_string(), (0..16).map(|_| rand::random::<u8>()).collect())
            }
        }
    } else {
        let dir = private_dir()?;
        let file = dir.join("xauthfile");
        let generated = Command::new(xauth)
            .arg("-f")
            .arg(&file)
            .args(["generate", &xauth_name(display), "MIT-MAGIC-COOKIE-1", "untrusted", "timeout", &timeout.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let result = match generated {
            Ok(s) if s.success() => list_cookie(xauth, Some(&file), display),
            _ => Err(anyhow::anyhow!("xauth could not generate an untrusted cookie (the X server may lack the SECURITY extension; -Y forwards with full access)")),
        };
        let _ = std::fs::remove_dir_all(&dir);
        result?
    };
    let fake: Vec<u8> = (0..real.len()).map(|_| rand::random::<u8>()).collect();
    let refuse_after = (!trusted).then(|| std::time::Instant::now() + std::time::Duration::from_secs(timeout.into()));
    Ok(X11Auth { display: display.to_string(), proto, fake, real, screen: screen_of(display), refuse_after })
}

/// A new directory only this user can enter, for xauth's temporary file.
fn private_dir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    let dir = base.join(format!("qsh-xauth-{}-{:08x}", std::process::id(), rand::random::<u32>()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Connects to the local display: a Unix socket for `:N`, `unix:N` or a
/// socket path (macOS's XQuartz), else TCP port 6000+N.
async fn connect_display(display: &str) -> Result<Box<dyn Stream>> {
    let (host, rest) = display.rsplit_once(':').context("bad DISPLAY")?;
    let number: u32 = rest.split('.').next().unwrap_or("").parse().with_context(|| format!("bad DISPLAY {display:?}"))?;
    #[cfg(unix)]
    {
        let path = if host.starts_with('/') {
            // XQuartz: the display is the socket's path, maybe with ".screen".
            let full = PathBuf::from(display);
            Some(if full.exists() { full } else { PathBuf::from(display.rsplit_once('.').map_or(display, |(p, _)| p)) })
        } else if host.is_empty() || host == "unix" {
            Some(PathBuf::from(format!("/tmp/.X11-unix/X{number}")))
        } else {
            None
        };
        if let Some(path) = path {
            let sock = tokio::net::UnixStream::connect(&path).await.with_context(|| format!("cannot connect to {}", path.display()))?;
            return Ok(Box::new(sock));
        }
    }
    let host = if host.is_empty() || host == "unix" { "localhost" } else { host };
    let port = u16::try_from(6000 + number).context("bad display number")?;
    let tcp = tokio::net::TcpStream::connect((host, port)).await.with_context(|| format!("cannot connect to {host}:{port}"))?;
    let _ = tcp.set_nodelay(true);
    Ok(Box::new(tcp))
}

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

/// Reads the X11 connection setup from `r`, checks its authentication
/// against the fake cookie and returns the setup with the real cookie.
async fn rewrite_setup<R: AsyncRead + Unpin>(r: &mut R, auth: &X11Auth) -> Result<Vec<u8>> {
    let mut head = [0u8; 12];
    r.read_exact(&mut head).await?;
    let u16_at = |i: usize| match head[0] {
        b'B' => u16::from_be_bytes([head[i], head[i + 1]]),
        b'l' => u16::from_le_bytes([head[i], head[i + 1]]),
        _ => 0,
    };
    if !matches!(head[0], b'B' | b'l') {
        bail!("not an X11 connection setup");
    }
    let (name_len, data_len) = (u16_at(6) as usize, u16_at(8) as usize);
    let mut rest = vec![0u8; name_len + pad4(name_len) + data_len + pad4(data_len)];
    r.read_exact(&mut rest).await?;
    let name = &rest[..name_len];
    let data = &rest[name_len + pad4(name_len)..name_len + pad4(name_len) + data_len];
    if name != auth.proto.as_bytes() {
        bail!("X11 connection uses another authentication protocol");
    }
    // In constant time: how much of a guess matched must not show.
    let differs = data.len() != auth.fake.len() || data.iter().zip(&auth.fake).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0;
    if differs {
        bail!("X11 authentication data does not match the fake cookie");
    }
    let real_len = u16::try_from(auth.real.len()).context("cookie too long")?;
    let mut out = head.to_vec();
    let put = match head[0] {
        b'B' => real_len.to_be_bytes(),
        _ => real_len.to_le_bytes(),
    };
    out[8..10].copy_from_slice(&put);
    out.extend_from_slice(name);
    out.extend(std::iter::repeat_n(0, pad4(name_len)));
    out.extend_from_slice(&auth.real);
    out.extend(std::iter::repeat_n(0, pad4(auth.real.len())));
    Ok(out)
}

/// Serves a connection to the forwarded display: checks and replaces its
/// cookie, then relays it to the local display.
pub async fn serve(auth: &X11Auth, send: SendHalf, mut recv: RecvHalf) -> Result<()> {
    if auth.refuse_after.is_some_and(|t| std::time::Instant::now() >= t) {
        bail!("rejected X11 connection after ForwardX11Timeout expired");
    }
    let setup = rewrite_setup(&mut recv, auth).await?;
    let mut display = connect_display(&auth.display).await?;
    display.write_all(&setup).await?;
    let (r, w) = tokio::io::split(display);
    crate::transport::bridge(r, w, send, recv).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(order: u8, name: &[u8], data: &[u8]) -> Vec<u8> {
        let le = order == b'l';
        let n16 = |n: usize| if le { (n as u16).to_le_bytes() } else { (n as u16).to_be_bytes() };
        let mut v = vec![order, 0];
        v.extend(n16(11));
        v.extend(n16(0));
        v.extend(n16(name.len()));
        v.extend(n16(data.len()));
        v.extend([0, 0]);
        v.extend(name);
        v.extend(std::iter::repeat_n(0, pad4(name.len())));
        v.extend(data);
        v.extend(std::iter::repeat_n(0, pad4(data.len())));
        v
    }

    #[tokio::test]
    async fn setup_cookie_is_replaced() {
        let auth = X11Auth { display: ":0".into(), proto: "MIT-MAGIC-COOKIE-1".into(), fake: vec![1; 16], real: vec![2; 16], screen: 0, refuse_after: None };
        for order in *b"lB" {
            let input = setup(order, b"MIT-MAGIC-COOKIE-1", &[1; 16]);
            let out = rewrite_setup(&mut input.as_slice(), &auth).await.unwrap();
            assert_eq!(out, setup(order, b"MIT-MAGIC-COOKIE-1", &[2; 16]));
        }
        let wrong = setup(b'l', b"MIT-MAGIC-COOKIE-1", &[3; 16]);
        assert!(rewrite_setup(&mut wrong.as_slice(), &auth).await.is_err());
        let short = setup(b'l', b"MIT-MAGIC-COOKIE-1", &[1; 15]);
        assert!(rewrite_setup(&mut short.as_slice(), &auth).await.is_err());
        let other = setup(b'l', b"XDM-AUTHORIZATION-1", &[1; 16]);
        assert!(rewrite_setup(&mut other.as_slice(), &auth).await.is_err());
        assert_eq!(screen_of("localhost:10.2"), 2);
        assert_eq!(screen_of(":0"), 0);
        assert_eq!(xauth_name("localhost:10.0"), "unix:10.0");
    }
}
