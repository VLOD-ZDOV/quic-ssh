//! Application protocol: length-prefixed postcard messages on QUIC/yamux streams.
//!
//! Every operation runs on its own bidirectional stream. The first stream of a
//! connection carries [`Hello`]; each later stream starts with a [`Request`].

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ALPN: &[u8] = b"qsh/1";
/// Offered (never selected) by clients that want the server's host certificate.
pub const ALPN_HOST_CERT: &[u8] = b"qsh-host-cert";
pub const VERSION: u32 = 6;
/// Oldest client protocol version the server still accepts. Newer versions are
/// accepted too: their unknown requests are answered with an error, so newer
/// clients can detect what an older server supports.
pub const MIN_VERSION: u32 = 1;
const MAX_MSG: usize = 1 << 20;

#[derive(Serialize, Deserialize, Debug)]
pub enum Hello {
    /// Log in as `user`; the key is the one from the TLS client certificate.
    Login { version: u32, user: String },
    /// Pair a new client key with `user` using a one-time code (see `pair`).
    Pair { version: u32, user: String },
    // --- protocol version 4 ---
    /// Log in to resume the persistent session `token` (see `Request::Resume`).
    /// The key is checked as for `Login`; the token, which only a client that
    /// completed the whole login received, stands in for the second factor.
    Resume { version: u32, user: String, token: Vec<u8> },
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Reply {
    Ok,
    Err(String),
    /// Answer to [`Request::Download`]; `size` raw bytes follow.
    File { size: u64, mode: u32 },
    // --- protocol version 3 ---
    /// Answer to [`Request::RemoteForward`]: the port actually bound.
    Bound { port: u16 },
    // --- protocol version 4 (sent only to clients that announced it) ---
    /// Login complete; carries the server's protocol version.
    Welcome { version: u32 },
    /// The key from the TLS handshake is not enough: prove another key with
    /// [`Auth::Query`] / [`Auth::PublicKey`], or give up with [`Auth::Done`].
    AuthKey,
    /// Answer a question with [`Auth::Response`] (second factor).
    Prompt { text: String, echo: bool },
    /// Answer to `Request::Persistent` / `Request::Resume`: the session's token.
    Session { token: Vec<u8> },
    // --- protocol version 6 ---
    /// Text to show before logging in (the server's `banner`); the login
    /// goes on with the next reply.
    Banner(String),
}

/// Client messages on the hello stream while logging in (protocol version 4).
#[derive(Serialize, Deserialize, Debug)]
pub enum Auth {
    /// Would this key (SSH wire format, or a certificate) be accepted? Answered
    /// with `Reply::Ok` or `Reply::AuthKey`, without a signature, so security
    /// keys are only touched for keys that will work.
    Query { key: Vec<u8> },
    /// Proof of a key: an SSH signature over [`auth_data`].
    PublicKey { key: Vec<u8>, signature: Vec<u8> },
    /// Answer to `Reply::Prompt`.
    Response(String),
    /// No more keys to offer.
    Done,
}

/// SSHSIG namespace of login signatures; keeps them apart from signatures for
/// SSH logins, git commits or files made with the same key.
pub const AUTH_NAMESPACE: &str = "qsh-login@quic-ssh";

/// The data a client signs to prove `key` for `user` on the connection with
/// TLS `exporter`: an SSHSIG-wrapped hash of all three, so it can come from
/// an ssh-agent and cannot be replayed on another connection.
pub fn auth_data(exporter: &[u8; 32], user: &str, key: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64 + user.len() + key.len());
    for part in [b"qsh-userauth-v1".as_slice(), exporter, user.as_bytes(), key] {
        msg.extend_from_slice(&(part.len() as u32).to_be_bytes());
        msg.extend_from_slice(part);
    }
    ssh_key::SshSig::signed_data(AUTH_NAMESPACE, ssh_key::HashAlg::Sha512, &msg).expect("encoding cannot fail")
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PtySpec {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    /// Run a command (`None` = login shell). Followed by [`ClientMsg`]/[`ServerMsg`] frames.
    Exec { command: Option<String>, env: Vec<(String, String)>, pty: Option<PtySpec> },
    /// Connect to `host:port` from the server; after `Reply::Ok` the stream carries raw bytes.
    DirectTcp { host: String, port: u16 },
    /// Store `size` raw bytes at `path` (a directory means `path/name`). A final `Reply` follows.
    Upload { path: String, name: String, size: u64, mode: u32 },
    /// Fetch a file; answered with `Reply::File` and raw bytes.
    Download { path: String },
    // --- protocol version 2 ---
    /// Answered with `Reply::Ok` (round-trip time measurement).
    Ping,
    /// Speed test: after `Reply::Ok` the server sends `bytes` raw bytes.
    SpeedDown { bytes: u64 },
    /// Speed test: after `Reply::Ok` the client sends up to `bytes` raw bytes and
    /// closes its side; the server answers `Reply::File { size: received, mode: 0 }`.
    SpeedUp { bytes: u64 },
    // --- protocol version 3 ---
    /// Run a subsystem (e.g. `sftp`) without a shell; then like `Exec` without a PTY.
    Subsystem { name: String, env: Vec<(String, String)> },
    /// Listen on the server (`-R`). Answered with `Reply::Bound`; connections then
    /// arrive as server-opened streams starting with [`Opened::Forwarded`]. Closing
    /// this stream cancels the forward.
    RemoteForward { bind: String, port: u16 },
    /// Recursive upload: a tar stream of the directory's contents follows
    /// `Reply::Ok`; stored at `path`, or `path/name` if `path` is a directory.
    UploadTree { path: String, name: String },
    /// Recursive download: a tar stream of the directory's contents follows `Reply::Ok`.
    DownloadTree { path: String },
    // --- protocol version 4 ---
    /// `-A`: make the client's ssh-agent available to this connection's
    /// sessions (`SSH_AUTH_SOCK`). Each agent connection on the server arrives
    /// as a server-opened stream starting with [`Opened::Agent`]. Closing this
    /// stream ends the forwarding.
    AgentForward,
    /// Like `Exec` with a terminal, but the session survives the connection:
    /// answered with `Reply::Session` (or `Reply::Ok` if the server keeps no
    /// sessions), then `ClientMsg`/`ServerMsg` frames as for `Exec`.
    Persistent { command: Option<String>, env: Vec<(String, String)>, pty: PtySpec },
    /// Reattach to a persistent session after a lost connection. Output from
    /// byte `received` on is sent again (as far as the server still has it).
    Resume { token: Vec<u8>, received: u64 },
    // --- protocol version 5 ---
    /// A file transfer with zstd compression: after the first reply, the
    /// side that sends the data compresses everything it sends on the
    /// stream, to its end (including a final reply after a tree download).
    Compressed(Transfer),
}

/// The file transfers that can be compressed. A type of its own, not a
/// boxed `Request`: a recursive type would let a peer nest it deep enough
/// to overflow the stack while decoding.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Transfer {
    Upload { path: String, name: String, size: u64, mode: u32 },
    Download { path: String },
    UploadTree { path: String, name: String },
    DownloadTree { path: String },
}

impl From<Transfer> for Request {
    fn from(t: Transfer) -> Request {
        match t {
            Transfer::Upload { path, name, size, mode } => Request::Upload { path, name, size, mode },
            Transfer::Download { path } => Request::Download { path },
            Transfer::UploadTree { path, name } => Request::UploadTree { path, name },
            Transfer::DownloadTree { path } => Request::DownloadTree { path },
        }
    }
}

/// First message on a stream the server opens to the client.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Opened {
    /// A connection to a `-R` listener on `port`, from `origin`; raw bytes follow.
    Forwarded { port: u16, origin: String },
    /// A program on the server talks to the forwarded agent; raw bytes follow.
    Agent,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientMsg {
    Stdin(Vec<u8>),
    StdinEof,
    Resize { cols: u16, rows: u16 },
    // --- protocol version 2 ---
    /// Keystrokes with timing obfuscation: `data` padded with `pad` to a fixed
    /// size. Empty `data` is chaff, which the server answers with `ServerMsg::Pong`.
    Typed { data: Vec<u8>, pad: Vec<u8> },
    // --- protocol version 4 ---
    /// End a persistent session now (the user quit), instead of keeping it
    /// for a reconnect.
    Hangup,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum ServerMsg {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit { code: Option<i32>, signal: Option<i32> },
    // --- protocol version 2 ---
    /// Reply to chaff, sized like a one-character echo.
    Pong(Vec<u8>),
}

/// Accepted user names: 1–64 of `[A-Za-z0-9._-]`, not starting with `-`.
/// Keeps shell metacharacters, control characters and option-like names out
/// of everything downstream (compare OpenSSH 10.1/10.6 username fixes).
pub fn valid_user_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub async fn write_msg<W: AsyncWrite + Unpin + ?Sized, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let body = postcard::to_stdvec(msg)?;
    let mut buf = Vec::with_capacity(body.len() + 4);
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Reads one message; `Ok(None)` on a clean end of stream before a new frame.
pub async fn read_msg_opt<R: AsyncRead + Unpin + ?Sized, T: DeserializeOwned>(
    r: &mut R,
) -> Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MSG {
        bail!("message too large ({len} bytes)");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    match postcard::from_bytes(&body) {
        Ok(msg) => Ok(Some(msg)),
        Err(_) => Err(Malformed.into()),
    }
}

/// A frame that arrived intact but could not be decoded, e.g. a message type
/// from a newer peer. Inside a session it can be skipped; the stream is still in sync.
#[derive(Debug)]
pub struct Malformed;

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed or unknown message")
    }
}

impl std::error::Error for Malformed {}

pub async fn read_msg<R: AsyncRead + Unpin + ?Sized, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    read_msg_opt(r).await?.context("stream closed unexpectedly")
}

/// Reads a `Reply` and turns `Reply::Err` into an error.
/// Fails with the peer's error text, made safe to print: no control
/// characters (escape sequences could redraw the terminal), at most 500
/// characters.
pub async fn expect_ok<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> Result<Reply> {
    match read_msg(r).await? {
        Reply::Err(e) => bail!("{}", e.chars().filter(|c| !c.is_control()).take(500).collect::<String>()),
        other => Ok(other),
    }
}

/// Messages read by a task of their own, for loops that wait on other
/// events too. A frame read inside `select!` is dropped half-way when
/// another branch wins, which loses bytes and with them the framing; taking
/// a message from a channel can be cancelled safely. The task stops at the
/// end of the stream or an error, and when this is dropped.
pub struct Reader<T> {
    rx: tokio::sync::mpsc::Receiver<Result<Option<T>>>,
    task: tokio::task::JoinHandle<()>,
    last: std::sync::Arc<std::sync::Mutex<std::time::Instant>>,
}

impl<T: DeserializeOwned + Send + 'static> Reader<T> {
    pub fn spawn<R: AsyncRead + Unpin + Send + 'static>(mut r: R) -> Reader<T> {
        // A few messages ahead at most, so flow control still reaches the sender.
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let last = std::sync::Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        let heard = last.clone();
        let task = tokio::spawn(async move {
            loop {
                let msg = read_msg_opt::<_, T>(&mut r).await;
                *heard.lock().unwrap() = std::time::Instant::now();
                let more = match &msg {
                    Ok(Some(_)) => true,
                    Ok(None) => false,
                    Err(e) => e.is::<Malformed>(),
                };
                if tx.send(msg).await.is_err() || !more {
                    break;
                }
            }
        });
        Reader { rx, task, last }
    }

    /// When the last message (or the end of the stream) arrived.
    pub fn last_received(&self) -> std::time::Instant {
        *self.last.lock().unwrap()
    }

    /// A handle on [`Reader::last_received`] for other tasks.
    pub fn heard(&self) -> std::sync::Arc<std::sync::Mutex<std::time::Instant>> {
        self.last.clone()
    }

    /// Like [`read_msg_opt`]; `Ok(None)` also after the end was reported once.
    pub async fn next(&mut self) -> Result<Option<T>> {
        self.rx.recv().await.unwrap_or(Ok(None))
    }
}

impl<T> Drop for Reader<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Waiting for a message can be given up (e.g. in `select!`) at any time
    /// without losing a frame, even one that arrives in pieces.
    #[tokio::test]
    async fn reader_survives_cancellation() {
        let (mut a, b) = tokio::io::duplex(1 << 16);
        let mut reader = Reader::<ServerMsg>::spawn(b);
        let mut frame = Vec::new();
        write_msg(&mut frame, &ServerMsg::Stdout(vec![5; 3000])).await.unwrap();
        let mut got = Vec::new();
        for piece in frame.chunks(7) {
            a.write_all(piece).await.unwrap();
            // Give up waiting right away, as select! does when another branch wins.
            if let Ok(msg) = tokio::time::timeout(std::time::Duration::ZERO, reader.next()).await {
                got.extend(msg.unwrap());
            }
            tokio::task::yield_now().await;
        }
        drop(a);
        while let Some(msg) = reader.next().await.unwrap() {
            got.push(msg);
        }
        assert!(got.contains(&ServerMsg::Stdout(vec![5; 3000])), "{} messages", got.len());
    }

    #[test]
    fn compressed_requests_do_not_nest() {
        let t = Transfer::Download { path: "a".into() };
        let bytes = postcard::to_stdvec(&Request::Compressed(t.clone())).unwrap();
        assert!(matches!(postcard::from_bytes::<Request>(&bytes).unwrap(), Request::Compressed(x) if x == t));
        // What used to nest (Compressed inside Compressed) is now just malformed.
        let compressed = bytes[0];
        let nested = [vec![compressed; 100_000], vec![0x03, 0x01, b'a']].concat();
        assert!(postcard::from_bytes::<Request>(&nested).is_err());
    }

    #[tokio::test]
    async fn frames_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            write_msg(&mut a, &ServerMsg::Stdout(vec![7; 1000])).await.unwrap();
            write_msg(&mut a, &ServerMsg::Exit { code: Some(3), signal: None }).await.unwrap();
        });
        let m: ServerMsg = read_msg(&mut b).await.unwrap();
        assert_eq!(m, ServerMsg::Stdout(vec![7; 1000]));
        let m: ServerMsg = read_msg(&mut b).await.unwrap();
        assert_eq!(m, ServerMsg::Exit { code: Some(3), signal: None });
        writer.await.unwrap();
        assert!(read_msg_opt::<_, ServerMsg>(&mut b).await.unwrap().is_none());
    }

    #[test]
    fn user_names() {
        for ok in ["root", "alice", "first.last", "svc_backup", "user-1"] {
            assert!(valid_user_name(ok), "{ok}");
        }
        for bad in ["", "-oProxyCommand=x", "a b", "a$b", "a\\b", "a`id`", "a;b", "a\nb", "a/b", "a:b", &"x".repeat(65)] {
            assert!(!valid_user_name(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn rejects_oversized() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(read_msg::<_, Reply>(&mut b).await.is_err());
    }
}
