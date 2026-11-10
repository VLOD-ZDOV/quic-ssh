//! Application protocol: length-prefixed postcard messages on QUIC/yamux streams.
//!
//! Every operation runs on its own bidirectional stream. The first stream of a
//! connection carries [`Hello`]; each later one the client opens starts with
//! a [`Request`], and each one the server opens with [`Opened`].

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ALPN: &[u8] = b"qsh/1";
/// Offered (never selected) by clients that want the server's host certificate.
pub const ALPN_HOST_CERT: &[u8] = b"qsh-host-cert";
pub const VERSION: u32 = 11;
/// From this version a connection that resumed a session may forward too.
pub const FORWARDS_ON_RESUME: u32 = 10;
/// From this protocol version: `Request::Hold` and packed terminal output.
pub const HOLD_AND_PACK: u32 = 11;
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
    /// No key was accepted, but a password may be: answer with
    /// [`Auth::Response`] (the password) or give up with [`Auth::Done`].
    Password,
    // --- protocol version 8 ---
    /// Answer to `Request::UploadResume`: the target already has `have`
    /// bytes, whose SHA-256 is `prefix` (empty when `have` is 0).
    Partial { have: u64, prefix: Vec<u8> },
    /// Answer to `Request::DownloadFrom`: the file's `size` and `mode`; the
    /// bytes from `start` on follow.
    FileFrom { size: u64, mode: u32, start: u64 },
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
    // --- protocol version 6 ---
    /// Connect to the Unix socket `path` on the server (`-L ...:/path`);
    /// after `Reply::Ok` the stream carries raw bytes.
    DirectStreamLocal { path: String },
    /// Listen on the Unix socket `path` on the server (`-R /path:...`).
    /// Answered with `Reply::Ok`; connections arrive as server-opened
    /// streams starting with [`Opened::ForwardedStreamLocal`]. Closing this
    /// stream cancels the forward.
    RemoteForwardStreamLocal { path: String },
    /// X11 forwarding (`-X`/`-Y`) for this connection's sessions: they get a
    /// display whose connections arrive as server-opened streams starting
    /// with [`Opened::X11`]. `proto` and `cookie` (hex) are the fake
    /// authentication the sessions use. Closing this stream ends it.
    X11Forward { proto: String, cookie: String, screen: u32 },
    /// A tunnel device on the server (`-w`): TUN, or TAP with `ethernet`;
    /// `unit` picks its number. After `Reply::Ok`, packets follow both
    /// ways, each with a 4-byte big-endian length in front.
    Tunnel { ethernet: bool, unit: Option<u32> },
    // --- protocol version 8 ---
    /// An upload that may continue a partial file: answered with
    /// `Reply::Partial` for what is there, then the client sends a
    /// [`ResumeFrom`], and after `Reply::Ok` the bytes from there on.
    UploadResume { path: String, name: String, size: u64, mode: u32 },
    /// A download that continues a local partial file of `offset` bytes
    /// whose SHA-256 is `prefix`: answered with `Reply::FileFrom`, and the
    /// bytes from its `start` (`offset` if the beginnings match, else 0).
    DownloadFrom { path: String, offset: u64, prefix: Vec<u8> },
    // --- protocol version 9 ---
    /// Answered with `Reply::Ok` if this connection may start sessions, or
    /// an error if its one-time code has run out (`totp_valid_for`): for a
    /// shared connection, before it is used.
    MayStart,
    // --- protocol version 11 ---
    /// `-N`: no program, but a token to come back with, as from a session:
    /// answered with `Reply::Session`. The stream stays open until the
    /// connection goes or the client says `ClientMsg::Hangup`.
    Hold,
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
    UploadResume { path: String, name: String, size: u64, mode: u32 },
    DownloadFrom { path: String, offset: u64, prefix: Vec<u8> },
}

/// The client's answer to `Reply::Partial`: where the upload goes on, the
/// partial file's size if its beginning matches, else 0.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ResumeFrom {
    pub offset: u64,
}

/// Lower-case hex, for hashes passed on a helper's command line.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

/// SHA-256 of the first `n` bytes of `r` (fewer if it ends before).
pub fn prefix_sha256(r: impl std::io::Read, n: u64) -> std::io::Result<Vec<u8>> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    std::io::copy(&mut r.take(n), &mut hasher)?;
    Ok(hasher.finalize().to_vec())
}

impl From<Transfer> for Request {
    fn from(t: Transfer) -> Request {
        match t {
            Transfer::Upload { path, name, size, mode } => Request::Upload { path, name, size, mode },
            Transfer::Download { path } => Request::Download { path },
            Transfer::UploadTree { path, name } => Request::UploadTree { path, name },
            Transfer::DownloadTree { path } => Request::DownloadTree { path },
            Transfer::UploadResume { path, name, size, mode } => Request::UploadResume { path, name, size, mode },
            Transfer::DownloadFrom { path, offset, prefix } => Request::DownloadFrom { path, offset, prefix },
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
    // --- protocol version 6 ---
    /// A connection to a `-R` Unix socket listener at `path`; raw bytes follow.
    ForwardedStreamLocal { path: String },
    /// A program on the server opened the forwarded X11 display; raw bytes
    /// of the X11 protocol follow.
    X11 { origin: String },
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
    /// Terminal output shown so far on this stream, in bytes: the server
    /// then keeps at most [`SHOWN_WINDOW`] more on the way. Older servers
    /// skip it.
    Shown(u64),
    // --- protocol version 11 ---
    /// `-C`: send this stream's output as `ServerMsg::StdoutPacked` when that
    /// is smaller.
    Compress,
}

/// Terminal output a server lets be on the way before the client showed it
/// (see [`ClientMsg::Shown`]): what still scrolls by after a ^C. A stream's
/// own flow-control window is much larger, for fast transfers.
pub const SHOWN_WINDOW: u64 = 1 << 20;
/// How often a client reports [`ClientMsg::Shown`].
pub const SHOWN_EVERY: u64 = 64 << 10;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum ServerMsg {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit { code: Option<i32>, signal: Option<i32> },
    // --- protocol version 2 ---
    /// Reply to chaff, sized like a one-character echo.
    Pong(Vec<u8>),
    // --- protocol version 11 ---
    /// `Stdout` as a zstd frame of its own, so nothing has to be kept in
    /// step across a reconnect.
    StdoutPacked(Vec<u8>),
}

/// Shorter output goes as it is: a typed character's echo stays quick to
/// take in and out of the context.
const PACK_FROM: usize = 16;
/// Largest message the merging of queued output aims for.
pub const MERGE_UP_TO: usize = 64 << 10;
/// Most output one packed message may unpack to: a bomb must not fill the memory.
const MAX_UNPACKED: usize = 4 << 20;
/// 1 MiB on both sides, which a phone can spare.
const WINDOW_LOG: u32 = 20;
/// Packed sizes come in steps of this. A guess that matches a secret on the
/// screen would otherwise show as a message a byte smaller, even encrypted.
/// RFC 7541 7.1: padding limits such probing but does not end it.
const SIZE_STEP: usize = 16;
/// Marks a chunk of a packed message that went as it is.
const CHUNK_AS_IS: u32 = 1 << 31;
/// How much output is judged at a time, and how long output that did not
/// shrink then goes as it is.
const PROBE: u64 = 256 << 10;
const SKIP: std::time::Duration = std::time::Duration::from_secs(1);

/// Packs a stream's output (`ClientMsg::Compress`) as one zstd frame that
/// never ends, so that what repeats a screen earlier takes next to nothing.
/// The frame lives as long as the stream, on purpose: starting afresh would
/// give someone guessing at a secret by message sizes a clean context to
/// measure in, which is what such an attack needs.
pub struct Packer {
    encoder: zstd::stream::write::Encoder<'static, Vec<u8>>,
    /// Bytes in and out since the last judgement.
    seen: (u64, u64),
    skip_until: Option<std::time::Instant>,
    failed: bool,
}

impl Packer {
    pub fn new() -> Result<Packer> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1)?;
        encoder.window_log(WINDOW_LOG)?;
        Ok(Packer { encoder, seen: (0, 0), skip_until: None, failed: false })
    }

    fn compress(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        use std::io::Write;
        self.encoder.write_all(data)?;
        self.encoder.flush()?;
        Ok(std::mem::take(self.encoder.get_mut()))
    }

    /// Adds a piece of output to `body`, packed unless it is a secret or too
    /// short to gain anything.
    fn chunk(&mut self, piece: &[u8], secret: bool, body: &mut Vec<u8>) -> std::io::Result<()> {
        if piece.is_empty() {
            return Ok(());
        }
        if secret || piece.len() < PACK_FROM {
            body.extend_from_slice(&(piece.len() as u32 | CHUNK_AS_IS).to_le_bytes());
            body.extend_from_slice(piece);
            return Ok(());
        }
        let small = self.compress(piece)?;
        self.seen = (self.seen.0 + piece.len() as u64, self.seen.1 + small.len() as u64);
        body.extend_from_slice(&(small.len() as u32).to_le_bytes());
        body.extend_from_slice(&small);
        Ok(())
    }

    /// `msg` as it goes out.
    pub fn pack(&mut self, msg: ServerMsg) -> ServerMsg {
        let ServerMsg::Stdout(data) = msg else { return msg };
        let skipping = self.skip_until.is_some_and(|t| std::time::Instant::now() < t);
        if self.failed || skipping || data.len() < PACK_FROM {
            return ServerMsg::Stdout(data);
        }
        let mut body = Vec::with_capacity(data.len() / 4);
        let mut at = 0;
        let mut done = Ok(());
        for span in secret_spans(&data) {
            done = done.and_then(|()| self.chunk(&data[at..span.start], false, &mut body));
            done = done.and_then(|()| self.chunk(&data[span.clone()], true, &mut body));
            at = span.end;
        }
        if done.and_then(|()| self.chunk(&data[at..], false, &mut body)).is_err() {
            self.failed = true;
            return ServerMsg::Stdout(data);
        }
        if self.seen.0 >= PROBE {
            if self.seen.1 * 20 > self.seen.0 * 19 {
                self.skip_until = Some(std::time::Instant::now() + SKIP);
            }
            self.seen = (0, 0);
        }
        ServerMsg::StdoutPacked(padded(body))
    }
}

/// Words whose value is worth keeping out of the context, as an HTTP/2 client
/// keeps cookies out of its table (RFC 7541 7.1.3). The first group runs to
/// the end of the line.
const WHOLE_LINE_WORDS: [&[u8]; 3] = [b"authorization", b"cookie", b"bearer"];
const VALUE_WORDS: [&[u8]; 10] = [b"password", b"passwd", b"passphrase", b"pwd", b"secret", b"token", b"api_key", b"apikey", b"api-key", b"session"];
/// A token is a run of this many characters that does not look like a word.
const TOKEN_LEN: usize = 16;
/// What is cut off by the end of a message may be a token in two halves.
const CUT_LEN: usize = 6;

fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'_' | b'-')
}

fn looks_random(run: &[u8]) -> bool {
    run.iter().all(u8::is_ascii_hexdigit) || (run.iter().any(u8::is_ascii_digit) && run.iter().any(u8::is_ascii_alphabetic))
}

/// The parts of `data` that look like secrets, in order and not overlapping.
/// Compression can only give away what it compares, so these never reach
/// the context. Padding only makes guessing dearer; this is what ends it, for
/// what is found here.
fn secret_spans(data: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut spans: Vec<std::ops::Range<usize>> = Vec::new();
    let mut at = 0;
    while at < data.len() {
        if token_byte(data[at]) {
            let end = data[at..].iter().position(|b| !token_byte(*b)).map_or(data.len(), |n| at + n);
            let run = &data[at..end];
            let cut = at == 0 || end == data.len();
            if run.len() >= if cut { CUT_LEN } else { TOKEN_LEN } && looks_random(run) {
                spans.push(at..end);
            }
            // The word before a `=` or `:`, or one followed by a value.
            let lower = run.to_ascii_lowercase();
            let whole_line = WHOLE_LINE_WORDS.iter().any(|w| ends_with_word(&lower, w));
            if whole_line || VALUE_WORDS.iter().any(|w| ends_with_word(&lower, w)) {
                if let Some(value) = value_after(data, end, whole_line) {
                    spans.push(value);
                }
            }
            at = end;
        } else {
            at += 1;
        }
    }
    spans.sort_by_key(|s| s.start);
    let mut merged: Vec<std::ops::Range<usize>> = Vec::with_capacity(spans.len());
    for span in spans {
        match merged.last_mut() {
            Some(last) if span.start <= last.end => last.end = last.end.max(span.end),
            _ => merged.push(span),
        }
    }
    merged
}

fn ends_with_word(run: &[u8], word: &[u8]) -> bool {
    run.windows(word.len()).any(|w| w == word)
}

/// What follows a keyword: after `=`, `:` or a space, to the end of the value
/// (or of the line, for a header).
fn value_after(data: &[u8], word_end: usize, whole_line: bool) -> Option<std::ops::Range<usize>> {
    let skip = |b: &u8| matches!(b, b' ' | b'\t' | b'"' | b'\'' | b'=' | b':');
    // All of them: a value after more would go unseen (and be compressed).
    let separators = data[word_end..].iter().take_while(|b| skip(b)).count();
    let names_a_value = data[word_end..word_end + separators].iter().any(|b| matches!(b, b'=' | b':'));
    if separators == 0 || !(names_a_value || whole_line) {
        return None;
    }
    let start = word_end + separators;
    let ends = |b: &u8| if whole_line { matches!(b, b'\n' | b'\r') } else { matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'&' | b';' | b',') };
    let end = data[start..].iter().position(ends).map_or(data.len(), |n| start + n);
    (end > start).then_some(start..end)
}

/// The first byte says how much padding comes next; then come chunks, each
/// after its length as a little-endian `u32`. Half the messages get a step
/// more, so that a size says less about which step it just missed.
fn padded(small: Vec<u8>) -> Vec<u8> {
    let extra = if rand::random::<bool>() { SIZE_STEP } else { 0 };
    let pad = (SIZE_STEP - (small.len() + 1) % SIZE_STEP) % SIZE_STEP + extra;
    let mut out = vec![0; 1 + pad + small.len()];
    out[0] = pad as u8;
    out[1 + pad..].copy_from_slice(&small);
    out
}

/// Collects unpacked output, up to [`MAX_UNPACKED`] per message.
struct Limited(Vec<u8>);

impl std::io::Write for Limited {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.0.len() + data.len() > MAX_UNPACKED {
            return Err(std::io::Error::other("packed output is too large"));
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The client's side of a [`Packer`], for one stream.
pub struct Unpacker(zstd::stream::write::Decoder<'static, Limited>);

impl Unpacker {
    pub fn new() -> Result<Unpacker> {
        let mut decoder = zstd::stream::write::Decoder::new(Limited(Vec::new()))?;
        decoder.window_log_max(WINDOW_LOG)?;
        Ok(Unpacker(decoder))
    }

    /// The output in a [`ServerMsg::StdoutPacked`].
    pub fn unpack(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        use std::io::Write;
        let (pad, rest) = data.split_first().context("empty packed output")?;
        let mut body = rest.get(*pad as usize..).context("bad packing")?;
        let mut out = Vec::new();
        while !body.is_empty() {
            let (head, rest) = body.split_first_chunk::<4>().context("bad packing")?;
            let head = u32::from_le_bytes(*head);
            let len = (head & !CHUNK_AS_IS) as usize;
            let piece = rest.get(..len).context("bad packing")?;
            body = &rest[len..];
            if head & CHUNK_AS_IS != 0 {
                out.extend_from_slice(piece);
            } else {
                self.0.write_all(piece).context("bad packed output")?;
                self.0.flush().context("bad packed output")?;
                out.append(&mut self.0.get_mut().0);
            }
            if out.len() > MAX_UNPACKED {
                bail!("packed output is too large");
            }
        }
        Ok(out)
    }
}

/// Accepted user names: 1–64 of `[A-Za-z0-9._-]`, not starting with `-`.
/// Keeps shell metacharacters, control characters and option-like names out
/// of everything downstream (compare OpenSSH 10.1/10.6 username fixes).
/// A character that must not reach a terminal from text we do not control:
/// controls (Cc: escape sequences, `\r`), and invisible format characters
/// (Cf: bidi overrides like U+202E that reorder what the user sees,
/// zero-width ones) plus line/paragraph separators. `char::is_control`
/// alone sees only Cc. Like OpenSSH's `strnvis`.
pub fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 | 0x180E
            | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF
            | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

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
    read_msg_opt_capped(r, MAX_MSG).await
}

/// Like [`read_msg_opt`], but rejects frames larger than `limit`. Used before
/// login, where a small cap keeps an anonymous peer from sending a huge frame
/// (e.g. a megabyte-long user name) that would then be logged.
pub async fn read_msg_opt_capped<R: AsyncRead + Unpin + ?Sized, T: DeserializeOwned>(
    r: &mut R,
    limit: usize,
) -> Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > limit {
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

/// Reads one length-prefixed message, rejecting frames larger than `limit`.
pub async fn read_msg_capped<R: AsyncRead + Unpin + ?Sized, T: DeserializeOwned>(r: &mut R, limit: usize) -> Result<T> {
    read_msg_opt_capped(r, limit).await?.context("stream closed unexpectedly")
}

/// The server answered a request with `Reply::Err` (as opposed to a
/// broken connection).
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// Reads a `Reply` and turns `Reply::Err` into an error.
/// Fails with the peer's error text, made safe to print: no control
/// characters (escape sequences could redraw the terminal), at most 500
/// characters.
pub async fn expect_ok<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> Result<Reply> {
    match read_msg(r).await? {
        Reply::Err(e) => Err(Refused(e.chars().filter(|&c| !hidden(c)).take(500).collect()).into()),
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

    #[test]
    fn packed_output_comes_back_whole() {
        let (mut packer, mut unpacker) = (Packer::new().unwrap(), Unpacker::new().unwrap());
        let mut out = 0;
        let line = |n: u32| format!("2026-11-03 INFO worker-{} request /api/items?page={n} status=200\n", n % 16).into_bytes();
        for n in 0..2000 {
            let text = line(n);
            let ServerMsg::StdoutPacked(small) = packer.pack(ServerMsg::Stdout(text.clone())) else { panic!("not packed") };
            assert_eq!(small.len() % SIZE_STEP, 0);
            out += small.len();
            assert_eq!(unpacker.unpack(&small).unwrap(), text);
        }
        // Lines this short only shrink with what came before them.
        assert!(out * 3 < (0..2000).map(|n| line(n).len()).sum::<usize>() * 2, "{out}");
        assert_eq!(packer.pack(ServerMsg::Stdout(b"x".to_vec())), ServerMsg::Stdout(b"x".to_vec()));
        assert!(Unpacker::new().unwrap().unpack(&[1]).is_err());
        assert!(Unpacker::new().unwrap().unpack(&[0, 1, 2, 3, 4, 5]).is_err());
    }

    #[test]
    fn what_looks_secret_stays_out_of_the_context() {
        let spans = |text: &str| secret_spans(text.as_bytes()).iter().map(|s| text[s.clone()].to_string()).collect::<Vec<_>>();
        let cases: [(&str, &[&str]); 9] = [
            ("  GET /x?session=4f2a9c1d77e0b3a6 status=200 ok\n", &["4f2a9c1d77e0b3a6"]),
            ("  password: hunter2 and more\n", &["hunter2"]),
            ("  password:          hunter2 aligned\n", &["hunter2"]),
            ("  export API_KEY=\"abc\" now\n", &["abc"]),
            ("  Authorization: Basic dXNlcjpwYXNz\r\n  next\n", &["Basic dXNlcjpwYXNz"]),
            ("  sk1234567890abcdefghij is it\n", &["sk1234567890abcdefghij"]),
            ("  an internationalization of words\n", &[]),
            ("  /usr/share/doc/some-package/README\n", &[]),
            ("  3.14 and 2026-11-03 at 10:00 ok\n", &[]),
        ];
        for (text, want) in cases {
            assert_eq!(spans(text), want, "{text}");
        }
        // Not even a match with a line before it can show.
        let (mut packer, mut unpacker) = (Packer::new().unwrap(), Unpacker::new().unwrap());
        let line = b"  a long enough line with token=hunter2hunter2 in it, and the end\n";
        let ServerMsg::StdoutPacked(first) = packer.pack(ServerMsg::Stdout(line.to_vec())) else { panic!("not packed") };
        assert_eq!(unpacker.unpack(&first).unwrap(), line);
        assert!(first.windows(14).any(|w| w == b"hunter2hunter2"));
    }

    #[test]
    fn output_that_does_not_shrink_goes_as_it_is() {
        let mut packer = Packer::new().unwrap();
        let mut state = 1u64;
        let mut noise = || -> Vec<u8> {
            (0..1024).flat_map(|_| { state ^= state << 13; state ^= state >> 7; state ^= state << 17; state.to_le_bytes() }).collect()
        };
        let raw = (0..64).filter(|_| matches!(packer.pack(ServerMsg::Stdout(noise())), ServerMsg::Stdout(_))).count();
        assert!(raw > 0, "no message was let through");
    }

    #[test]
    fn a_decompression_bomb_stops() {
        let (mut packer, mut unpacker) = (Packer::new().unwrap(), Unpacker::new().unwrap());
        let ServerMsg::StdoutPacked(bomb) = packer.pack(ServerMsg::Stdout(vec![0; MAX_UNPACKED + 1])) else { panic!("not packed") };
        assert!(unpacker.unpack(&bomb).is_err());
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

    #[test]
    fn hidden_chars() {
        for c in ['\x1b', '\r', '\u{85}', '\u{202E}', '\u{202C}', '\u{2066}', '\u{200B}', '\u{FEFF}', '\u{2028}', '\u{E0041}'] {
            assert!(hidden(c), "{c:?}");
        }
        for c in ['a', 'я', ' ', '€', '\u{1F600}', '中'] {
            assert!(!hidden(c), "{c:?}");
        }
    }

    #[tokio::test]
    async fn rejects_oversized() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(read_msg::<_, Reply>(&mut b).await.is_err());
    }
}
