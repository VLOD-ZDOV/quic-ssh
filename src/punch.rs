//! Experimental NAT traversal: UDP hole punching.
//!
//! Two `qsh punch` processes on different networks learn their public
//! addresses from STUN, exchange them out of band (a chat message, or the
//! terminal when `serve` asks), and then both send UDP packets to each other
//! for as long as the tunnel runs. Each packet opens the NAT mapping on the
//! sending side; once the first packets cross, the mapping on both sides is
//! open and QUIC runs end to end through it.
//!
//! `serve` runs next to a qshd that cannot be reached from outside and passes
//! the punched packets to it; `dial` listens on loopback, where the local
//! `qsh` connects. The bytes that cross the hole are a normal qsh connection:
//! TLS is still between `qsh` and `qshd`, and the host key is checked as usual,
//! so the shared secret below only keeps stray packets out of the tunnel.
//!
//! Limits, by design: this is a cone-NAT trick. A symmetric NAT (including
//! most CGNAT) gives a different mapping per destination, and punching then
//! fails; when the NAT changes the port it uses for us, the tunnel follows
//! the new one, which covers the case of only one side being symmetric.

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sha2::{Digest as _, Sha256};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{timeout, Instant};

/// Marks our datagrams, so that a stray packet cannot reach qshd.
const MAGIC: [u8; 4] = *b"QSHP";
const KEY_LEN: usize = 16;
const HEADER: usize = MAGIC.len() + KEY_LEN;
const MAX_DATAGRAM: usize = 2048;

/// How often each side sends an empty packet to keep its NAT mapping open.
const KEEPALIVE: Duration = Duration::from_secs(1);
const STUN_TIMEOUT: Duration = Duration::from_millis(1200);
const STUN_TRIES: usize = 3;

/// Public STUN servers asked for our address.
const STUN_SERVERS: &[(&str, u16)] = &[("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)];

pub struct ServeOptions {
    /// Where the punching socket binds (`0.0.0.0:0` unless `--punch-port`).
    pub bind: SocketAddr,
    /// The other side's public address; when `None`, it is read from stdin.
    pub peer: Option<SocketAddr>,
    pub secret: String,
    pub stun: bool,
    /// The local qshd the punched packets are passed to.
    pub target: SocketAddr,
}

pub struct DialOptions {
    pub bind: SocketAddr,
    /// The other side's public address.
    pub peer: SocketAddr,
    pub secret: String,
    pub stun: bool,
    /// Where the local `qsh` connects.
    pub listen: SocketAddr,
}

/// Reads a peer address: `1.2.3.4:5678`, `[2001:db8::1]:5678`, or a name.
pub async fn resolve(s: &str) -> Result<SocketAddr> {
    if let Ok(a) = s.trim().parse::<SocketAddr>() {
        return Ok(a);
    }
    let mut it = tokio::net::lookup_host(s.trim()).await.with_context(|| format!("cannot resolve {s:?}"))?;
    it.next().with_context(|| format!("{s:?} has no addresses"))
}

fn say(line: impl std::fmt::Display) {
    println!("{line}");
    // Piped output is block-buffered otherwise, and the other side waits for
    // these lines.
    let _ = std::io::stdout().flush();
}

fn key(secret: &str) -> [u8; KEY_LEN] {
    let digest = Sha256::digest(secret.as_bytes());
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&digest[..KEY_LEN]);
    k
}

/// The secret both sides give, or a fresh one (also says whether it is fresh).
pub fn secret(given: Option<String>) -> (String, bool) {
    match given {
        Some(s) if !s.is_empty() => (s, false),
        _ => {
            let mut raw = [0u8; KEY_LEN];
            rand::Rng::fill(&mut rand::thread_rng(), &mut raw);
            (raw.iter().map(|b| format!("{b:02x}")).collect(), true)
        }
    }
}

/// Where the punching socket binds: the peer's family, any local address.
pub fn bind_for(peer: Option<SocketAddr>, port: Option<u16>) -> SocketAddr {
    let port = port.unwrap_or(0);
    match peer {
        Some(p) if p.is_ipv6() => (Ipv6Addr::UNSPECIFIED, port).into(),
        _ => (Ipv4Addr::UNSPECIFIED, port).into(),
    }
}

fn frame(key: &[u8; KEY_LEN], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(key);
    out.extend_from_slice(payload);
    out
}

fn unframe<'a>(key: &[u8; KEY_LEN], buf: &'a [u8]) -> Option<&'a [u8]> {
    if buf.len() < HEADER || buf[..MAGIC.len()] != MAGIC || buf[MAGIC.len()..HEADER] != *key {
        return None;
    }
    Some(&buf[HEADER..])
}

/// A `serve` side: waits for the peer, keeps the hole open, and passes
/// packets between the punched socket and the local qshd.
pub async fn serve(o: ServeOptions) -> Result<()> {
    let sock = UdpSocket::bind(o.bind).await.with_context(|| format!("cannot bind {}", o.bind))?;
    let key = key(&o.secret);
    let target = UdpSocket::bind(loopback(o.target)).await?;
    target.connect(o.target).await.with_context(|| format!("cannot reach {}", o.target))?;
    say(format!("qsh punch: punched socket on {}", sock.local_addr()?));
    if o.stun && !o.bind.ip().is_loopback() {
        report_public(&sock).await;
    }
    let peer = match o.peer {
        Some(p) => p,
        None => {
            say("qsh punch: paste the other side's public address here and press Enter:");
            read_peer().await?
        }
    };
    say(format!("qsh punch: punching {peer}, forwarding to {}", o.target));
    relay(sock, &key, peer, Role::Serve { target }).await
}

/// A `dial` side: punches the hole, and listens on loopback for the local
/// `qsh` to connect to.
pub async fn dial(o: DialOptions) -> Result<()> {
    let sock = UdpSocket::bind(o.bind).await.with_context(|| format!("cannot bind {}", o.bind))?;
    let key = key(&o.secret);
    let listen = UdpSocket::bind(o.listen).await.with_context(|| format!("cannot bind {}", o.listen))?;
    let addr = listen.local_addr()?;
    say(format!("qsh punch: punched socket on {}", sock.local_addr()?));
    if o.stun && !o.bind.ip().is_loopback() {
        report_public(&sock).await;
    }
    say(format!("qsh punch: punching {}, listening for qsh on {addr}", o.peer));
    if addr.ip().is_loopback() {
        let port = addr.port();
        if port == crate::DEFAULT_PORT {
            say("qsh punch: in another terminal, connect with `qsh 127.0.0.1`");
        } else {
            say(format!("qsh punch: in another terminal, connect with `qsh -p {port} 127.0.0.1` (a new port means an unknown host key: --accept-new-host once)"));
        }
    }
    relay(sock, &key, o.peer, Role::Dial { listen }).await
}

enum Role {
    Serve { target: UdpSocket },
    Dial { listen: UdpSocket },
}

/// The shared state of a punch: who we send to, and, on the dial side, the
/// local `qsh` that last sent us something.
struct Hole {
    sock: UdpSocket,
    key: [u8; KEY_LEN],
    peer: Mutex<SocketAddr>,
    local: Mutex<Option<SocketAddr>>,
}

async fn relay(sock: UdpSocket, key: &[u8; KEY_LEN], peer: SocketAddr, role: Role) -> Result<()> {
    let hole = Arc::new(Hole { sock, key: *key, peer: Mutex::new(peer), local: Mutex::new(None) });
    say("qsh punch: waiting for the first packet to cross the NAT");
    match role {
        Role::Serve { target } => {
            let target = Arc::new(target);
            tokio::select! {
                r = punch_to_local(&hole, &target, true) => r,
                r = local_to_punch(&hole, &target) => r,
                r = keepalive(&hole) => r,
                _ = tokio::signal::ctrl_c() => Ok(()),
            }
        }
        Role::Dial { listen } => {
            let listen = Arc::new(listen);
            tokio::select! {
                r = punch_to_local(&hole, &listen, false) => r,
                r = local_to_punch(&hole, &listen) => r,
                r = keepalive(&hole) => r,
                _ = tokio::signal::ctrl_c() => Ok(()),
            }
        }
    }
}

/// Punched socket -> local socket. Keepalives (empty payloads) only refresh
/// the mapping; a packet from a new address moves the peer there, which is
/// what a NAT that picks a different port for us looks like.
async fn punch_to_local(hole: &Hole, local: &UdpSocket, connected: bool) -> Result<()> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut announced = false;
    loop {
        let (n, from) = hole.sock.recv_from(&mut buf).await?;
        let Some(payload) = unframe(&hole.key, &buf[..n]) else {
            tracing::debug!("{from}: not ours, dropped");
            continue;
        };
        {
            let mut peer = hole.peer.lock().await;
            if *peer != from {
                say(format!("qsh punch: peer moved from {peer} to {from} (its NAT changed the port)"));
                *peer = from;
            }
        }
        if !announced {
            announced = true;
            say(format!("qsh punch: the hole is open ({from})"));
        }
        if payload.is_empty() {
            continue;
        }
        let sent = if connected {
            local.send(payload).await
        } else {
            let Some(to) = *hole.local.lock().await else { continue };
            local.send_to(payload, to).await
        };
        if let Err(e) = sent {
            // A missing qshd answers ICMP; it is not worth ending the tunnel.
            tracing::debug!("cannot pass a packet to {}: {e}", local.local_addr().map(|a| a.to_string()).unwrap_or_default());
        }
    }
}

/// Local socket -> punched socket. On the dial side the first sender is the
/// local `qsh`, whose address is remembered for the way back.
async fn local_to_punch(hole: &Hole, local: &UdpSocket) -> Result<()> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, from) = local.recv_from(&mut buf).await?;
        *hole.local.lock().await = Some(from);
        let peer = *hole.peer.lock().await;
        let packet = frame(&hole.key, &buf[..n]);
        if let Err(e) = hole.sock.send_to(&packet, peer).await {
            tracing::debug!("cannot send to {peer}: {e}");
        }
    }
}

async fn keepalive(hole: &Hole) -> Result<()> {
    let packet = frame(&hole.key, &[]);
    loop {
        let peer = *hole.peer.lock().await;
        if let Err(e) = hole.sock.send_to(&packet, peer).await {
            tracing::debug!("keepalive to {peer}: {e}");
        }
        tokio::time::sleep(KEEPALIVE).await;
    }
}

/// A local socket of the same family as `remote` to talk to it with.
fn loopback(remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv4() {
        (Ipv4Addr::LOCALHOST, 0).into()
    } else {
        (Ipv6Addr::LOCALHOST, 0).into()
    }
}

async fn read_peer() -> Result<SocketAddr> {
    let line = tokio::task::spawn_blocking(|| {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).map(|_| s)
    })
    .await
    .context("cannot read stdin")?
    .context("cannot read stdin")?;
    if line.trim().is_empty() {
        bail!("no peer address given");
    }
    resolve(&line).await
}

/// Asks STUN for our address and prints it. Two servers also tell a symmetric
/// NAT apart: its mapping to each one has a different port.
async fn report_public(sock: &UdpSocket) {
    let mut seen: Vec<SocketAddr> = Vec::new();
    for (host, port) in STUN_SERVERS {
        let Some(server) = tokio::net::lookup_host((*host, *port)).await.ok().and_then(|mut it| it.next()) else {
            tracing::debug!("{host}:{port}: cannot resolve");
            continue;
        };
        match stun_once(sock, server).await {
            Ok(addr) => {
                say(format!("qsh punch: STUN says your public address is {addr} -- send it to the other side"));
                seen.push(addr);
            }
            Err(e) => tracing::debug!("{host}:{port}: {e:#}"),
        }
    }
    if seen.len() >= 2 && seen[0].port() != seen[1].port() {
        say("qsh punch: warning: STUN servers see different ports, so this is probably a symmetric NAT (or CGNAT); punching through it usually fails. A relay (qsh -R) is then the way.");
    }
    if seen.is_empty() {
        say("qsh punch: no STUN server answered; find your public address another way, or use `qsh -R` through a reachable host.");
    }
}

/// One STUN binding request, retried while there is no answer.
async fn stun_once(sock: &UdpSocket, server: SocketAddr) -> Result<SocketAddr> {
    let mut txn = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut txn);
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    req[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
    req[8..].copy_from_slice(&txn);
    let mut buf = [0u8; 512];
    for _ in 0..STUN_TRIES {
        sock.send_to(&req, server).await.with_context(|| format!("cannot send to {server}"))?;
        let deadline = Instant::now() + STUN_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let Ok(Ok((n, from))) = timeout(left, sock.recv_from(&mut buf)).await else {
                break;
            };
            if from.ip() != server.ip() {
                continue;
            }
            if let Some(addr) = parse_stun(&buf[..n], &txn) {
                return Ok(addr);
            }
        }
    }
    bail!("no binding response from {server}")
}

/// The address in a STUN binding success response for `txn`.
fn parse_stun(buf: &[u8], txn: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 || buf[0] != 0x01 || buf[1] != 0x01 || buf[4..8] != [0x21, 0x12, 0xA4, 0x42] || buf[8..20] != txn[..] {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    let end = (20 + len).min(buf.len());
    let mut pos = 20;
    let (mut xor, mut plain) = (None, None);
    while pos + 4 <= end {
        let ty = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let alen = usize::from(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));
        let start = pos + 4;
        let stop = start.checked_add(alen)?;
        if stop > end {
            break;
        }
        let val = &buf[start..stop];
        match ty {
            0x0020 => xor = xor.or_else(|| mapped(val, txn, true)),
            0x0001 => plain = plain.or_else(|| mapped(val, txn, false)),
            _ => {}
        }
        pos = start + alen.div_ceil(4) * 4;
    }
    xor.or(plain)
}

fn mapped(v: &[u8], txn: &[u8; 12], xor: bool) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let mask = |b: u8, i: usize| if xor { b ^ [0x21, 0x12, 0xA4, 0x42u8][i] } else { b };
    let port = u16::from_be_bytes([v[2], v[3]]) ^ if xor { 0x2112 } else { 0 };
    match v[1] {
        0x01 if v.len() >= 8 => {
            let ip = [mask(v[4], 0), mask(v[5], 1), mask(v[6], 2), mask(v[7], 3)];
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        0x02 if v.len() >= 20 => {
            let mut ip = [0u8; 16];
            for (i, b) in v[4..20].iter().enumerate() {
                let x = if !xor {
                    *b
                } else if i < 4 {
                    b ^ [0x21, 0x12, 0xA4, 0x42][i]
                } else {
                    b ^ txn[i - 4]
                };
                ip[i] = x;
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let k = key("secret");
        let p = frame(&k, b"hello");
        assert_eq!(unframe(&k, &p), Some(&b"hello"[..]));
        assert_eq!(unframe(&key("other"), &p), None);
        assert_eq!(unframe(&k, &p[..HEADER - 1]), None);
        assert_eq!(unframe(&k, b"not a qsh punch packet"), None);
        assert_eq!(unframe(&k, &frame(&k, &[])), Some(&b""[..]));
    }

    /// A binding success response with a XOR-MAPPED-ADDRESS, as a server sends.
    fn binding_response(txn: &[u8; 12], addr: SocketAddr) -> Vec<u8> {
        let mut attr = vec![0x00, 0x20, 0x00, 0x08, 0x00, 0x01];
        let port = addr.port() ^ 0x2112;
        attr.extend_from_slice(&port.to_be_bytes());
        match addr.ip() {
            IpAddr::V4(ip) => {
                attr.extend_from_slice(&[ip.octets()[0] ^ 0x21, ip.octets()[1] ^ 0x12, ip.octets()[2] ^ 0xA4, ip.octets()[3] ^ 0x42]);
            }
            IpAddr::V6(_) => unreachable!(),
        }
        let mut out = vec![0x01, 0x01];
        out.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        out.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        out.extend_from_slice(txn);
        out.extend_from_slice(&attr);
        out
    }

    #[test]
    fn reads_a_stun_answer() {
        let txn = *b"0123456789ab";
        let want: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        assert_eq!(parse_stun(&binding_response(&txn, want), &txn), Some(want));
        assert_eq!(parse_stun(&binding_response(&txn, want), b"aaaaaaaaaaaa"), None);
    }

    #[test]
    fn reads_a_plain_mapped_address() {
        let txn = *b"0123456789ab";
        let mut attr = vec![0x00, 0x01, 0x00, 0x08, 0x00, 0x01];
        attr.extend_from_slice(&8080u16.to_be_bytes());
        attr.extend_from_slice(&[192, 0, 2, 9]);
        let mut out = vec![0x01, 0x01];
        out.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        out.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        out.extend_from_slice(&txn);
        out.extend_from_slice(&attr);
        assert_eq!(parse_stun(&out, &txn), Some("192.0.2.9:8080".parse().unwrap()));
    }
}
