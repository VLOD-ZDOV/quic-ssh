//! Robustness checks with mutated input, on stable Rust: every parser of data
//! from the network or from files must reject bad input without panicking,
//! and tar extraction must never write outside its target directory.
//!
//! Deterministic (fixed seeds), short by default; for a longer run:
//! `QSH_FUZZ_ITERS=200000 cargo test --release --test fuzz`.

use std::io::Read;
use std::path::Path;

use qsh::proto;

fn iterations() -> usize {
    std::env::var("QSH_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

const INTERESTING: [u8; 12] = [0, 1, 0x7f, 0x80, 0xff, b'\n', b'"', b',', b'=', b'.', b'/', b'%'];

/// A random mutation of `seed`: flipped bits, odd bytes, cut, repeated or
/// spliced pieces, or huge length fields.
fn mutate(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut data = seeds[rng.below(seeds.len())].clone();
    for _ in 0..1 + rng.below(4) {
        let len = data.len();
        match rng.below(8) {
            0 if len > 0 => {
                let i = rng.below(len);
                data[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                data[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            2 => {
                let i = rng.below(len + 1);
                let n = 1 + rng.below(8);
                let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                data.splice(i..i, bytes);
            }
            3 if len > 0 => {
                let a = rng.below(len);
                let b = (a + 1 + rng.below(16)).min(len);
                data.drain(a..b);
            }
            4 => data.truncate(rng.below(len + 1)),
            5 if len > 0 => {
                let a = rng.below(len);
                let b = (a + 1 + rng.below(32)).min(len);
                let piece = data[a..b].to_vec();
                let at = rng.below(len + 1);
                data.splice(at..at, piece);
            }
            6 if len >= 4 => {
                let i = rng.below(len - 3);
                let v = [0u32, 1, 0x7fff_ffff, u32::MAX, 1 << 20, 1 << 24][rng.below(6)];
                data[i..i + 4].copy_from_slice(&v.to_be_bytes());
            }
            _ => {
                let other = &seeds[rng.below(seeds.len())];
                if !other.is_empty() {
                    let a = rng.below(other.len());
                    let at = rng.below(len + 1);
                    data.splice(at..at, other[a..].iter().copied().take(64));
                }
            }
        }
    }
    data
}

fn text(rng: &mut Rng, seeds: &[&str]) -> String {
    let seeds: Vec<Vec<u8>> = seeds.iter().map(|s| s.as_bytes().to_vec()).collect();
    String::from_utf8_lossy(&mutate(rng, &seeds)).into_owned()
}

fn frame<T: serde::Serialize>(msg: &T) -> Vec<u8> {
    let body = postcard::to_stdvec(msg).unwrap();
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend(body);
    out
}

#[test]
fn protocol_messages() {
    use proto::*;
    let seeds = vec![
        frame(&Hello::Login { version: 4, user: "alice".into() }),
        frame(&Hello::Resume { version: 4, user: "bob".into(), token: vec![7; 32] }),
        frame(&Request::Exec { command: Some("ls -la".into()), env: vec![("LANG".into(), "C".into())], pty: Some(PtySpec { term: "xterm".into(), cols: 80, rows: 24 }) }),
        frame(&Request::Upload { path: "a/b".into(), name: "c".into(), size: 1 << 40, mode: 0o644 }),
        frame(&Request::Resume { token: vec![1; 16], received: u64::MAX }),
        frame(&Request::RemoteForward { bind: "::".into(), port: 8080 }),
        frame(&Reply::Prompt { text: "Code: ".into(), echo: false }),
        frame(&Reply::Welcome { version: 4 }),
        frame(&Auth::PublicKey { key: vec![0; 51], signature: vec![1; 83] }),
        frame(&ClientMsg::Typed { data: b"x".to_vec(), pad: vec![0; 7] }),
        frame(&ServerMsg::Exit { code: Some(1), signal: None }),
        frame(&Opened::Forwarded { port: 22, origin: "192.0.2.1:5000".into() }),
    ];
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let mut rng = Rng(0x1234_5678_9abc_def1);
    rt.block_on(async {
        for _ in 0..iterations() {
            let data = mutate(&mut rng, &seeds);
            let _ = read_msg_opt::<_, Hello>(&mut data.as_slice()).await;
            let _ = read_msg_opt::<_, Request>(&mut data.as_slice()).await;
            let _ = read_msg_opt::<_, Reply>(&mut data.as_slice()).await;
            let _ = read_msg_opt::<_, Auth>(&mut data.as_slice()).await;
            let _ = read_msg_opt::<_, ClientMsg>(&mut data.as_slice()).await;
            let _ = read_msg_opt::<_, ServerMsg>(&mut data.as_slice()).await;
            let _ = read_msg_opt::<_, Opened>(&mut data.as_slice()).await;
            let _ = read_msg_opt::<_, Vec<u8>>(&mut data.as_slice()).await;
        }
    });
}

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";

// The server side exists only on Unix.
#[cfg(unix)]
#[test]
fn authorized_keys_lines() {
    let seeds = [
        KEY.to_string(),
        format!("restrict,command=\"echo hi\",from=\"192.0.2.0/24,!192.0.2.9\" {KEY}"),
        format!("expiry-time=\"20300101\",permitopen=\"db:5432\",permitlisten=\"localhost:8080\" {KEY}"),
        format!("expiry-time=\"203001011230Z\",no-touch-required,verify-required {KEY}"),
        format!("cert-authority,principals=\"alice,bob\" {KEY}"),
        format!("environment=\"A=B\",no-pty,pty,agent-forwarding {KEY}"),
    ];
    let seeds: Vec<&str> = seeds.iter().map(String::as_str).collect();
    let mut rng = Rng(0xfeed_beef_0000_0001);
    for _ in 0..iterations() {
        let t = text(&mut rng, &seeds);
        if let Some(entry) = qsh::authkeys::parse_list(&t, |_, _| {}).first() {
            let _ = entry.restrictions.may_open("db", 5432);
            let _ = entry.restrictions.may_listen("localhost", 8080);
        }
    }
}

#[test]
fn client_config_and_saved_connections() {
    let seeds = [
        "Host web*.example.com !web9.example.com\n  User deploy\n  Port 2222\n  IdentityFile ~/.ssh/%r@%h\n  LocalForward 8080 localhost:80\n",
        "Match all\nInclude config.d/*\nHost a\n  ProxyJump b,c\n  EscapeChar ^A\n  ObscureKeystrokeTiming interval:40\n",
        "Host=x\n\tHostName=\"two words\"\n  ControlPath ~/.c/%C\n  ControlPersist 1h30m\n  PredictiveEcho yes\n",
    ];
    let base = std::env::temp_dir().join("qsh-fuzz-no-such-dir");
    let mut rng = Rng(0x0bad_cafe_1234_5678);
    for _ in 0..iterations() {
        let t = text(&mut rng, &seeds);
        let cfg = qsh::client::config::parse(&t, "web1.example.com", &base, true);
        let _ = qsh::client::config::keystroke_interval(cfg.obscure_keystrokes.as_deref());
        let _ = cfg.control_persist.as_deref().map(qsh::client::control::parse_persist);
        let _ = qsh::client::saved::parse(&t);
        let _ = qsh::client::parse_escape(cfg.escape_char.as_deref());
    }
}

#[test]
fn destinations_and_arguments() {
    let seeds = ["alice@example.com:2222", "u@[2001:db8::1]:22", "[::1]", "host", "-oProxyCommand=x", "a@b@c:1:2"];
    let words = ["-p", "22", "-L", "8080:localhost:80", "-o", "Port=1", "-tt", "-N", "--full", "--transport", "quic", "host", "--", "ls", "-J", "a,b", "-O", "check", "-S", "/tmp/s", "-M", "-e", "^A"];
    let mut rng = Rng(0x5eed_0000_aaaa_5555);
    for _ in 0..iterations() {
        let dest = text(&mut rng, &seeds);
        let _ = qsh::client::Target::parse_with(&dest, None, None, rng.below(2) == 0);
        let args: Vec<String> = (0..rng.below(8)).map(|_| words[rng.below(words.len())].to_string()).collect();
        let _ = qsh::client::cli::SshArgs::parse(args);
    }
}

#[test]
fn small_parsers() {
    let mut rng = Rng(0x7777_1111_2222_3333);
    let ip: std::net::IpAddr = "192.0.2.77".parse().unwrap();
    for _ in 0..iterations() {
        let t = text(&mut rng, &["JBSWY3DPEHPK3PXP", "abcd-efgh", "192.0.2.0/24,!10.0.0.0/8", "2001:db8::/129", "*.example.*", KEY]);
        let _ = qsh::totp::base32_decode(&t);
        let _ = qsh::pair::normalize(&t);
        let _ = qsh::pattern::cidr_contains(&t, ip);
        let _ = qsh::pattern::address_allowed(&t, ip);
        let _ = qsh::pattern::source_address_allowed(&t, ip);
        let _ = qsh::pattern::wildcard(&t, "web1.example.com");
        let _ = qsh::keys::parse_key_list(&t);
        let _ = qsh::client::predict::parse_mode(&t);
    }
}

// The server side exists only on Unix.
#[cfg(unix)]
#[test]
fn revocation_lists() {
    fn string(v: &[u8]) -> Vec<u8> {
        let mut out = (v.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(v);
        out
    }
    let blob = ssh_key::PublicKey::from_openssh(KEY).unwrap().to_bytes().unwrap();
    let mut krl = b"SSHKRL\n\0".to_vec();
    krl.extend(1u32.to_be_bytes());
    krl.extend([0u8; 24]);
    krl.extend(string(b""));
    krl.extend(string(b""));
    krl.push(2);
    krl.extend(string(&string(&blob)));
    let mut certs = string(&blob);
    certs.extend(string(b""));
    for (kind, data) in [(0x20u8, 5u64.to_be_bytes().to_vec()), (0x22, [7u64.to_be_bytes().to_vec(), string(&[0x81, 0x01])].concat()), (0x23, string(b"id"))] {
        certs.push(kind);
        certs.extend(string(&data));
    }
    krl.push(1);
    krl.extend(string(&certs));
    let seeds = vec![krl, format!("{KEY}\n# comment\n").into_bytes()];
    let offered = qsh::authkeys::Offered::from_bytes(&blob).unwrap();
    let mut rng = Rng(0x0101_0202_0303_0404);
    for _ in 0..iterations() {
        let data = mutate(&mut rng, &seeds);
        if let Ok(list) = qsh::server::revoked::Revoked::parse(&data) {
            let _ = list.revoked(&offered);
        }
        let _ = qsh::authkeys::Offered::from_bytes(&data);
    }
}

/// Lists every path under `dir` (relative), including symlinks.
fn all_paths(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            out.push(p.strip_prefix(dir).unwrap().to_path_buf());
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(p);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn tar_extraction_stays_inside() {
    let src = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(src.path().join("sub/deep")).unwrap();
    std::fs::write(src.path().join("a.txt"), "alpha").unwrap();
    std::fs::write(src.path().join("sub/deep/b"), vec![7u8; 3000]).unwrap();
    let mut archive = Vec::new();
    qsh::tree::write_tree(src.path(), &mut archive).unwrap();
    // A hostile archive: absolute and parent paths, a symlink, a device.
    let mut evil = tar::Builder::new(Vec::new());
    for (path, kind) in [("../outside", tar::EntryType::Regular), ("x/../../outside", tar::EntryType::Regular), ("link", tar::EntryType::Symlink), ("dev", tar::EntryType::Char)] {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_size(if kind == tar::EntryType::Regular { 3 } else { 0 });
        h.set_mode(0o4755);
        if kind == tar::EntryType::Symlink {
            h.set_link_name("/").unwrap();
        }
        // set_path refuses `..`; write the raw name like an attacker would.
        let name = &mut h.as_old_mut().name;
        name.fill(0);
        name[..path.len()].copy_from_slice(path.as_bytes());
        h.set_cksum();
        let data: &[u8] = if kind == tar::EntryType::Regular { b"bad" } else { b"" };
        evil.append(&h, data).unwrap();
    }
    let evil = evil.into_inner().unwrap();
    let seeds = vec![archive, evil];
    let mut rng = Rng(0x7a7a_7a7a_1357_9bdf);
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("keep"), "untouched").unwrap();
    for i in 0..iterations() / 4 {
        let data = mutate(&mut rng, &seeds);
        let dest = root.path().join(format!("d{i}"));
        std::fs::create_dir(&dest).unwrap();
        let _ = qsh::tree::extract_tree(data.as_slice(), &dest);
        for p in all_paths(&dest) {
            let full = dest.join(&p);
            let meta = std::fs::symlink_metadata(&full).unwrap();
            assert!(meta.is_dir() || meta.is_file(), "extracted something else: {p:?}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(meta.permissions().mode() & 0o7000, 0, "setuid/setgid/sticky kept on {p:?}");
            }
        }
        std::fs::remove_dir_all(&dest).unwrap();
        // Nothing next to the target changed.
        assert_eq!(all_paths(root.path()), vec![std::path::PathBuf::from("keep")], "wrote outside the target");
        assert_eq!(std::fs::read_to_string(root.path().join("keep")).unwrap(), "untouched");
    }
    // The chunked framing around tar streams.
    let mut chunked = Vec::new();
    for piece in [&b"hello "[..], b"world", b""] {
        chunked.extend((piece.len() as u32).to_be_bytes());
        chunked.extend_from_slice(piece);
    }
    for _ in 0..iterations() {
        let data = mutate(&mut rng, std::slice::from_ref(&chunked));
        let mut r = qsh::tree::Unchunk::new(data.as_slice());
        let _ = std::io::copy(&mut (&mut r).take(1 << 16), &mut std::io::sink());
        let _ = r.finish();
    }
}

