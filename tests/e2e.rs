//! End-to-end tests: a real `qshd` (unprivileged mode) and `qsh` processes,
//! each with its own temporary HOME, talking over loopback.

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const QSH: &str = env!("CARGO_BIN_EXE_qsh");
const QSHD: &str = env!("CARGO_BIN_EXE_qshd");

fn user() -> String {
    nix::unistd::User::from_uid(nix::unistd::getuid()).unwrap().unwrap().name
}

/// A port free on both UDP and TCP.
fn free_port() -> u16 {
    loop {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

struct Server {
    child: Child,
    home: TempDir,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn start() -> Server {
        Self::start_with("127.0.0.1", "")
    }

    /// `config` is written to qshd.toml; `listen_ip` lets a test leave UDP unanswered.
    fn start_with(listen_ip: &str, config: &str) -> Server {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".config/qsh");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("qshd.toml"), config).unwrap();
        let mut child = Command::new(QSHD)
            .args(["serve", "--listen", &format!("{listen_ip}:0")])
            .env("HOME", home.path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The server logs "listening on IP:PORT"; keep draining its log afterwards.
        let mut lines = std::io::BufReader::new(child.stderr.take().unwrap()).lines();
        let port = loop {
            let line = lines.next().expect("server exited before listening").unwrap();
            if let Some(rest) = line.split("listening on ").nth(1) {
                let addr = rest.split_whitespace().next().unwrap();
                break addr.rsplit(':').next().unwrap().parse().unwrap();
            }
        };
        std::thread::spawn(move || lines.for_each(drop));
        Server { child, home, port }
    }

    fn pair_code(&self) -> String {
        let out = Command::new(QSHD).arg("pair").env("HOME", self.home.path()).output().unwrap();
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        text.split_whitespace().nth(2).unwrap().to_string()
    }

    fn authorized_keys(&self) -> PathBuf {
        self.home.path().join(".config/qsh/authorized_keys")
    }
}

struct Client {
    home: TempDir,
}

impl Client {
    fn new() -> Client {
        Client { home: tempfile::tempdir().unwrap() }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(QSH);
        c.args(args).env("HOME", self.home.path()).stdin(Stdio::null());
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    /// Pairs with the server, which adds our key and pins its host key.
    fn paired(server: &Server) -> Client {
        let c = Client::new();
        let code = server.pair_code();
        let out = c.run(&["pair", "-p", &server.port.to_string(), &dest(), &code]);
        assert!(out.status.success(), "pair failed: {}", String::from_utf8_lossy(&out.stderr));
        c
    }
}

fn dest() -> String {
    format!("{}@127.0.0.1", user())
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn exec(c: &Client, s: &Server, transport: &str, command: &str) -> Output {
    c.run(&["--transport", transport, "-p", &s.port.to_string(), &dest(), "/bin/sh", "-c", &format!("'{command}'")])
}

#[test]
fn exec_over_both_transports() {
    let s = Server::start();
    let c = Client::paired(&s);
    for t in ["quic", "tcp"] {
        let out = exec(&c, &s, t, "echo hi; echo oops >&2");
        assert!(out.status.success(), "{t}: {}", stderr(&out));
        assert_eq!(stdout(&out), "hi\n", "{t}");
        assert!(stderr(&out).contains("oops"), "{t}");
        let out = exec(&c, &s, t, "exit 42");
        assert_eq!(out.status.code(), Some(42), "{t}");
    }
}

#[test]
fn stdin_is_forwarded() {
    let s = Server::start();
    let c = Client::paired(&s);
    for t in ["quic", "tcp"] {
        let mut child = c
            .cmd(&["--transport", t, "-p", &s.port.to_string(), &dest(), "wc", "-c"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let data = vec![b'x'; 300_000];
        child.stdin.take().unwrap().write_all(&data).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{t}");
        assert_eq!(stdout(&out).trim(), "300000", "{t}");
    }
}

fn pseudo_random(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e3779b97f4a7c15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[test]
fn copy_roundtrip() {
    let s = Server::start();
    let c = Client::paired(&s);
    let data = pseudo_random(10 * 1024 * 1024 + 123);
    let local = c.home.path().join("big.bin");
    std::fs::write(&local, &data).unwrap();
    let port = s.port.to_string();
    for t in ["quic", "tcp"] {
        let remote = format!("{}:copy-{t}.bin", dest());
        let out = c.run(&["cp", "--transport", t, "-p", &port, local.to_str().unwrap(), &remote]);
        assert!(out.status.success(), "upload {t}: {}", stderr(&out));
        assert_eq!(std::fs::read(s.home.path().join(format!("copy-{t}.bin"))).unwrap(), data);

        let back = c.home.path().join(format!("back-{t}.bin"));
        let out = c.run(&["cp", "--transport", t, "-p", &port, &remote, back.to_str().unwrap()]);
        assert!(out.status.success(), "download {t}: {}", stderr(&out));
        assert_eq!(std::fs::read(&back).unwrap(), data);
    }
    // Upload into a directory keeps the file name; missing remote files are reported.
    std::fs::create_dir(s.home.path().join("inbox")).unwrap();
    let remote_dir = format!("{}:inbox/", dest());
    let out = c.run(&["cp", "-p", &port, local.to_str().unwrap(), &remote_dir]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(s.home.path().join("inbox/big.bin").exists());
    let missing = format!("{}:does-not-exist", dest());
    let out = c.run(&["cp", "-p", &port, &missing, c.home.path().to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("does-not-exist"), "{}", stderr(&out));
}

/// Echo server that answers each connection with "echo:" + what it received.
fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
                let _ = s.write_all(b"echo:");
                let _ = s.write_all(&buf);
            });
        }
    });
    port
}

#[test]
fn local_port_forwarding() {
    let s = Server::start();
    let c = Client::paired(&s);
    let target = echo_server();
    for t in ["quic", "tcp"] {
        let local = free_port();
        let spec = format!("{local}:127.0.0.1:{target}");
        let mut child = c
            .cmd(&["--transport", t, "-p", &s.port.to_string(), "-N", "-L", &spec, &dest()])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut sock = loop {
            if let Ok(sock) = std::net::TcpStream::connect(("127.0.0.1", local)) {
                break sock;
            }
            assert!(Instant::now() < deadline, "forward did not come up");
            sleep(Duration::from_millis(50));
        };
        // Write a lot without reading, half-close, then read a lot back: the
        // stream must keep flowing in both phases.
        let payload = pseudo_random(32 * 1024 * 1024);
        sock.write_all(&payload).unwrap();
        sock.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        sock.read_to_end(&mut reply).unwrap();
        assert_eq!(&reply[..5], b"echo:", "{t}");
        assert!(reply[5..] == payload[..], "{t}: payload mismatch ({} bytes)", reply.len());
        child.kill().unwrap();
        child.wait().unwrap();
    }
}

#[test]
fn unknown_key_is_denied() {
    let s = Server::start();
    let c = Client::new();
    let out = c.run(&["keygen"]);
    assert!(out.status.success());
    let out = c.run(&["--accept-new-host", "-p", &s.port.to_string(), &dest(), "true"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("access denied"), "{}", stderr(&out));
}

#[test]
fn wrong_pair_code_is_rejected_and_burned() {
    let s = Server::start();
    let c = Client::new();
    let code = s.pair_code();
    let port = s.port.to_string();
    let out = c.run(&["pair", "-p", &port, &dest(), "zzzz-zzzz"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("wrong pairing code"), "{}", stderr(&out));
    // The real code no longer works either: one guess per code.
    let out = c.run(&["pair", "-p", &port, &dest(), &code]);
    assert!(!out.status.success());
    assert!(!s.authorized_keys().exists() || std::fs::read_to_string(s.authorized_keys()).unwrap().is_empty());
}

#[test]
fn changed_host_key_is_refused() {
    let s = Server::start();
    let c = Client::paired(&s);
    // Point the client's known_hosts entry at a different key.
    let kh = c.home.path().join(".config/qsh/known_hosts");
    let other = qsh::keys::Identity::generate().public().to_openssh("");
    let line = std::fs::read_to_string(&kh).unwrap();
    let host = line.split_whitespace().next().unwrap();
    std::fs::write(&kh, format!("{host} {other}\n")).unwrap();
    let out = exec(&c, &s, "quic", "echo should-not-run");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("REMOTE HOST IDENTIFICATION HAS CHANGED"), "{}", stderr(&out));
    assert!(!stdout(&out).contains("should-not-run"));
}

#[test]
fn ssh_authorized_keys_are_honored() {
    let s = Server::start_with("127.0.0.1", "use_ssh_authorized_keys = true\n");
    let c = Client::new();
    assert!(c.run(&["keygen"]).status.success());
    let pubkey = std::fs::read_to_string(c.home.path().join(".config/qsh/id_ed25519.pub")).unwrap();
    let ssh_dir = s.home.path().join(".ssh");
    std::fs::create_dir(&ssh_dir).unwrap();
    // Lines with options cannot be enforced and must not grant access.
    std::fs::write(ssh_dir.join("authorized_keys"), format!("from=\"10.9.9.9\" {pubkey}")).unwrap();
    let port = s.port.to_string();
    let out = c.run(&["--accept-new-host", "-p", &port, &dest(), "true"]);
    assert!(!out.status.success());
    std::fs::write(ssh_dir.join("authorized_keys"), &pubkey).unwrap();
    let out = c.run(&["--accept-new-host", "-p", &port, &dest(), "echo", "ok"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "ok\n");
}

#[test]
fn auto_falls_back_to_tcp() {
    let s = Server::start();
    let c = Client::paired(&s);
    // Swallow UDP: a proxy that accepts TCP connections on a fresh port and
    // relays them to the server, while nothing answers UDP on that port.
    let (udp_blackhole, relay) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        if let Ok(tcp) = TcpListener::bind(("127.0.0.1", udp.local_addr().unwrap().port())) {
            break (udp, tcp);
        }
    };
    let port = relay.local_addr().unwrap().port();
    let server_port = s.port;
    std::thread::spawn(move || {
        for client in relay.incoming().flatten() {
            let upstream = std::net::TcpStream::connect(("127.0.0.1", server_port)).unwrap();
            let (mut c_read, mut u_write) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
            std::thread::spawn(move || std::io::copy(&mut c_read, &mut u_write));
            let (mut c_write, mut u_read) = (client, upstream);
            std::thread::spawn(move || std::io::copy(&mut u_read, &mut c_write));
        }
    });
    // The relay uses another port, so the pinned host entry does not apply.
    let start = Instant::now();
    let out = c.run(&["-v", "--accept-new-host", "-p", &port.to_string(), &dest(), "echo", "via-fallback"]);
    drop(udp_blackhole);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "via-fallback\n");
    assert!(stderr(&out).contains("over tcp"), "{}", stderr(&out));
    assert!(start.elapsed() < Duration::from_secs(8));
}


#[test]
fn killed_client_stops_remote_command() {
    let s = Server::start();
    let c = Client::paired(&s);
    for t in ["quic", "tcp"] {
        let pidfile = s.home.path().join(format!("pid-{t}"));
        let script = format!("echo $$ > {}; exec sleep 30", pidfile.display());
        let mut child = c
            .cmd(&["--transport", t, "-p", &s.port.to_string(), &dest(), "/bin/sh", "-c", &format!("'{script}'")])
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let pid = loop {
            if let Ok(p) = std::fs::read_to_string(&pidfile) {
                if let Ok(p) = p.trim().parse::<i32>() {
                    break p;
                }
            }
            assert!(Instant::now() < deadline, "remote command did not start");
            sleep(Duration::from_millis(50));
        };
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(child.id() as i32), nix::sys::signal::Signal::SIGTERM).unwrap();
        child.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::path::Path::new(&format!("/proc/{pid}")).exists() {
            // A zombie briefly remains until the server reaps it.
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if stat.contains(") Z ") {
                break;
            }
            assert!(Instant::now() < deadline, "{t}: remote process survived the client");
            sleep(Duration::from_millis(50));
        }
    }
}
