//! End-to-end tests: a real `qshd` (unprivileged mode) and `qsh` processes,
//! each with its own temporary HOME, talking over loopback.
#![cfg(unix)]

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
        Self::start_listen(&format!("{listen_ip}:0"), config)
    }

    fn start_listen(listen: &str, config: &str) -> Server {
        Self::start_in(tempfile::tempdir().unwrap(), listen, config)
    }

    /// Starts in a prepared HOME (e.g. with a host key and certificate).
    fn start_in(home: TempDir, listen: &str, config: &str) -> Server {
        let dir = home.path().join(".config/qsh");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("qshd.toml"), config).unwrap();
        let mut child = Command::new(QSHD)
            .args(["serve", "--listen", listen])
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
        // No agent from the environment running the tests; tests that need one set it.
        c.args(args).env("HOME", self.home.path()).env_remove("SSH_AUTH_SOCK").stdin(Stdio::null());
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

#[test]
fn host_alias_from_config_files() {
    let s = Server::start();
    let c = Client::new();
    // A custom-named key, as referenced by IdentityFile, authorized through the
    // server's ~/.ssh/authorized_keys.
    let key = c.home.path().join(".ssh/work_key");
    assert!(c.run(&["keygen", key.to_str().unwrap()]).status.success());
    let ssh_dir = s.home.path().join(".ssh");
    std::fs::create_dir(&ssh_dir).unwrap();
    std::fs::copy(key.with_extension("pub"), ssh_dir.join("authorized_keys")).unwrap();
    // ~/.ssh/config supplies HostName/User/IdentityFile (its Port is the SSH
    // port and must be ignored); ~/.config/qsh/config supplies the qsh port.
    std::fs::write(
        c.home.path().join(".ssh/config"),
        format!("Host box\n  HostName 127.0.0.1\n  User {}\n  Port 22\n  IdentityFile ~/.ssh/work_key\n", user()),
    )
    .unwrap();
    std::fs::create_dir_all(c.home.path().join(".config/qsh")).unwrap();
    std::fs::write(c.home.path().join(".config/qsh/config"), format!("Host box\n  Port {}\n", s.port)).unwrap();

    let out = c.run(&["--accept-new-host", "box", "echo", "alias-ok"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "alias-ok\n");

    let local = c.home.path().join("note.txt");
    std::fs::write(&local, "via alias").unwrap();
    let out = c.run(&["cp", local.to_str().unwrap(), "box:note.txt"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::read_to_string(s.home.path().join("note.txt")).unwrap(), "via alias");
}

// ---------------------------------------------------------------------------
// `--full`: OpenSSH config compatibility and handover to ssh/scp.

/// A fake `ssh`/`scp` that records its arguments, put first in PATH.
fn fake_openssh(dir: &std::path::Path) -> (String, PathBuf) {
    let log = dir.join("openssh-args");
    for tool in ["ssh", "scp"] {
        let script = dir.join(tool);
        std::fs::write(&script, format!("#!/bin/sh\necho \"{tool} $*\" >> '{}'\nexit 7\n", log.display())).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}", dir.display(), std::env::var("PATH").unwrap_or_default());
    (path, log)
}

/// A UDP port with nothing listening (the kernel answers with ICMP unreachable).
fn closed_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Tests that probe or occupy qshd's standard port 4422 must not overlap.
static STANDARD_PORT: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn full_mode_uses_qshd_on_ssh_port_and_config() {
    let _port = STANDARD_PORT.lock().unwrap_or_else(|e| e.into_inner());
    // --full also looks on 4422; a qshd running there (e.g. this machine's own) would answer first.
    if UdpSocket::bind(("127.0.0.1", qsh::DEFAULT_PORT)).is_err() || TcpListener::bind(("127.0.0.1", qsh::DEFAULT_PORT)).is_err() {
        eprintln!("skipped: port {} is in use on this machine", qsh::DEFAULT_PORT);
        return;
    }
    // qshd on UDP only, as it would run on port 22 next to sshd.
    let s = Server::start_with("127.0.0.1", "tcp = false\n");
    let c = Client::paired(&s);
    let fwd_target = echo_server();
    let fwd_local = free_port();
    std::fs::create_dir_all(c.home.path().join(".ssh")).unwrap();
    std::fs::write(
        c.home.path().join(".ssh/config"),
        format!(
            "Host box\n  HostName 127.0.0.1\n  Port {}\n  User {}\n  LocalForward {fwd_local} 127.0.0.1:{fwd_target}\n",
            s.port,
            user()
        ),
    )
    .unwrap();
    // Without --full the ssh Port is ignored and nothing listens on 4422.
    let out = c.run(&["--accept-new-host", "--transport", "quic", "box", "true"]);
    assert!(!out.status.success());
    // With --full: Port and LocalForward come from ~/.ssh/config.
    let mut child = c
        .cmd(&["--full", "--accept-new-host", "box", "sleep", "5"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut sock = loop {
        if let Ok(sock) = std::net::TcpStream::connect(("127.0.0.1", fwd_local)) {
            break sock;
        }
        assert!(Instant::now() < deadline, "LocalForward from ~/.ssh/config did not come up");
        sleep(Duration::from_millis(50));
    };
    sock.write_all(b"cfg").unwrap();
    sock.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = String::new();
    sock.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "echo:cfg");
    child.kill().unwrap();
    child.wait().unwrap();
    let out = c.run(&["--full", "box", "echo", "via-qsh"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "via-qsh\n");
}

/// The common setup: qshd on its standard port 4422, sshd's port (22) in
/// ~/.ssh/config. `--full` must find qshd on 4422 instead of falling back to ssh.
#[test]
fn full_mode_finds_qshd_on_standard_port() {
    let _port = STANDARD_PORT.lock().unwrap_or_else(|e| e.into_inner());
    if UdpSocket::bind(("127.0.0.1", qsh::DEFAULT_PORT)).is_err() || TcpListener::bind(("127.0.0.1", qsh::DEFAULT_PORT)).is_err() {
        eprintln!("skipped: port {} is in use on this machine", qsh::DEFAULT_PORT);
        return;
    }
    let s = Server::start_listen(&format!("127.0.0.1:{}", qsh::DEFAULT_PORT), "");
    let c = Client::paired(&s);
    let bin = tempfile::tempdir().unwrap();
    let (path, log) = fake_openssh(bin.path());
    std::fs::create_dir_all(c.home.path().join(".ssh")).unwrap();
    // Port 22 here is sshd's; nothing qsh-related listens on UDP 22.
    std::fs::write(c.home.path().join(".ssh/config"), format!("Host std\n  HostName 127.0.0.1\n  Port 22\n  User {}\n", user())).unwrap();
    let out = c.cmd(&["--full", "-v", "std", "echo", "quic-on-4422"]).env("PATH", &path).output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "quic-on-4422\n");
    assert!(stderr(&out).contains("over quic"), "{}", stderr(&out));
    assert!(!log.exists(), "ssh was used instead of qshd");
}

#[test]
fn full_mode_hands_over_to_ssh_and_scp() {
    let c = Client::new();
    assert!(c.run(&["keygen"]).status.success());
    let bin = tempfile::tempdir().unwrap();
    let (path, log) = fake_openssh(bin.path());
    let port = closed_udp_port();
    std::fs::create_dir_all(c.home.path().join(".ssh")).unwrap();
    std::fs::write(
        c.home.path().join(".ssh/config"),
        format!("Host plain\n  HostName 127.0.0.1\n  Port {port}\nHost jumped\n  HostName 127.0.0.1\n  ProxyJump bastion\n"),
    )
    .unwrap();
    // Pin the qsh port too, so a qshd on 4422 from a parallel test is not found.
    std::fs::create_dir_all(c.home.path().join(".config/qsh")).unwrap();
    std::fs::write(c.home.path().join(".config/qsh/config"), format!("Host plain\n  Port {port}\n")).unwrap();
    let run = |args: &[&str]| c.cmd(args).env("PATH", &path).output().unwrap();

    // No qshd on the UDP port: closed ports are detected at once, not after a timeout.
    let start = Instant::now();
    let out = run(&["--full", "-t", "-L", "9000:db:5432", "plain", "uname", "-a"]);
    assert_eq!(out.status.code(), Some(7), "exit code of ssh is passed through");
    assert!(start.elapsed() < Duration::from_millis(900), "took {:?}", start.elapsed());
    // Hosts behind ProxyJump go straight to ssh.
    run(&["--full", "jumped", "id"]);
    // `cp` hands over to scp.
    run(&["--full", "-p", "2200", "cp", "local.txt", "plain:remote.txt"]);
    // The second attempt uses the "no qshd here" cache.
    run(&["--full", "plain", "true"]);
    let calls = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = calls.lines().collect();
    assert_eq!(lines[0], "ssh -t -L 9000:db:5432 -- plain uname -a");
    assert_eq!(lines[1], "ssh -- jumped id");
    assert_eq!(lines[2], "scp -P 2200 -- local.txt plain:remote.txt");
    assert_eq!(lines[3], "ssh -- plain true");
    assert!(c.home.path().join(".config/qsh/no-qshd").exists());
}

// ---------------------------------------------------------------------------
// Regression tests derived from OpenSSH vulnerabilities (see docs/openssh-cve-review.md).

/// CVE-2006-0225, CVE-2020-15778: scp passed paths through a shell.
#[test]
fn cve_cp_paths_are_not_shell_evaluated() {
    let s = Server::start();
    let c = Client::paired(&s);
    let port = s.port.to_string();
    let local = c.home.path().join("f.txt");
    std::fs::write(&local, "x").unwrap();
    let evil = "a$(touch PWNED1)`touch PWNED2`;touch PWNED3";
    let out = c.run(&["cp", "-p", &port, local.to_str().unwrap(), &format!("{}:{evil}", dest())]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(s.home.path().join(evil).exists(), "file is stored under the literal name");
    let out = c.run(&["cp", "-p", &port, &format!("{}:$(touch PWNED4)", dest()), c.home.path().to_str().unwrap()]);
    assert!(!out.status.success());
    for n in 1..=4 {
        let name = format!("PWNED{n}");
        assert!(!s.home.path().join(&name).exists() && !c.home.path().join(&name).exists(), "{name} was created");
    }
}

/// OpenSSH 10.3: scp kept setuid/setgid bits on downloaded files.
#[test]
fn cve_download_strips_setuid_bits() {
    use std::os::unix::fs::PermissionsExt;
    let s = Server::start();
    let c = Client::paired(&s);
    let remote = s.home.path().join("suid");
    std::fs::write(&remote, "x").unwrap();
    std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o6755)).unwrap();
    let local = c.home.path().join("suid");
    let out = c.run(&["cp", "-p", &s.port.to_string(), &format!("{}:suid", dest()), local.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::metadata(&local).unwrap().permissions().mode() & 0o7000, 0);
}

/// OpenSSH 10.4/10.6: a download could land outside the intended directory.
#[test]
fn cve_download_target_stays_in_destination() {
    let s = Server::start();
    let c = Client::paired(&s);
    std::fs::create_dir(s.home.path().join("dir")).unwrap();
    let into = c.home.path().join("into");
    std::fs::create_dir(&into).unwrap();
    for remote in ["dir/..", ".", "dir/."] {
        let out = c.run(&["cp", "-p", &s.port.to_string(), &format!("{}:{remote}", dest()), into.to_str().unwrap()]);
        assert!(!out.status.success(), "{remote} was accepted");
    }
    assert_eq!(std::fs::read_dir(&into).unwrap().count(), 0);
}

/// OpenSSH 10.0: DisableForwarding did not disable everything it should.
#[test]
fn cve_forwarding_can_be_disabled() {
    let s = Server::start_with("127.0.0.1", "allow_tcp_forwarding = false\n");
    let c = Client::paired(&s);
    let target = echo_server();
    let local = free_port();
    let spec = format!("{local}:127.0.0.1:{target}");
    let mut child = c.cmd(&["-p", &s.port.to_string(), "-N", "-L", &spec, &dest()]).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut sock = loop {
        if let Ok(sock) = std::net::TcpStream::connect(("127.0.0.1", local)) {
            break sock;
        }
        assert!(Instant::now() < deadline, "listener did not come up");
        sleep(Duration::from_millis(50));
    };
    let _ = sock.write_all(b"ping");
    let _ = sock.shutdown(std::net::Shutdown::Write);
    let mut reply = Vec::new();
    let _ = sock.read_to_end(&mut reply);
    assert!(reply.is_empty(), "data was forwarded although forwarding is disabled");
    child.kill().unwrap();
    child.wait().unwrap();
}

/// CVE-2025-26465 class: an error while checking the host key must not skip the check.
#[test]
fn cve_host_key_errors_fail_closed() {
    use std::os::unix::fs::PermissionsExt;
    let s = Server::start();
    let c = Client::paired(&s);
    let kh = c.home.path().join(".config/qsh/known_hosts");
    std::fs::set_permissions(&kh, std::fs::Permissions::from_mode(0o000)).unwrap();
    let out = c.run(&["--accept-new-host", "-p", &s.port.to_string(), &dest(), "echo", "ran"]);
    std::fs::set_permissions(&kh, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!out.status.success());
    assert!(!stdout(&out).contains("ran"));
}

/// CVE-2018-15473, CVE-2016-6210: user enumeration through different answers or timing.
#[test]
fn cve_no_user_enumeration() {
    let s = Server::start();
    let c = Client::new();
    assert!(c.run(&["keygen"]).status.success());
    let port = s.port.to_string();
    let attempt = |who: &str| {
        let start = Instant::now();
        let out = c.run(&["--accept-new-host", "--transport", "tcp", "-p", &port, &format!("{who}@127.0.0.1"), "true"]);
        (start.elapsed(), stderr(&out))
    };
    let (mut known, mut unknown) = (Vec::new(), Vec::new());
    for _ in 0..15 {
        let (t, e) = attempt(&user());
        known.push((t, e));
        let (t, e) = attempt("qsh-no-such-user");
        unknown.push((t, e));
    }
    // The server's answer is the same; only the echoed user name in the local hint differs.
    let msg = |e: &str| {
        let line = e.lines().find(|l| l.starts_with("qsh:")).unwrap_or("").to_string();
        line.split(" for ").next().unwrap_or("").to_string()
    };
    assert!(msg(&known[0].1).contains("access denied"), "{}", known[0].1);
    assert_eq!(msg(&known[0].1), msg(&unknown[0].1));
    let median = |v: &mut Vec<(Duration, String)>| {
        v.sort_by_key(|x| x.0);
        v[v.len() / 2].0
    };
    let (k, u) = (median(&mut known), median(&mut unknown));
    eprintln!("median time: existing user {k:?}, unknown user {u:?}");
    let diff = k.abs_diff(u);
    assert!(diff < Duration::from_millis(15), "timing differs by {diff:?}");
}

/// CVE-2025-26466 class: unauthenticated connections from one address must not lock out others.
#[test]
fn cve_preauth_flood_is_contained() {
    let s = Server::start();
    let c = Client::paired(&s);
    let port = s.port;
    let rt = tokio::runtime::Runtime::new().unwrap();
    // 60 TCP connections from 127.0.0.2 that never start TLS. (macOS only
    // has 127.0.0.1 on loopback unless an alias is added.)
    if std::net::TcpListener::bind("127.0.0.2:0").is_err() {
        return eprintln!("skipped: 127.0.0.2 is not available");
    }
    let flood: Vec<tokio::net::TcpStream> = rt.block_on(async {
        let mut v = Vec::new();
        for _ in 0..60 {
            let sock = tokio::net::TcpSocket::new_v4().unwrap();
            sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
            if let Ok(conn) = sock.connect(([127, 0, 0, 1], port).into()).await {
                v.push(conn);
            }
        }
        v
    });
    assert!(flood.len() >= 50, "flood connections were not established");
    sleep(Duration::from_millis(300));
    // A real user from another address still gets in, over both transports.
    for t in ["quic", "tcp"] {
        let out = exec(&c, &s, t, "echo still-ok");
        assert!(out.status.success(), "{t}: {}", stderr(&out));
        assert_eq!(stdout(&out), "still-ok\n");
    }
    drop(flood);
}

/// Typing into a real terminal with keystroke timing obfuscation (on by
/// default): every character arrives, in order, and chaff never leaks into
/// the session.
#[test]
fn interactive_typing_with_keystroke_obfuscation() {
    let s = Server::start();
    let c = Client::paired(&s);
    let pty = nix::pty::openpty(None, None).unwrap();
    let slave = || Stdio::from(std::fs::File::from(pty.slave.try_clone().unwrap()));
    let mut child = Command::new(QSH)
        .args(["-t", "-p", &s.port.to_string(), &dest(), "cat"])
        .env("HOME", c.home.path())
        .env("TERM", "xterm")
        .stdin(slave())
        .stdout(slave())
        .stderr(slave())
        .spawn()
        .unwrap();
    let mut master = std::fs::File::from(pty.master);
    nix::fcntl::fcntl(&master, nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK)).unwrap();
    sleep(Duration::from_millis(800));
    let typed = "hello-qsh";
    for ch in typed.bytes() {
        master.write_all(&[ch]).unwrap();
        sleep(Duration::from_millis(30));
    }
    // Wait through the chaff tail, collecting the echo.
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        let mut buf = [0u8; 4096];
        match master.read(&mut buf) {
            Ok(n) if n > 0 => out.extend_from_slice(&buf[..n]),
            _ => sleep(Duration::from_millis(20)),
        }
    }
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains(typed), "echo was {text:?}");
    assert!(!text.contains('\0'), "chaff leaked into the terminal: {text:?}");
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn speed_test_command() {
    let s = Server::start();
    let c = Client::paired(&s);
    for t in ["quic", "tcp"] {
        let out = c.run(&["speed", "--transport", t, "--seconds", "1", "-p", &s.port.to_string(), &dest()]);
        assert!(out.status.success(), "{t}: {}", stderr(&out));
        let text = stdout(&out);
        for label in ["ping", "download", "upload", "Mbit/s"] {
            assert!(text.contains(label), "{t}: {text}");
        }
    }
}

/// `qsh ui` in a real terminal: lists the configured host, finds qshd on it, quits on `q`.
#[test]
fn ui_lists_hosts_and_quits() {
    let s = Server::start();
    let c = Client::paired(&s);
    std::fs::write(
        c.home.path().join(".config/qsh/config"),
        format!("Host box\n  HostName 127.0.0.1\n  Port {}\n  User {}\n", s.port, user()),
    )
    .unwrap();
    let pty = nix::pty::openpty(Some(&nix::pty::Winsize { ws_row: 30, ws_col: 100, ws_xpixel: 0, ws_ypixel: 0 }), None).unwrap();
    let slave = || Stdio::from(std::fs::File::from(pty.slave.try_clone().unwrap()));
    let mut child = Command::new(QSH)
        .arg("ui")
        .env("HOME", c.home.path())
        .env("TERM", "xterm-256color")
        .stdin(slave())
        .stdout(slave())
        .stderr(slave())
        .spawn()
        .unwrap();
    let mut master = std::fs::File::from(pty.master);
    nix::fcntl::fcntl(&master, nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK)).unwrap();
    let mut screen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let mut buf = [0u8; 65536];
        match master.read(&mut buf) {
            Ok(n) if n > 0 => screen.extend_from_slice(&buf[..n]),
            _ => sleep(Duration::from_millis(50)),
        }
        let text = String::from_utf8_lossy(&screen);
        if text.contains("box") && text.contains("quic") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&screen).into_owned();
    assert!(text.contains("box"), "host missing from the menu");
    assert!(text.contains("quic"), "qshd was not detected over QUIC");
    master.write_all(b"q").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "ui did not quit on q");
        let _ = master.read(&mut [0u8; 65536]);
        sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// v0.4: OpenSSH tools on top of qsh, forwarding, jump hosts, escapes, -f.

fn tree(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("sub/deep")).unwrap();
    std::fs::write(root.join("a.txt"), "alpha").unwrap();
    std::fs::write(root.join("sub/b.bin"), pseudo_random(300_000)).unwrap();
    std::fs::write(root.join("sub/deep/c"), "").unwrap();
}

fn same_tree(a: &std::path::Path, b: &std::path::Path) {
    for rel in ["a.txt", "sub/b.bin", "sub/deep/c"] {
        assert_eq!(std::fs::read(a.join(rel)).unwrap(), std::fs::read(b.join(rel)).unwrap(), "{rel}");
    }
}

#[test]
fn cp_recursive_roundtrip() {
    let s = Server::start();
    let c = Client::paired(&s);
    let src = c.home.path().join("proj");
    tree(&src);
    let port = s.port.to_string();
    for t in ["quic", "tcp"] {
        let out = c.run(&["cp", "-r", "--transport", t, "-p", &port, src.to_str().unwrap(), &format!("{}:up-{t}", dest())]);
        assert!(out.status.success(), "{t}: {}", stderr(&out));
        same_tree(&src, &s.home.path().join(format!("up-{t}")));
        let back = c.home.path().join(format!("back-{t}"));
        std::fs::create_dir(&back).unwrap();
        let out = c.run(&["cp", "-r", "--transport", t, "-p", &port, &format!("{}:up-{t}", dest()), back.to_str().unwrap()]);
        assert!(out.status.success(), "{t}: {}", stderr(&out));
        same_tree(&src, &back.join(format!("up-{t}")));
    }
}

#[test]
fn cp_recursive_edge_cases() {
    use std::os::unix::fs::PermissionsExt;
    let s = Server::start();
    let c = Client::paired(&s);
    let port = s.port.to_string();
    // Names that look like options stay names.
    let src = c.home.path().join("-data");
    tree(&src);
    let out = c.run(&["cp", "-r", "-p", &port, src.to_str().unwrap(), &format!("{}:-backup", dest())]);
    assert!(out.status.success(), "{}", stderr(&out));
    same_tree(&src, &s.home.path().join("-backup"));
    // A remote path without a name (`host:`) copies its contents into the target.
    let whole = c.home.path().join("whole");
    let out = c.run(&["cp", "-r", "-p", &port, &format!("{}:", dest()), whole.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    same_tree(&src, &whole.join("-backup"));
    // A file the server cannot read makes the copy fail instead of silently ending early.
    if !nix_is_root() {
        let bad = s.home.path().join("bad");
        tree(&bad);
        std::fs::set_permissions(bad.join("a.txt"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let out = c.run(&["cp", "-r", "-p", &port, &format!("{}:bad", dest()), c.home.path().to_str().unwrap()]);
        assert!(!out.status.success(), "copy of an unreadable tree succeeded");
        assert!(stderr(&out).contains("copy incomplete"), "{}", stderr(&out));
    }
}

fn nix_is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// ProxyCommand cannot be followed by qsh itself: never connect around it.
#[test]
fn proxy_command_is_not_bypassed() {
    let s = Server::start();
    let c = Client::paired(&s);
    let out = c.run(&["-p", &s.port.to_string(), "-o", "ProxyCommand=nc %h %p", &dest(), "true"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("ProxyCommand"), "{}", stderr(&out));
}

/// sftp, scp (SFTP mode), rsync and git, all with qsh as their transport.
#[test]
fn openssh_tools_over_qsh() {
    let s = Server::start();
    let c = Client::paired(&s);
    let port = s.port.to_string();
    let env = |cmd: &mut Command| {
        cmd.env("HOME", c.home.path()).stdin(Stdio::null());
    };
    let have = |tool: &str| Command::new(tool).arg("-V").output().is_ok() || Command::new(tool).arg("--version").output().is_ok();

    if have("sftp") {
        let local = c.home.path().join("f.txt");
        std::fs::write(&local, "via sftp").unwrap();
        let batch = c.home.path().join("batch");
        std::fs::write(&batch, format!("put {} sftp.txt\nget sftp.txt {}\nls\n", local.display(), c.home.path().join("got.txt").display())).unwrap();
        let mut cmd = Command::new("sftp");
        cmd.args(["-S", QSH, "-P", &port, "-b", batch.to_str().unwrap(), &dest()]);
        env(&mut cmd);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "sftp: {}", stderr(&out));
        assert_eq!(std::fs::read_to_string(s.home.path().join("sftp.txt")).unwrap(), "via sftp");
        assert_eq!(std::fs::read_to_string(c.home.path().join("got.txt")).unwrap(), "via sftp");
    }
    if have("scp") {
        let src = c.home.path().join("scp-tree");
        tree(&src);
        let mut cmd = Command::new("scp");
        cmd.args(["-S", QSH, "-P", &port, "-r", src.to_str().unwrap(), &format!("{}:scp-tree", dest())]);
        env(&mut cmd);
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "scp: {}", stderr(&out));
        same_tree(&src, &s.home.path().join("scp-tree"));
    }
    if have("rsync") {
        let src = c.home.path().join("rsync-src");
        tree(&src);
        let mut cmd = Command::new("rsync");
        cmd.args(["-a", "-e", &format!("{QSH} -p {port}"), &format!("{}/", src.display()), &format!("{}:rsync-dst/", dest())]);
        env(&mut cmd);
        let out = cmd.output().unwrap();
        let version = Command::new("rsync").arg("--version").output().map(|o| stdout(&o)).unwrap_or_default();
        let remote = Command::new("/usr/bin/rsync").arg("--version").output().map(|o| stdout(&o)).unwrap_or_default();
        assert!(
            out.status.success(),
            "rsync: {}\nlocal: {}\n/usr/bin/rsync: {}",
            stderr(&out),
            version.lines().next().unwrap_or_default(),
            remote.lines().next().unwrap_or_default()
        );
        same_tree(&src, &s.home.path().join("rsync-dst"));
    }
    if have("git") {
        let git = |args: &[&str], dir: &std::path::Path| {
            let mut cmd = Command::new("git");
            cmd.args(args).current_dir(dir).env("GIT_SSH_COMMAND", format!("{QSH} -p {port}"));
            env(&mut cmd);
            let out = cmd.output().unwrap();
            assert!(out.status.success(), "git {args:?}: {}", stderr(&out));
        };
        let remote = s.home.path().join("repo.git");
        git(&["init", "-q", "--bare", remote.to_str().unwrap()], c.home.path());
        let work = c.home.path().join("work");
        std::fs::create_dir(&work).unwrap();
        git(&["init", "-q", "-b", "main"], &work);
        git(&["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "hi"], &work);
        git(&["push", "-q", &format!("{}:{}", dest(), remote.display()), "main"], &work);
        git(&["clone", "-q", &format!("{}:{}", dest(), remote.display()), "cloned"], c.home.path());
        assert!(c.home.path().join("cloned/.git").exists());
    }
}

#[test]
fn remote_forward_dynamic_socks_and_stdio() {
    let s = Server::start();
    let c = Client::paired(&s);
    let target = echo_server();
    let port = s.port.to_string();

    // -W: stdin/stdout to host:port through the server.
    let mut child = c
        .cmd(&["-p", &port, "-W", &format!("127.0.0.1:{target}"), &dest()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"stdio").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(stdout(&out), "echo:stdio");

    // -R: the server listens, connections come back to the client side.
    let remote_port = free_port();
    let socks_port = free_port();
    let mut child = c
        .cmd(&["-p", &port, "-N", "-R", &format!("{remote_port}:127.0.0.1:{target}"), "-D", &socks_port.to_string(), &dest()])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let connect = |p: u16| {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(s) = std::net::TcpStream::connect(("127.0.0.1", p)) {
                return s;
            }
            assert!(Instant::now() < deadline, "port {p} did not come up");
            sleep(Duration::from_millis(50));
        }
    };
    let mut sock = connect(remote_port);
    sock.write_all(b"reverse").unwrap();
    sock.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = String::new();
    sock.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "echo:reverse");

    // -D: SOCKS5 CONNECT through the server.
    let mut sock = connect(socks_port);
    sock.write_all(&[5, 1, 0]).unwrap();
    let mut buf = [0u8; 2];
    sock.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [5, 0]);
    let [hi, lo] = target.to_be_bytes();
    sock.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, hi, lo]).unwrap();
    let mut rep = [0u8; 10];
    sock.read_exact(&mut rep).unwrap();
    assert_eq!(rep[1], 0, "SOCKS request failed");
    sock.write_all(b"socks").unwrap();
    sock.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = String::new();
    sock.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "echo:socks");
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn jump_host() {
    let bastion = Server::start();
    let inner = Server::start();
    let c = Client::paired(&bastion);
    let code = inner.pair_code();
    let out = c.run(&["pair", "-p", &inner.port.to_string(), &dest(), &code]);
    assert!(out.status.success(), "{}", stderr(&out));
    let jump = format!("{}:{}", dest(), bastion.port);
    let out = c.run(&["-v", "-J", &jump, "-p", &inner.port.to_string(), &dest(), "echo", "through-the-bastion"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "through-the-bastion\n");
    assert!(stderr(&out).contains("through a jump host"), "{}", stderr(&out));
}

#[test]
fn escape_sequence_disconnects() {
    let s = Server::start();
    let c = Client::paired(&s);
    let pty = nix::pty::openpty(None, None).unwrap();
    let slave = || Stdio::from(std::fs::File::from(pty.slave.try_clone().unwrap()));
    let mut child = Command::new(QSH)
        .args(["-t", "-p", &s.port.to_string(), &dest(), "sleep", "60"])
        .env("HOME", c.home.path())
        .stdin(slave())
        .stdout(slave())
        .stderr(slave())
        .spawn()
        .unwrap();
    let mut master = std::fs::File::from(pty.master);
    sleep(Duration::from_millis(800));
    master.write_all(b"\r~.").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(Instant::now() < deadline, "~. did not end the session");
        sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(255));
}

#[test]
fn background_after_login() {
    let s = Server::start();
    let c = Client::paired(&s);
    let target = echo_server();
    let local = free_port();
    let start = Instant::now();
    // Like ssh -f, the background process keeps stdout/stderr, so do not capture them.
    let status = c
        .cmd(&["--transport", "tcp", "-f", "-N", "-L", &format!("{local}:127.0.0.1:{target}"), "-p", &s.port.to_string(), &dest()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(start.elapsed() < Duration::from_secs(5), "-f did not return");
    // The forward keeps working from the background process.
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", local)).unwrap();
    sock.write_all(b"bg").unwrap();
    sock.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = String::new();
    sock.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "echo:bg");
    // Without a command or -N, -f is refused like in ssh.
    let out = c.run(&["-f", "-p", &s.port.to_string(), &dest()]);
    assert!(!out.status.success());
}

/// Installed as `ssh`: OpenSSH semantics, and the fallback finds the real ssh, not itself.
#[test]
fn installed_as_ssh() {
    let s = Server::start();
    let c = Client::paired(&s);
    let bin = tempfile::tempdir().unwrap();
    let ssh = bin.path().join("ssh");
    std::os::unix::fs::symlink(QSH, &ssh).unwrap();
    let fake = tempfile::tempdir().unwrap();
    let (path, log) = fake_openssh(fake.path());
    let path = format!("{}:{path}", bin.path().display());
    let run = |args: &[&str]| Command::new(&ssh).args(args).env("HOME", c.home.path()).env("PATH", &path).stdin(Stdio::null()).output().unwrap();
    // An explicit port: qshd answers there, so it is a qsh session.
    let out = run(&["-p", &s.port.to_string(), &dest(), "echo", "qsh-as-ssh"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "qsh-as-ssh\n");
    // `cp` is a host name for ssh, not a tool.
    let closed = closed_udp_port().to_string();
    let out = run(&["-p", &closed, "cp", "echo", "x"]);
    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));
    let calls = std::fs::read_to_string(&log).unwrap();
    assert_eq!(calls.trim(), format!("ssh -p {closed} -- cp echo x"));
    // -G works (git uses it to detect an OpenSSH-compatible client).
    let out = run(&["-G", "-p", "2222", "somehost"]);
    assert!(stdout(&out).contains("port 2222"), "{}", stdout(&out));
}

// ---------------------------------------------------------------------------
// v0.5: keys of any type, ssh-agent, authorized_keys options, certificates.

fn have(tool: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {tool}")]).output().is_ok_and(|o| o.status.success())
}

/// `ssh-keygen -t <kind>` without a passphrase; returns the private key path.
fn keygen(dir: &std::path::Path, name: &str, kind: &str) -> PathBuf {
    let path = dir.join(name);
    let out = Command::new("ssh-keygen").args(["-q", "-t", kind, "-N", "", "-C", name, "-f"]).arg(&path).output().unwrap();
    assert!(out.status.success(), "ssh-keygen: {}", stderr(&out));
    path
}

fn public(path: &std::path::Path) -> String {
    std::fs::read_to_string(format!("{}.pub", path.display())).unwrap().trim().to_string()
}

/// A server whose ~/.ssh/authorized_keys holds `lines`, and a client with known host key.
fn server_with_keys(config: &str, lines: &[String]) -> (Server, Client) {
    let s = Server::start_with("127.0.0.1", config);
    let ssh = s.home.path().join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("authorized_keys"), lines.join("\n") + "\n").unwrap();
    (s, Client::new())
}

struct AgentProc {
    child: Child,
    sock: PathBuf,
    _dir: TempDir,
}

impl Drop for AgentProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_agent() -> AgentProc {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("agent.sock");
    let child = Command::new("ssh-agent").args(["-D", "-a"]).arg(&sock).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "ssh-agent did not start");
        sleep(Duration::from_millis(20));
    }
    AgentProc { child, sock, _dir: dir }
}

#[test]
fn rsa_and_ecdsa_keys_from_files() {
    if !have("ssh-keygen") {
        return eprintln!("skipped: no ssh-keygen");
    }
    let keys = tempfile::tempdir().unwrap();
    let rsa = keygen(keys.path(), "rsa", "rsa");
    let ecdsa = keygen(keys.path(), "ecdsa", "ecdsa");
    let small = {
        let path = keys.path().join("small");
        let out = Command::new("ssh-keygen").args(["-q", "-t", "rsa", "-b", "1024", "-N", "", "-f"]).arg(&path).output().unwrap();
        out.status.success().then_some(path)
    };
    let mut lines = vec![public(&rsa), public(&ecdsa)];
    lines.extend(small.iter().map(|p| public(p)));
    let (s, c) = server_with_keys("", &lines);
    let port = s.port.to_string();
    for key in [&rsa, &ecdsa] {
        let out = c.run(&["--accept-new-host", "-p", &port, "-i", key.to_str().unwrap(), &dest(), "echo", "in"]);
        assert!(out.status.success(), "{}: {}", key.display(), stderr(&out));
        assert_eq!(stdout(&out), "in\n");
    }
    if let Some(small) = small {
        let out = c.run(&["--accept-new-host", "-p", &port, "-i", small.to_str().unwrap(), &dest(), "true"]);
        assert!(!out.status.success(), "a 1024-bit RSA key was accepted");
    }
    // An unknown key is still refused.
    let other = keygen(keys.path(), "other", "ecdsa");
    let out = c.run(&["--accept-new-host", "-p", &port, "-i", other.to_str().unwrap(), &dest(), "true"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("access denied"), "{}", stderr(&out));
}

#[test]
fn keys_from_ssh_agent() {
    if !have("ssh-agent") || !have("ssh-add") {
        return eprintln!("skipped: no ssh-agent");
    }
    let keys = tempfile::tempdir().unwrap();
    let ecdsa = keygen(keys.path(), "agent_ecdsa", "ecdsa");
    let rsa = keygen(keys.path(), "agent_rsa", "rsa");
    let (s, c) = server_with_keys("", &[public(&rsa)]);
    let agent = start_agent();
    for key in [&ecdsa, &rsa] {
        let out = Command::new("ssh-add").arg(key).env("SSH_AUTH_SOCK", &agent.sock).output().unwrap();
        assert!(out.status.success(), "ssh-add: {}", stderr(&out));
    }
    // The key files are elsewhere: only the agent can sign.
    std::fs::remove_file(&rsa).unwrap();
    let run = |extra: &[&str]| {
        let mut args = vec!["--accept-new-host", "-p"];
        let port = s.port.to_string();
        args.push(&port);
        args.extend_from_slice(extra);
        let d = dest();
        args.extend_from_slice(&[&d, "echo", "agent"]);
        c.cmd(&args).env("SSH_AUTH_SOCK", &agent.sock).output().unwrap()
    };
    let out = run(&[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "agent\n");
    // IdentityAgent none: no agent, no key.
    let out = run(&["-o", "IdentityAgent=none"]);
    assert!(!out.status.success());
}

#[test]
fn authorized_keys_options_are_enforced() {
    if !have("ssh-keygen") {
        return eprintln!("skipped: no ssh-keygen");
    }
    let keys = tempfile::tempdir().unwrap();
    let forced = keygen(keys.path(), "forced", "ed25519");
    let limited = keygen(keys.path(), "limited", "ecdsa");
    let elsewhere = keygen(keys.path(), "elsewhere", "ecdsa");
    let target = echo_server();
    let lines = vec![
        format!(r#"command="echo forced:$SSH_ORIGINAL_COMMAND" {}"#, public(&forced)),
        format!(r#"no-pty,permitopen="127.0.0.1:{target}" {}"#, public(&limited)),
        format!(r#"from="203.0.113.0/24" {}"#, public(&elsewhere)),
        format!("unknown-option {}", public(&elsewhere)),
    ];
    let (s, c) = server_with_keys("", &lines);
    let port = s.port.to_string();
    let q = |key: &PathBuf, args: &[&str]| {
        let mut all = vec!["--accept-new-host", "-p", &port, "-i", key.to_str().unwrap()];
        all.extend_from_slice(args);
        c.run(&all)
    };
    // command=: whatever is asked, the forced command runs and sees the original.
    let out = q(&forced, &[&dest(), "id"]);
    assert_eq!(stdout(&out), "forced:id\n", "{}", stderr(&out));
    let f = keys.path().join("f.txt");
    std::fs::write(&f, "x").unwrap();
    let out = q(&forced, &["cp", f.to_str().unwrap(), &format!("{}:f.txt", dest())]);
    assert!(!out.status.success() && !s.home.path().join("f.txt").exists(), "cp despite command=");
    // no-pty: the session runs without a terminal.
    let out = q(&limited, &["-tt", &dest(), "sh", "-c", "'[ -t 0 ] && echo tty || echo no-tty'"]);
    assert_eq!(stdout(&out).trim(), "no-tty", "{}", stderr(&out));
    // permitopen: only the listed destination.
    let ok = q(&limited, &["-W", &format!("127.0.0.1:{target}"), &dest()]);
    assert!(ok.status.success(), "{}", stderr(&ok));
    let other = echo_server();
    let denied = q(&limited, &["-W", &format!("127.0.0.1:{other}"), &dest()]);
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("not permitted"), "{}", stderr(&denied));
    // from=: the key does not work from this address (and the bad line is ignored).
    let out = q(&elsewhere, &[&dest(), "true"]);
    assert!(!out.status.success());
}

#[test]
fn user_certificates() {
    if !have("ssh-keygen") {
        return eprintln!("skipped: no ssh-keygen");
    }
    let keys = tempfile::tempdir().unwrap();
    let ca = keygen(keys.path(), "ca", "ed25519");
    let sign = |key: &PathBuf, extra: &[&str]| {
        let out = Command::new("ssh-keygen")
            .args(["-q", "-s", ca.to_str().unwrap(), "-I", "test-cert", "-V", "-5m:+1h"])
            .args(extra)
            .arg(format!("{}.pub", key.display()))
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen -s: {}", stderr(&out));
    };
    // An Ed25519 key (used for TLS) and an ECDSA key, both with certificates.
    let ed = keygen(keys.path(), "ed", "ed25519");
    sign(&ed, &["-n", &user()]);
    let ec = keygen(keys.path(), "ec", "ecdsa");
    sign(&ec, &["-n", &user(), "-O", "force-command=echo from-cert"]);
    let wrong = keygen(keys.path(), "wrong", "ecdsa");
    sign(&wrong, &["-n", "somebody-else"]);

    // Trusted by the server for everyone.
    let ca_file = keys.path().join("user_ca.pub");
    std::fs::copy(format!("{}.pub", ca.display()), &ca_file).unwrap();
    let (s, c) = server_with_keys(&format!("trusted_user_ca_keys = \"{}\"\n", ca_file.display()), &[]);
    let port = s.port.to_string();
    let q = |key: &PathBuf, cmd: &str| c.run(&["--accept-new-host", "-p", &port, "-i", key.to_str().unwrap(), &dest(), cmd]);
    let out = q(&ed, "echo cert");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "cert\n");
    let out = q(&ec, "id");
    assert_eq!(stdout(&out), "from-cert\n", "force-command: {}", stderr(&out));
    assert!(!q(&wrong, "true").status.success(), "certificate for another principal accepted");

    // Trusted by the user through a cert-authority line.
    let (s, c) = server_with_keys("", &[format!("cert-authority,principals=\"somebody-else\" {}", public(&ca))]);
    let out = c.run(&["--accept-new-host", "-p", &s.port.to_string(), "-i", wrong.to_str().unwrap(), &dest(), "echo", "ca-line"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "ca-line\n");
    let out = c.run(&["--accept-new-host", "-p", &s.port.to_string(), "-i", ed.to_str().unwrap(), &dest(), "true"]);
    assert!(!out.status.success(), "principal outside principals= accepted");
}

#[test]
fn agent_forwarding() {
    if !have("ssh-agent") || !have("ssh-add") {
        return eprintln!("skipped: no ssh-agent");
    }
    let keys = tempfile::tempdir().unwrap();
    let key = keygen(keys.path(), "fwd", "ecdsa");
    let restricted = keygen(keys.path(), "restricted", "ed25519");
    let (s, c) = server_with_keys("", &[public(&key), format!("no-agent-forwarding {}", public(&restricted))]);
    let agent = start_agent();
    let out = Command::new("ssh-add").arg(&key).env("SSH_AUTH_SOCK", &agent.sock).output().unwrap();
    assert!(out.status.success(), "ssh-add: {}", stderr(&out));
    let port = s.port.to_string();
    let run = |args: &[&str]| {
        let mut all = vec!["--accept-new-host", "-p", &port];
        all.extend_from_slice(args);
        c.cmd(&all).env("SSH_AUTH_SOCK", &agent.sock).output().unwrap()
    };
    // With -A the remote side sees our agent's key; the socket is private to the user.
    let out = run(&["-A", &dest(), "sh -c 'ssh-add -l; ls -l $SSH_AUTH_SOCK'"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("fwd (ECDSA)"), "{text}");
    assert!(text.lines().last().unwrap_or_default().starts_with("srw------- "), "{text}");
    // Without -A there is no agent over there.
    let show = "sh -c 'echo [$SSH_AUTH_SOCK]'";
    let out = run(&[&dest(), show]);
    assert_eq!(stdout(&out), "[]\n");
    // no-agent-forwarding: refused with a warning, the session still runs.
    let out = run(&["-A", "-i", restricted.to_str().unwrap(), "-o", "IdentitiesOnly=yes", &dest(), show]);
    assert_eq!(stdout(&out), "[]\n", "{}", stderr(&out));
    assert!(stderr(&out).contains("agent forwarding refused"), "{}", stderr(&out));
}

/// An askpass program that answers with the lines of `answers`, one per call.
fn askpass_script(dir: &std::path::Path, answers: &[String]) -> PathBuf {
    let list = dir.join("answers");
    std::fs::write(&list, answers.join("\n") + "\n").unwrap();
    let _ = std::fs::remove_file(dir.join("count"));
    let script = dir.join("askpass.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nn=$(( $(cat '{1}' 2>/dev/null || echo 0) + 1 ))\necho $n > '{1}'\nsed -n \"${{n}}p\" '{0}'\necho \"$1\" >> '{2}'\n",
            list.display(),
            dir.join("count").display(),
            dir.join("asked").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    script
}

#[test]
fn one_time_codes() {
    use qsh::totp;
    let s = Server::start();
    let c = Client::paired(&s);
    let secret = b"0123456789abcdefghij";
    let path = totp::secret_path(s.home.path());
    std::fs::write(&path, totp::base32_encode(secret)).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let step = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / totp::STEP;
    let code = |s: u64| format!("{:06}", totp::code(secret, s));
    let dir = tempfile::tempdir().unwrap();
    let port = s.port.to_string();
    let login = |answers: &[String]| {
        let script = askpass_script(dir.path(), answers);
        c.cmd(&["-p", &port, &dest(), "echo", "in"]).env("SSH_ASKPASS", &script).env("SSH_ASKPASS_REQUIRE", "force").output().unwrap()
    };
    // A wrong code, then the right one.
    let now = step();
    let out = login(&["000000".to_string(), code(now)]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "in\n");
    assert!(std::fs::read_to_string(dir.path().join("asked")).unwrap().contains("One-time code"));
    // The same code cannot be used again.
    let out = login(&[code(now), code(now), code(now)]);
    assert!(!out.status.success(), "a code was accepted twice");
    // The next one works.
    let out = login(&[code(now + 1)]);
    assert!(out.status.success(), "{}", stderr(&out));
    // BatchMode never prompts.
    let out = c.run(&["-p", &port, "-o", "BatchMode=yes", &dest(), "true"]);
    assert!(!out.status.success());
    // A secret others can read is not used, and the login is refused (not let through).
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    let out = login(&[code(now + 1)]);
    assert!(!out.status.success(), "a world-readable secret turned 2FA off");
}

#[test]
fn one_time_codes_required() {
    let s = Server::start_with("127.0.0.1", "totp = \"required\"\n");
    let c = Client::paired(&s);
    let out = c.run(&["-p", &s.port.to_string(), &dest(), "true"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("qshd totp"), "{}", stderr(&out));
}

#[test]
fn host_certificates() {
    if !have("ssh-keygen") {
        return eprintln!("skipped: no ssh-keygen");
    }
    let keys = tempfile::tempdir().unwrap();
    let ca = keygen(keys.path(), "host_ca", "ed25519");
    let start = |principal: &str| {
        let home = tempfile::tempdir().unwrap();
        let out = Command::new(QSHD).arg("init").env("HOME", home.path()).output().unwrap();
        assert!(out.status.success(), "qshd init: {}", stderr(&out));
        let host_pub = home.path().join(".config/qsh/host_ed25519.pub");
        let out = Command::new("ssh-keygen")
            .args(["-q", "-s", ca.to_str().unwrap(), "-I", "test-host", "-h", "-n", principal, "-V", "-5m:+1h"])
            .arg(&host_pub)
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen -h: {}", stderr(&out));
        Server::start_in(home, "127.0.0.1:0", "")
    };
    let c = Client::new();
    assert!(c.run(&["keygen"]).status.success());
    let client_pub = std::fs::read_to_string(c.home.path().join(".config/qsh/id_ed25519.pub")).unwrap();
    let known = c.home.path().join(".config/qsh/known_hosts");
    std::fs::write(&known, format!("@cert-authority 127.0.0.1,[127.0.0.1]:* {}\n", public(&ca))).unwrap();
    let login = |s: &Server| {
        std::fs::write(s.authorized_keys(), &client_pub).unwrap();
        c.run(&["-o", "StrictHostKeyChecking=yes", "-p", &s.port.to_string(), &dest(), "echo", "trusted"])
    };
    // Signed for this host name: trusted without any prompt or known_hosts entry.
    let good = start("127.0.0.1");
    let out = login(&good);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "trusted\n");
    // Signed for another name: not trusted (StrictHostKeyChecking=yes refuses).
    let other = start("other.example.com");
    assert!(!login(&other).status.success(), "certificate for another host accepted");
    // A revoked CA is not trusted either.
    let mut text = std::fs::read_to_string(&known).unwrap();
    text.push_str(&format!("@revoked * {}\n", public(&ca)));
    std::fs::write(&known, text).unwrap();
    assert!(!login(&good).status.success(), "revoked CA accepted");
}

/// A UDP relay to `port` that can drop everything, like a network outage.
struct Relay {
    port: u16,
    blackhole: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

fn udp_relay(target: u16) -> Relay {
    udp_relay_with_delay(target, Duration::ZERO)
}

/// Sends each datagram on after `delay` (in order), like a long link.
fn delayed_sender(sock: UdpSocket, delay: Duration) -> std::sync::mpsc::Sender<(Vec<u8>, Option<std::net::SocketAddr>)> {
    let (tx, rx) = std::sync::mpsc::channel::<(Vec<u8>, Option<std::net::SocketAddr>)>();
    std::thread::spawn(move || {
        let mut queue: std::collections::VecDeque<(Instant, Vec<u8>, Option<std::net::SocketAddr>)> = std::collections::VecDeque::new();
        loop {
            let next = match queue.front() {
                Some((due, _, _)) => rx.recv_timeout(due.saturating_duration_since(Instant::now())),
                None => rx.recv().map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected),
            };
            match next {
                Ok((data, to)) => queue.push_back((Instant::now() + delay, data, to)),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            while queue.front().is_some_and(|(due, _, _)| *due <= Instant::now()) {
                let (_, data, to) = queue.pop_front().unwrap();
                let _ = match to {
                    Some(to) => sock.send_to(&data, to),
                    None => sock.send(&data),
                };
            }
        }
    });
    tx
}

fn udp_relay_with_delay(target: u16, delay: Duration) -> Relay {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    let front = UdpSocket::bind("127.0.0.1:0").unwrap();
    let back = UdpSocket::bind("127.0.0.1:0").unwrap();
    back.connect(("127.0.0.1", target)).unwrap();
    let port = front.local_addr().unwrap().port();
    let blackhole = Arc::new(AtomicBool::new(false));
    let client = Arc::new(Mutex::new(None));
    {
        let (front, blackhole, client) = (front.try_clone().unwrap(), blackhole.clone(), client.clone());
        let to_server = delayed_sender(back.try_clone().unwrap(), delay);
        std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            while let Ok((n, from)) = front.recv_from(&mut buf) {
                *client.lock().unwrap() = Some(from);
                if !blackhole.load(Ordering::SeqCst) {
                    let _ = to_server.send((buf[..n].to_vec(), None));
                }
            }
        });
    }
    let hole = blackhole.clone();
    let to_client = delayed_sender(front, delay);
    std::thread::spawn(move || {
        let blackhole = hole;
        let mut buf = [0u8; 65536];
        while let Ok(n) = back.recv(&mut buf) {
            let to = *client.lock().unwrap();
            if let (Some(to), false) = (to, blackhole.load(Ordering::SeqCst)) {
                let _ = to_client.send((buf[..n].to_vec(), Some(to)));
            }
        }
    });
    Relay { port, blackhole }
}

/// Reads the child's output until `needle` shows up (or panics after `secs`).
fn wait_for_output(rx: &std::sync::mpsc::Receiver<String>, seen: &mut String, needle: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !seen.contains(needle) {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(chunk) => seen.push_str(&chunk),
            Err(_) => panic!("{needle:?} did not show up; output so far: {seen:?}"),
        }
    }
}

#[test]
fn session_survives_network_outage() {
    use std::sync::atomic::Ordering;
    let s = Server::start();
    let c = Client::paired(&s);
    let relay = udp_relay(s.port);
    let mut child = c
        .cmd(&[
            "-tt", "--transport", "quic", "--accept-new-host", "-o", "ServerAliveInterval=1", "-o", "ServerAliveCountMax=2",
            "-p", &relay.port.to_string(), &dest(), "sh",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    for pipe in [Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>, Box::new(child.stderr.take().unwrap())] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut pipe = pipe;
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = pipe.read(&mut buf) {
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        });
    }
    let mut seen = String::new();
    stdin.write_all(b"echo be$((1+1))fore\n").unwrap();
    wait_for_output(&rx, &mut seen, "be2fore", 10);
    // Output produced while the network is down must arrive after the reconnect.
    stdin.write_all(b"sleep 3; echo dur$((2+2))ing\n").unwrap();
    sleep(Duration::from_millis(300));
    relay.blackhole.store(true, Ordering::SeqCst);
    wait_for_output(&rx, &mut seen, "reconnecting", 15);
    sleep(Duration::from_secs(4));
    relay.blackhole.store(false, Ordering::SeqCst);
    wait_for_output(&rx, &mut seen, "reconnected", 30);
    wait_for_output(&rx, &mut seen, "dur4ing", 10);
    // The same shell is still there.
    stdin.write_all(b"echo af$((3+3))ter; exit 7\n").unwrap();
    wait_for_output(&rx, &mut seen, "af6ter", 10);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(7), "{seen}");
}

#[test]
fn hangup_ends_a_persistent_session() {
    let s = Server::start();
    let c = Client::paired(&s);
    // The session's shell is gone once the client quits normally (SIGTERM here).
    let mut child = c
        .cmd(&["-tt", "-p", &s.port.to_string(), &dest(), "sh", "-c", "'echo $$ > persist.pid; sleep 60'"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid_file = s.home.path().join("persist.pid");
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::fs::read_to_string(&pid_file).map(|t| t.trim().is_empty()).unwrap_or(true) {
        assert!(Instant::now() < deadline, "session did not start");
        sleep(Duration::from_millis(50));
    }
    let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(child.id() as i32), nix::sys::signal::Signal::SIGTERM).unwrap();
    child.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok() {
        assert!(Instant::now() < deadline, "the session outlived the client's SIGTERM");
        sleep(Duration::from_millis(50));
    }
}

/// A login with a resume token skips the one-time code, so it must not give
/// more than the resumed session: no commands, files or forwarding.
#[test]
fn resume_login_can_only_resume() {
    use qsh::client::{self, ConnectOptions, Target};
    use qsh::proto::{read_msg, write_msg, PtySpec, Reply, Request};
    let s = Server::start();
    let c = Client::paired(&s);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut target = Target::parse_with(&dest(), Some(s.port), Some(c.home.path()), false).unwrap();
        target.identity_agent = Some(None);
        target.known_hosts_file = Some(c.home.path().join(".config/qsh/known_hosts"));
        let key = c.home.path().join(".config/qsh/id_ed25519");
        let opts = ConnectOptions { identities: vec![key], ..Default::default() };
        // A persistent session over a normal login.
        let conn = client::connect(&target, &opts).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let pty = PtySpec { term: "xterm".into(), cols: 80, rows: 24 };
        write_msg(&mut send, &Request::Persistent { command: Some("sleep 30".into()), env: vec![], pty }).await.unwrap();
        let Reply::Session { token } = read_msg(&mut recv).await.unwrap() else { panic!("no session") };
        // A resume login works, but only for Resume of that token.
        let resumed = client::connect(&target, &ConnectOptions { resume: Some(token.clone()), ..opts.clone() }).await.unwrap();
        for request in [
            Request::Exec { command: Some("id".into()), env: vec![], pty: None },
            Request::Download { path: ".config/qsh/authorized_keys".into() },
            Request::DirectTcp { host: "127.0.0.1".into(), port: s.port },
            Request::Resume { token: vec![0; 16], received: 0 },
        ] {
            let (mut send, mut recv) = resumed.open_bi().await.unwrap();
            write_msg(&mut send, &request).await.unwrap();
            match read_msg::<_, Reply>(&mut recv).await.unwrap() {
                Reply::Err(e) => assert!(e.contains("only resume"), "{e}"),
                other => panic!("{request:?} was answered with {other:?}"),
            }
        }
        let (mut send, mut recv) = resumed.open_bi().await.unwrap();
        write_msg(&mut send, &Request::Resume { token, received: 0 }).await.unwrap();
        assert!(matches!(read_msg::<_, Reply>(&mut recv).await.unwrap(), Reply::Session { .. }));
        // An unknown token is refused at login.
        let refused = client::connect(&target, &ConnectOptions { resume: Some(vec![7; 16]), ..opts.clone() }).await;
        let err = refused.err().expect("unknown token accepted");
        assert!(format!("{err:#}").contains("session is gone"), "{err:#}");
        drop(conn);
    });
}

/// Like openrsync: stdin and stdout are one non-blocking socket.
#[test]
fn nonblocking_stdio_from_the_parent() {
    use std::os::fd::OwnedFd;
    let s = Server::start();
    let c = Client::paired(&s);
    let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    theirs.set_nonblocking(true).unwrap();
    let out = theirs.try_clone().unwrap();
    let mut child = c
        .cmd(&["-p", &s.port.to_string(), &dest(), "cat"])
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::from(OwnedFd::from(out)))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Give qsh time to start reading before any data is there.
    sleep(Duration::from_millis(500));
    ours.write_all(b"through a non-blocking socket\n").unwrap();
    ours.shutdown(std::net::Shutdown::Write).unwrap();
    let mut text = String::new();
    ours.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = ours.read_to_string(&mut text);
    let status = child.wait().unwrap();
    assert_eq!(text, "through a non-blocking socket\n");
    assert!(status.success());
}

/// Wrong one-time codes are counted over all connections, so reconnecting
/// does not give a key thief unlimited guesses.
#[test]
fn one_time_code_guessing_is_limited_across_connections() {
    use qsh::totp;
    let s = Server::start();
    let c = Client::paired(&s);
    let secret = b"another secret bytes";
    let path = totp::secret_path(s.home.path());
    std::fs::write(&path, totp::base32_encode(secret)).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let port = s.port.to_string();
    let login = |answers: &[String]| {
        let script = askpass_script(dir.path(), answers);
        c.cmd(&["-p", &port, &dest(), "true"]).env("SSH_ASKPASS", &script).env("SSH_ASKPASS_REQUIRE", "force").output().unwrap()
    };
    let wrong = vec!["000000".to_string(); 3];
    for _ in 0..4 {
        assert!(!login(&wrong).status.success());
    }
    // Even the right code is refused now, until the window passes.
    let step = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / totp::STEP;
    let out = login(&[format!("{:06}", totp::code(secret, step))]);
    assert!(!out.status.success(), "the right code was accepted during the lockout");
    assert!(stderr(&out).contains("too many wrong one-time codes"), "{}", stderr(&out));
}

/// `ControlMaster auto` + `ControlPersist` in qsh's config: the first run
/// leaves a master in the background, later runs (sessions, copies) go
/// through it without a login of their own, and `-O check|exit` talk to it.
#[test]
fn connection_sharing_with_a_background_master() {
    let s = Server::start();
    let c = Client::paired(&s);
    std::fs::write(c.home.path().join(".config/qsh/config"), "Host *\n    ControlMaster auto\n    ControlPersist 60\n    ControlPath /tmp/qsh-test-%C\n").unwrap();
    let port = s.port.to_string();
    let out = c.run(&["-p", &port, &dest(), "echo", "one"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "one\n");
    let out = c.run(&["-O", "check", "-p", &port, &dest()]);
    assert!(stderr(&out).contains("Master running"), "{}", stderr(&out));
    // Without the key on the server only the master's connection still works.
    std::fs::remove_file(s.authorized_keys()).unwrap();
    for i in 0..3 {
        let out = c.run(&["-v", "-p", &port, &dest(), "echo", &format!("via-master-{i}")]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), format!("via-master-{i}\n"));
        assert!(stderr(&out).contains("shared connection"), "{}", stderr(&out));
    }
    let local = c.home.path().join("shared.txt");
    std::fs::write(&local, b"copied through the master").unwrap();
    let out = c.run(&["cp", "-p", &port, local.to_str().unwrap(), &format!("{}:shared.txt", dest())]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::read(s.home.path().join("shared.txt")).unwrap(), b"copied through the master");
    let mut child = c.cmd(&["-p", &port, &dest(), "wc", "-c"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(&[b'x'; 100_000]).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(stdout(&out).trim(), "100000");
    // -R needs a connection of its own (the server's streams would reach the master).
    let out = c.run(&["-o", "BatchMode=yes", "-R", "0:127.0.0.1:9", "-p", &port, &dest(), "true"]);
    assert!(!out.status.success(), "-R went through the master");
    let out = c.run(&["-O", "exit", "-p", &port, &dest()]);
    assert!(out.status.success(), "{}", stderr(&out));
    sleep(Duration::from_millis(300));
    let out = c.run(&["-O", "check", "-p", &port, &dest()]);
    assert!(!out.status.success(), "the master is still there");
    let out = c.run(&["-o", "BatchMode=yes", "-p", &port, &dest(), "true"]);
    assert!(!out.status.success(), "logged in without a key");
}

/// `-M -f -N -S path`: a master in the foreground process (here sent to the
/// background with -f); `-S path` uses it.
#[test]
fn connection_sharing_with_an_explicit_socket() {
    let s = Server::start();
    let c = Client::paired(&s);
    let port = s.port.to_string();
    let sock = c.home.path().join("master.sock");
    let sock = sock.to_str().unwrap();
    let status = c.cmd(&["-M", "-f", "-N", "-S", sock, "-p", &port, &dest()]).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
    assert!(status.success());
    std::fs::remove_file(s.authorized_keys()).unwrap();
    let out = c.run(&["-S", sock, "-p", &port, &dest(), "echo", "shared"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "shared\n");
    // Without -S this run has no master to use.
    let out = c.run(&["-p", &port, "-o", "BatchMode=yes", &dest(), "true"]);
    assert!(!out.status.success());
    let out = c.run(&["-S", sock, "-O", "exit", &dest()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::path::Path::new(sock).exists() {
        assert!(Instant::now() < deadline, "the master did not exit");
        sleep(Duration::from_millis(50));
    }
}

/// A terminal session started through a master keeps running when the
/// master goes away: qsh logs in by itself and resumes it.
#[test]
fn shared_session_survives_the_master() {
    let s = Server::start();
    let c = Client::paired(&s);
    std::fs::write(c.home.path().join(".config/qsh/config"), "Host *\n    ControlMaster auto\n    ControlPersist 60\n    ControlPath /tmp/qsh-test-%C\n").unwrap();
    let port = s.port.to_string();
    assert!(c.run(&["-p", &port, &dest(), "true"]).status.success());
    let mut child = c
        .cmd(&["-tt", "-v", "-o", "ServerAliveInterval=1", "-o", "ServerAliveCountMax=2", "-p", &port, &dest(), "sh"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    for pipe in [Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>, Box::new(child.stderr.take().unwrap())] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut pipe = pipe;
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = pipe.read(&mut buf) {
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        });
    }
    let mut seen = String::new();
    stdin.write_all(b"echo be$((1+1))fore\n").unwrap();
    wait_for_output(&rx, &mut seen, "be2fore", 10);
    assert!(seen.contains("shared connection"), "{seen}");
    assert!(c.run(&["-O", "exit", "-p", &port, &dest()]).status.success());
    wait_for_output(&rx, &mut seen, "reconnected", 30);
    stdin.write_all(b"echo af$((3+3))ter; exit 7\n").unwrap();
    wait_for_output(&rx, &mut seen, "af6ter", 10);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(7), "{seen}");
}

/// On a slow link, typed characters show up before the server's echo, and
/// the screen ends up exactly as the server drew it.
#[test]
fn typing_is_predicted_on_a_slow_link() {
    let s = Server::start();
    let c = Client::paired(&s);
    let relay = udp_relay_with_delay(s.port, Duration::from_millis(150));
    let pty = nix::pty::openpty(Some(&nix::pty::Winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 }), None).unwrap();
    let slave = || Stdio::from(std::fs::File::from(pty.slave.try_clone().unwrap()));
    let mut child = Command::new(QSH)
        .args(["-t", "--accept-new-host", "--transport", "quic", "-p", &relay.port.to_string(), &dest(), "env PS1=\'$ \' sh"])
        .env("HOME", c.home.path())
        .env("TERM", "xterm-256color")
        .stdin(slave())
        .stdout(slave())
        .stderr(slave())
        .spawn()
        .unwrap();
    let mut master = std::fs::File::from(pty.master);
    nix::fcntl::fcntl(&master, nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK)).unwrap();
    let mut screen = vt100::Parser::new(24, 80, 0);
    let read_until = |master: &mut std::fs::File, screen: &mut vt100::Parser, what: &dyn Fn(&str) -> bool, secs: f64| {
        let deadline = Instant::now() + Duration::from_secs_f64(secs);
        loop {
            let mut buf = [0u8; 65536];
            match master.read(&mut buf) {
                Ok(n) if n > 0 => screen.process(&buf[..n]),
                _ => sleep(Duration::from_millis(5)),
            }
            if what(&screen.screen().contents()) {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
        }
    };
    assert!(read_until(&mut master, &mut screen, &|t| t.contains("$ "), 15.0), "no prompt: {}", screen.screen().contents());
    // The first character confirms that the server echoes; it takes a round trip.
    master.write_all(b"e").unwrap();
    assert!(read_until(&mut master, &mut screen, &|t| t.contains("$ e"), 5.0));
    let started = Instant::now();
    master.write_all(b"c").unwrap();
    assert!(read_until(&mut master, &mut screen, &|t| t.contains("$ ec"), 5.0));
    let shown = started.elapsed();
    assert!(shown < Duration::from_millis(200), "the typed character took {shown:?} to show up");
    master.write_all(b"ho pre$((1+1))dicted\r").unwrap();
    assert!(read_until(&mut master, &mut screen, &|t| t.contains("\npre2dicted"), 10.0), "{}", screen.screen().contents());
    assert!(screen.screen().contents().contains("$ echo pre$((1+1))dicted\n"), "{}", screen.screen().contents());
    master.write_all(b"exit\r").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "qsh did not exit");
        let _ = master.read(&mut [0u8; 65536]);
        sleep(Duration::from_millis(20));
    }
}

/// `revoked_keys`: a key list or a KRL from `ssh-keygen -k` (keys,
/// certificate serials and key IDs); an unreadable list refuses everyone.
#[test]
fn revoked_keys_and_krl() {
    if !have("ssh-keygen") {
        return eprintln!("skipped: no ssh-keygen");
    }
    let keys = tempfile::tempdir().unwrap();
    let ca = keygen(keys.path(), "ca", "ed25519");
    let certified = keygen(keys.path(), "certified", "ed25519");
    let out = Command::new("ssh-keygen")
        .args(["-q", "-s", ca.to_str().unwrap(), "-I", "laptop", "-z", "42", "-n", &user(), "-V", "-5m:+1h"])
        .arg(format!("{}.pub", certified.display()))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let ec = keygen(keys.path(), "ec", "ecdsa");
    let ed = keygen(keys.path(), "ed", "ed25519");
    let list = keys.path().join("revoked");
    std::fs::write(&list, "").unwrap();
    let ca_file = keys.path().join("user_ca.pub");
    std::fs::copy(format!("{}.pub", ca.display()), &ca_file).unwrap();
    let config = format!("trusted_user_ca_keys = \"{}\"\nrevoked_keys = \"{}\"\n", ca_file.display(), list.display());
    let (s, c) = server_with_keys(&config, &[public(&ec), public(&ed)]);
    let port = s.port.to_string();
    let works = |key: &PathBuf| {
        let out = c.run(&["--accept-new-host", "-o", "BatchMode=yes", "-p", &port, "-i", key.to_str().unwrap(), &dest(), "true"]);
        if !out.status.success() {
            eprintln!("{}: {}", key.display(), stderr(&out));
        }
        out.status.success()
    };
    let krl = |extra: &[&str], input: &str| {
        let spec = keys.path().join("spec");
        std::fs::write(&spec, input).unwrap();
        let _ = std::fs::remove_file(&list);
        let out = Command::new("ssh-keygen").args(["-q", "-k", "-f", list.to_str().unwrap()]).args(extra).arg(&spec).output().unwrap();
        assert!(out.status.success(), "ssh-keygen -k: {}", stderr(&out));
    };
    assert!(works(&ec) && works(&ed) && works(&certified), "nothing is revoked yet");
    std::fs::write(&list, public(&ec) + "\n").unwrap();
    assert!(!works(&ec), "revoked by the text list");
    assert!(works(&ed));
    krl(&[], &public(&ed));
    assert!(!works(&ed), "revoked by a KRL");
    assert!(works(&ec));
    let ca_pub = format!("{}.pub", ca.display());
    krl(&["-s", &ca_pub], "serial: 40-45\n");
    assert!(!works(&certified), "certificate serial revoked");
    krl(&["-s", &ca_pub], "id: laptop\n");
    assert!(!works(&certified), "certificate key ID revoked");
    krl(&["-s", &ca_pub], "serial: 43\n");
    assert!(works(&certified), "another serial");
    krl(&[], &public(&ca));
    assert!(!works(&certified), "the CA itself revoked");
    std::fs::write(&list, "garbage\n").unwrap();
    assert!(!works(&ec) && !works(&ed), "a damaged list must refuse everyone");
}

/// `qsh multi`: a command on several hosts (named or from a group), output
/// prefixed per host, failures summed up at the end.
#[test]
fn command_on_several_hosts() {
    let a = Server::start();
    let b = Server::start();
    let c = Client::paired(&a);
    // The same client key on the second server.
    std::fs::create_dir_all(b.authorized_keys().parent().unwrap()).unwrap();
    std::fs::copy(a.authorized_keys(), b.authorized_keys()).unwrap();
    let host_a = format!("{}:{}", dest(), a.port);
    let host_b = format!("{}:{}", dest(), b.port);
    std::fs::write(c.home.path().join(".config/qsh/groups"), format!("both = [{host_a:?}, {host_b:?}]\n")).unwrap();
    let out = c.run(&["multi", "--accept-new-host", "-g", "both", "--", "echo", "hello", "from", "$HOME"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    for (host, server) in [(&host_a, &a), (&host_b, &b)] {
        let line = format!("{host} | hello from {}", server.home.path().display());
        assert!(text.lines().any(|l| l.trim_end() == line), "missing {line:?} in\n{text}");
    }
    // A failing command and an unreachable host are reported, and set the exit code.
    let dead = format!("{}:{}", dest(), free_port());
    let out = c.run(&["multi", "--transport", "tcp", &host_a, &dead, "--", "exit", "3"]);
    assert_eq!(out.status.code(), Some(255), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains(&format!("{host_a}: exit code 3")), "{err}");
    assert!(err.contains(&format!("{dead}: could not connect")), "{err}");
    let out = c.run(&["multi", "-g", "nope", "--", "true"]);
    assert!(!out.status.success());
}

/// `qsh cp -C`: zstd-compressed copies, files and trees, both ways.
#[test]
fn compressed_copies() {
    let s = Server::start();
    let c = Client::paired(&s);
    let port = s.port.to_string();
    let text: Vec<u8> = (0..200_000).flat_map(|i| format!("line {i}: the same old text again\n").into_bytes()).collect();
    let random = pseudo_random(1_000_000);
    let src = c.home.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("text.txt"), &text).unwrap();
    std::fs::write(src.join("sub/random.bin"), &random).unwrap();
    for (t, file, data) in [("quic", "text.txt", &text), ("tcp", "sub/random.bin", &random)] {
        let local = src.join(file);
        let out = c.run(&["cp", "-C", "--transport", t, "-p", &port, local.to_str().unwrap(), &format!("{}:up-{t}", dest())]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(&std::fs::read(s.home.path().join(format!("up-{t}"))).unwrap(), data, "upload over {t}");
        let back = c.home.path().join(format!("down-{t}"));
        let out = c.run(&["cp", "-C", "--transport", t, "-p", &port, &format!("{}:up-{t}", dest()), back.to_str().unwrap()]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(&std::fs::read(&back).unwrap(), data, "download over {t}");
    }
    let out = c.run(&["cp", "-v", "-C", "-p", &port, &format!("{}:up-quic", dest()), c.home.path().join("v").to_str().unwrap()]);
    assert!(out.status.success() && !stderr(&out).contains("without compression"), "{}", stderr(&out));
    // `Compression yes` in the config works like -C.
    std::fs::write(c.home.path().join(".config/qsh/config"), "Host *\n    Compression yes\n").unwrap();
    let out = c.run(&["cp", "-r", "-p", &port, src.to_str().unwrap(), &format!("{}:tree", dest())]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::read(s.home.path().join("tree/text.txt")).unwrap(), text);
    let back = c.home.path().join("back");
    std::fs::create_dir(&back).unwrap();
    let out = c.run(&["cp", "-r", "-p", &port, &format!("{}:tree", dest()), back.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::read(back.join("tree/sub/random.bin")).unwrap(), random);
    assert_eq!(std::fs::read(back.join("tree/text.txt")).unwrap(), text);
    // A failure inside a compressed tree download still reaches the client.
    let locked = s.home.path().join("tree/sub");
    std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
    let out = c.run(&["cp", "-r", "-p", &port, &format!("{}:tree", dest()), c.home.path().join("again").to_str().unwrap()]);
    std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    if nix::unistd::geteuid().is_root() {
        return; // root reads it anyway
    }
    assert!(!out.status.success(), "unreadable directory not reported");
}

/// A control socket that cannot be made (here: a path longer than Unix
/// sockets allow) only means no sharing; the command still runs.
#[test]
fn sharing_falls_back_when_the_socket_cannot_be_made() {
    let s = Server::start();
    let c = Client::paired(&s);
    let long = c.home.path().join("x".repeat(120));
    std::fs::create_dir_all(&long).unwrap();
    let config = format!("Host *\n    ControlMaster auto\n    ControlPersist 60\n    ControlPath {}/%C\n", long.display());
    std::fs::write(c.home.path().join(".config/qsh/config"), config).unwrap();
    let out = c.run(&["-p", &s.port.to_string(), &dest(), "echo", "still works"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "still works\n");
    assert!(stderr(&out).contains("not sharing"), "{}", stderr(&out));
}

/// A directory whose ancestors only root or this user can write to.
fn safe_dir() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let me = nix::unistd::geteuid().as_raw();
    let candidates = [PathBuf::from(env!("CARGO_TARGET_TMPDIR")), std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default().join(".cache")];
    candidates.into_iter().find(|dir| {
        std::fs::create_dir_all(dir).is_ok()
            && dir.ancestors().all(|p| std::fs::metadata(p).is_ok_and(|m| (m.uid() == 0 || m.uid() == me) && m.mode() & 0o022 == 0))
    })
}

/// `authorized_keys_command`: keys printed by a program, with tokens; an
/// unsafe program (writable by others) is not run.
#[test]
fn keys_from_a_command() {
    let c = Client::new();
    let out = c.run(&["keygen"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let public = std::fs::read_to_string(c.home.path().join(".config/qsh/id_ed25519.pub")).unwrap();
    // Not below a directory others can write to (like /tmp): those are refused.
    let Some(base) = safe_dir() else {
        return eprintln!("skipped: no directory here that only root and this user can write to");
    };
    let dir = tempfile::tempdir_in(base).unwrap();
    let keys = dir.path().join("keys");
    std::fs::write(&keys, &public).unwrap();
    let log = dir.path().join("log");
    let prog = dir.path().join("prog");
    std::fs::write(&prog, format!("#!/bin/sh\necho \"$@\" >> {}\ncat {}\n", log.display(), keys.display())).unwrap();
    std::fs::set_permissions(&prog, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    std::fs::set_permissions(dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let s = Server::start_with("127.0.0.1", &format!("authorized_keys_command = \"{} %u %t %f\"\n", prog.display()));
    let port = s.port.to_string();
    let out = c.run(&["--accept-new-host", "-p", &port, &dest(), "echo", "via-command"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "via-command\n");
    let args = std::fs::read_to_string(&log).unwrap();
    assert!(args.starts_with(&format!("{} ssh-ed25519 SHA256:", user())), "{args}");
    // Writable by others: refused, so the login fails.
    std::fs::set_permissions(&prog, std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
    let out = c.run(&["-o", "BatchMode=yes", "-p", &port, &dest(), "true"]);
    assert!(!out.status.success(), "an unsafe command was used");
}

/// A host without an open port: it keeps `qsh -N -R` to a public qshd, and
/// clients reach it with `-J public`. The session is encrypted end to end
/// (the public host only relays the bytes).
#[test]
fn reaching_a_host_without_an_open_port() {
    let public = Server::start();
    let hidden = Server::start();
    let c = Client::paired(&public);
    // The client's key is accepted on the hidden host too.
    std::fs::create_dir_all(hidden.authorized_keys().parent().unwrap()).unwrap();
    std::fs::copy(public.authorized_keys(), hidden.authorized_keys()).unwrap();
    // The hidden host's tunnel (here run with the same key, as its own user would).
    let relay_port = free_port();
    let mut tunnel = c
        .cmd(&["-N", "-R", &format!("{relay_port}:127.0.0.1:{}", hidden.port), "-p", &public.port.to_string(), &dest()])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let jump = format!("{}:{}", dest(), public.port);
    let target = format!("{}@localhost:{relay_port}", user());
    let out = loop {
        let out = c.run(&["--accept-new-host", "-J", &jump, &target, "echo", "behind-nat"]);
        if out.status.success() || Instant::now() > deadline {
            break out;
        }
        sleep(Duration::from_millis(200));
    };
    let _ = tunnel.kill();
    let _ = tunnel.wait();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "behind-nat\n");
}
