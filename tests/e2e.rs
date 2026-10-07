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
        Self::start_listen(&format!("{listen_ip}:0"), config)
    }

    fn start_listen(listen: &str, config: &str) -> Server {
        let home = tempfile::tempdir().unwrap();
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
        std::os::unix::fs::PermissionsExt::set_mode(&mut std::fs::metadata(&script).unwrap().permissions(), 0o755);
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}", dir.display(), std::env::var("PATH").unwrap_or_default());
    (path, log)
}

/// A UDP port with nothing listening (the kernel answers with ICMP unreachable).
fn closed_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn full_mode_uses_qshd_on_ssh_port_and_config() {
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
    // 60 TCP connections from 127.0.0.2 that never start TLS.
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
    std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0).unwrap_or(false)
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
        assert!(out.status.success(), "rsync: {}", stderr(&out));
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
