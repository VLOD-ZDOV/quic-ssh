//! qshd on Windows, end to end with qsh: commands, a terminal (ConPTY),
//! copies both ways, over QUIC and TCP.
//!
//! Runs only with QSH_WINDOWS_E2E=1 (as in CI): qsh and qshd find this
//! account's profile from the system, so the test writes keys into its real
//! `~/.config/qsh`. QSH_WINDOWS_E2E_WINE=1 skips what Wine cannot do: QUIC
//! (its UDP sockets lack options QUIC needs) and ConPTY (it refuses the
//! pseudo console's flags).
#![cfg(windows)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Output, Stdio};

const QSH: &str = env!("CARGO_BIN_EXE_qsh");
const QSHD: &str = env!("CARGO_BIN_EXE_qshd");

/// Stops qshd even when an assertion fails.
struct Server(std::process::Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

#[test]
fn qshd_on_windows() {
    if std::env::var_os("QSH_WINDOWS_E2E").is_none() {
        return;
    }
    let home = dirs::home_dir().unwrap();
    let dir = home.join(".config").join("qsh");
    if !dir.join("id_ed25519").exists() {
        assert!(Command::new(QSH).arg("keygen").output().unwrap().status.success());
    }
    let key = std::fs::read_to_string(dir.join("id_ed25519.pub")).unwrap();
    let keys = dir.join("authorized_keys");
    let had = std::fs::read_to_string(&keys).unwrap_or_default();
    if !had.contains(key.trim()) {
        std::fs::write(&keys, format!("{had}{key}")).unwrap();
    }

    let mut server = Server(Command::new(QSHD).args(["serve", "--listen", "127.0.0.1:0"]).stderr(Stdio::piped()).spawn().unwrap());
    let mut lines = BufReader::new(server.0.stderr.take().unwrap()).lines();
    let port = loop {
        let line = lines.next().expect("qshd ended").unwrap();
        if let Some(rest) = line.split("listening on 127.0.0.1:").nth(1) {
            break rest.split(|c: char| !c.is_ascii_digit()).next().unwrap().to_string();
        }
    };
    std::thread::spawn(move || lines.for_each(drop));
    let dest = format!("{}@127.0.0.1", std::env::var("USERNAME").unwrap());
    let qsh = |transport: &str, args: &[&str]| {
        Command::new(QSH).args(["--accept-new-host", "--transport", transport, "-p", &port]).args(args).stdin(Stdio::null()).output().unwrap()
    };

    // Policies match the name: another spelling of the account is refused.
    let upper = std::env::var("USERNAME").unwrap().to_uppercase();
    if upper != std::env::var("USERNAME").unwrap() {
        let out = qsh("tcp", &[&format!("{upper}@127.0.0.1"), "echo in"]);
        assert!(!out.status.success() && !text(&out).contains("in\n"), "{}", text(&out));
    }

    let wine = std::env::var_os("QSH_WINDOWS_E2E_WINE").is_some();
    let transports: &[&str] = if wine { &["tcp"] } else { &["quic", "tcp"] };
    for &t in transports {
        let out = qsh(t, &[&dest, "echo hello & exit 3"]);
        assert!(text(&out).contains("hello"), "{t}: {:?} {}", out.status, text(&out));
        assert_eq!(out.status.code(), Some(3), "{t}: {}", text(&out));
        if !wine {
            let out = qsh(t, &["-tt", &dest, "echo terminal-ok"]);
            assert!(text(&out).contains("terminal-ok"), "{t}: {}", text(&out));
        }

        let data: Vec<u8> = (0..2_000_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let local = std::env::temp_dir().join(format!("qsh-win-{t}.bin"));
        std::fs::write(&local, &data).unwrap();
        let remote = format!("{dest}:qsh-win-{t}.bin");
        let out = Command::new(QSH).args(["cp", "--transport", t, "-p", &port]).arg(&local).arg(&remote).output().unwrap();
        assert!(out.status.success(), "{t}: {}", text(&out));
        let back = std::env::temp_dir().join(format!("qsh-win-{t}.back"));
        let out = Command::new(QSH).args(["cp", "--transport", t, "-p", &port, &remote]).arg(&back).output().unwrap();
        assert!(out.status.success(), "{t}: {}", text(&out));
        assert_eq!(std::fs::read(&back).unwrap(), data);
        let _ = std::fs::remove_file(home.join(format!("qsh-win-{t}.bin")));
    }
    drop(server);
    std::fs::write(&keys, had).unwrap();
}
