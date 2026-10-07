# quic-ssh (qsh)

**English** | [Русский](README.ru.md)

[![CI](https://github.com/VLOD-ZDOV/quic-ssh/actions/workflows/ci.yml/badge.svg)](https://github.com/VLOD-ZDOV/quic-ssh/actions/workflows/ci.yml)

`qsh` is an `ssh` replacement that runs over **QUIC (UDP)**. If UDP is blocked, it falls back to **TLS over TCP** on its own. The server, `qshd`, listens on the same port (**4422** by default) over both UDP and TCP.

Why QUIC:

- **Faster connections:** on a 50 ms RTT link, running a command is 3.4× faster than with ssh (see [benchmarks](#benchmarks)).
- **Better on bad networks:** BBR congestion control keeps throughput up under packet loss (Wi-Fi, mobile).
- **No head-of-line blocking:** every session, port forward and copy has its own stream, so a slow `cp` never stalls your terminal.
- **Survives client address changes** (NAT rebinding).
- **Built-in keep-alive.**

Features:

- interactive shell with a PTY, window resizing and exit codes;
- remote commands (`qsh host cmd`) with stdin/stdout/stderr;
- local port forwarding (`-L`);
- file copy (`qsh cp`);
- Ed25519 key login only (your existing `~/.ssh/id_ed25519` works);
- pairing with a one-time code, so you never copy keys by hand.

## Installation

### Prebuilt binaries

Static Linux builds for x86_64 and aarch64 are on the [Releases](https://github.com/VLOD-ZDOV/quic-ssh/releases) page:

```sh
ARCH=$(uname -m)   # x86_64 or aarch64
curl -fsSL https://github.com/VLOD-ZDOV/quic-ssh/releases/latest/download/qsh-$ARCH-linux.tar.gz | tar xz
sudo install -m755 qsh-$ARCH-linux/qsh qsh-$ARCH-linux/qshd /usr/local/bin/
```

The same archive works for both client and server. Checksums are in `SHA256SUMS`.

### From source

You need a recent stable Rust toolchain. No C libraries are required.

```sh
git clone https://github.com/VLOD-ZDOV/quic-ssh && cd quic-ssh
cargo build --release          # target/release/qsh and target/release/qshd
sudo install -m755 target/release/qsh target/release/qshd /usr/local/bin/
```

## Quick start

**1. Server.** Open port **4422 for both UDP and TCP** in your firewall, then run:

```sh
sudo qshd                  # system mode: every user can log in
# or simply
qshd                       # user mode: only this user can log in
```

On first start it creates a host key and prints its fingerprint.

**2. Pairing.** On the server, as the user you will log in as:

```sh
qshd pair
# Pairing code: k7f3-9qxm  (single use, valid 10 minutes)
# On the client run:
#   qsh pair user@server k7f3-9qxm
```

On the client:

```sh
qsh pair user@server k7f3-9qxm
```

`pair` adds the client key on the server (`~/.config/qsh/authorized_keys`) and pins the server key on the client (`~/.config/qsh/known_hosts`). If the client has no key yet, one is created at `~/.config/qsh/id_ed25519`.

**3. Log in.**

```sh
qsh user@server
```

Pairing is optional: if your key is already in `~/.ssh/authorized_keys` on the server (for example, after `ssh-copy-id`), `qsh` accepts it. On first connect it shows the host fingerprint, like ssh does.

### Running as a service

```sh
# system mode
sudo cp contrib/qshd.service /etc/systemd/system/
sudo systemctl enable --now qshd

# user mode (no root)
mkdir -p ~/.config/systemd/user
cp contrib/qshd-user.service ~/.config/systemd/user/qshd.service
systemctl --user enable --now qshd
loginctl enable-linger "$USER"     # keep it running without an active session
```

The unit files are in `contrib/`, both in the repository and in the release archive.

## Usage

```sh
qsh user@host                          # interactive shell
qsh user@host uname -a                 # run a command
qsh -t user@host htop                  # command with a forced PTY
qsh -L 8080:localhost:80 user@host     # port forward (+ shell)
qsh -N -L 5432:db.internal:5432 host   # port forward only
qsh cp file.txt user@host:dir/         # upload
qsh cp user@host:logs/app.log .        # download
qsh -p 2222 user@host                  # another port (or user@host:2222)
qsh --transport tcp user@host          # force TCP (or quic)
qsh -v user@host                       # show which transport is used
qsh keygen                             # create ~/.config/qsh/id_ed25519
```

The client key is chosen in this order: `-i FILE`, then `~/.ssh/id_ed25519`, then `~/.config/qsh/id_ed25519`. An encrypted key prompts for its passphrase.

## Server configuration

| Mode | Run as | Who can log in | Files |
|---|---|---|---|
| system | root | any user (with their own keys) | `/etc/qsh/config.toml`, `/etc/qsh/host_ed25519` |
| user | a regular user | only that user | `~/.config/qsh/qshd.toml`, `~/.config/qsh/host_ed25519` |

The config file is optional. Defaults:

```toml
listen = "[::]:4422"            # UDP and TCP; falls back to 0.0.0.0 if IPv6 is disabled
# host_key = "/etc/qsh/host_ed25519"
use_ssh_authorized_keys = true  # also accept ~/.ssh/authorized_keys
allow_tcp_forwarding = true
max_connections = 256
```

User keys live in `~/.config/qsh/authorized_keys` and, if enabled, `~/.ssh/authorized_keys`. Only `ssh-ed25519` lines count. Lines with options (`from=`, `command=` and so on) are **ignored**, because qsh cannot enforce those restrictions.

Logs go to stderr (journald). Set the level with `QSHD_LOG`, for example `QSHD_LOG=qsh=debug`.

## Benchmarks

Compared with OpenSSH 10 (`ssh`/`scp` with default settings). The network is emulated with `tc netem` on loopback inside a separate network namespace (MTU 1500). Both sides run on the same machine.

**Connect and run `true`** (median of 10 runs):

| Network | ssh | qsh (QUIC) | qsh (TCP fallback) |
|---|---:|---:|---:|
| loopback, no delay | 87 ms | 37 ms | 15 ms |
| RTT 50 ms, 100 Mbit/s | 631 ms | **188 ms** | 217 ms |
| RTT 100 ms, 1% loss, 20 Mbit/s | 1183 ms (worst 1750) | **343 ms** (worst 345) | 420 ms (worst 1551) |

**File upload** (`scp` vs `qsh cp`, median of 3 runs):

| Network | Size | scp | qsh (QUIC) | qsh (TCP fallback) |
|---|---:|---:|---:|---:|
| loopback, no delay | 200 MiB | 5.8 Gbit/s | 5.2 Gbit/s | 16.8 Gbit/s |
| RTT 50 ms, 100 Mbit/s | 50 MiB | 66.2 Mbit/s | **85.2 Mbit/s** | 79.2 Mbit/s |
| RTT 100 ms, 1% loss, 20 Mbit/s | 10 MiB | 10.4 Mbit/s | **16.3 Mbit/s** | 14.1 Mbit/s |

Takeaways:

- **Connecting** is 3–3.4× faster than ssh on any link with noticeable latency. QUIC combines the transport and TLS handshakes into 1 RTT, while ssh spends several RTTs on version exchange, key exchange and authentication.
- **Under packet loss**, QUIC with BBR uses almost the whole link (16.3 of 20 Mbit/s), while scp gets about half.
- **On loopback**, QUIC is CPU-bound (encryption and UDP in userspace), so TCP is faster there. On real links the network, not the CPU, is the bottleneck.

To reproduce (needs only util-linux, iproute2 and OpenSSH; no root):

```sh
cargo build --release
python3 bench/bench.py
```

## Security

- **Encryption** is TLS 1.3 only (rustls with ring), over both QUIC and TCP. There is no custom cryptography.
- **The server** presents a self-signed certificate carrying its Ed25519 key. The client checks that key against `known_hosts` (TOFU, like ssh). If the key changes, the connection is dropped before any data is sent.
- **The client** logs in with mutual TLS using its Ed25519 key. The signature is checked inside the TLS handshake, so the login is bound to the channel. There are no passwords at all.
- **Pairing** uses SPAKE2 over the code plus key confirmation bound to the TLS session (exporter) and both keys. A man in the middle can neither brute-force the code offline nor relay the proof. The code is single-use (burned after the first attempt, even a failed one) and expires after 10 minutes.
- **Privileges:** in system mode, user processes run with the user's uid, gid and groups. File operations (`cp`, writing authorized_keys during pairing) are done by a `qshd` helper process running as the user, so root never opens paths the user controls. authorized_keys and the directories leading to it are checked following sshd's StrictModes rules.
- **Resource limits:** handshake and hello timeouts, connection and stream limits, 60 s idle timeout.
- **Disconnects:** if the client goes away, the session's whole process group gets SIGHUP, then SIGKILL after 2 s. Unlike ssh, a command without a PTY does not keep running unattended. On SIGINT/SIGTERM/SIGHUP the client closes the connection cleanly, so the server knows right away instead of waiting for the timeout.

This is a young project and has not had an external audit. For critical systems, keep regular ssh as a fallback way in.

## Limitations

- No PAM, utmp/wtmp or `systemd-logind` sessions (`loginctl` will not show the login).
- No agent forwarding, X11, `-R` or recursive `cp -r`.
- Linux/Unix only.

## Development

```sh
cargo test                        # unit tests and end-to-end tests (real qshd/qsh on loopback)
tests/system-mode.sh              # system mode (qshd as root): real root via sudo, or a user namespace without it
cargo clippy --all-targets -- -D warnings
python3 bench/bench.py            # benchmark against OpenSSH
```

To cut a release, push a `vX.Y.Z` tag. GitHub Actions builds static binaries and publishes the release.

## License

[GPL-3.0](LICENSE)
