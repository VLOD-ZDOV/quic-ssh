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
- pairing with a one-time code, so you never copy keys by hand;
- host aliases from your existing `~/.ssh/config` (`qsh myserver`).

## Installation

### Prebuilt binaries

Static Linux builds for x86_64 and aarch64 are on the [Releases](https://github.com/VLOD-ZDOV/quic-ssh/releases) page:

```sh
ARCH=$(uname -m)   # x86_64 or aarch64
curl -fsSL https://github.com/VLOD-ZDOV/quic-ssh/releases/latest/download/qsh-$ARCH-linux.tar.gz | tar xz
sudo install -m755 qsh-$ARCH-linux/qsh qsh-$ARCH-linux/qshd /usr/local/bin/
```

The same archive works for both client and server. Checksums are in `SHA256SUMS`.

### Android (Termux)

A native Android build (bionic libc, so DNS works) is in the releases as `qsh-aarch64-android`:

```sh
pkg install curl
curl -fsSL https://github.com/VLOD-ZDOV/quic-ssh/releases/latest/download/qsh-aarch64-android.tar.gz | tar xz
install -m755 qsh-aarch64-android/qsh qsh-aarch64-android/qshd $PREFIX/bin/
qsh pair user@server CODE      # then: qsh ui
```

Termux sends taps as mouse clicks, so `qsh ui` works by touch: tap a host to select it, tap it again to connect.

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
qsh keygen                             # create ~/.config/qsh/id_ed25519 (or: qsh keygen FILE)
qsh -f myserver                        # OpenSSH-compatible mode, see below
qsh ui                                 # host menu with status and speed test
```

The client key is chosen in this order: `-i FILE`, then the first Ed25519 `IdentityFile` from the config (see below), then `~/.ssh/id_ed25519`, then `~/.config/qsh/id_ed25519`. An encrypted key prompts for its passphrase.

### Host aliases (`~/.ssh/config`)

qsh reads your existing `~/.ssh/config`, so hosts you already use with ssh work by name:

```
# ~/.ssh/config
Host myserver
    HostName 203.0.113.10
    User root
    IdentityFile ~/.ssh/work_key
```

```sh
qsh myserver                        # = qsh -i ~/.ssh/work_key root@203.0.113.10
qsh cp backup.tar myserver:/srv/
```

From `~/.ssh/config` qsh takes `HostName`, `User` and `IdentityFile` (only Ed25519 keys; others are skipped). `Port` is ignored there, because it is the SSH port. For qsh-specific settings, including the port, use `~/.config/qsh/config` with the same syntax; its values take precedence:

```
# ~/.config/qsh/config
Host myserver
    Port 8080
```

Supported: `Host` patterns (`*`, `?`, `!`), `HostName`, `User`, `Port`, `IdentityFile`, `LocalForward`, `RequestTTY`, `Include`, `Match all`. Other `Match` blocks are skipped. Command-line values (`user@`, `:port`, `-p`, `-i`) always win.

### OpenSSH-compatible mode (`-f`, `--full`)

With `-f`, qsh behaves like a drop-in for `ssh`:

- It also reads `Port`, `LocalForward` and `RequestTTY` from `~/.ssh/config`. Without `-f`, these describe the ssh session and are ignored.
- It looks for qshd **both** on the ssh port (default 22) **and** on 4422, in parallel, and uses whichever answers. On 22, qshd can run UDP-only next to sshd (`tcp = false` in the server config). An explicit qsh port (`-p`, `:port` or `Port` in `~/.config/qsh/config`) means only that port is tried.
- If no qshd answers within 1 s, or the host is configured with `ProxyJump`/`ProxyCommand` (which qsh cannot do), qsh runs the regular **`ssh`** (or **`scp`** for `qsh -f cp`) with the same arguments. ssh then applies its whole config itself: agent, jump hosts, its own known_hosts.
- Hosts without qshd are remembered for an hour, so later connections go straight to ssh. `--transport quic` forces a new check.
- A wrong host key or a refused login never falls back to ssh.

```sh
qsh -f myserver                 # QUIC if qshd is there, otherwise plain ssh
qsh -f -v myserver              # prints which one was used
alias ssh='qsh -f'              # if you want it everywhere
```

### Host menu and speed test (`qsh ui`, `qsh speed`)

`qsh ui` opens an interactive menu of every host from `~/.ssh/config`, `~/.config/qsh/config` and known_hosts:

- **Live status:** each host is checked in the background for qshd (TLS handshake with a throwaway key, no login). The list shows `● quic 42 ms`, `● tcp` (UDP blocked) or `○ ssh` (no qshd), and whether the host key is known, new or changed.
- **⏎ / tap** connects with `qsh -f`, so hosts without qshd open with plain ssh. When the session ends you return to the menu.
- **`s`** runs a speed test with a speedometer: latency (5 pings), then 5 s download and 5 s upload, with a live needle and graph.
- **`p`** pairs with a code from `qshd pair`, **`/`** filters, **`r`** re-checks, **`q`** quits.
- The layout adapts to narrow phone screens, and the mouse and touch work (scroll, tap).

`qsh speed host` runs the same test in plain text:

```
$ qsh speed myserver
root@203.0.113.10:4422 over quic
ping          79.3 ms  (min 78.9, max 81.2)
download     107.2 Mbit/s  (64.0 MiB in 5.0 s)
upload        70.1 Mbit/s  (41.8 MiB in 5.0 s)
```

### Keystroke timing protection

In interactive sessions qsh hides the rhythm of your typing from anyone watching the network, like OpenSSH's `ObscureKeystrokeTiming`:

- **How it works:** while you type, packets leave on a fixed 20 ms clock and all have the same size. Ticks with nothing to send carry fake keystrokes ("chaff"), which also continue for a random 1–2 s after you stop, and the server answers chaff like a real echo. Pastes and command output are not affected.
- **Why it matters:** without it, the gaps between keystrokes are visible on the wire. Measured over many sessions, they can narrow down passwords typed inside the session (`sudo`, `su`) and show which commands are being typed.
- **Cost (measured):** keystrokes reach the server **10 ms later on average, at most 20 ms**. The first key after a pause is sent at once. While typing, about 6× more small packets (≈50/s each way, a few KB/s). There is no cost when idle and for bulk data.
- **Settings:** `ObscureKeystrokeTiming no` or `ObscureKeystrokeTiming interval:40` in `~/.config/qsh/config` (or `~/.ssh/config`). Only interactive sessions with a PTY are affected.

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
max_startups = 64               # unauthenticated connections at once (like sshd's MaxStartups)
max_startups_per_ip = 8         # ... from one IP address
tcp = true                      # false: UDP only, e.g. on port 22 next to sshd for `qsh -f`
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

**Real server over the internet** (median of 15 runs; transfers: 20 MiB, median of 3):

| | Connect + `true` | Upload | Download |
|---|---:|---:|---:|
| ssh / scp | 1000 ms | 53 Mbit/s | 53 Mbit/s |
| qsh (QUIC) | **309 ms** | 70 Mbit/s | **107 Mbit/s** |
| qsh (TCP fallback) | 337 ms | **107 Mbit/s** | 94 Mbit/s |

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
- **Resource limits:** handshake and hello timeouts, a limit on unauthenticated connections in total and per IP (like MaxStartups), connection and stream limits, 60 s idle timeout.
- **Port forwarding** in system mode connects as the user, not as root, so firewall rules based on uid apply. Accounts whose expiry date has passed (`chage -E`, `usermod -e`) are refused.
- **Disconnects:** if the client goes away, the session's whole process group gets SIGHUP, then SIGKILL after 2 s. Unlike ssh, a command without a PTY does not keep running unattended. On SIGINT/SIGTERM/SIGHUP the client closes the connection cleanly, so the server knows right away instead of waiting for the timeout.

All OpenSSH security advisories since 2006 have been checked against qsh. Each one is either not applicable, covered by a test that reproduces the attack, or fixed; see [docs/openssh-cve-review.md](docs/openssh-cve-review.md). Dependencies are checked with `cargo audit` in CI.

This is still a young project and has not had an external audit. For critical systems, keep regular ssh as a fallback way in.

## Limitations

- No PAM (2FA, `pam_access`, `pam_limits`), utmp/wtmp or `systemd-logind` sessions (`loginctl` will not show the login).
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
