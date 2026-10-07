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
- port forwarding: local (`-L`), remote (`-R`), SOCKS proxy (`-D`), stdio (`-W`) and jump hosts (`-J`);
- file copy, including directories (`qsh cp -r`);
- the same command-line options as `ssh`, so `sftp`, `scp`, `rsync`, `git` and `sshfs` can run over qsh;
- **sessions that survive network outages:** after a lost connection, qsh reconnects by itself and the shell is still there, with the output you missed;
- key login with any SSH key (Ed25519, ECDSA, RSA, security keys), ssh-agent and agent forwarding (`-A`), OpenSSH user and host certificates;
- optional one-time codes (TOTP) as a second factor, without PAM;
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

### macOS

Client and server, for Apple Silicon (`aarch64`) and Intel (`x86_64`):

```sh
ARCH=$(uname -m | sed s/arm64/aarch64/)
curl -fsSL https://github.com/VLOD-ZDOV/quic-ssh/releases/latest/download/qsh-$ARCH-macos.tar.gz | tar xz
sudo install -m755 qsh-$ARCH-macos/qsh qsh-$ARCH-macos/qshd /usr/local/bin/
```

Downloaded with curl, the binaries carry no quarantine flag. If you download them with a browser, clear it with `xattr -d com.apple.quarantine qsh qshd`. To run qshd as a service, see `contrib/qshd.plist`. On macOS, account expiry is not checked, because macOS has no shadow database.

### Windows

The client, `qsh.exe`, is in `qsh-x86_64-windows.zip`. Unzip it to a folder on your `PATH`. qsh uses `%USERPROFILE%\.ssh` (keys, `config`, `known_hosts` markers) and `%USERPROFILE%\.config\qsh`, and it talks to the Windows OpenSSH agent service (`ssh-agent`) on its own. All features except `-f` are available. `--full` runs `ssh.exe` and waits for it. The Windows build is new and tested automatically; interactive use has seen less real-world testing than on Linux, so please report problems. The server, qshd, needs Linux, macOS or another Unix system.

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
qsh -N -R 8080:localhost:3000 host     # remote forward: host's port 8080 -> your port 3000
qsh -N -D 1080 host                    # SOCKS4/5 proxy on localhost:1080
qsh -J bastion user@internal           # through a jump host (both run qshd)
qsh -f -N -L 5432:db:5432 host         # log in, then go to the background
qsh -A host                            # forward your ssh-agent
qsh cp file.txt user@host:dir/         # upload
qsh cp user@host:logs/app.log .        # download
qsh cp -r project/ user@host:src/      # copy a directory (either direction)
qsh -p 2222 user@host                  # another port (or user@host:2222)
qsh --transport tcp user@host          # force TCP (or quic)
qsh -v user@host                       # show which transport is used
qsh -G myserver                        # print the resolved settings for a host
qsh keygen                             # create ~/.config/qsh/id_ed25519 (or: qsh keygen FILE)
qsh --full myserver                      # OpenSSH-compatible mode, see below
qsh ui                                 # host menu with status and speed test
```

Options work as in `ssh`: they can be combined (`-tt`, `-NL…`), placed after the host, and given with or without a space (`-p22`). Also supported: `-l user`, `-o Key=value`, `-F configfile`, `-4`/`-6`, `-q`, `-n`, `-s` (subsystem), `-g` (let other hosts use local forwards), `-e` (escape character), `-T`/`-t`/`-tt`. Other ssh flags are accepted and ignored (`-v` lists them).

In a session, `~.` at the start of a line disconnects, even when the server no longer responds; `~?` lists the escapes and `~~` sends a literal `~`.

### Keys, ssh-agent and certificates

qsh logs in with the same keys as ssh, in this order:

1. **The TLS handshake key:** the first Ed25519 key among `-i`, the config's `IdentityFile`s, `~/.ssh/id_ed25519` and `~/.config/qsh/id_ed25519`. If the server accepts it, the login takes no extra round trip.
2. **Otherwise, as in ssh:**
   - certificates (`<key>-cert.pub`, `CertificateFile`);
   - the keys in your ssh-agent (`SSH_AUTH_SOCK`, `IdentityAgent`; `IdentitiesOnly` is honoured);
   - key files of any type: `-i`/`IdentityFile`, or by default `~/.ssh/id_rsa`, `id_ecdsa`, `id_ed25519`.

   qsh first asks the server which keys it would accept, so a security key is only touched for a key that works. The signature is bound to the TLS session.

Security keys (`sk-ssh-ed25519`, `sk-ecdsa`) work through ssh-agent (`ssh-add ~/.ssh/id_ed25519_sk`). Encrypted keys prompt for their passphrase. `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE` work as in OpenSSH.

`-A` (or `ForwardAgent yes`) makes your agent available on the server through `SSH_AUTH_SOCK`. The socket sits in a private directory owned by you.

### Sessions that survive disconnects

A terminal session (a login shell, or a command with `-t`) is kept by the server for an hour after the connection is lost:

- qsh notices the loss within about 15 s, reconnects by itself, and shows the output you missed. Full-screen programs redraw.
- Wi-Fi to mobile switches, laptop sleep and short outages no longer kill your shell. Over QUIC, a change of address (NAT rebinding) usually needs no reconnect at all.
- Keys typed during an outage are dropped, and `~.` gives up waiting.
- Quitting normally (exit, `~.`, closing the terminal) ends the session on the server as usual.
- Turn it off with `PersistSession no` in `~/.config/qsh/config` (or `-o PersistSession=no`). Sessions with port or agent forwarding are not kept.
- `ServerAliveInterval` and `ServerAliveCountMax` set how quickly a dead connection is noticed. For other sessions they work as in ssh.

### Connection sharing (`ControlMaster`)

Like ssh, qsh can keep one connection and run later sessions, commands and copies to the same host through it, without a new handshake and login:

```
# ~/.config/qsh/config
Host *
    ControlMaster auto
    ControlPersist 10m
```

- `ControlMaster auto`: use a running master, or become one. `yes` (or `-M`) always becomes one. The default `no` uses a master only if `ControlPath` is set.
- `ControlPersist 10m` keeps the master in the background for 10 minutes after the last session (`yes` until `-O exit`). Without it the first qsh is the master and, when its own session ends, waits for the others.
- The socket is in `~/.config/qsh/ctl/` by default (`ControlPath`, or `-S path`; tokens `%h %p %r %C`). ssh's `ControlPath` is not used: those sockets speak ssh's protocol.
- `qsh -O check host`, `-O exit`, `-O stop` as in ssh.
- Runs with `-R` or `-A` use a connection of their own. A terminal session started through a master survives the master: qsh logs in by itself and resumes it.
- Not on Windows.

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

From `~/.ssh/config` qsh takes `HostName`, `User` and `IdentityFile`. `Port` is ignored there, because it is the SSH port. For qsh-specific settings, including the port, use `~/.config/qsh/config` with the same syntax; its values take precedence:

```
# ~/.config/qsh/config
Host myserver
    Port 8080
```

Supported: `Host` patterns (`*`, `?`, `!`), `HostName`, `User`, `Port`, `IdentityFile`, `LocalForward`, `RemoteForward`, `DynamicForward`, `RequestTTY`, `BatchMode`, `StrictHostKeyChecking`, `EscapeChar`, `AddressFamily`, `LogLevel`, `IdentitiesOnly`, `IdentityAgent`, `CertificateFile`, `ForwardAgent`, `ServerAliveInterval`, `ServerAliveCountMax`, `PersistSession` and `PredictiveEcho` (qsh only), `ControlMaster`, `ControlPersist`, `ControlPath` (in `~/.config/qsh/config`), `ProxyJump` (in `~/.config/qsh/config`), `Include`, `Match all`. Other `Match` blocks are skipped. Command-line values (`user@`, `:port`, `-p`, `-i`) always win.

### OpenSSH-compatible mode (`--full`)

With `--full` (automatic when qsh is installed as `ssh`), qsh behaves like a drop-in for `ssh`:

- It also reads `Port`, `LocalForward`, `RemoteForward`, `DynamicForward` and `RequestTTY` from `~/.ssh/config`. Without `--full`, these describe the ssh session and are ignored.
- It looks for qshd **both** on the ssh port (default 22) **and** on 4422, in parallel, and uses whichever answers. On 22, qshd can run UDP-only next to sshd (`tcp = false` in the server config). An explicit qsh port (`-p`, `:port` or `Port` in `~/.config/qsh/config`) means only that port is tried.
- If no qshd answers within 1 s, or `~/.ssh/config` gives the host a `ProxyJump`/`ProxyCommand` (the hops may not run qshd), qsh runs the regular **`ssh`** (or **`scp`** for `qsh --full cp`) with the same arguments. ssh then applies its whole config itself: agent, jump hosts, its own known_hosts.
- Hosts without qshd are remembered for an hour, so later connections go straight to ssh. `--transport quic` forces a new check.
- A wrong host key or a refused login never falls back to ssh.

```sh
qsh --full myserver               # QUIC if qshd is there, otherwise plain ssh
qsh --full -v myserver            # prints which one was used
```

### OpenSSH tools over qsh

Programs that run `ssh` underneath can use qsh instead:

```sh
sftp -S qsh user@host                         # needs sftp-server on the server (package openssh-sftp-server)
scp -S qsh file.txt user@host:dir/
rsync -a -e qsh project/ user@host:src/
GIT_SSH_COMMAND=qsh git clone user@host:repo.git
sshfs -o ssh_command=qsh user@host:/srv /mnt/srv
```

To make every program use qsh, install it as `ssh` earlier in your `PATH`. Run as `ssh`, qsh turns on `--full`, so hosts without qshd are still reached with the real ssh:

```sh
ln -s "$(command -v qsh)" ~/.local/bin/ssh
```

### Host menu and speed test (`qsh ui`, `qsh speed`)

`qsh ui` opens a connection menu with every host from `~/.ssh/config`, `~/.config/qsh/config`, known_hosts and the connections you saved in it:

- **Status:** each host is checked in the background for qshd (TLS handshake with a throwaway key, no login). The list shows `● quic 42 ms`, `● tcp` (UDP blocked) or `○ ssh` (no qshd), and whether the host key is known, new or changed. Results are cached for 10 minutes in `~/.config/qsh/ui-state.toml`, so reopening the menu does not contact every server again; **`r`** checks everything now.
- **Connecting:** **⏎ / tap** connects (with `--full` by default, so hosts without qshd open with plain ssh). When the session ends you return to the menu. Recently used hosts move to the top.
- **One-off connection:** **`c`** connects once to `user@host[:port]` without saving anything.
- **Saved connections:**
  - **`n`** adds one: name, address, user, port, key file, transport (auto/QUIC/TCP), and whether to fall back to ssh.
  - **`e`** edits a saved connection, and **`d`** deletes it.
  - They are stored in `~/.config/qsh/ui-hosts` (ssh_config syntax), so `qsh NAME` works on the command line too.
  - Your own config files are never written. For a host from them, **`e`** only changes the menu's settings (transport, ssh fallback), and a saved name cannot clash with a host of yours.
- **History:** **`Tab`** shows the history with the result of each connection. **⏎** connects again, **`a`** saves an entry as a connection, **`d`** removes it.
- **Speed test:** **`s`** runs it with a speedometer: latency (5 pings), then 5 s download and 5 s upload, with a live needle and graph.
- **Other keys:** **`p`** pairs with a code from `qshd pair`, **`/`** filters, **`q`** quits.
- **Screens:** the layout adapts to narrow phone screens, and the mouse and touch work (scroll, tap).

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

### Typing on slow links (echo prediction)

Like mosh, qsh shows what you type before the server's echo arrives, when echoes take longer than about 30 ms:

- qsh keeps a copy of the screen as the server drew it. A typed character is drawn at the cursor only on an empty cell, and only after an earlier keystroke on the same line came back exactly as predicted.
- Enter, arrows, Ctrl keys and the like start over: after a password prompt nothing is shown until the server itself echoes a character, so a hidden password is never drawn.
- When the server's output differs, the predicted characters are erased before it is shown, so the screen always ends up exactly as the server drew it.
- `PredictiveEcho auto` (default), `yes` (also on fast links) or `no`, in `~/.config/qsh/config` or with `-o`.

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
tcp = true                      # false: UDP only, e.g. on port 22 next to sshd for `qsh --full`
gateway_ports = "no"            # -R listens on loopback only; "yes": all addresses; "clientspecified"

max_auth_tries = 6              # failed key proofs per connection
allow_agent_forwarding = true
totp = "optional"               # one-time codes: "off", "optional" (for users who set them up), "required"
session_timeout = 3600          # seconds a disconnected terminal session is kept; 0 = off
# trusted_user_ca_keys = "/etc/qsh/user_ca.pub"   # CAs that sign user certificates (principal = user name)
# host_certificate = "/etc/qsh/host_ed25519-cert.pub"   # used automatically if it exists
# revoked_keys = "/etc/qsh/revoked_keys"   # keys that may not log in: a key list or a KRL (ssh-keygen -k)

[subsystems]                    # for `qsh -s` and sftp; run as `$SHELL -c command`
# sftp = "/usr/lib/openssh/sftp-server"   # found automatically if installed
```

Remote forwards (`-R`) listen where `gateway_ports` allows, and users other than root cannot listen on ports below 1024. `allow_tcp_forwarding = false` turns off `-L`, `-R`, `-D` and `-W`.

User keys live in `~/.config/qsh/authorized_keys` and, if enabled, `~/.ssh/authorized_keys`. All key types work, except DSA and RSA below 2048 bits. These options are enforced:

- `command=` (the original command goes to `SSH_ORIGINAL_COMMAND`; file transfer is refused);
- `from=` (addresses and CIDR);
- `restrict`, `no-pty`/`pty`, `no-port-forwarding`/`port-forwarding`, `no-agent-forwarding`/`agent-forwarding`;
- `permitopen=`, `permitlisten=`, `expiry-time=`;
- `cert-authority` with `principals=`;
- `no-touch-required`, `verify-required`.

A line with any other option is **not used at all**: a restriction qsh cannot enforce never turns into access.

**Certificates.** Sign keys with `ssh-keygen -s ca -I id -n USER key.pub`, then trust the CA either server-wide (`trusted_user_ca_keys`) or per user with a `cert-authority` line. `force-command`, `source-address` and the `permit-*` extensions are enforced. For host certificates, sign the host key (`ssh-keygen -s ca -I host -h -n host.example.com /etc/qsh/host_ed25519.pub`) and add `@cert-authority *.example.com <CA key>` to `~/.config/qsh/known_hosts` or `~/.ssh/known_hosts` on clients: hosts with a valid certificate are trusted without the first-connection question. `@revoked` lines are honoured.

**Revoking keys.** `revoked_keys` names a file with public keys (one per line) or a KRL made with `ssh-keygen -k`, which can also revoke certificates by serial number or key ID, and whole CAs. It is read at every login, so changes apply at once. If the file is set but cannot be read, no key is accepted.

**One-time codes (TOTP).** As the user on the server, run `qshd totp`. It shows a QR code for any authenticator app and turns codes on once you type one back. From then on, logins ask for a code after the key, and each code works only once. `qshd totp --disable` turns them off. With `totp = "required"`, accounts without codes cannot log in. Resuming a dropped session does not ask again.

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

**Memory** (RSS, OpenSSH 10.5 vs qsh; one session running a command):

| | ssh / sshd | qsh / qshd |
|---|---:|---:|
| Server, idle | 8.6 MB | 7.5 MB |
| Server, extra per session | +23 MB | +3–5 MB |
| Client during a session | 11–13 MB | 9 MB |
| Client, peak while sending 1 GiB | 11 MB | 17 MB |

sshd starts separate processes for each connection; qshd serves all sessions in one process. The per-session figures include the remote command itself (about 1–2 MB).

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
- **The client** logs in with mutual TLS using its Ed25519 key, or after the handshake with a signature by any SSH key or certificate over data bound to the TLS session. Either way, the login cannot be relayed to another connection. There are no passwords at all. A second factor (TOTP) can be added.
- **Pairing** uses SPAKE2 over the code plus key confirmation bound to the TLS session (exporter) and both keys. A man in the middle can neither brute-force the code offline nor relay the proof. The code is single-use (burned after the first attempt, even a failed one) and expires after 10 minutes.
- **Privileges:** in system mode, user processes run with the user's uid, gid and groups. File operations (`cp`, writing authorized_keys during pairing) are done by a `qshd` helper process running as the user, so root never opens paths the user controls. Like sshd, file transfers and subsystems (sftp) start through the user's login shell, so `nologin` or `git-shell` also block them. authorized_keys and the directories leading to it are checked following sshd's StrictModes rules.
- **Resource limits:** handshake and hello timeouts, a limit on unauthenticated connections in total and per IP (like MaxStartups), connection and stream limits, 60 s idle timeout.
- **Directory copy** (`cp -r`) unpacks only regular files and directories. Absolute paths, `..`, links and device files are refused, and setuid/setgid bits are dropped, so a malicious server cannot write outside the target directory.
- **Port forwarding** in system mode connects as the user, not as root, so firewall rules based on uid apply. Accounts whose expiry date has passed (`chage -E`, `usermod -e`) are refused.
- **Disconnects:** a command without a terminal is stopped when its client goes away: its whole process group gets SIGHUP, then SIGKILL after 2 s. Unlike ssh, it does not keep running unattended. A terminal session is kept for `session_timeout` so the client can resume it; only a client of the same user that holds the session's 128-bit token can do that. On SIGINT/SIGTERM/SIGHUP the client ends the session and closes the connection cleanly.
- **Agent forwarding** uses a socket in a fresh private directory owned by the user. Connections from other users are refused (checked with `SO_PEERCRED`). The socket is removed when the client disconnects.

All OpenSSH security advisories since 2006 have been checked against qsh. Each one is either not applicable, covered by a test that reproduces the attack, or fixed; see [docs/openssh-cve-review.md](docs/openssh-cve-review.md). Dependencies are checked with `cargo audit` in CI.

This is still a young project and has not had an external audit. For critical systems, keep regular ssh as a fallback way in.

## Limitations

- No PAM (`pam_access`, `pam_limits`), utmp/wtmp or `systemd-logind` sessions (`loginctl` will not show the login). 2FA is built in (TOTP).
- No X11 or tunnels (`-w`).
- Security keys only through ssh-agent; no PKCS#11 in qsh itself (use the agent for that too).
- As with scp and sftp, a shell startup file that prints text for non-interactive shells (e.g. `~/.zshenv`) breaks `qsh cp`.
- `-J` works only when every hop runs qshd; with `--full`, `ProxyJump`/`ProxyCommand` hosts are handed to ssh.
- qshd runs on Linux, macOS and other Unix systems; on Windows there is only the client.

### Upgrading

qsh 0.5 works with qshd 0.4 and newer. Keys other than the Ed25519 TLS key, agent forwarding, one-time codes, host certificates and persistent sessions need qshd 0.5. qsh 0.4 and 0.5 need at least qshd 0.4: older servers reject them with "unsupported protocol version", so update qshd first. qshd 0.5 still accepts older clients.

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
