#!/usr/bin/env bash
# End-to-end test of qshd's system mode (running as root, switching to the
# logged-in user). Usage: tests/system-mode.sh [BIN_DIR]  (default target/debug)
#
# As real root (e.g. `sudo` in CI) it creates two temporary users with useradd
# and removes them afterwards. As a regular user it re-runs itself inside a
# user + mount namespace (needs newuidmap and an /etc/subuid range): there it is
# root, other uids are mapped from /etc/subuid, and the test users are added to
# private copies of /etc/passwd and /etc/group. The host system is not changed.
set -euo pipefail

BIN_DIR=$(cd "${1:-target/debug}" && pwd)

if [[ $EUID -ne 0 ]]; then
    me=$(id -un)
    subuid=$(grep "^$me:" /etc/subuid | cut -d: -f2) || { echo "no /etc/subuid range for $me" >&2; exit 1; }
    subgid=$(grep "^$me:" /etc/subgid | cut -d: -f2) || { echo "no /etc/subgid range for $me" >&2; exit 1; }
    exec unshare --map-root-user --map-users="1:$subuid:65535" --map-groups="1:$subgid:65535" \
        --setgroups allow --mount env QSH_TEST_NS=1 "$0" "$BIN_DIR"
fi

T=$(mktemp -d)
chmod 755 "$T"
PASS=0
FAIL=0
SERVER_PID=
JAIL=

ok() { echo "  ok   $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }
check() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }

cleanup() {
    [[ -n $SERVER_PID ]] && kill "$SERVER_PID" 2>/dev/null || true
    if [[ -z ${QSH_TEST_NS:-} ]]; then
        userdel -r qsh-alice 2>/dev/null || true
        userdel -r qsh-bob 2>/dev/null || true
        userdel -r qsh-nol 2>/dev/null || true
        groupdel qsh-team 2>/dev/null || true
    fi
    [[ -n ${JAIL:-} ]] && rm -rf "$JAIL"
    rm -rf "$T"
}
trap cleanup EXIT

# --- test users -------------------------------------------------------------
# qsh-nol has a nologin shell: like with sshd, that must also block file access.
NOLOGIN=/bin/false
for p in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin; do [[ -x $p ]] && { NOLOGIN=$p; break; }; done
if [[ -n ${QSH_TEST_NS:-} ]]; then
    mkdir -p "$T/home/alice" "$T/home/bob" "$T/home/nol"
    cp /etc/passwd "$T/passwd"
    cp /etc/group "$T/group"
    cat >> "$T/passwd" <<EOF
qsh-alice:x:2001:2001::$T/home/alice:/bin/sh
qsh-bob:x:2002:2002::$T/home/bob:/bin/sh
qsh-nol:x:2003:2003::$T/home/nol:$NOLOGIN
EOF
    cat >> "$T/group" <<EOF
qsh-alice:x:2001:
qsh-bob:x:2002:
qsh-nol:x:2003:
qsh-team:x:2010:qsh-alice
EOF
    mount --bind "$T/passwd" /etc/passwd
    mount --bind "$T/group" /etc/group
    chown 2001:2001 "$T/home/alice"
    chown 2002:2002 "$T/home/bob"
    chown 2003:2003 "$T/home/nol"
    chmod 700 "$T/home/alice" "$T/home/bob" "$T/home/nol"
else
    groupadd qsh-team
    useradd -m -s /bin/sh -U qsh-alice
    useradd -m -s /bin/sh -U qsh-bob
    useradd -m -s "$NOLOGIN" -U qsh-nol
    usermod -aG qsh-team qsh-alice
fi
ALICE_UID=$(id -u qsh-alice)
BOB_UID=$(id -u qsh-bob)
TEAM_GID=$(getent group qsh-team | cut -d: -f3)
ALICE_HOME=$(getent passwd qsh-alice | cut -d: -f6)
BOB_HOME=$(getent passwd qsh-bob | cut -d: -f6)
NOL_UID=$(id -u qsh-nol)
NOL_HOME=$(getent passwd qsh-nol | cut -d: -f6)

as_user() { local u=$1; shift; setpriv --reuid "$u" --regid "$u" --init-groups env HOME="$(getent passwd "$u" | cut -d: -f6)" "$@"; }

# --- server -------------------------------------------------------------------
# Binaries in a world-readable place, as after a normal install.
mkdir "$T/bin"
cp "$BIN_DIR/qsh" "$BIN_DIR/qshd" "$T/bin/"
chmod 755 "$T/bin" "$T/bin/qsh" "$T/bin/qshd"
QSH="$T/bin/qsh"
QSHD="$T/bin/qshd"
mkdir -m 1777 "$T/shared"
cat > "$T/config.toml" <<EOF
listen = "127.0.0.1:0"
host_key = "$T/host_ed25519"
# The checks below fail logins on purpose.
per_source_penalties = false

[subsystems]
probe = "touch $T/shared/probe-\$USER"
EOF
"$QSHD" -c "$T/config.toml" serve 2> "$T/server.log" &
SERVER_PID=$!
for _ in $(seq 100); do
    PORT=$(sed -n 's/.*listening on 127.0.0.1:\([0-9]*\).*/\1/p' "$T/server.log")
    [[ -n $PORT ]] && break
    sleep 0.1
done
[[ -n $PORT ]] || { cat "$T/server.log"; echo "server did not start" >&2; exit 1; }

# Client runs as root with its own HOME; what matters is the remote user.
mkdir -p "$T/client"
q() { HOME="$T/client" "$QSH" --accept-new-host -p "$PORT" "$@" < /dev/null; }

echo "system mode test ($([[ -n ${QSH_TEST_NS:-} ]] && echo "user namespace" || echo "real root")), port $PORT"

# --- pairing ------------------------------------------------------------------
CODE=$(as_user qsh-alice "$QSHD" pair | awk '/Pairing code/{print $3}')
check "pairing as qsh-alice" q pair qsh-alice@127.0.0.1 "$CODE"
AK="$ALICE_HOME/.config/qsh/authorized_keys"
check "paired key stored as alice, mode 600" \
    test "$(stat -c '%u %a' "$AK" 2>/dev/null)" = "$ALICE_UID 600"

# --- identity and privileges ----------------------------------------------------
OUT=$(q qsh-alice@127.0.0.1 id 2>&1 || true)
check "runs as alice's uid" grep -q "uid=$ALICE_UID(qsh-alice)" <<<"$OUT"
check "has supplementary group qsh-team" grep -q "$TEAM_GID(qsh-team)" <<<"$OUT"
check "no root group" bash -c "! grep -qE '[=,]0\(' <<<'$OUT'"
OUT=$(q qsh-alice@127.0.0.1 "grep -E '^(CapEff|CapPrm|CapBnd)' /proc/self/status | head -2" 2>&1 || true)
check "no effective/permitted capabilities" bash -c "[[ \$(grep -c '0000000000000000' <<<'$OUT') -eq 2 ]]"
OUT=$(q qsh-alice@127.0.0.1 'echo "$HOME|$USER|$(pwd)"' 2>&1 || true)
check "HOME, USER and cwd are alice's" test "$OUT" = "$ALICE_HOME|qsh-alice|$ALICE_HOME"
# Only stdin, stdout and stderr (and ls's own listing): nothing of qshd's,
# such as another session's terminal, reaches a user's program.
OUT=$(q qsh-alice@127.0.0.1 'ls /proc/self/fd' 2>&1 | tr '\n' ' ' || true)
check "no descriptors inherited from qshd" test "$OUT" = "0 1 2 3 "

# --- authorization ----------------------------------------------------------------
check "alice's key cannot log in as bob" bash -c "! HOME='$T/client' '$QSH' -p $PORT qsh-bob@127.0.0.1 true </dev/null 2>/dev/null"
install -d -m 700 -o "$BOB_UID" -g "$BOB_UID" "$BOB_HOME/.config" "$BOB_HOME/.config/qsh"
# A symlink to a file that contains the key must not be followed.
cp "$AK" "$T/linked_keys"
chmod 644 "$T/linked_keys"
ln -s "$T/linked_keys" "$BOB_HOME/.config/qsh/authorized_keys"
chown -h "$BOB_UID:$BOB_UID" "$BOB_HOME/.config/qsh/authorized_keys"
check "symlinked authorized_keys is refused" bash -c "! HOME='$T/client' '$QSH' -p $PORT qsh-bob@127.0.0.1 true </dev/null 2>/dev/null"
rm "$BOB_HOME/.config/qsh/authorized_keys"
install -o "$BOB_UID" -g "$BOB_UID" -m 664 "$AK" "$BOB_HOME/.config/qsh/authorized_keys"
check "group-writable authorized_keys is refused" bash -c "! HOME='$T/client' '$QSH' -p $PORT qsh-bob@127.0.0.1 true </dev/null 2>/dev/null"
chmod 600 "$BOB_HOME/.config/qsh/authorized_keys"
OUT=$(q qsh-bob@127.0.0.1 id -u 2>&1 || true)
check "bob logs in once the file is safe" test "$OUT" = "$BOB_UID"
if [[ -n ${QSH_TEST_NS:-} ]]; then
    echo "  skip expired account is refused (needs real root and /etc/shadow)"
else
    usermod -e 1 qsh-bob
    check "expired account is refused" bash -c "! HOME='$T/client' '$QSH' -p $PORT qsh-bob@127.0.0.1 true </dev/null 2>/dev/null"
    usermod -e '' qsh-bob
fi

# --- file copy ----------------------------------------------------------------------
head -c 3000000 /dev/urandom > "$T/payload"
check "upload to alice's home" q cp "$T/payload" qsh-alice@127.0.0.1:up.bin
check "uploaded file belongs to alice" test "$(stat -c %u "$ALICE_HOME/up.bin" 2>/dev/null)" = "$ALICE_UID"
check "uploaded content intact" cmp -s "$T/payload" "$ALICE_HOME/up.bin"
check "download alice's file" q cp qsh-alice@127.0.0.1:up.bin "$T/down.bin"
check "downloaded content intact" cmp -s "$T/payload" "$T/down.bin"
mkdir "$T/rootonly"
chmod 755 "$T/rootonly"
check "upload into a root-owned dir is denied" bash -c "! HOME='$T/client' '$QSH' cp -p $PORT '$T/payload' 'qsh-alice@127.0.0.1:$T/rootonly/' 2>/dev/null"
check "nothing was written there" test -z "$(ls -A "$T/rootonly")"
echo "top secret" > "$T/secret"
chmod 600 "$T/secret"
check "download of a root-only file is denied" bash -c "! HOME='$T/client' '$QSH' cp -p $PORT 'qsh-alice@127.0.0.1:$T/secret' '$T/stolen' 2>/dev/null"
check "no file was created locally" test ! -e "$T/stolen"
check "alice cannot read bob's home" bash -c "! HOME='$T/client' '$QSH' cp -p $PORT 'qsh-alice@127.0.0.1:$BOB_HOME/.config/qsh/authorized_keys' '$T/x' 2>/dev/null"

# --- restricted shells ----------------------------------------------------------------
install -d -m 700 -o "$NOL_UID" -g "$NOL_UID" "$NOL_HOME/.config" "$NOL_HOME/.config/qsh"
install -o "$NOL_UID" -g "$NOL_UID" -m 600 "$AK" "$NOL_HOME/.config/qsh/authorized_keys"
q -s qsh-alice@127.0.0.1 probe >/dev/null 2>&1 || true
check "subsystems run (through the user's shell)" test -e "$T/shared/probe-qsh-alice"
check "nologin user cannot run commands" bash -c "! HOME='$T/client' '$QSH' -p $PORT qsh-nol@127.0.0.1 true </dev/null &>/dev/null"
HOME="$T/client" "$QSH" -p "$PORT" -s qsh-nol@127.0.0.1 probe </dev/null >/dev/null 2>&1 || true
check "nologin user cannot run subsystems" test ! -e "$T/shared/probe-qsh-nol"
check "nologin user gets no sftp subsystem" bash -c "! HOME='$T/client' '$QSH' -p $PORT -s qsh-nol@127.0.0.1 sftp </dev/null &>/dev/null"
check "internal-sftp as a client command goes to the shell" bash -c "! HOME='$T/client' '$QSH' -p $PORT qsh-nol@127.0.0.1 internal-sftp </dev/null &>/dev/null"
check "nologin user cannot upload" bash -c "! HOME='$T/client' '$QSH' cp -p $PORT '$T/payload' qsh-nol@127.0.0.1:up.bin 2>/dev/null"
check "nothing was written to its home" test ! -e "$NOL_HOME/up.bin"
echo hidden > "$NOL_HOME/file"
chown "$NOL_UID:$NOL_UID" "$NOL_HOME/file"
check "nologin user cannot download" bash -c "! HOME='$T/client' '$QSH' cp -p $PORT qsh-nol@127.0.0.1:file '$T/nol-file' 2>/dev/null"
check "nologin user cannot download trees" bash -c "! HOME='$T/client' '$QSH' cp -r -p $PORT qsh-nol@127.0.0.1:.config '$T/nol-tree' 2>/dev/null"

# --- port forwarding runs as the user (compare CVE-2016-10010) ------------------------
# A listener that reports its port and holds one connection open, silently.
python3 - "$T/fwd_port" <<'PY' &
import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(1)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
c, _ = s.accept()
time.sleep(60)
PY
LISTENER_PID=$!
for _ in $(seq 50); do [[ -s "$T/fwd_port" ]] && break; sleep 0.1; done
FWD_TARGET=$(cat "$T/fwd_port")
FWD_LOCAL=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
HOME="$T/client" "$QSH" -p "$PORT" -N -L "$FWD_LOCAL:127.0.0.1:$FWD_TARGET" qsh-alice@127.0.0.1 < /dev/null 2>/dev/null &
FWD_PID=$!
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$FWD_LOCAL) 2>/dev/null && break; sleep 0.1; done
exec 3<>"/dev/tcp/127.0.0.1/$FWD_LOCAL"
sleep 0.5
# Owner uid (field 8 of /proc/net/tcp) of the socket that connected to the listener.
TARGET_HEX=$(printf '%04X' "$FWD_TARGET")
FWD_UID=$(awk -v p=":$TARGET_HEX" '$3 ~ p"$" && $4 == "01" {print $8; exit}' /proc/net/tcp)
check "forwarded connection is made as alice, not root" test "$FWD_UID" = "$ALICE_UID"
# A quiet forwarded connection must not stall the server (the helper once
# copied with splice(), which kept the pipe that qshd reads locked).
check "server answers while a forwarded connection is quiet" \
    timeout 10 env HOME="$T/client" "$QSH" -p "$PORT" qsh-alice@127.0.0.1 true < /dev/null
exec 3>&-
kill "$FWD_PID" "$LISTENER_PID" 2>/dev/null || true

# --- agent forwarding ------------------------------------------------------------------
if command -v ssh-agent >/dev/null && command -v ssh-add >/dev/null; then
    ssh-keygen -q -t ecdsa -N '' -C fwd-test -f "$T/agent_key"
    ssh-agent -D -a "$T/agent.sock" >/dev/null 2>&1 &
    AGENT_PID=$!
    for _ in $(seq 50); do [[ -S "$T/agent.sock" ]] && break; sleep 0.1; done
    SSH_AUTH_SOCK="$T/agent.sock" ssh-add -q "$T/agent_key" 2>/dev/null
    OUT=$(SSH_AUTH_SOCK="$T/agent.sock" q -A qsh-alice@127.0.0.1 'stat -c "SOCK=%u:%a" "$SSH_AUTH_SOCK"; stat -c "DIR=%u:%a" "$(dirname "$SSH_AUTH_SOCK")"; ssh-add -l' 2>&1 || true)
    check "forwarded agent socket belongs to alice, mode 600" grep -q "SOCK=$ALICE_UID:600" <<<"$OUT"
    check "its directory belongs to alice, mode 700" grep -q "DIR=$ALICE_UID:700" <<<"$OUT"
    check "the client's agent is reachable through it" grep -q "fwd-test" <<<"$OUT"
    kill "$AGENT_PID" 2>/dev/null || true
else
    echo "  skip agent forwarding (no ssh-agent)"
fi

# --- remote forwarding limits --------------------------------------------------------
OUT=$(HOME="$T/client" timeout 10 "$QSH" -p "$PORT" -o ExitOnForwardFailure=yes -N -R 80:127.0.0.1:9 qsh-alice@127.0.0.1 </dev/null 2>&1 || true)
check "non-root user cannot listen on a privileged port (-R 80)" grep -q "only root may listen" <<<"$OUT"

# --- Unix socket forwarding as the user -------------------------------------------------
HOME="$T/client" timeout 20 "$QSH" -p "$PORT" -o ExitOnForwardFailure=yes -N -R "$T/shared/alice-fwd.sock:127.0.0.1:9" qsh-alice@127.0.0.1 </dev/null >/dev/null 2>&1 &
FWD_CLIENT=$!
for _ in $(seq 100); do [[ -S $T/shared/alice-fwd.sock ]] && break; sleep 0.1; done
check "-R socket belongs to alice, mode 600" test "$(stat -c '%u %a' "$T/shared/alice-fwd.sock" 2>/dev/null)" = "$ALICE_UID 600"
kill "$FWD_CLIENT" 2>/dev/null || true
wait "$FWD_CLIENT" 2>/dev/null || true
install -d -m 700 "$T/rootsock"
python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); import time; time.sleep(30)" "$T/rootsock/s" &
SOCK_SERVER=$!
for _ in $(seq 50); do [[ -S $T/rootsock/s ]] && break; sleep 0.1; done
OUT=$(HOME="$T/client" timeout 10 "$QSH" -p "$PORT" -W "$T/rootsock/s" qsh-alice@127.0.0.1 </dev/null 2>&1 || true)
check "alice cannot reach root's socket (-W /path)" grep -qi "permission denied" <<<"$OUT"
kill "$SOCK_SERVER" 2>/dev/null || true

# --- PTY ------------------------------------------------------------------------------
# `script` gives qsh a terminal; markers keep the values apart from terminal noise.
OUT=$(HOME="$T/client" script -qec "'$QSH' -t -p $PORT qsh-alice@127.0.0.1 'echo TTY=\$(stat -c %u:%g:%a \$(tty)) UID=\$(id -u)'" /dev/null < /dev/null || true)
[[ -n ${QSH_DEBUG:-} ]] && { echo "PTY OUTPUT:"; cat -v <<<"$OUT"; }
if [[ -n ${QSH_TEST_NS:-} ]]; then
    # devpts belongs to the host namespace, so the terminal cannot be chowned here.
    echo "  skip pty owned by alice, group tty, mode 620 (needs real root)"
else
    TTY_GID=$(getent group tty | cut -d: -f3)
    check "pty owned by alice, group tty, mode 620" grep -q "TTY=$ALICE_UID:$TTY_GID:620 " <<<"$OUT"
fi
check "pty session runs as alice" grep -qE "UID=$ALICE_UID\b" <<<"$OUT"
if [[ -z ${QSH_TEST_NS:-} && -f /var/log/wtmp ]] && command -v last >/dev/null; then
    check "the terminal login is in wtmp (last)" bash -c "last -w | grep -q '^qsh-alice '"
    OUT=$( (sleep 3; printf 'exit\n') | HOME="$T/client" timeout 15 script -qec "'$QSH' -tt -p $PORT qsh-alice@127.0.0.1" /dev/null 2>&1 || true)
    [[ -n ${QSH_DEBUG:-} ]] && { echo "LOGIN SHELL OUTPUT:"; cat -v <<<"$OUT"; }
    check "a login shell shows the last login" grep -q "Last login:" <<<"$OUT"
else
    echo "  skip login records (need real root and /var/log/wtmp)"
fi

# --- password authentication (after a config reload) --------------------------------------
PW_HASH=$(openssl passwd -6 -salt qshtest 'correct horse')
if [[ -n ${QSH_TEST_NS:-} ]]; then
    { grep -v '^qsh-bob:' /etc/shadow 2>/dev/null || true; echo "qsh-bob:$PW_HASH:19000:0:99999:7:::"; } > "$T/shadow"
    chmod 600 "$T/shadow"
    mount --bind "$T/shadow" /etc/shadow
else
    usermod -p "$PW_HASH" qsh-bob
fi
cat >> "$T/config.toml" <<EOF

[[match]]
user = "qsh-bob"
password_authentication = true
EOF
kill -HUP "$SERVER_PID"
sleep 0.5
mkdir -p "$T/client-pw"
printf '#!/bin/sh\necho "$QSH_TEST_PASSWORD"\n' > "$T/askpass"
chmod 755 "$T/askpass"
pw_login() {
    HOME="$T/client-pw" SSH_ASKPASS="$T/askpass" SSH_ASKPASS_REQUIRE=force QSH_TEST_PASSWORD="$1" \
        "$QSH" --accept-new-host -p "$PORT" qsh-bob@127.0.0.1 id -u </dev/null 2>/dev/null
}
check "password login with the right password" test "$(pw_login 'correct horse')" = "$BOB_UID"
OUT=$(pw_login 'wrong horse' || true)
check "a wrong password is refused" test -z "$OUT"
check "no password for users without it enabled" bash -c "! HOME='$T/client-pw' SSH_ASKPASS='$T/askpass' SSH_ASKPASS_REQUIRE=force QSH_TEST_PASSWORD=x '$QSH' -p $PORT qsh-alice@127.0.0.1 true </dev/null 2>/dev/null"

# --- tunnel devices (-w) ---------------------------------------------------------------------
if [[ -n ${QSH_TEST_NS:-} || ! -c /dev/net/tun ]] || ! command -v ip >/dev/null; then
    echo "  skip tunnel devices (need real root and /dev/net/tun)"
else
    cat >> "$T/config.toml" <<EOF

[[match]]
user = "qsh-alice"
permit_tunnel = "point-to-point"
EOF
    kill -HUP "$SERVER_PID"
    sleep 0.5
    HOME="$T/client" timeout 30 "$QSH" -p "$PORT" -o ExitOnForwardFailure=yes -w 101:102 -N qsh-alice@127.0.0.1 </dev/null >/dev/null 2>"$T/tun.err" &
    TUN_CLIENT=$!
    for _ in $(seq 100); do [[ -e /sys/class/net/tun101 && -e /sys/class/net/tun102 ]] && break; sleep 0.1; done
    check "-w creates both tunnel devices" test -e /sys/class/net/tun101 -a -e /sys/class/net/tun102
    ip link set tun101 up 2>/dev/null || true
    ip link set tun102 up 2>/dev/null || true
    ip addr add 10.211.0.1/30 dev tun101 2>/dev/null || true
    RX_BEFORE=$(cat /sys/class/net/tun102/statistics/rx_packets 2>/dev/null || echo 0)
    ping -c 3 -W 1 -I tun101 10.211.0.2 >/dev/null 2>&1 || true
    RX_AFTER=$(cat /sys/class/net/tun102/statistics/rx_packets 2>/dev/null || echo 0)
    check "packets into one device come out of the other" test "$RX_AFTER" -gt "$RX_BEFORE"
    OUT=$(HOME="$T/client" timeout 10 "$QSH" -p "$PORT" -o Tunnel=ethernet -o ExitOnForwardFailure=yes -w any:any -N qsh-alice@127.0.0.1 </dev/null 2>&1 || true)
    check "an ethernet tunnel is refused by point-to-point" grep -q "not allowed" <<<"$OUT"
    kill "$TUN_CLIENT" 2>/dev/null || true
    wait "$TUN_CLIENT" 2>/dev/null || true
    [[ -n ${QSH_DEBUG:-} ]] && cat "$T/tun.err"
fi

# --- chroot_directory and internal-sftp (after a config reload) -----------------------------
if [[ -n ${QSH_TEST_NS:-} ]] || ! command -v sftp >/dev/null; then
    # In the namespace, / belongs to an unmapped uid, so no path passes the ownership check.
    echo "  skip chroot_directory and internal-sftp (need real root and sftp)"
else
    JAIL=$(mktemp -d -p / qsh-jail.XXXXXX)
    chmod 755 "$JAIL"
    install -d -o "$NOL_UID" -g "$NOL_UID" "$JAIL/upload"
    install -d -o "$BOB_UID" -g "$BOB_UID" "$JAIL/bob"
    cat >> "$T/config.toml" <<EOF

[[match]]
user = "qsh-nol"
chroot_directory = "$JAIL"
force_command = "internal-sftp"

[[match]]
user = "qsh-bob"
chroot_directory = "$JAIL"
EOF
    kill -HUP "$SERVER_PID"
    sleep 0.5
    echo "in jail" > "$T/jail-src"
    printf 'put %s upload/in.txt\nls /\n' "$T/jail-src" > "$T/batch"
    OUT=$(HOME="$T/client" sftp -S "$QSH" -P "$PORT" -b "$T/batch" qsh-nol@127.0.0.1 2>&1 </dev/null || true)
    [[ -n ${QSH_DEBUG:-} ]] && { echo "SFTP OUTPUT:"; cat <<<"$OUT"; }
    check "nologin user gets internal-sftp in the chroot" cmp -s "$T/jail-src" "$JAIL/upload/in.txt"
    check "the upload belongs to the user" test "$(stat -c %u "$JAIL/upload/in.txt" 2>/dev/null)" = "$NOL_UID"
    printf 'get /etc/passwd %s\n' "$T/escaped" > "$T/batch"
    HOME="$T/client" sftp -S "$QSH" -P "$PORT" -b "$T/batch" qsh-nol@127.0.0.1 </dev/null >/dev/null 2>&1 || true
    check "files outside the chroot are out of reach (sftp)" test ! -e "$T/escaped"
    check "qsh cp into a chroot lands inside it" q cp "$T/jail-src" qsh-bob@127.0.0.1:/bob/x.txt
    check "... in the jail directory" cmp -s "$T/jail-src" "$JAIL/bob/x.txt"
    check "files outside the chroot are out of reach (cp)" bash -c "! HOME='$T/client' '$QSH' cp -p $PORT 'qsh-bob@127.0.0.1:/etc/passwd' '$T/escaped2' 2>/dev/null"
    # Unix socket forwarding happens inside the chroot too.
    python3 -c "import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); c,_=s.accept(); c.sendall(b'outside\n'); time.sleep(5)" "$T/shared/open.sock" &
    OPEN_SERVER=$!
    for _ in $(seq 50); do [[ -S $T/shared/open.sock ]] && break; sleep 0.1; done
    chmod 777 "$T/shared/open.sock"
    OUT=$(HOME="$T/client" timeout 10 "$QSH" -p "$PORT" -W "$T/shared/open.sock" qsh-bob@127.0.0.1 </dev/null 2>&1 || true)
    check "sockets outside the chroot are out of reach (-W)" test "$(grep -c outside <<<"$OUT")" = 0
    kill "$OPEN_SERVER" 2>/dev/null || true
    HOME="$T/client" timeout 20 "$QSH" -p "$PORT" -o ExitOnForwardFailure=yes -N -R "/bob/r.sock:127.0.0.1:9" qsh-bob@127.0.0.1 </dev/null >/dev/null 2>&1 &
    FWD_CLIENT=$!
    for _ in $(seq 100); do [[ -S $JAIL/bob/r.sock ]] && break; sleep 0.1; done
    check "-R sockets are made inside the chroot" test -S "$JAIL/bob/r.sock"
    kill "$FWD_CLIENT" 2>/dev/null || true
    wait "$FWD_CLIENT" 2>/dev/null || true
    chmod 775 "$JAIL"
    check "a group-writable chroot is refused" bash -c "! HOME='$T/client' '$QSH' cp -p $PORT '$T/jail-src' qsh-bob@127.0.0.1:/bob/y.txt 2>/dev/null"
    check "... and nothing is written there" test ! -e "$JAIL/bob/y.txt"
fi

# --- pairing hardening ------------------------------------------------------------------
as_user qsh-bob ln -s /nonexistent "$BOB_HOME/.config/qsh/pending_pair"
check "symlinked pending_pair is refused" bash -c "! HOME='$T/client' '$QSH' pair -p $PORT qsh-bob@127.0.0.1 aaaa-bbbb </dev/null 2>/dev/null"
check "unknown user gets the generic pairing error" bash -c "HOME='$T/client' '$QSH' pair -p $PORT qsh-nobody-here@127.0.0.1 aaaa-bbbb </dev/null 2>&1 | grep -q 'no active pairing code'"

echo
echo "passed: $PASS, failed: $FAIL"
if [[ $FAIL -ne 0 ]]; then
    echo "--- server log"
    cat "$T/server.log"
    exit 1
fi
