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

ok() { echo "  ok   $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }
check() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }

cleanup() {
    [[ -n $SERVER_PID ]] && kill "$SERVER_PID" 2>/dev/null || true
    if [[ -z ${QSH_TEST_NS:-} ]]; then
        userdel -r qsh-alice 2>/dev/null || true
        userdel -r qsh-bob 2>/dev/null || true
        groupdel qsh-team 2>/dev/null || true
    fi
    rm -rf "$T"
}
trap cleanup EXIT

# --- test users -------------------------------------------------------------
if [[ -n ${QSH_TEST_NS:-} ]]; then
    mkdir -p "$T/home/alice" "$T/home/bob"
    cp /etc/passwd "$T/passwd"
    cp /etc/group "$T/group"
    cat >> "$T/passwd" <<EOF
qsh-alice:x:2001:2001::$T/home/alice:/bin/sh
qsh-bob:x:2002:2002::$T/home/bob:/bin/sh
EOF
    cat >> "$T/group" <<EOF
qsh-alice:x:2001:
qsh-bob:x:2002:
qsh-team:x:2010:qsh-alice
EOF
    mount --bind "$T/passwd" /etc/passwd
    mount --bind "$T/group" /etc/group
    chown 2001:2001 "$T/home/alice"
    chown 2002:2002 "$T/home/bob"
    chmod 700 "$T/home/alice" "$T/home/bob"
else
    groupadd qsh-team
    useradd -m -s /bin/sh -U qsh-alice
    useradd -m -s /bin/sh -U qsh-bob
    usermod -aG qsh-team qsh-alice
fi
ALICE_UID=$(id -u qsh-alice)
BOB_UID=$(id -u qsh-bob)
TEAM_GID=$(getent group qsh-team | cut -d: -f3)
ALICE_HOME=$(getent passwd qsh-alice | cut -d: -f6)
BOB_HOME=$(getent passwd qsh-bob | cut -d: -f6)

as_user() { local u=$1; shift; setpriv --reuid "$u" --regid "$u" --init-groups env HOME="$(getent passwd "$u" | cut -d: -f6)" "$@"; }

# --- server -------------------------------------------------------------------
# Binaries in a world-readable place, as after a normal install.
mkdir "$T/bin"
cp "$BIN_DIR/qsh" "$BIN_DIR/qshd" "$T/bin/"
chmod 755 "$T/bin" "$T/bin/qsh" "$T/bin/qshd"
QSH="$T/bin/qsh"
QSHD="$T/bin/qshd"
cat > "$T/config.toml" <<EOF
listen = "127.0.0.1:0"
host_key = "$T/host_ed25519"
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
