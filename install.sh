#!/bin/sh
# qsh installer for Linux, macOS and Termux:
#   curl -fsSL https://github.com/VLOD-ZDOV/quic-ssh/releases/latest/download/install.sh | sh
# Asks what to install. Without a terminal, or to skip the questions:
#   ... | sh -s -- --client | --server [--service | --no-service]
# QSH_VERSION=v1.0.2 picks a release (default: the latest), QSH_BIN_DIR the install directory.
set -eu

REPO=VLOD-ZDOV/quic-ssh

say() { printf '%s\n' "$*"; }
die() { printf 'qsh install: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: install.sh [--client | --server | --update] [--service | --no-service]
  --client      install qsh only
  --update      update what is installed in QSH_BIN_DIR (what qsh update runs)
  --server      install qsh and qshd
  --service     run qshd as a service that starts at boot
  --no-service  do not set up a service
Without options it asks. QSH_VERSION picks a release, QSH_BIN_DIR the directory.
EOF
}

what='' service=''
for a in "$@"; do
    case $a in
        --client) what=client ;;
        --server) what=server ;;
        --update) what=update ;;
        --service) service=yes ;;
        --no-service) service=no ;;
        -h | --help) usage; exit 0 ;;
        *) die "unknown option: $a" ;;
    esac
done

# Piped into sh, stdin is this script, so questions go to the terminal.
has_tty() { (exec </dev/tty) 2>/dev/null; }
ask() {
    printf '%s' "$1" >/dev/tty
    read -r REPLY </dev/tty || REPLY=
}

os=$(uname -s)
arch=$(uname -m)
case $arch in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) die "no prebuilt binaries for $arch; build from source (see the README)" ;;
esac
case $os in
    Linux)
        case ${PREFIX:-} in
            *com.termux*) plat=android ;;
            *) plat=linux ;;
        esac ;;
    Darwin) plat=macos ;;
    MINGW* | MSYS* | CYGWIN*) die "on Windows run in PowerShell: irm https://github.com/$REPO/releases/latest/download/install.ps1 | iex" ;;
    *) die "no prebuilt binaries for $os; build from source (see the README)" ;;
esac
[ "$plat" = android ] && [ "$arch" != aarch64 ] && die "the Termux build is for aarch64 only"

if [ -z "$what" ]; then
    if has_tty; then
        say "qsh installer ($plat, $arch)"
        say "  1) client only (qsh)"
        say "  2) client and server (qsh + qshd)"
        ask "Choose [1]: "
        case $REPLY in
            2) what=server ;;
            "" | 1) what=client ;;
            *) die "unknown choice: $REPLY" ;;
        esac
    else
        what=client
    fi
fi
if [ "$what" = server ] && [ -z "$service" ]; then
    if has_tty; then
        ask "Run qshd as a service that starts at boot? [Y/n]: "
        case $REPLY in
            "" | [Yy]*) service=yes ;;
            *) service=no ;;
        esac
    else
        service=no
    fi
fi

# root: how to run commands as root ("" when we are root, "none" when we cannot).
if [ "$(id -u)" = 0 ]; then
    root=
elif command -v sudo >/dev/null 2>&1; then
    root=sudo
elif command -v doas >/dev/null 2>&1; then
    root=doas
else
    root=none
fi
as_root() {
    [ "$root" = none ] && die "need root for: $*"
    $root "$@"
}

if [ "$plat" = android ]; then
    bin=${QSH_BIN_DIR:-$PREFIX/bin}
elif [ -n "${QSH_BIN_DIR:-}" ]; then
    bin=$QSH_BIN_DIR
elif [ "$root" != none ]; then
    bin=/usr/local/bin
else
    bin=$HOME/.local/bin
fi

update=no
if [ "$what" = update ]; then
    update=yes service=no
    [ -x "$bin/qsh" ] || die "no qsh in $bin"
    if [ -x "$bin/qshd" ]; then what=server; else what=client; fi
    have=$("$bin/qsh" --version 2>&1 | awk '{ print $2 }')
    if [ -n "${QSH_VERSION:-}" ]; then
        tag=$QSH_VERSION
    elif command -v curl >/dev/null 2>&1; then
        tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" 2>/dev/null) || tag=
        tag=${tag##*/}
    else
        tag=
    fi
    if [ -n "$have" ] && [ "v$have" = "$tag" ]; then
        say "qsh $have is up to date"
        exit 0
    fi
fi

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "need curl or wget"
    fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' INT TERM

if [ -n "${QSH_VERSION:-}" ]; then
    url=https://github.com/$REPO/releases/download/$QSH_VERSION
else
    url=https://github.com/$REPO/releases/latest/download
fi
name=qsh-$arch-$plat
say "Downloading $name.tar.gz"
fetch "$url/$name.tar.gz" "$tmp/$name.tar.gz" || die "download failed: $url/$name.tar.gz"
fetch "$url/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $url/SHA256SUMS"

want=$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || die "$name.tar.gz is not in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp/$name.tar.gz" | awk '{ print $1 }')
else
    got=$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{ print $1 }')
fi
[ "$got" = "$want" ] || die "checksum mismatch for $name.tar.gz"
tar xzf "$tmp/$name.tar.gz" -C "$tmp"
dist=$tmp/$name

files=$dist/qsh
[ "$what" = server ] && files="$files $dist/qshd"
if [ -d "$bin" ] && [ -w "$bin" ]; then
    sudo_bin=
elif [ "$root" = none ]; then
    mkdir -p "$bin"
    sudo_bin=
else
    sudo_bin=$root
    $sudo_bin mkdir -p "$bin"
fi
# shellcheck disable=SC2086
$sudo_bin install -m755 $files "$bin/"
if [ "$what" = server ]; then say "Installed qsh and qshd to $bin"; else say "Installed qsh to $bin"; fi

qshd=$bin/qshd
# A root service must not run a binary that a user can replace.
if [ "$(id -u)" = 0 ] || [ -n "$sudo_bin" ]; then sys=yes; else sys=no; fi
# A unit that is already there may be edited by the admin: keep it.
put_unit() { # src dest [root]
    if [ -e "$2" ]; then
        say "Keeping the existing $2"
    else
        sed "s|/usr/local/bin/qshd|$qshd|g" "$1" >"$tmp/unit"
        ${3:-} mkdir -p "$(dirname "$2")"
        ${3:-} cp "$tmp/unit" "$2"
        say "Wrote $2"
    fi
}

service_linux() {
    if [ ! -d /run/systemd/system ]; then
        say "No systemd here: start '$qshd serve' with your init system (see the README)."
        return
    fi
    if [ "$sys" = yes ]; then
        put_unit "$dist/contrib/qshd.service" /etc/systemd/system/qshd.service "$root"
        as_root systemctl daemon-reload
        as_root systemctl enable --quiet qshd
        as_root systemctl restart qshd
        say "qshd runs as a system service (every user can log in): systemctl status qshd"
    else
        put_unit "$dist/contrib/qshd-user.service" "$HOME/.config/systemd/user/qshd.service"
        systemctl --user daemon-reload
        systemctl --user enable --quiet qshd
        systemctl --user restart qshd
        loginctl enable-linger "$(id -un)" 2>/dev/null ||
            say "Run 'loginctl enable-linger' to keep qshd running after you log out."
        say "qshd runs as a user service (only you can log in): systemctl --user status qshd"
    fi
}

service_macos() {
    [ "$sys" = yes ] || die "a launchd service needs qshd installed by root; $bin is writable by you"
    put_unit "$dist/contrib/qshd.plist" /Library/LaunchDaemons/qshd.plist "$root"
    if as_root launchctl print system/qshd >/dev/null 2>&1; then
        as_root launchctl kickstart -k system/qshd
    else
        as_root launchctl bootstrap system /Library/LaunchDaemons/qshd.plist
    fi
    say "qshd runs as a launchd service; log: /var/log/qshd.log"
}

service_android() {
    sv=$PREFIX/var/service/qshd
    if [ -e "$sv/run" ]; then
        say "Keeping the existing $sv/run"
    else
        mkdir -p "$sv"
        printf '#!%s/bin/sh\nexec %s serve 2>&1\n' "$PREFIX" "$qshd" >"$sv/run"
        chmod 755 "$sv/run"
        say "Wrote $sv/run"
    fi
    if command -v sv-enable >/dev/null 2>&1 && sv-enable qshd 2>/dev/null; then
        sv restart qshd >/dev/null 2>&1 || true
        say "qshd runs as a Termux service: sv status qshd"
    else
        say "To run it as a service: pkg install termux-services, restart Termux, then sv-enable qshd"
    fi
}

# On an update, restart a running service so it uses the new qshd.
restart_running() {
    case $plat in
        linux)
            if [ -d /run/systemd/system ]; then
                if systemctl is-active --quiet qshd 2>/dev/null; then
                    as_root systemctl restart qshd && say "Restarted the qshd service"
                elif systemctl --user is-active --quiet qshd 2>/dev/null; then
                    systemctl --user restart qshd && say "Restarted the qshd user service"
                fi
            fi ;;
        macos)
            if [ "$root" != none ] && $root launchctl print system/qshd >/dev/null 2>&1; then
                as_root launchctl kickstart -k system/qshd && say "Restarted the qshd service"
            fi ;;
        android)
            if command -v sv >/dev/null 2>&1 && sv status qshd 2>/dev/null | grep -q '^run'; then
                sv restart qshd >/dev/null && say "Restarted the qshd service"
            fi ;;
    esac
}

if [ "$what" = server ]; then
    if [ "$service" = yes ]; then
        "service_$plat"
    else
        restart_running
    fi
fi

if [ "$update" = yes ]; then
    say "Updated to $("$bin/qsh" --version 2>&1 | awk '{ print $2 }')"
    exit 0
fi
case :$PATH: in
    *:"$bin":*) ;;
    *) say "Add $bin to your PATH." ;;
esac
say ""
if [ "$what" = server ]; then
    say "Open port 4422 for UDP and TCP in the firewall. To add a client, run 'qshd pair' on this"
    say "machine as the user who will log in, then the 'qsh pair' command it prints on the client."
else
    say "Next: run 'qshd pair' on the server, then the 'qsh pair user@server CODE' command it prints."
fi
