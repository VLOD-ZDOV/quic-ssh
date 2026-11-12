#!/usr/bin/env python3
"""A menu for building qsh and qshd with a chosen set of Cargo features.

    scripts/build.py                      the menu (Linux, macOS)
    scripts/build.py --profile hardened --build
    scripts/build.py --features shell,exec,files --print
    scripts/build.py --profile minimal --map
    scripts/build.py --check              the tables below against the source

Only the standard library is used. The feature list and its descriptions are
read from Cargo.toml; which file belongs to which feature is the FILES table.
"""

import argparse
import os
import re
import shutil
import textwrap
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The menu's order. A feature Cargo.toml has and this does not goes to "Other"
# (and fails --check).
GROUPS = [
    ("Sessions", ["shell", "exec", "persist", "predict"]),
    ("Logging in", ["tofu", "pair", "password", "root-login", "user-rc", "pam", "hardened"]),
    ("Files", ["files", "compress"]),
    ("Network", ["forwarding", "agent", "x11", "tunnel", "punch", "sharing"]),
    ("Tools", ["ui", "speed", "self-update"]),
]

# "full" is Cargo.toml's default list.
PROFILES = {
    "hardened": ["shell", "exec", "files", "compress", "persist", "tofu", "predict", "forwarding", "pair", "hardened"],
    "minimal": ["shell", "exec"],
    "forward-only": ["forwarding"],
}
PROFILE_ORDER = ["hardened", "full", "minimal", "forward-only"]
PROFILE_NOTES = {
    "hardened": "the main things, stricter qshd defaults",
    "full": "everything, as in the releases",
    "minimal": "a shell and commands, nothing else",
    "forward-only": "port forwards with -N, no sessions",
}

# Source file -> the features it serves; it is in use while any of them is
# on. An empty list: always in use. A file whose `mod` line has
# `#[cfg(feature = ...)]` is found in the source and not compiled at all.
FILES = {
    "src/agent.rs": [],
    "src/authkeys.rs": [],
    "src/bin/qsh.rs": [],
    "src/bin/qshd/app.rs": [],
    "src/bin/qshd/main.rs": [],
    "src/client/auth.rs": [],
    "src/client/cli.rs": [],
    "src/client/completions.rs": [],
    "src/client/config.rs": [],
    "src/client/control.rs": ["sharing"],
    "src/client/copy.rs": ["files"],
    "src/client/copy_id.rs": [],
    "src/client/doctor.rs": [],
    "src/client/forward.rs": ["forwarding", "tunnel"],
    "src/client/groups.rs": ["exec", "ui"],
    "src/client/keys_vt.rs": ["shell", "exec"],
    "src/client/keystroke.rs": ["shell", "exec"],
    "src/client/known_hosts.rs": [],
    "src/client/mod.rs": [],
    "src/client/multi.rs": ["exec"],
    "src/client/predict.rs": ["predict"],
    "src/client/restore.rs": ["persist"],
    "src/client/saved.rs": [],
    "src/client/session.rs": [],
    "src/client/socks.rs": ["forwarding"],
    "src/client/speed.rs": [],
    "src/client/tui.rs": ["ui"],
    "src/client/tui/forwards.rs": ["ui"],
    "src/client/tui/text.rs": ["ui"],
    "src/client/ui_state.rs": ["ui"],
    "src/client/x11.rs": ["x11"],
    "src/config.rs": [],
    "src/keys.rs": [],
    "src/lib.rs": [],
    "src/pair.rs": ["pair"],
    "src/pattern.rs": [],
    "src/platform.rs": [],
    "src/pq.rs": [],
    "src/prompt.rs": [],
    "src/proto.rs": [],
    "src/punch.rs": ["punch"],
    "src/release.rs": ["self-update"],
    "src/server/agent.rs": ["agent"],
    "src/server/auth.rs": [],
    "src/server/exec.rs": ["shell", "exec", "files"],
    "src/server/files.rs": ["files"],
    "src/server/helpers.rs": [],
    "src/server/keys_command.rs": [],
    "src/server/login_record.rs": ["shell", "exec"],
    "src/server/mod.rs": [],
    "src/server/pam.rs": ["pam"],
    "src/server/penalty.rs": [],
    "src/server/persist.rs": ["persist"],
    "src/server/revoked.rs": [],
    "src/server/sftp.rs": ["files"],
    "src/server/transfer.rs": ["files"],
    "src/server/users.rs": [],
    "src/server/users_windows.rs": [],
    "src/server/x11.rs": ["x11"],
    "src/tls.rs": [],
    "src/totp.rs": [],
    "src/transport/mod.rs": [],
    "src/transport/quic.rs": [],
    "src/transport/shared.rs": ["sharing"],
    "src/transport/tcp.rs": [],
    "src/tree.rs": ["files"],
    "src/tunnel.rs": ["tunnel"],
}

# qshd settings the menu can write to a qshd.toml: (name, values, what it is).
# The first value is the usual default; HARDENED has the other build's.
SETTINGS = [
    ("max_auth_tries", [6, 1, 2, 3, 4, 10], "failed key proofs per connection"),
    ("login_grace_time", [120, 15, 30, 60, 300], "seconds to log in"),
    ("max_startups_per_ip", [8, 2, 4, 16], "connections logging in at once, per address"),
    ("max_sessions", [10, 1, 2, 4, 20], "sessions per connection"),
    ("session_timeout", [3600, 0, 300, 600, 86400], "seconds a disconnected session is kept"),
    ("allow_tcp_forwarding", [True, "local", "remote", "no"], "-L/-D/-W (local) and -R (remote)"),
    ("require_post_quantum", [False, True], "only clients with the post-quantum key exchange (2.0+)"),
    ("permit_root_login", ["prohibit-password", "forced-commands-only", "no", "yes"], "root logins"),
    ("password_authentication", [False, True], "passwords, besides keys"),
    ("totp", ["optional", "required", "off"], "one-time codes after the key"),
    ("allow_agent_forwarding", [True, False], "-A"),
    ("x11_forwarding", [False, True], "-X/-Y"),
    ("permit_user_rc", [True, False], "~/.ssh/rc"),
    ("permit_tty", [True, False], "terminals"),
    ("print_motd", [True, False], "/etc/motd at login"),
]
HARDENED = {
    "max_auth_tries": 3,
    "login_grace_time": 30,
    "max_startups_per_ip": 4,
    "max_sessions": 4,
    "session_timeout": 600,
    "allow_tcp_forwarding": "local",
    "require_post_quantum": True,
}
# A setting the build turns off whatever the file says: (feature, forced value).
FORCED = {
    "allow_tcp_forwarding": ("forwarding", "no"),
    "permit_root_login": ("root-login", "no"),
    "password_authentication": ("password", False),
    "allow_agent_forwarding": ("agent", False),
    "x11_forwarding": ("x11", False),
    "permit_user_rc": ("user-rc", False),
    "session_timeout": ("persist", 0),
}

RED, YELLOW = "red", "yellow"


def read_features():
    """Cargo.toml's [features]: ({name: description}, the default list)."""
    described, default, comment, inside = {}, [], [], False
    with open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("["):
                inside = line.strip() == "[features]"
                continue
            if not inside:
                continue
            if line.startswith("#"):
                comment.append(line.lstrip("# "))
                continue
            m = re.match(r"([A-Za-z0-9_-]+)\s*=\s*\[(.*)\]", line)
            if m and m.group(1) == "default":
                default = re.findall(r'"([^"]+)"', m.group(2))
            elif m:
                described[m.group(1)] = " ".join(comment)
            comment = []
    return described, default


def source_files():
    """The Rust files of the crate, as git knows them (else as the disk has)."""
    try:
        out = subprocess.run(["git", "ls-files", "src"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        files = {p for p in out.splitlines() if p.endswith(".rs")}
        if files:
            # And what the table already names: a new file, not yet added to git.
            return sorted(files | {p for p in FILES if os.path.exists(os.path.join(ROOT, p))})
    except (OSError, subprocess.CalledProcessError):
        pass
    found = []
    for base, _, names in os.walk(os.path.join(ROOT, "src")):
        found += [os.path.relpath(os.path.join(base, n), ROOT).replace(os.sep, "/") for n in names if n.endswith(".rs")]
    return sorted(found)


GATED_MOD = re.compile(
    r'#\[cfg\((?:all\()?feature = "([A-Za-z0-9_-]+)"[^\]]*\]\s*(?:(?:///|#\[)[^\n]*\s*)*(?:pub(?:\([a-z]+\))? )?mod ([a-z0-9_]+);'
)


def gated_modules(files):
    """{path prefix: feature} for modules behind `#[cfg(feature = ...)]`."""
    gated = {}
    for path in files:
        with open(os.path.join(ROOT, path), encoding="utf-8") as f:
            text = f.read()
        name = os.path.basename(path)
        here = os.path.dirname(path) if name in ("mod.rs", "lib.rs", "main.rs") else path[: -len(".rs")]
        for feature, module in GATED_MOD.findall(text):
            gated[f"{here}/{module}"] = feature
    return gated


def file_map(on, files, gated):
    """[(path, state, features)]: "in", "off" (compiled, never reached) or
    "absent" (not compiled)."""
    rows = []
    for path in files:
        stem = path[: -len(".rs")]
        cut = next((f for prefix, f in gated.items() if stem == prefix or stem.startswith(prefix + "/")), None)
        owners = FILES.get(path, [])
        if cut and cut not in on:
            state = "absent"
        elif owners and not any(o in on for o in owners):
            state = "off"
        else:
            state = "in"
        rows.append((path, state, owners))
    return rows


def warnings(on):
    """[(level, text)] for a set of features, the worst first."""
    w = []
    sessions = "shell" in on or "exec" in on
    if not (sessions or on & {"forwarding", "files", "tunnel"}):
        w.append((RED, "nothing to do: no shell, commands, forwards, files or tunnels; logging in works and that is all"))
    elif not sessions:
        w.append((RED, "no shell and no exec: `qsh host` and `qsh host command` are refused; only -N (forwards), cp and the like work"))
    if "root-login" not in on:
        w.append((RED, "no root-login: root cannot log in at all, not even with a key, and qshd.toml cannot bring it back; "
                       "on a server you reach as root, set up a user with a key and sudo first"))
    if "password" in on and "root-login" in on:
        w.append((RED, "password + root-login: with permit_root_login = \"yes\" root can be tried with passwords"))
    if sessions and "shell" not in on:
        w.append((YELLOW, "no shell: `qsh host` is refused, only `qsh host command`"))
    if sessions and "exec" not in on:
        w.append((YELLOW, "no exec: `qsh host command`, `qsh multi` and keys with a forced command (command=, force_command) are refused"))
    if not sessions:
        idle = sorted(on & {"persist", "predict", "x11", "agent", "user-rc"})
        if idle:
            w.append((YELLOW, f"{', '.join(idle)}: of no use without shell or exec"))
    if "compress" in on and not on & {"files", "exec", "shell"}:
        w.append((YELLOW, "compress: of no use without files or sessions"))
    if "tofu" not in on:
        how = "pair, " if "pair" in on else ""
        w.append((YELLOW, f"no tofu: qsh connects only to hosts already in known_hosts ({how}`qsh copy-id`, by hand, or a @cert-authority)"))
    if "password" in on:
        w.append((YELLOW, "password: qshd can take passwords (password_authentication), which can be guessed; keys cannot"))
    if "self-update" not in on:
        w.append((YELLOW, "no self-update: `qsh update` is gone; watch for releases and rebuild"))
    if "pam" in on:
        w.append((YELLOW, "pam: Linux only, needs libpam's headers (libpam0g-dev, pam-devel); not for static builds"))
    if "hardened" in on:
        w.append((YELLOW, "hardened: qshd starts from 3 key proofs, 30 s to log in, 4 sessions, no -R, 10 min for lost sessions, no clients older than 2.0"))
    if "punch" in on:
        w.append((YELLOW, "punch: `qsh punch` talks to public STUN servers"))
    return sorted(w, key=lambda x: x[0] != RED)


def default_for(name, values, on):
    return HARDENED.get(name, values[0]) if "hardened" in on else values[0]


def effective(name, value, on):
    """(value in effect, the feature that forces it or None)."""
    forced = FORCED.get(name)
    if forced and forced[0] not in on:
        return forced[1], forced[0]
    return value, None


def toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v) if isinstance(v, int) else f'"{v}"'


def config_text(settings, on):
    """A qshd.toml with what differs from this build's defaults ("" if nothing)."""
    lines = []
    for name, values, what in SETTINGS:
        value = settings.get(name, default_for(name, values, on))
        if value != default_for(name, values, on) and effective(name, value, on)[1] is None:
            lines.append(f"{name} = {toml_value(value)}".ljust(40) + f"# {what}")
    if not lines:
        return ""
    return "# Written by scripts/build.py: what differs from this build's defaults.\n" + "\n".join(lines) + "\n"


def cargo_command(on, bins, target=None, jobs=None):
    cmd = ["cargo", "build", "--release", "--locked", "--no-default-features"]
    if on:
        cmd += ["--features", ",".join(sorted(on))]
    # Always by name: other programs in src/bin are not part of a build.
    for b in bins or ["qsh", "qshd"]:
        cmd += ["--bin", b]
    if target:
        cmd += ["--target", target]
    if jobs:
        cmd += ["-j", str(jobs)]
    return cmd


def out_dir(target):
    return os.path.join(ROOT, "target", *([target] if target else []), "release")


def build(on, bins, settings, target=None, jobs=None):
    """Runs cargo; then says where the programs are. The exit code."""
    cmd = cargo_command(on, bins, target, jobs)
    print("$ " + " ".join(cmd), flush=True)
    nice = shutil.which("nice")
    code = subprocess.call(([nice] if nice else []) + cmd, cwd=ROOT)
    if code != 0:
        return code
    where = out_dir(target)
    for b in bins or ["qsh", "qshd"]:
        for name in (b, b + ".exe"):
            path = os.path.join(where, name)
            if os.path.exists(path):
                print(f"{os.path.relpath(path, ROOT)}  {os.path.getsize(path) / 1048576:.1f} MiB")
    text = config_text(settings, on)
    if text:
        path = os.path.join(where, "qshd.toml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"{os.path.relpath(path, ROOT)}  the settings chosen; install it as qshd's config (see README, Server configuration)")
    return 0


def print_warnings(on, out=sys.stderr):
    color = out.isatty()
    for level, text in warnings(on):
        mark = "!!" if level == RED else " !"
        code = "31;1" if level == RED else "33"
        print(f"\033[{code}m{mark} {text}\033[0m" if color else f"{mark} {text}", file=out)


def print_map(on):
    files = source_files()
    marks = {"in": "+", "off": "~", "absent": "-"}
    for path, state, owners in file_map(on, files, gated_modules(files)):
        print(f"{marks[state]} {state:<6} {path}" + (f"  ({', '.join(owners)})" if owners else ""))
    print("\n+ in: compiled and used   ~ off: compiled, its requests are refused   - absent: not compiled")


def check():
    """The tables against Cargo.toml and the source; problems, one per line."""
    described, default = read_features()
    files = source_files()
    grouped = [f for _, fs in GROUPS for f in fs]
    problems = []
    problems += [f"Cargo.toml feature {f!r} is in no GROUPS entry" for f in described if f not in grouped]
    problems += [f"GROUPS names {f!r}, which Cargo.toml does not have" for f in grouped if f not in described]
    problems += [f"default feature {f!r} is not defined" for f in default if f not in described]
    for name, fs in PROFILES.items():
        problems += [f"profile {name}: no feature {f!r}" for f in fs if f not in described]
    problems += [f"{p} is not in FILES (add it, with the features it serves)" for p in files if p not in FILES]
    problems += [f"FILES has {p}, which is not in the source" for p in FILES if p not in files]
    for path, owners in FILES.items():
        problems += [f"FILES[{path}]: no feature {f!r}" for f in owners if f not in described]
    for prefix, feature in gated_modules(files).items():
        for path in files:
            stem = path[: -len(".rs")]
            if (stem == prefix or stem.startswith(prefix + "/")) and feature not in FILES.get(path, [feature]):
                problems.append(f"{path} is compiled only with {feature!r}; FILES says {FILES[path]}")
    for name, values, _ in SETTINGS:
        if name in HARDENED and HARDENED[name] not in values:
            problems.append(f"SETTINGS[{name}] lacks the hardened default {HARDENED[name]!r}")
    return problems


class Menu:
    """The curses screen: features on the left, the file map or the settings
    on the right, warnings and the command below."""

    def __init__(self, described, default, on, bins):
        self.described, self.default = described, default
        self.on = set(on)
        self.bins = bins
        self.settings = {}
        known = [f for _, fs in GROUPS for f in fs]
        other = [f for f in described if f not in known]
        self.groups = [(g, [f for f in fs if f in described]) for g, fs in GROUPS] + ([("Other", other)] if other else [])
        self.features = [f for _, fs in self.groups for f in fs]
        self.files = source_files()
        self.gated = gated_modules(self.files)
        self.tab = 0  # 0: features, 1: settings
        self.row = [0, 0]
        self.scroll = 0
        self.message = ""

    def profile(self):
        for name in PROFILE_ORDER:
            if self.on == set(self.default if name == "full" else PROFILES[name]):
                return name
        return "custom"

    def next_profile(self):
        names = PROFILE_ORDER
        current = self.profile()
        name = names[(names.index(current) + 1) % len(names)] if current in names else names[0]
        self.on = set(self.default if name == "full" else PROFILES[name])
        self.message = f"{name}: {PROFILE_NOTES[name]}"

    def setting(self, i):
        name, values, what = SETTINGS[i]
        return name, values, what, self.settings.get(name, default_for(name, values, self.on))

    def step(self, by):
        name, values, _, value = self.setting(self.row[1])
        if effective(name, value, self.on)[1]:
            self.message = f"{name}: this build has no {FORCED[name][0]}; nothing to set"
            return
        order = sorted(values, key=lambda v: (isinstance(v, bool), v)) if all(isinstance(v, int) and not isinstance(v, bool) for v in values) else values
        i = order.index(value) if value in order else 0
        self.settings[name] = order[(i + by) % len(order)]

    def key(self, k):
        import curses

        self.message = ""
        count = len(self.features) if self.tab == 0 else len(SETTINGS)
        if k in (ord("q"), 27):
            return "quit"
        if k in (ord("\n"), curses.KEY_ENTER, ord("b")):
            return "build"
        if k == ord("\t"):
            self.tab = 1 - self.tab
        elif k in (curses.KEY_UP, ord("k")):
            self.row[self.tab] = (self.row[self.tab] - 1) % count
        elif k in (curses.KEY_DOWN, ord("j")):
            self.row[self.tab] = (self.row[self.tab] + 1) % count
        elif k == ord("p"):
            self.next_profile()
        elif k == ord("t"):
            order = [[], ["qsh"], ["qshd"]]
            self.bins = order[(order.index(self.bins) + 1) % 3] if self.bins in order else []
        elif k == curses.KEY_NPAGE:
            self.scroll += 10
        elif k == curses.KEY_PPAGE:
            self.scroll = max(0, self.scroll - 10)
        elif self.tab == 0:
            if k == ord(" "):
                self.on ^= {self.features[self.row[0]]}
            elif k == ord("a"):
                self.on = set(self.default)
            elif k == ord("n"):
                self.on = set()
        elif k in (ord(" "), curses.KEY_RIGHT, ord("l")):
            self.step(1)
        elif k in (curses.KEY_LEFT, ord("h")):
            self.step(-1)
        elif k == ord("r"):
            self.settings = {}
        return None

    def draw(self, scr):
        import curses

        scr.erase()
        height, width = scr.getmaxyx()
        if height < 16 or width < 70:
            scr.addnstr(0, 0, "The window is too small (70x16 at least); q quits.", width - 1)
            scr.refresh()
            return
        bold, dim = curses.A_BOLD, curses.A_DIM
        red, yellow, green = (curses.color_pair(n) for n in (1, 2, 3))

        def put(y, x, text, attr=0, limit=None):
            room = (limit if limit is not None else width - x) - 0
            if 0 <= y < height and room > 1:
                scr.addnstr(y, x, text, min(room, width - x - 1), attr)

        # Warnings wrap to the window; the red ones come first and are never cut.
        warns = []
        for level, text in warnings(self.on):
            lines = textwrap.wrap(text, max(20, width - 6))
            warns += [(level, ("!! " if level == RED else " ! ") + lines[0])] + [(level, "   " + more) for more in lines[1:]]
        most = max(5, height // 3)
        bottom = min(len(warns), most) + 4
        top, body = 2, height - 2 - bottom
        left = 30
        bins = " ".join(self.bins) if self.bins else "qsh + qshd"
        put(0, 0, f" qsh build   profile: {self.profile()}   builds: {bins}", bold)
        put(1, 0, "─" * (width - 1), dim)

        # Left: the features (or, on the settings tab, still the features, dimmed).
        y = top
        index = 0
        for group, features in self.groups:
            if y < top + body:
                put(y, 1, group, dim | bold, left)
            y += 1
            for f in features:
                if y < top + body:
                    here = self.tab == 0 and index == self.row[0]
                    attr = curses.A_REVERSE if here else (0 if self.tab == 0 else dim)
                    put(y, 1, f"[{'x' if f in self.on else ' '}] {f}".ljust(left - 3), attr, left)
                y += 1
                index += 1

        x = left + 1
        for row in range(top, top + body):
            put(row, left - 1, "│", dim)
        if self.tab == 0:
            rows = file_map(self.on, self.files, self.gated)
            counts = {s: sum(1 for r in rows if r[1] == s) for s in ("in", "off", "absent")}
            put(top, x, f"Files: {counts['in']} in, {counts['off']} off, {counts['absent']} not compiled", bold)
            room = body - 1
            self.scroll = max(0, min(self.scroll, max(0, len(rows) - room)))
            looks = {"in": ("●", green), "off": ("◐", yellow), "absent": ("○", dim)}
            for i, (path, state, owners) in enumerate(rows[self.scroll : self.scroll + room]):
                mark, attr = looks[state]
                label = {"in": "", "off": "off", "absent": "not compiled"}[state]
                put(top + 1 + i, x, f"{mark} {path[4:]:<26} {label:<12} {', '.join(owners)}", attr)
        else:
            put(top, x, "qshd settings, written to qshd.toml beside the programs", bold)
            for i in range(len(SETTINGS)):
                if i >= body - 1:
                    break
                name, values, what, value = self.setting(i)
                shown, forced = effective(name, value, self.on)
                changed = forced is None and value != default_for(name, values, self.on)
                text = f"{name:<24} {toml_value(shown):<22}"
                note = f"no {forced} in this build" if forced else what
                attr = curses.A_REVERSE if i == self.row[1] else (dim if forced else (bold if changed else 0))
                put(top + 1 + i, x, f"{'*' if changed else ' '} {text} {note}", attr)

        y = height - bottom
        put(y, 0, "─" * (width - 1), dim)
        for level, text in warns[:most]:
            y += 1
            put(y, 1, text, (red | bold) if level == RED else yellow)
        if len(warns) > most:
            put(y, width - 22, " more: see --print ", yellow)
        feature = self.features[self.row[0]]
        about = self.described.get(feature, "") if self.tab == 0 else SETTINGS[self.row[1]][2]
        put(height - 3, 1, self.message or (f"{feature}: {about}" if self.tab == 0 else about), bold if self.message else 0)
        put(height - 2, 1, "$ " + " ".join(cargo_command(self.on, self.bins)), dim)
        keys = "space toggle  a all  n none" if self.tab == 0 else "←/→ change  r reset"
        put(height - 1, 1, f"{keys}  p profile  t qsh/qshd  Tab {'settings' if self.tab == 0 else 'features'}  PgUp/PgDn files  Enter build  q quit", dim)
        scr.refresh()

    def run(self, scr):
        import curses

        curses.curs_set(0)
        curses.use_default_colors()
        for n, color in ((1, curses.COLOR_RED), (2, curses.COLOR_YELLOW), (3, curses.COLOR_GREEN)):
            curses.init_pair(n, color, -1)
        while True:
            self.draw(scr)
            done = self.key(scr.getch())
            if done:
                return done


def main():
    described, default = read_features()
    names = PROFILE_ORDER
    ap = argparse.ArgumentParser(description="Build qsh and qshd with a chosen set of features; without options, a menu.")
    ap.add_argument("--profile", choices=names, help="start from a profile: " + "; ".join(f"{n} ({PROFILE_NOTES[n]})" for n in names))
    ap.add_argument("--features", metavar="A,B", help="exactly these features (or, after --profile, +a,-b to add and remove)")
    ap.add_argument("--bin", action="append", choices=["qsh", "qshd"], help="build only this program (default: both)")
    ap.add_argument("--target", help="passed to cargo (a target triple)")
    ap.add_argument("-j", "--jobs", type=int, help="passed to cargo")
    ap.add_argument("--print", action="store_true", help="print the cargo command (warnings go to stderr) and stop")
    ap.add_argument("--map", action="store_true", help="print which source files the build uses and stop")
    ap.add_argument("--build", action="store_true", help="build without the menu")
    ap.add_argument("--yes", action="store_true", help="with --build: do not ask about red warnings")
    ap.add_argument("--list", action="store_true", help="list the features and profiles")
    ap.add_argument("--check", action="store_true", help="check this script's tables against Cargo.toml and src/")
    args = ap.parse_args()

    if args.check:
        problems = check()
        for p in problems:
            print(p, file=sys.stderr)
        print(f"{len(FILES)} files, {len(described)} features: " + ("ok" if not problems else f"{len(problems)} problem(s)"))
        return 1 if problems else 0
    if args.list:
        for group, features in GROUPS:
            print(group)
            for f in features:
                print(f"  {f:<12} {'default' if f in default else '       '}  {described.get(f, '')}")
        print("Profiles")
        for n in names:
            print(f"  {n:<12} {PROFILE_NOTES[n]}: {', '.join(default if n == 'full' else PROFILES[n])}")
        return 0

    chosen = args.profile or "hardened"
    on = set(default if chosen == "full" else PROFILES[chosen])
    if args.features:
        parts = [p.strip() for p in args.features.split(",") if p.strip()]
        if not all(p[0] in "+-" for p in parts):
            if args.profile and any(p[0] in "+-" for p in parts):
                ap.error("--features: all with + or -, or none")
            on = set()
        for p in parts:
            name = p.lstrip("+-")
            if name not in described:
                ap.error(f"no feature {name!r} (see --list)")
            (on.discard if p.startswith("-") else on.add)(name)
    bins = args.bin or []
    settings = {}

    if args.map:
        print_map(on)
        return 0
    if args.print:
        print_warnings(on)
        print(" ".join(cargo_command(on, bins, args.target, args.jobs)))
        return 0
    if not args.build:
        try:
            import curses
        except ImportError:
            curses = None
        if curses is None or not (sys.stdin.isatty() and sys.stdout.isatty()):
            ap.error("the menu needs a terminal and Python's curses; use --profile/--features with --build or --print")
        menu = Menu(described, default, on, bins)
        if curses.wrapper(menu.run) != "build":
            return 0
        on, bins, settings = menu.on, menu.bins, menu.settings

    print_warnings(on, sys.stdout)
    if not args.yes and any(level == RED for level, _ in warnings(on)):
        if not sys.stdin.isatty():
            print("red warnings: not building (--yes builds anyway)", file=sys.stderr)
            return 1
        if input("Build with the red warnings above? [y/N] ").strip().lower() not in ("y", "yes"):
            return 1
    return build(on, bins, settings, args.target, args.jobs)


if __name__ == "__main__":
    sys.exit(main())
