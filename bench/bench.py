#!/usr/bin/env python3
"""Benchmark qsh against OpenSSH under emulated network conditions.

Runs entirely inside an unprivileged user+network namespace (`unshare -c -n`),
so no root is needed and the host network is untouched. Inside, it starts a
private sshd and qshd on the loopback interface and shapes it with `tc netem`.

Usage: python3 bench/bench.py [--qsh target/release/qsh] [--qshd target/release/qshd]
Requires: unshare (util-linux), tc/ip (iproute2), OpenSSH (ssh, scp, sshd, ssh-keygen).
"""

import argparse
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

SSH_PORT = 22022
QSH_PORT = 24422

# name, netem arguments (None = no shaping), upload size in MiB
SCENARIOS = [
    ("loopback, no delay", None, 200),
    ("RTT 50 ms, 100 Mbit/s", "delay 25ms rate 100mbit limit 100000", 50),
    ("RTT 100 ms, 1% loss, 20 Mbit/s", "delay 50ms loss 1% rate 20mbit limit 100000", 10),
]


def sh(*args, **kw):
    return subprocess.run(args, check=True, **kw)


def find_sshd():
    for p in ("/usr/sbin/sshd", "/usr/bin/sshd", shutil.which("sshd")):
        if p and os.path.exists(p):
            return p
    sys.exit("sshd not found")


class Bench:
    def __init__(self, args, tmp):
        self.args = args
        self.tmp = tmp
        self.user = subprocess.check_output(["id", "-un"], text=True).strip()
        self.server_home = os.path.join(tmp, "server")
        self.client_home = os.path.join(tmp, "client")
        for d in (self.server_home, self.client_home):
            os.makedirs(os.path.join(d, ".ssh"), mode=0o700)
            os.makedirs(os.path.join(d, ".config"), mode=0o700)
        # One client key for both tools.
        self.key = os.path.join(self.client_home, ".ssh", "id_ed25519")
        sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key)
        auth = os.path.join(self.server_home, ".ssh", "authorized_keys")
        shutil.copy(self.key + ".pub", auth)
        os.chmod(auth, 0o600)
        self.procs = []

    def start_servers(self):
        host_key = os.path.join(self.tmp, "ssh_host_ed25519")
        sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", host_key)
        cfg = os.path.join(self.tmp, "sshd_config")
        with open(cfg, "w") as f:
            f.write(
                f"Port {SSH_PORT}\nListenAddress 127.0.0.1\nHostKey {host_key}\n"
                f"AuthorizedKeysFile {self.server_home}/.ssh/authorized_keys\n"
                "PidFile none\nUsePAM no\nStrictModes no\nPasswordAuthentication no\n"
                "KbdInteractiveAuthentication no\nSubsystem sftp internal-sftp\n"
                # Same empty shell config for both servers.
                f"SetEnv XDG_CONFIG_HOME={self.server_home}/.config\n"
            )
        self.procs.append(subprocess.Popen(
            [find_sshd(), "-D", "-e", "-f", cfg], stderr=subprocess.DEVNULL))
        env = dict(os.environ, HOME=self.server_home)
        self.procs.append(subprocess.Popen(
            [self.args.qshd, "serve", "--listen", f"127.0.0.1:{QSH_PORT}"],
            env=env, stderr=subprocess.DEVNULL))
        time.sleep(1.0)

    def stop(self):
        for p in self.procs:
            p.terminate()
            p.wait()

    def ssh_cmd(self, *extra):
        return [
            "-F", "none", "-i", self.key, "-o", "BatchMode=yes",
            "-o", f"UserKnownHostsFile={self.client_home}/.ssh/known_hosts",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ControlMaster=no", *extra,
        ]

    def tools(self):
        dest = f"{self.user}@127.0.0.1"
        qsh = [self.args.qsh, "--accept-new-host", "-p", str(QSH_PORT)]
        return {
            "ssh": {
                "exec": ["ssh", *self.ssh_cmd("-p", str(SSH_PORT)), dest, "true"],
                "copy": lambda src, dst: ["scp", "-q", *self.ssh_cmd("-P", str(SSH_PORT)), src, f"{dest}:{dst}"],
            },
            "qsh (QUIC)": {
                "exec": [*qsh, "--transport", "quic", dest, "true"],
                "copy": lambda src, dst: [self.args.qsh, "cp", "--accept-new-host", "-p", str(QSH_PORT),
                                          "--transport", "quic", src, f"{dest}:{dst}"],
            },
            "qsh (TCP)": {
                "exec": [*qsh, "--transport", "tcp", dest, "true"],
                "copy": lambda src, dst: [self.args.qsh, "cp", "--accept-new-host", "-p", str(QSH_PORT),
                                          "--transport", "tcp", src, f"{dest}:{dst}"],
            },
        }

    def timed(self, argv):
        env = dict(os.environ, HOME=self.client_home)
        start = time.perf_counter()
        p = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Plain blocking wait: `subprocess.run(timeout=...)` polls with up to
        # 50 ms sleeps, which would round every measurement up.
        if p.wait() != 0:
            raise RuntimeError(f"{argv[0]} failed")
        return time.perf_counter() - start

    def run(self):
        tools = self.tools()
        for t in tools.values():  # warm up and record host keys
            self.timed(t["exec"])
        results = []
        for name, netem, size_mib in SCENARIOS:
            if netem:
                sh("tc", "qdisc", "replace", "dev", "lo", "root", "netem", *netem.split())
            else:
                subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"], stderr=subprocess.DEVNULL)
            src = os.path.join(self.tmp, f"payload-{size_mib}")
            if not os.path.exists(src):
                with open(src, "wb") as f:
                    f.write(os.urandom(size_mib << 20))
            print(f"== {name}", file=sys.stderr)
            for tool, t in tools.items():
                lat = [self.timed(t["exec"]) for _ in range(self.args.runs)]
                dst = os.path.join(self.server_home, f"upload-{tool[:3]}")
                copies = [self.timed(t["copy"](src, dst)) for _ in range(self.args.copy_runs)]
                mbps = size_mib * 8 * 1.048576 / statistics.median(copies)
                row = (name, tool, statistics.median(lat) * 1000, max(lat) * 1000, size_mib, mbps)
                print(f"   {tool:11} connect+exec {row[2]:7.0f} ms (max {row[3]:5.0f})"
                      f"   upload {size_mib} MiB: {mbps:7.1f} Mbit/s", file=sys.stderr)
                results.append(row)
        return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qsh", default="target/release/qsh")
    ap.add_argument("--qshd", default="target/release/qshd")
    ap.add_argument("--runs", type=int, default=10, help="connect+exec runs per tool")
    ap.add_argument("--copy-runs", type=int, default=3, help="upload runs per tool")
    args = ap.parse_args()
    args.qsh, args.qshd = os.path.abspath(args.qsh), os.path.abspath(args.qshd)

    if os.environ.get("QSH_BENCH_NS") != "1":
        env = dict(os.environ, QSH_BENCH_NS="1")
        os.execvpe("unshare", ["unshare", "-c", "-n", "--keep-caps", sys.executable,
                               os.path.abspath(__file__), *sys.argv[1:]], env)

    sh("ip", "link", "set", "lo", "up")
    sh("ip", "link", "set", "lo", "mtu", "1500")  # realistic packet sizes
    with tempfile.TemporaryDirectory() as tmp:
        b = Bench(args, tmp)
        b.start_servers()
        try:
            results = b.run()
        finally:
            b.stop()

    print("| Network | Tool | Connect + `true`, median | Worst | Upload | Throughput |")
    print("|---|---|---:|---:|---:|---:|")
    for name, tool, med, worst, size, mbps in results:
        print(f"| {name} | {tool} | {med:.0f} ms | {worst:.0f} ms | {size} MiB | {mbps:.1f} Mbit/s |")


if __name__ == "__main__":
    main()
