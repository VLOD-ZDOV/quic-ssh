use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use qsh::client::cli::{SshArgs, USAGE, WITH_VALUE};
use qsh::client::config::Sources;
use qsh::client::copy::{self, Location};
use qsh::client::forward::{self, Forward};
use qsh::client::session::SessionOptions;
use qsh::client::{self, session, ConnectOptions, Target};
use qsh::keys::{home_dir, qsh_dir, Identity};
use qsh::transport::{Mode, Unreachable};

/// `qsh cp|pair|keygen|speed|ui ...`
#[derive(Parser)]
#[command(name = "qsh", version)]
struct ToolCli {
    #[command(subcommand)]
    cmd: Cmd,

    #[command(flatten)]
    conn: ConnArgs,
}

const TOOLS: [&str; 5] = ["cp", "pair", "keygen", "speed", "ui"];

/// True when the first positional argument names a tool command. Only the
/// first position counts, so `qsh host cp a b` runs `cp a b` remotely.
fn is_tool_invocation(args: &[String]) -> bool {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--" {
            return false;
        }
        if let Some(long) = a.strip_prefix("--") {
            if matches!(long, "port" | "identity" | "transport" | "login") {
                it.next();
            }
        } else if let Some(short) = a.strip_prefix('-').filter(|s| !s.is_empty()) {
            // A value-taking option consumes the rest of the cluster or the next argument.
            if let Some(i) = short.find(|c| WITH_VALUE.contains(c)) {
                if i == short.len() - 1 {
                    it.next();
                }
            }
        } else {
            return TOOLS.contains(&a.as_str());
        }
    }
    false
}

#[derive(Args, Clone)]
struct ConnArgs {
    /// Server port (default 4422)
    #[arg(short = 'p', long, global = true)]
    port: Option<u16>,

    /// Private key (default ~/.ssh/id_ed25519, then ~/.config/qsh/id_ed25519)
    #[arg(short = 'i', long, global = true, value_name = "FILE")]
    identity: Vec<PathBuf>,

    /// Transport to use
    #[arg(long, value_enum, default_value = "auto", global = true)]
    transport: Mode,

    /// Trust an unknown host key without asking (a changed key is still refused)
    #[arg(long, global = true)]
    accept_new_host: bool,

    /// Verbose output
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    /// OpenSSH compatibility: use the ssh config fully, and fall back to
    /// OpenSSH's scp/ssh where the host has no qshd
    #[arg(long, global = true)]
    full: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Copy files: qsh cp [-r] SRC DST, where one side is [user@]host:path
    Cp {
        /// Copy directories recursively
        #[arg(short = 'r')]
        recursive: bool,
        src: String,
        dst: String,
    },
    /// Pair with a server using a code from `qshd pair` (adds your key there, pins its key here)
    Pair {
        /// [user@]host[:port]
        destination: String,
        /// Code printed by `qshd pair`
        code: String,
    },
    /// Create a new key at ~/.config/qsh/id_ed25519 (or FILE)
    Keygen {
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
    },
    /// Measure latency and throughput to a server
    Speed {
        /// [user@]host[:port]
        destination: String,
        /// Seconds per direction
        #[arg(long, default_value_t = 5)]
        seconds: u64,
    },
    /// Interactive host menu with status and speed test
    Ui,
}

impl ConnArgs {
    fn options(&self) -> ConnectOptions {
        ConnectOptions {
            identities: self.identity.clone(),
            transport: self.transport,
            accept_new_host: self.accept_new_host,
            full: self.full,
        }
    }
}

/// True when this binary was started as `ssh` (e.g. through a symlink).
fn invoked_as_ssh(argv0: &str) -> bool {
    Path::new(argv0).file_name().is_some_and(|n| n == "ssh")
}

fn init_logging(verbose: bool, quiet: bool) {
    let filter = if verbose { "qsh=debug" } else if quiet { "qsh=error" } else { "qsh=warn" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .init();
}

fn finish(result: Result<i32>) -> ! {
    let code = match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("qsh: {e:#}");
            255
        }
    };
    // Exit right away: a blocked stdin reader thread must not keep the process alive.
    std::process::exit(code);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let as_ssh = invoked_as_ssh(&args[0]);
    // As `ssh`, every word is ssh's: `ssh cp` connects to a host named cp.
    if !as_ssh && is_tool_invocation(&args) {
        let cli = ToolCli::parse_from(args);
        init_logging(cli.conn.verbose, false);
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        finish(rt.block_on(tool_main(cli)));
    }
    let mut a = match SshArgs::parse(args[1..].iter().cloned()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("qsh: {e}\n{USAGE}");
            std::process::exit(255);
        }
    };
    if a.help {
        println!("{USAGE}");
        std::process::exit(0);
    }
    if a.print_version {
        eprintln!("qsh {} (QUIC; OpenSSH-compatible options)", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    a.full |= as_ssh;
    if a.background && std::env::var_os(DAEMON_FD).is_none() {
        finish(run_in_background(&args));
    }
    init_logging(a.verbose > 0, a.quiet);
    for ignored in &a.ignored {
        tracing::debug!("ignoring {ignored}");
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    finish(rt.block_on(session_main(a)));
}

/// Environment variable carrying the readiness pipe to a backgrounded qsh.
const DAEMON_FD: &str = "QSH_BACKGROUND_FD";

/// `-f`: runs qsh again as a child that logs in (it may still ask questions on
/// the terminal), then detaches; this process exits once the child is ready.
fn run_in_background(args: &[String]) -> Result<i32> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    // Only the write end is handed to the child (by number); the read end must not leak.
    let (read, write) = nix::unistd::pipe()?;
    nix::fcntl::fcntl(&read, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(&args[1..])
        .env(DAEMON_FD, write.as_raw_fd().to_string())
        .spawn()?;
    drop(write);
    let mut status = String::new();
    let _ = std::fs::File::from(read).read_to_string(&mut status);
    if status.trim() == "ok" {
        return Ok(0);
    }
    // The child failed before it was ready and has reported why.
    Ok(child.wait()?.code().unwrap_or(255))
}

/// In a backgrounded child: tell the parent we are ready, then detach from the
/// terminal (new session, stdin from /dev/null; output stays, like ssh -f).
fn detach() -> Result<()> {
    use std::io::Write;
    use std::os::fd::{FromRawFd, OwnedFd};
    let Some(fd) = std::env::var(DAEMON_FD).ok().and_then(|v| v.parse::<i32>().ok()) else {
        return Ok(());
    };
    let null = std::fs::File::open("/dev/null")?;
    nix::unistd::dup2_stdin(&null)?;
    let _ = nix::unistd::setsid();
    // SAFETY: the fd was created for us by the parent and is used only here.
    let mut pipe = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    pipe.write_all(b"ok")?;
    Ok(())
}

async fn tool_main(cli: ToolCli) -> Result<i32> {
    let opts = cli.conn.options();
    match cli.cmd {
        Cmd::Keygen { file } => keygen(file),
        Cmd::Pair { destination, code } => {
            let target = Target::parse(&destination, cli.conn.port, cli.conn.full)?;
            client::pair(&target, &opts, &code).await?;
            Ok(0)
        }
        Cmd::Cp { recursive, src, dst } => cp(&src, &dst, recursive, &cli.conn).await,
        Cmd::Speed { destination, seconds } => {
            let target = Target::parse(&destination, cli.conn.port, cli.conn.full)?;
            speed_test(&target, &opts, Duration::from_secs(seconds)).await
        }
        Cmd::Ui => qsh::client::tui::run(opts).await,
    }
}

/// `-G`: prints the resolved settings, like ssh. Tools (e.g. git) also use it
/// to detect an OpenSSH-compatible client.
fn print_config(t: &Target) {
    println!("user {}\nhostname {}\nport {}", t.user, t.host, t.port);
    for f in &t.identity_files {
        println!("identityfile {}", f.display());
    }
    for (name, list) in [("localforward", &t.local_forwards), ("remoteforward", &t.remote_forwards), ("dynamicforward", &t.dynamic_forwards)] {
        for f in list {
            println!("{name} {f}");
        }
    }
    if let Some(j) = &t.proxy_jump {
        println!("proxyjump {j}");
    }
    println!("batchmode {}", if t.batch_mode { "yes" } else { "no" });
}

async fn session_main(a: SshArgs) -> Result<i32> {
    let Some(dest) = a.destination.clone() else {
        bail!("missing destination\n{USAGE}");
    };
    let mut overrides = Vec::new();
    if let Some(j) = &a.jump {
        overrides.push(format!("ProxyJump {j}"));
    }
    overrides.extend(a.override_lines());
    let sources = Sources { full: a.full, overrides, ssh_config: a.config_file.clone() };
    let target = Target::resolve(&dest, a.port, &sources)?;
    if a.print_config {
        print_config(&target);
        return Ok(0);
    }
    if a.background && !a.no_command && a.command.is_empty() && a.stdio_forward.is_none() {
        bail!("cannot go to the background (-f) without a command or -N");
    }
    let opts = ConnectOptions {
        identities: a.identities.clone(),
        transport: a.transport,
        accept_new_host: a.accept_new_host,
        full: a.full,
    };
    if a.full && target.needs_proxy {
        return exec_openssh("ssh", ssh_args(&a, &target), "the ssh config uses ProxyJump/ProxyCommand");
    }
    let quiet = a.quiet || target.quiet;
    // ClearAllForwardings drops the forwards from the config and the command line.
    let clear = target.clear_all_forwardings;
    let mut locals = Vec::new();
    let mut remotes = Vec::new();
    let mut dynamics: Vec<(String, bool)> = Vec::new();
    if !clear {
        for (specs, required) in [(&a.local_forwards, true), (&target.local_forwards, false)] {
            for s in specs {
                locals.push((Forward::parse(s).with_context(|| format!("-L {s}"))?, required));
            }
        }
        for s in a.remote_forwards.iter().chain(&target.remote_forwards) {
            remotes.push(Forward::parse(s).with_context(|| format!("-R {s}"))?);
        }
        dynamics.extend(a.dynamic_forwards.iter().map(|s| (s.clone(), true)));
        dynamics.extend(target.dynamic_forwards.iter().map(|s| (s.clone(), false)));
    }

    let conn = match client::connect(&target, &opts).await {
        Ok(c) => Arc::new(c),
        Err(e) if a.full && e.is::<Unreachable>() => {
            return exec_openssh("ssh", ssh_args(&a, &target), &format!("{e:#}"));
        }
        Err(e) => return Err(e),
    };
    if let Some(spec) = &a.stdio_forward {
        forward::stdio(&conn, spec).await?;
        conn.close().await;
        return Ok(0);
    }
    for (f, required) in locals {
        let spec = f.describe();
        match forward::start_local(conn.clone(), f, a.gateway_ports).await {
            Ok(()) => {}
            // Like ssh: a forward from the config that cannot bind is only a warning.
            Err(e) if !required => eprintln!("qsh: warning: LocalForward {spec}: {e:#}"),
            Err(e) => return Err(e),
        }
    }
    for (spec, required) in dynamics {
        match forward::start_dynamic(conn.clone(), &spec, a.gateway_ports).await {
            Ok(()) => {}
            Err(e) if !required => eprintln!("qsh: warning: DynamicForward {spec}: {e:#}"),
            Err(e) => return Err(e),
        }
    }
    let _remote = forward::start_remote(&conn, &remotes, quiet).await?;
    if a.background {
        detach()?;
    }

    if a.no_command {
        tokio::select! {
            _ = conn.closed() => bail!("connection closed"),
            _ = session::termination_signal(true) => {}
        }
        conn.close().await;
        return Ok(0);
    }
    let command = (!a.command.is_empty()).then(|| a.command.join(" "));
    let subsystem = a.subsystem.then(|| command.clone()).flatten();
    if a.subsystem && subsystem.is_none() {
        bail!("-s needs a subsystem name, e.g. `qsh -s host sftp`");
    }
    let stdin_tty = std::io::stdin().is_terminal() && !a.stdin_null && !a.background;
    let pty = if subsystem.is_some() || a.no_tty {
        false
    } else if a.tty >= 2 {
        true
    } else if a.tty == 1 {
        if !stdin_tty && !quiet {
            eprintln!("Pseudo-terminal will not be allocated because stdin is not a terminal.");
        }
        stdin_tty
    } else {
        match target.request_tty.as_deref() {
            Some("force") => true,
            Some("yes") => stdin_tty,
            Some("no") => false,
            _ => command.is_none() && stdin_tty,
        }
    };
    let escape_char = match &a.escape_char {
        Some(e) => client::parse_escape(Some(e)),
        None => target.escape_char,
    };
    let code = session::run(
        &conn,
        SessionOptions {
            command,
            subsystem,
            pty,
            keystroke_interval: target.keystroke_interval,
            escape_char,
            stdin_null: a.stdin_null || a.background,
        },
    )
    .await?;
    conn.close().await;
    Ok(code)
}

/// Arguments for OpenSSH's ssh: everything ssh understands, as given.
fn ssh_args(a: &SshArgs, target: &Target) -> Vec<String> {
    let mut args = a.passthrough.clone();
    if let Some(p) = target.cli_port {
        args.push("-p".into());
        args.push(p.to_string());
    }
    // `--` so the destination can never be read as an option.
    args.push("--".into());
    args.push(target.ssh_dest.clone());
    args.extend(a.command.iter().cloned());
    args
}

/// Finds OpenSSH's `tool` in PATH, skipping qsh itself (when qsh is
/// installed as `ssh`, a plain lookup would find qsh again).
fn find_openssh(tool: &str) -> Result<PathBuf> {
    let me = std::env::current_exe().ok().and_then(|p| p.canonicalize().ok());
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|c| c.is_file() && c.canonicalize().ok() != me)
        .with_context(|| format!("OpenSSH's {tool} was not found in PATH"))
}

/// `--full`: replaces this process with OpenSSH's `tool` (ssh or scp).
fn exec_openssh(tool: &str, args: Vec<String>, reason: &str) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    tracing::info!("using {tool}: {reason}");
    let program = find_openssh(tool)?;
    let mut cmd = std::process::Command::new(&program);
    cmd.args(args);
    if let Some(fd) = std::env::var(DAEMON_FD).ok().and_then(|v| v.parse::<i32>().ok()) {
        // In a `-f` child: ssh gets `-f` too and goes to the background by itself.
        // Closing the readiness pipe makes our parent wait for ssh's own exit
        // instead of for the pipe, which ssh would otherwise keep open.
        // SAFETY: the fd was created for this process by the parent and is not used elsewhere.
        unsafe { libc::close(fd) };
        cmd.env_remove(DAEMON_FD);
    }
    Err(anyhow!("cannot run {}: {}", program.display(), cmd.exec()))
}

async fn speed_test(target: &Target, opts: &ConnectOptions, seconds: Duration) -> Result<i32> {
    use std::io::Write;
    use qsh::client::speed;
    let conn = client::connect(target, opts).await?;
    println!("{}@{} over {}", target.user, conn.remote_addr(), conn.transport_name());
    let mut pings = Vec::new();
    for _ in 0..5 {
        pings.push(speed::ping(&conn).await?);
    }
    pings.sort();
    println!("ping      {:>8.1} ms  (min {:.1}, max {:.1})", ms(pings[2]), ms(pings[0]), ms(pings[4]));
    let live = |label: &'static str| {
        move |bytes: u64, elapsed: Duration| {
            print!("\r{label}  {:>8.1} Mbit/s ", speed::mbps(bytes, elapsed));
            let _ = std::io::stdout().flush();
        }
    };
    let (bytes, t) = speed::download(&conn, seconds, live("download")).await?;
    println!("\rdownload  {:>8.1} Mbit/s  ({:.1} MiB in {:.1} s)", speed::mbps(bytes, t), bytes as f64 / 1048576.0, t.as_secs_f64());
    let (bytes, t) = speed::upload(&conn, seconds, live("upload  ")).await?;
    println!("\rupload    {:>8.1} Mbit/s  ({:.1} MiB in {:.1} s)", speed::mbps(bytes, t), bytes as f64 / 1048576.0, t.as_secs_f64());
    conn.close().await;
    Ok(0)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn keygen(file: Option<PathBuf>) -> Result<i32> {
    let path = match file {
        Some(f) => f,
        None => qsh_dir(&home_dir()?).join("id_ed25519"),
    };
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let id = Identity::generate();
    id.save(&path, "qsh")?;
    println!("Saved {} ({})", path.display(), id.public().fingerprint());
    println!("Public key: {}", id.public().to_openssh("qsh"));
    Ok(0)
}

async fn cp(src: &str, dst: &str, recursive: bool, args: &ConnArgs) -> Result<i32> {
    enum Direction {
        Upload { local: PathBuf, remote: String },
        Download { remote: String, local: PathBuf },
    }
    let (dest, direction) = match (Location::parse(src), Location::parse(dst)) {
        (Location::Local(local), Location::Remote { dest, path }) => (dest, Direction::Upload { local, remote: path }),
        (Location::Remote { dest, path }, Location::Local(local)) => (dest, Direction::Download { remote: path, local }),
        (Location::Local(_), Location::Local(_)) => bail!("one of SRC/DST must be remote ([user@]host:path)"),
        (Location::Remote { .. }, Location::Remote { .. }) => bail!("remote-to-remote copies are not supported"),
    };
    let target = Target::parse(&dest, args.port, args.full)?;
    let scp_args = || {
        let mut v = Vec::new();
        if let Some(p) = args.port {
            v.extend(["-P".to_string(), p.to_string()]);
        }
        for i in &args.identity {
            v.extend(["-i".to_string(), i.display().to_string()]);
        }
        if recursive {
            v.push("-r".into());
        }
        if args.verbose {
            v.push("-v".into());
        }
        v.extend(["--".to_string(), src.to_string(), dst.to_string()]);
        v
    };
    if args.full && target.needs_proxy {
        return exec_openssh("scp", scp_args(), "the ssh config uses ProxyJump/ProxyCommand");
    }
    let conn = match client::connect(&target, &args.options()).await {
        Ok(c) => c,
        Err(e) if args.full && e.is::<Unreachable>() => return exec_openssh("scp", scp_args(), &format!("{e:#}")),
        Err(e) => return Err(e),
    };
    let result = match (direction, recursive) {
        (Direction::Upload { local, remote }, false) => copy::upload(&conn, &local, &remote).await,
        (Direction::Upload { local, remote }, true) => copy::upload_tree(&conn, &local, &remote).await,
        (Direction::Download { remote, local }, false) => copy::download(&conn, &remote, &local).await,
        (Direction::Download { remote, local }, true) => copy::download_tree(&conn, &remote, &local).await,
    };
    conn.close().await;
    result.map(|()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(args: &str) -> bool {
        let v: Vec<String> = std::iter::once("qsh").chain(args.split_whitespace()).map(String::from).collect();
        is_tool_invocation(&v)
    }

    #[test]
    fn tool_commands_only_in_first_position() {
        assert!(tool("cp a host:b"));
        assert!(tool("-p 2222 pair u@host code"));
        assert!(tool("--accept-new-host --transport tcp pair u@host code"));
        assert!(tool("-v keygen"));
        assert!(tool("--full cp a host:b"));
        assert!(tool("-oPort=1 speed h"));
        assert!(!tool("-f host"));
        assert!(!tool("host cp a b"));
        assert!(!tool("-p 22 host"));
        assert!(!tool("-L 8080:cp:80 host"));
        assert!(!tool("-tL 1:a:2 host pair"));
        assert!(!tool("-i cp host"));
        assert!(!tool("-o cp host"));
        assert!(!tool("-- cp"));
    }

    #[test]
    fn tool_parser_is_valid() {
        use clap::CommandFactory;
        ToolCli::command().debug_assert();
    }

    #[test]
    fn recognizes_ssh_name() {
        assert!(invoked_as_ssh("/usr/local/bin/ssh"));
        assert!(invoked_as_ssh("ssh"));
        assert!(!invoked_as_ssh("/usr/bin/qsh"));
        assert!(!invoked_as_ssh("sshd"));
    }
}
