#![forbid(unsafe_code)]
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

const TOOLS: [&str; 12] = ["cp", "pair", "keygen", "speed", "ui", "multi", "doctor", "update", "forget", "completions", "copy-id", "punch"];

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

    /// Verbose output: -vv and -vvv for more
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

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
        /// Compress the data (zstd); worth it for text on slow links
        #[arg(short = 'C')]
        compress: bool,
        /// The sources, then the destination (a directory if there are several sources)
        #[arg(required = true, num_args = 2.., value_name = "PATH")]
        paths: Vec<String>,
    },
    /// Pair with a server using a code from `qshd pair` (adds your key there, pins its key here)
    Pair {
        /// [user@]host[:port]
        destination: String,
        /// Code printed by `qshd pair` (asked for when not given: other
        /// local users can read a command line)
        code: Option<String>,
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
    /// Set a host up for qsh through ssh: add your key there and pin qshd's host key
    CopyId {
        /// [user@]host[:port] or an alias, as for ssh (the port is qshd's)
        destination: String,
    },
    /// Forget a host's key (after a legitimate change), as ssh-keygen -R
    Forget {
        /// [user@]host[:port] or an alias
        destination: String,
    },
    /// Check this computer's setup and, for a host, each step of connecting
    Doctor {
        /// [user@]host[:port] or an alias
        destination: Option<String>,
        /// The checks as JSON, for scripts
        #[arg(long)]
        json: bool,
    },
    /// Run a command on several hosts at once: qsh multi [-g GROUP] [HOST...] -- COMMAND
    Multi {
        /// Hosts of this group (from `qsh ui` or ~/.config/qsh/groups); repeatable
        #[arg(short = 'g', long = "group", value_name = "GROUP")]
        groups: Vec<String>,
        /// How many hosts at a time
        #[arg(short = 'P', long, default_value_t = 16)]
        parallel: usize,
        /// One JSON array at the end (host, exit code, output) instead of prefixed lines
        #[arg(long)]
        json: bool,
        /// [user@]host[:port] or an alias
        hosts: Vec<String>,
        /// The command (after --)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Print a completion script: bash, zsh or fish
    Completions {
        shell: Option<String>,
        /// List the host names to complete (what the scripts call)
        #[arg(long)]
        hosts: bool,
    },
    /// Update qsh, and qshd next to it, to the latest release; restarts a running qshd service
    Update {
        /// Release tag instead of the latest, for example v1.0.2
        version: Option<String>,
    },
    /// Experimental: reach a qshd behind NAT by punching a UDP hole
    Punch {
        #[command(subcommand)]
        cmd: PunchCmd,
    },
}

#[derive(Subcommand)]
enum PunchCmd {
    /// The side behind NAT: wait for the other side and pass the packets to the local qshd
    Serve {
        /// Where the local qshd listens
        #[arg(long, default_value = "127.0.0.1:4422")]
        to: std::net::SocketAddr,
        /// The other side's public address (asked for on stdin when missing)
        #[arg(long)]
        peer: Option<String>,
        /// Keep this local UDP port between runs, so its NAT mapping survives
        #[arg(long)]
        punch_port: Option<u16>,
        /// The shared secret both sides give (a fresh one is printed when missing);
        /// QSH_PUNCH_ID sets it without showing it to other local users
        #[arg(long, value_name = "STRING")]
        id: Option<String>,
        /// Do not ask STUN servers for the public address
        #[arg(long)]
        no_stun: bool,
    },
    /// The side that connects: punch the hole and listen on loopback for qsh
    Dial {
        /// The other side's public address
        #[arg(long)]
        peer: String,
        /// Where the local qsh connects (4422 keeps the host key entry the same as a normal connection)
        #[arg(long, default_value = "127.0.0.1:4422")]
        listen: std::net::SocketAddr,
        /// Keep this local UDP port between runs, so its NAT mapping survives
        #[arg(long)]
        punch_port: Option<u16>,
        /// The shared secret both sides give (a fresh one is printed when missing);
        /// QSH_PUNCH_ID sets it without showing it to other local users
        #[arg(long, value_name = "STRING")]
        id: Option<String>,
        /// Do not ask STUN servers for the public address
        #[arg(long)]
        no_stun: bool,
    },
}

impl ConnArgs {
    /// The same options as `qsh` arguments, for child processes.
    fn as_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(p) = self.port {
            args.extend(["-p".to_string(), p.to_string()]);
        }
        for i in &self.identity {
            args.extend(["-i".to_string(), i.display().to_string()]);
        }
        if self.transport != Mode::Auto {
            let name = if self.transport == Mode::Quic { "quic" } else { "tcp" };
            args.extend(["--transport".to_string(), name.to_string()]);
        }
        if self.accept_new_host {
            args.push("--accept-new-host".into());
        }
        for _ in 0..self.verbose {
            args.push("-v".into());
        }
        if self.full {
            args.push("--full".into());
        }
        args
    }

    fn options(&self) -> ConnectOptions {
        ConnectOptions {
            identities: self.identity.clone(),
            transport: self.transport,
            accept_new_host: self.accept_new_host,
            full: self.full,
            resume: None,
            share: true,
            host_keys_from_ssh: Vec::new(),
        }
    }
}

/// True when this binary was started as `ssh` (e.g. through a symlink).
fn invoked_as_ssh(argv0: &str) -> bool {
    Path::new(argv0).file_stem().is_some_and(|n| n == "ssh")
}

fn init_logging(verbose: u8, quiet: bool) {
    let filter = match verbose {
        0 if quiet => "qsh=error",
        0 => "qsh=warn",
        1 => "qsh=debug",
        2 => "qsh=trace",
        // The libraries too: the transport and TLS.
        _ => "qsh=trace,quinn=debug,quinn_proto=debug,rustls=debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .init();
}

/// What the transport's own words mean for the person reading them.
fn hint(e: &anyhow::Error) -> &'static str {
    let text = format!("{e:#}");
    if text.contains("reset by peer") {
        "\nThe server no longer knows this connection, as after a long sleep or a restart of qshd. Run qsh again."
    } else if text.contains("timed out") && text.contains("connection lost") {
        "\nNothing came back from the server for too long. Check the network and run qsh again."
    } else {
        ""
    }
}

fn finish(result: Result<i32>) -> ! {
    let code = match result {
        Ok(code) => code,
        Err(e) => {
            // Not eprintln: a closed stderr must not turn the code into a panic's.
            let _ = std::io::Write::write_fmt(&mut std::io::stderr(), format_args!("qsh: {e:#}{}\n", hint(&e)));
            255
        }
    };
    // Exit right away: a blocked stdin reader thread must not keep the process alive.
    std::process::exit(code);
}

fn main() {
    // A bug must not leave the terminal raw, or the process hanging on a
    // thread blocked reading stdin: restore the terminal and exit.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        // `qsh ui` reads the mouse: left on, every scroll would type escape codes.
        if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
            let _ = std::io::Write::write_all(&mut std::io::stdout(), b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l");
        }
        if qsh::platform::is_broken_pipe_print(info) {
            std::process::exit(141);
        }
        default_hook(info);
        std::process::exit(101);
    }));
    qsh::platform::blocking_stdio();
    let args = qsh::platform::args_or_exit("qsh");
    if let Ok(home) = qsh::keys::home_dir() {
        qsh::client::config::create_template(&home);
    }
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
        // As ssh (or with --full), what qsh does not understand is ssh's.
        Err(e) if as_ssh || args.iter().skip(1).any(|a| a == "--full") => {
            finish(exec_openssh("ssh", without_qsh_options(&args[1..]), &e))
        }
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
    // A background master or `-f` child may live long: it must not keep its
    // caller's pipes and files open (OpenSSH's closefrom(3)).
    #[cfg(unix)]
    if std::env::var_os(MASTER_FD).is_some() || std::env::var_os(DAEMON_FD).is_some() {
        qsh::platform::close_inherited_fds();
    }
    #[cfg(unix)]
    if std::env::var_os(MASTER_FD).is_some() {
        init_logging(a.verbose, a.quiet);
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        finish(rt.block_on(master_main(a)));
    }
    // ForkAfterAuthentication in the config means -f.
    #[cfg(unix)]
    let master = std::env::var_os(MASTER_FD).is_some();
    #[cfg(not(unix))]
    let master = false;
    if !a.background && !master && a.control_command.is_none() && std::env::var_os("QSH_NO_FORK").is_none() {
        if let Some(dest) = &a.destination {
            if Target::resolve(dest, a.port, &sources(&a)).is_ok_and(|t| t.fork_after_authentication) {
                a.background = true;
            }
        }
    }
    #[cfg(not(unix))]
    if a.background {
        finish(Err(anyhow!("-f (going to the background) is not supported on this system")));
    }
    #[cfg(unix)]
    if a.background && std::env::var_os(DAEMON_FD).is_none() {
        finish(run_in_background(&args));
    }
    init_logging(a.verbose, a.quiet);
    for ignored in &a.ignored {
        tracing::debug!("ignoring {ignored}");
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    finish(rt.block_on(session_main(a, &args)));
}

/// Environment variable carrying the readiness pipe to a backgrounded qsh.
#[cfg(unix)]
const DAEMON_FD: &str = "QSH_BACKGROUND_FD";

/// Environment variable carrying the readiness pipe to a background
/// connection master (`ControlPersist`).
#[cfg(unix)]
const MASTER_FD: &str = "QSH_MASTER_FD";

/// Runs qsh again as a child that reports a status word once it is logged
/// in (it may still ask questions on the terminal), over a Unix socket in a
/// private directory named in `env`. Nothing is inherited, so a process the
/// child starts later cannot keep this one waiting. Returns the word (empty
/// if the child ended without one) and the child.
#[cfg(unix)]
fn spawn_with_status(args: &[String], env: &str) -> Result<(String, std::process::Child)> {
    use std::io::Read;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::process::CommandExt;
    let base = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|p| p.is_dir()).unwrap_or_else(std::env::temp_dir);
    // A new directory only we can enter (creating it fails if the name exists).
    let dir = base.join(format!("qsh-{}-{:08x}", std::process::id(), rand::random::<u32>()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let result = (|| {
        let sock = dir.join("ready");
        let listener = std::os::unix::net::UnixListener::bind(&sock).with_context(|| format!("cannot listen on {}", sock.display()))?;
        listener.set_nonblocking(true).context("readiness socket")?;
        let mut child = std::process::Command::new(std::env::current_exe()?)
            // As typed: started as `ssh`, the child must know it too.
            .arg0(&args[0])
            .args(&args[1..])
            .env_remove(DAEMON_FD)
            .env_remove(MASTER_FD)
            .env(env, &sock)
            .spawn()
            .context("cannot start qsh again")?;
        loop {
            match listener.accept() {
                Ok((mut s, _)) => {
                    s.set_nonblocking(false).context("readiness connection")?;
                    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                    let mut status = String::new();
                    let _ = s.read_to_string(&mut status);
                    return Ok((status.trim().to_string(), child));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if child.try_wait()?.is_some() {
                        return Ok((String::new(), child));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(anyhow::Error::from(e).context("waiting for the background qsh")),
            }
        }
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// `-f`: runs qsh again as a child that logs in, then detaches; this process
/// exits once the child is ready.
#[cfg(unix)]
fn run_in_background(args: &[String]) -> Result<i32> {
    let (status, mut child) = spawn_with_status(args, DAEMON_FD)?;
    if status == "ok" {
        return Ok(0);
    }
    // The child failed before it was ready and has reported why.
    Ok(child.wait()?.code().unwrap_or(255))
}

/// In a child started by [`spawn_with_status`]: report `status` to the parent
/// and detach from the terminal (new session, stdin from /dev/null). With
/// `quiet`, output goes to /dev/null too; otherwise it stays, like ssh -f.
#[cfg(unix)]
fn detach(env: &str, status: &str, quiet: bool) -> Result<()> {
    use std::io::Write;
    let Some(path) = std::env::var_os(env) else {
        return Ok(());
    };
    // Report first: once stderr is gone, an error could not be seen.
    let mut parent = std::os::unix::net::UnixStream::connect(&path).with_context(|| format!("cannot reach {}", Path::new(&path).display()))?;
    let null = std::fs::OpenOptions::new().read(true).write(true).open("/dev/null")?;
    nix::unistd::dup2_stdin(&null).context("detaching stdin")?;
    if quiet {
        nix::unistd::dup2_stdout(&null).context("detaching stdout")?;
        nix::unistd::dup2_stderr(&null).context("detaching stderr")?;
    }
    let _ = nix::unistd::setsid();
    parent.write_all(status.as_bytes()).context("reporting to the parent")?;
    Ok(())
}

/// Starts a background master for `target` (`ControlPersist`) unless one is
/// running. Returns an exit code if the master could not log in (it has
/// said why), so the login is not tried, and failed, twice.
#[cfg(unix)]
async fn start_background_master(target: &Target, args: &[String]) -> Result<Option<i32>> {
    use qsh::transport::shared;
    let Some(path) = &target.sharing.path else { return Ok(None) };
    if shared::control(path, shared::Command::Check).await.is_ok() {
        return Ok(None);
    }
    let (status, mut child) = spawn_with_status(args, MASTER_FD)?;
    match status.as_str() {
        "ok" => Ok(None),
        // No qshd there (`--full`), or no socket: go on as usual (with
        // `--full` that hands over to ssh).
        "none" => {
            let _ = child.wait();
            Ok(None)
        }
        _ => Ok(Some(child.wait()?.code().unwrap_or(255))),
    }
}

/// The background master (`ControlPersist`): logs in, serves the connection
/// on its socket, and ends when it has been unused for the persist time,
/// on `-O exit`, or when the connection is lost.
#[cfg(unix)]
async fn master_main(a: SshArgs) -> Result<i32> {
    use qsh::client::control::Persist;
    use qsh::transport::shared::{InUse, Master};
    let dest = a.destination.clone().context("missing destination")?;
    let target = Target::resolve(&dest, a.port, &sources(&a))?;
    let path = target.sharing.path.clone().context("no ControlPath")?;
    prepare_control_dir(&path)?;
    // Before the login: failing after it would ask for a one-time code twice.
    if let Err(e) = qsh::transport::shared::can_listen(&path) {
        eprintln!("qsh: not sharing the connection: {e:#}");
        detach(MASTER_FD, "none", true)?;
        return Ok(255);
    }
    let opts = ConnectOptions {
        identities: a.identities.clone(),
        transport: a.transport,
        accept_new_host: a.accept_new_host,
        full: a.full,
        resume: None,
        share: false,
        host_keys_from_ssh: Vec::new(),
    };
    let conn = match client::connect(&target, &opts).await {
        Ok(c) => Arc::new(c),
        Err(e) if a.full && e.is::<Unreachable>() => {
            detach(MASTER_FD, "none", true)?;
            return Ok(255);
        }
        Err(e) => return Err(e),
    };
    let forwarder = forward::Forwarder::new(conn.clone(), a.gateway_ports, target.permit_remote_open, target.loopback_fallback);
    let master = match Master::start(forwarder.connections(), &path, Some(forward_hook(&forwarder)), forwarder.activity()) {
        Ok(m) => m,
        // Another qsh got there first: use that one.
        Err(e) if e.is::<InUse>() => {
            detach(MASTER_FD, "ok", true)?;
            conn.close().await;
            return Ok(0);
        }
        // E.g. a socket path that is too long: go on without sharing.
        Err(e) => {
            eprintln!("qsh: not sharing the connection: {e:#}");
            detach(MASTER_FD, "none", true)?;
            conn.close().await;
            return Ok(255);
        }
    };
    detach(MASTER_FD, "ok", true)?;
    let linger = match target.sharing.persist {
        Persist::Forever => None,
        Persist::For(d) => Some(d),
        Persist::No => Some(Duration::ZERO),
    };
    tokio::select! {
        () = master.wait_idle(&conn, Some(linger)) => {}
        _ = session::termination_signal(true) => {}
    }
    drop(master);
    conn.close().await;
    Ok(0)
}

/// Creates qsh's own socket directory (private); other ControlPath
/// directories are the user's business, as in ssh.
#[cfg(unix)]
fn prepare_control_dir(path: &Path) -> Result<()> {
    let default = qsh::client::control::default_dir(&home_dir()?);
    if path.parent() == Some(default.as_path()) {
        qsh::keys::create_private_dir(&default)?;
    }
    Ok(())
}

/// `-O check|exit|stop`.
async fn control_command(target: &Target, command: &str, a: &SshArgs) -> Result<i32> {
    #[cfg(unix)]
    {
        use qsh::transport::shared::{control, Command};
        let path = target
            .sharing
            .path
            .as_ref()
            .context("no control socket for this host (set ControlMaster or ControlPath, or use -S)")?;
        if matches!(command, "forward" | "cancel") {
            // `-O forward -L ... -R ...`: each forward goes to the master.
            let cancel = command == "cancel";
            let specs: Vec<(char, &String)> = a
                .local_forwards
                .iter()
                .map(|s| ('L', s))
                .chain(a.remote_forwards.iter().map(|s| ('R', s)))
                .chain(a.dynamic_forwards.iter().map(|s| ('D', s)))
                .collect();
            if specs.is_empty() {
                bail!("-O {command} needs forwards (-L, -R or -D)");
            }
            let mut code = 0;
            for (kind, spec) in specs {
                match control(path, Command::Forward { kind, spec: spec.clone(), cancel }).await {
                    // ssh prints the port a `-R 0:...` got.
                    Ok((_, msg)) if !msg.is_empty() => println!("{msg}"),
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("qsh: -{kind} {spec}: {e:#}");
                        code = 255;
                    }
                }
            }
            return Ok(code);
        }
        let (cmd, done) = match command {
            "check" => (Command::Check, None),
            "exit" => (Command::Exit, Some("Exit request sent.")),
            _ => (Command::Stop, Some("Stop listening request sent.")),
        };
        match control(path, cmd).await {
            Ok((pid, _)) => {
                eprintln!("{}", done.map(str::to_string).unwrap_or_else(|| format!("Master running (pid={pid})")));
                Ok(0)
            }
            Err(e) => {
                eprintln!("qsh: {e:#}");
                Ok(255)
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (target, command, a);
        bail!("connection sharing (-O) is not supported on this system")
    }
}

/// `-O forward` / `-O cancel` for a master, through its forwards.
#[cfg(unix)]
fn forward_hook(forwarder: &Arc<forward::Forwarder>) -> qsh::transport::shared::ForwardHook {
    let forwarder = forwarder.clone();
    Arc::new(move |kind, spec, cancel| {
        let forwarder = forwarder.clone();
        Box::pin(async move { forwarder.request(kind, &spec, cancel).await })
    })
}

fn sources(a: &SshArgs) -> Sources {
    let mut overrides = Vec::new();
    if let Some(j) = &a.jump {
        overrides.push(format!("ProxyJump {j}"));
    }
    overrides.extend(a.override_lines());
    Sources { full: a.full, overrides, ssh_config: a.config_file.clone(), user: a.login.clone() }
}

async fn tool_main(cli: ToolCli) -> Result<i32> {
    let opts = cli.conn.options();
    match cli.cmd {
        Cmd::Keygen { file } => keygen(file),
        Cmd::Pair { destination, code } => {
            let target = Target::parse(&destination, cli.conn.port, cli.conn.full)?;
            // The menu hands its code over in the environment, which only this user can read.
            let code = match code.or_else(|| std::env::var("QSH_PAIR_CODE").ok().filter(|c| !c.is_empty())) {
                Some(c) => c,
                None => qsh::prompt::line("Pairing code: ")?,
            };
            client::pair(&target, &opts, code.trim()).await.map_err(|e| with_doctor_hint(e, &target))?;
            Ok(0)
        }
        Cmd::Cp { recursive, compress, paths } => cp(&paths, (recursive, compress), &cli.conn).await,
        Cmd::Speed { destination, seconds } => {
            let target = Target::parse(&destination, cli.conn.port, cli.conn.full)?;
            speed_test(&target, &opts, Duration::from_secs(seconds)).await
        }
        Cmd::Ui => qsh::client::tui::run(opts).await,
        Cmd::Completions { shell, hosts } => {
            if hosts {
                for h in client::completions::hosts(&home_dir()?) {
                    println!("{h}");
                }
                return Ok(0);
            }
            let shell = shell.context("which shell: qsh completions bash|zsh|fish")?;
            print!("{}", client::completions::script(&shell).with_context(|| format!("no completions for {shell:?} (bash, zsh, fish)"))?);
            Ok(0)
        }
        Cmd::CopyId { destination } => {
            let target = Target::parse(&destination, cli.conn.port, cli.conn.full)?;
            client::copy_id::run(&target, &opts).await.map_err(|e| with_doctor_hint(e, &target))?;
            Ok(0)
        }
        Cmd::Forget { destination } => {
            let target = Target::parse(&destination, cli.conn.port, cli.conn.full)?;
            match client::forget(&target)? {
                (0, path) => println!("{} is not in {}", target.key_name(), path.display()),
                (n, path) => println!("removed {n} key{} of {} from {}", if n == 1 { "" } else { "s" }, target.key_name(), path.display()),
            }
            Ok(0)
        }
        Cmd::Doctor { destination, json } => qsh::client::doctor::run(destination.as_deref(), cli.conn.port, &opts, json).await,
        Cmd::Multi { groups, parallel, json, hosts, command } => {
            use qsh::client::{groups as host_groups, multi};
            let all = if groups.is_empty() { Default::default() } else { host_groups::load(&home_dir()?)? };
            let dests = multi::destinations(&all, &groups, &hosts)?;
            multi::run(&dests, &command, parallel, &cli.conn.as_args(), json).await
        }
        Cmd::Update { version } => update(version.as_deref()),
        Cmd::Punch { cmd } => {
            use qsh::punch;
            match cmd {
                PunchCmd::Serve { to, peer, punch_port, id, no_stun } => {
                    // QSH_PUNCH_ID keeps a chosen secret out of the process list (`--id` is visible there).
                    let (secret, fresh) = punch::secret(id.or_else(|| std::env::var("QSH_PUNCH_ID").ok()));
                    if fresh {
                        println!("qsh punch: shared id {secret} (give it to the other side with --id)");
                    }
                    let peer = match peer {
                        Some(p) => Some(punch::resolve(&p).await?),
                        None => None,
                    };
                    let bind = punch::bind_for(peer, punch_port);
                    punch::serve(punch::ServeOptions { bind, peer, secret, stun: !no_stun, target: to }).await?;
                    Ok(0)
                }
                PunchCmd::Dial { peer, listen, punch_port, id, no_stun } => {
                    // QSH_PUNCH_ID keeps a chosen secret out of the process list (`--id` is visible there).
                    let (secret, fresh) = punch::secret(id.or_else(|| std::env::var("QSH_PUNCH_ID").ok()));
                    if fresh {
                        println!("qsh punch: shared id {secret} (give it to the other side with --id)");
                    }
                    let peer = punch::resolve(&peer).await?;
                    let bind = punch::bind_for(Some(peer), punch_port);
                    punch::dial(punch::DialOptions { bind, peer, secret, stun: !no_stun, listen }).await?;
                    Ok(0)
                }
            }
        }
    }
}

const RELEASES: &str = "https://github.com/VLOD-ZDOV/quic-ssh/releases";

/// Runs the release's installer in update mode on the directory this qsh is
/// in, once the release's signed `SHA256SUMS` checks out and lists it.
fn update(version: Option<&str>) -> Result<i32> {
    if let Some(v) = version {
        if !v.starts_with('v') || !v[1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            bail!("not a release tag: {v} (for example v1.0.2)");
        }
    }
    let exe = std::env::current_exe().and_then(|p| p.canonicalize()).context("cannot find this qsh")?;
    let dir = exe.parent().context("cannot find this qsh")?;
    let base = match version {
        Some(v) => format!("{RELEASES}/download/{v}"),
        None => format!("{RELEASES}/latest/download"),
    };
    let tmp = std::env::temp_dir().join(format!("qsh-update-{}-{:016x}", std::process::id(), rand::random::<u64>()));
    qsh::keys::create_private_dir(&tmp)?;
    let result = update_in(&tmp, &base, version, dir);
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

fn update_in(tmp: &Path, base: &str, version: Option<&str>, dir: &Path) -> Result<i32> {
    use qsh::release;
    let installer = if cfg!(windows) { "install.ps1" } else { "install.sh" };
    for file in ["SHA256SUMS", "SHA256SUMS.sig", installer] {
        download(&format!("{base}/{file}"), &tmp.join(file)).with_context(|| format!("cannot download {file}"))?;
    }
    let sums = std::fs::read(tmp.join("SHA256SUMS"))?;
    let sig = std::fs::read_to_string(tmp.join("SHA256SUMS.sig"))?;
    release::verify(&sums, &sig).context("not updating")?;
    let sums_text = String::from_utf8_lossy(&sums);
    let tag = release::version(&sums_text).context("not updating: the signed SHA256SUMS names no release")?;
    let current = concat!("v", env!("CARGO_PKG_VERSION"));
    match version {
        // An old release's signed list must not pass for the one asked for.
        Some(v) if v != tag => bail!("not updating: asked for {v}, but the signed SHA256SUMS is for {tag}"),
        Some(_) => {}
        None if release::older(tag, current) => {
            bail!("not updating: the latest release ({tag}) is older than this qsh ({current}); use --version to go back")
        }
        None => {}
    }
    let script = std::fs::read(tmp.join(installer))?;
    let want = release::listed(&sums_text, installer).with_context(|| format!("not updating: {installer} is not in SHA256SUMS"))?;
    if release::sha256_hex(&script) != want {
        bail!("not updating: {installer} does not match its checksum");
    }
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("powershell");
        c.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]).arg(tmp.join(installer));
        c
    } else {
        let mut c = std::process::Command::new("sh");
        c.arg(tmp.join(installer)).arg("--update");
        c
    };
    // The installer takes the archives from that release and checks them
    // against the list checked here, not one it downloads again.
    cmd.env("QSH_BIN_DIR", dir).env("QSH_VERSION", tag).env("QSH_SUMS", tmp.join("SHA256SUMS"));
    let status = cmd.status().context("cannot run the installer")?;
    Ok(status.code().unwrap_or(1))
}

/// Saves `url` to `to` with curl or wget (PowerShell on Windows).
fn download(url: &str, to: &Path) -> Result<()> {
    use std::process::{Command, Stdio};
    let ok = if cfg!(windows) {
        // Through the environment: words after -Command are pasted into the script.
        let script = "$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri $env:QSH_DL_URL -OutFile $env:QSH_DL_TO -UseBasicParsing";
        Command::new("powershell").args(["-NoProfile", "-Command", script]).env("QSH_DL_URL", url).env("QSH_DL_TO", to).status()?.success()
    } else {
        let curl = Command::new("curl").args(["-fsSL", "-o"]).arg(to).arg(url).stdin(Stdio::null()).status();
        match curl {
            Ok(s) => s.success(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Command::new("wget").arg("-qO").arg(to).arg(url).stdin(Stdio::null()).status().context("need curl or wget")?.success(),
            Err(e) => return Err(e.into()),
        }
    };
    if !ok {
        bail!("{url}: download failed");
    }
    Ok(())
}

/// `-G`: prints the resolved settings, like ssh. Tools (e.g. git) also use it
/// to detect an OpenSSH-compatible client.
fn print_config(t: &Target) {
    print!("{}", config_lines(t));
}

/// The settings with the command-line switches the session applies on top
/// of the config (-A/-a, -t/-T, --accept-new-host), so -G shows what it gets.
fn with_switches(mut t: Target, a: &SshArgs) -> Target {
    t.forward_agent = a.forward_agent.unwrap_or(t.forward_agent);
    if a.no_tty {
        t.request_tty = Some("no".into());
    } else if a.tty > 0 {
        t.request_tty = Some(if a.tty >= 2 { "force" } else { "yes" }.into());
    }
    if a.accept_new_host {
        t.host_key_policy = client::HostKeyPolicy::AcceptNew;
    }
    t
}

/// The lines of [`print_config`], in a fixed order.
fn config_lines(t: &Target) -> String {
    use std::fmt::Write;
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    let mut out = format!("user {}\nhostname {}\nport {}\n", t.user, t.host, t.port);
    let mut line = |key: &str, value: &dyn std::fmt::Display| {
        let _ = writeln!(out, "{key} {value}");
    };
    for f in &t.identity_files {
        line("identityfile", &f.display());
    }
    for (name, list) in [("localforward", &t.local_forwards), ("remoteforward", &t.remote_forwards), ("dynamicforward", &t.dynamic_forwards)] {
        for f in list {
            line(name, f);
        }
    }
    if let Some(j) = &t.proxy_jump {
        line("proxyjump", j);
    }
    if let Some(c) = &t.proxy_command {
        line("proxycommand", c);
    }
    if let Some(p) = &t.sharing.path {
        line("controlpath", &p.display());
    }
    line("batchmode", &yes_no(t.batch_mode));
    let strict = match t.host_key_policy {
        client::HostKeyPolicy::Ask => "ask",
        client::HostKeyPolicy::AcceptNew => "accept-new",
        client::HostKeyPolicy::Strict => "true",
    };
    line("stricthostkeychecking", &strict);
    line("passwordauthentication", &yes_no(t.password_authentication));
    line("numberofpasswordprompts", &t.password_prompts);
    let user_file = t.known_hosts_file.clone().or_else(|| home_dir().ok().map(|h| qsh_dir(&h).join("known_hosts")));
    if let Some(f) = user_file {
        line("userknownhostsfile", &f.display());
    }
    // The further files qsh only reads: more UserKnownHostsFiles and GlobalKnownHostsFile.
    let read_also: Vec<String> = t.known_hosts_read_also.iter().map(|f| f.display().to_string()).collect();
    line("globalknownhostsfile", &if read_also.is_empty() { "none".to_string() } else { read_also.join(" ") });
    if let Some(c) = &t.known_hosts_command {
        line("knownhostscommand", c);
    }
    line("hashknownhosts", &yes_no(t.hash_known_hosts));
    if let Some(a) = &t.host_key_alias {
        line("hostkeyalias", a);
    }
    line("addkeystoagent", &t.add_keys_to_agent.as_deref().unwrap_or("no"));
    match (&t.forward_agent_socket, t.forward_agent) {
        (Some(socket), true) => line("forwardagent", &socket.display()),
        (_, on) => line("forwardagent", &yes_no(on)),
    }
    line("forwardx11", &yes_no(t.forward_x11.is_some()));
    line("forwardx11trusted", &yes_no(t.forward_x11 == Some(true)));
    line("identitiesonly", &yes_no(t.identities_only));
    line("requesttty", &t.request_tty.as_deref().unwrap_or("auto"));
    if let Some(c) = &t.local_command {
        line("localcommand", c);
    }
    line("clearallforwardings", &yes_no(t.clear_all_forwardings));
    out
}

/// `--save NAME`: keeps the connection for `qsh NAME` and `qsh ui`, then
/// it is made as usual.
fn save_connection(name: &str, dest: &str, a: &SshArgs) -> Result<()> {
    use qsh::client::saved;
    let (entry, left_out) = saved::from_args(name, dest, a).context("--save")?;
    let home = home_dir()?;
    let mut all = saved::load(&home)?;
    let exists = all.iter().any(|s| s.name == name);
    // A name from the user's own config would win over the saved one anyway.
    if !exists && client::config::host_aliases(&home).iter().any(|h| h == name) {
        bail!("--save: {name} is already a host in your config file; pick another name");
    }
    if exists && !a.save_force {
        bail!("--save: a connection named {name} is already saved (--force replaces it)");
    }
    all.retain(|s| s.name != name);
    all.push(entry);
    saved::save(&home, &all)?;
    if !a.quiet {
        eprintln!("qsh: saved as {name}: `qsh {name}` or qsh ui");
        for what in left_out {
            eprintln!("qsh: warning: not saved: {what}");
        }
    }
    Ok(())
}

async fn session_main(mut a: SshArgs, args: &[String]) -> Result<i32> {
    if let Some(why) = a.refused.clone() {
        if a.full {
            return exec_openssh("ssh", without_qsh_options(&args[1..]), &why);
        }
        bail!("{why}\n{USAGE}");
    }
    let Some(dest) = a.destination.clone() else {
        // `ssh -Q kex` and the like.
        if a.full {
            return exec_openssh("ssh", without_qsh_options(&args[1..]), "no destination for qsh");
        }
        bail!("missing destination\n{USAGE}");
    };
    if a.save_force && a.save.is_none() {
        bail!("--force goes with --save NAME");
    }
    if let Some(name) = &a.save {
        save_connection(name, &dest, &a)?;
    }
    let mut target = match Target::resolve(&dest, a.port, &sources(&a)) {
        Ok(t) => t,
        // A user or host qsh cannot take (an AD-style user, say): ssh's job.
        Err(e) if a.full && !e.is::<client::ConfigError>() => return exec_openssh("ssh", without_qsh_options(&args[1..]), &format!("{e:#}")),
        Err(e) => return Err(e),
    };
    if !(a.quiet || target.quiet) {
        for o in &target.unapplied {
            eprintln!("qsh: warning: {o} is not supported by qsh and has no effect");
        }
    }
    tracing::debug!(
        "{dest}: user {}, host {}, port {}{} (~/.config/qsh/config, then ~/.ssh/config; `qsh -G {dest}` shows the main settings)",
        target.user,
        target.host,
        target.port,
        target.alt_ports.iter().map(|p| format!(" or {p}")).collect::<String>()
    );
    if a.print_config {
        print_config(&with_switches(target, &a));
        return Ok(0);
    }
    if let Some(cmd) = &a.control_command {
        // With --full, a master qsh does not have is ssh's.
        if a.full && !target.sharing.path.as_ref().is_some_and(|p| p.exists()) {
            return exec_openssh("ssh", without_qsh_options(&args[1..]), "no qsh connection master for -O");
        }
        return control_command(&target, cmd, &a).await;
    }
    // Session settings from the config, as if given on the command line.
    if let Some(remote) = &target.remote_command {
        if !a.command.is_empty() {
            bail!("cannot execute both the command line and RemoteCommand");
        }
        a.command = vec![target.expand_tokens(remote)?];
    }
    match target.session_type.as_deref() {
        None | Some("default") => {}
        Some("none") => a.no_command = true,
        Some("subsystem") => a.subsystem = true,
        Some(other) => bail!("unknown SessionType {other:?} (none, subsystem, default)"),
    }
    a.stdin_null |= target.stdin_null;
    if a.background && !a.no_command && a.command.is_empty() && a.stdio_forward.is_none() {
        bail!("cannot go to the background (-f) without a command or -N");
    }
    if a.full && target.needs_proxy {
        return exec_openssh("ssh", ssh_args(&a, &target), "the ssh config uses ProxyJump/ProxyCommand");
    }
    let quiet = a.quiet || target.quiet;
    // ClearAllForwardings drops the forwards from the config and the command line.
    let clear = target.clear_all_forwardings;
    let mut locals: Vec<(Forward, bool)> = Vec::new();
    let mut remotes: Vec<(Forward, bool)> = Vec::new();
    let mut dynamics: Vec<(Forward, bool)> = Vec::new();
    // The same forward in two places (the command line, qsh's config that
    // `qsh ui` writes, ssh's config) is set up once.
    let add = |list: &mut Vec<(Forward, bool)>, f: Forward, required: bool| {
        if !list.iter().any(|(g, _)| *g == f) {
            list.push((f, required));
        }
    };
    if !clear {
        for (specs, required) in [(&a.local_forwards, true), (&target.local_forwards, false)] {
            for s in specs {
                add(&mut locals, Forward::parse(s).with_context(|| format!("-L {s}"))?, required);
            }
        }
        for (specs, required) in [(&a.remote_forwards, true), (&target.remote_forwards, false)] {
            for s in specs {
                add(&mut remotes, Forward::parse_remote(s).with_context(|| format!("-R {s}"))?, required);
            }
        }
        for (specs, required) in [(&a.dynamic_forwards, true), (&target.dynamic_forwards, false)] {
            for s in specs {
                add(&mut dynamics, Forward::parse_dynamic(s).with_context(|| format!("-D {s}"))?, required);
            }
        }
    }

    if a.full && target.permit_remote_open && remotes.iter().any(|(f, _)| matches!(f.dest, forward::Dest::Socks)) {
        return exec_openssh("ssh", ssh_args(&a, &target), "PermitRemoteOpen applies to this dynamic remote forward");
    }
    // -A / ForwardAgent: the agent qsh itself would use.
    let agent = match a.forward_agent.unwrap_or(target.forward_agent) {
        true => match (&target.forward_agent_socket, &target.identity_agent) {
            (Some(socket), _) => Some(socket.clone()),
            (None, Some(path)) => path.clone(),
            (None, None) => qsh::agent::default_path(),
        },
        false => None,
    };
    // Streams the server opens for -A and -X would reach the master, not
    // this qsh: such a run uses a connection of its own. A -R is the
    // master's to hold for this run (below).
    let share = agent.is_none() && target.forward_x11.is_none();
    let opts = ConnectOptions {
        identities: a.identities.clone(),
        transport: a.transport,
        accept_new_host: a.accept_new_host,
        full: a.full,
        resume: None,
        share,
        host_keys_from_ssh: Vec::new(),
    };
    let needs_this_connection = target.forward_x11.is_some() || target.tunnel.is_some();
    // Only a plain login in a terminal goes back to what was left there.
    let restoring = target.restore_session
        && target.persist_session
        && !needs_this_connection
        && a.command.is_empty()
        && !a.no_command
        && !a.no_tty
        && !a.subsystem
        && !a.background
        && a.stdio_forward.is_none()
        && std::io::stdin().is_terminal();
    let session_key = qsh::client::control::connection_hash(&target.host, target.port, &target.user);
    let (mut claim, mut left_behind, mut resumed) = (None, None, None);
    if restoring {
        let home = home_dir()?;
        for (found, token) in qsh::client::restore::left_behind(&home, &session_key) {
            let quiet_target = Target { batch_mode: true, quiet: true, ..target.clone() };
            match client::connect(&quiet_target, &ConnectOptions { resume: Some(token.clone()), ..opts.clone() }).await {
                Ok(c) => {
                    (claim, left_behind, resumed) = (Some(found), Some(token), Some(c));
                    break;
                }
                Err(e) if e.is::<client::LoginRefused>() => found.forget(),
                Err(e) => tracing::debug!("not going back to a session left running: {e:#}"),
            }
        }
        if claim.is_none() {
            match qsh::client::restore::Claim::new(&home, &session_key) {
                Ok(c) => claim = Some(c),
                Err(e) => eprintln!("qsh: warning: RestoreSession: {e:#}"),
            }
        }
    }
    // The agent and the display are offered to every session of the
    // connection: one with them is not one to share with later runs, and a
    // connection that came back with a token can do nothing else.
    #[cfg(unix)]
    let private = agent.is_some() || target.forward_x11.is_some() || left_behind.is_some();
    #[cfg(unix)]
    if share && resumed.is_none() && target.sharing.background_master() {
        if let Some(code) = start_background_master(&target, args).await? {
            return Ok(code);
        }
    }
    #[cfg(not(unix))]
    let _ = args;
    let connected = match resumed {
        Some(c) => Ok(c),
        None => client::connect(&target, &opts).await,
    };
    let conn = match connected {
        Ok(c) => Arc::new(c),
        Err(e) if a.full && e.is::<Unreachable>() => {
            return exec_openssh("ssh", ssh_args(&a, &target), &format!("{e:#}"));
        }
        Err(e) => return Err(with_doctor_hint(e, &target)),
    };
    // Only now: had ssh made the connection, it would have used them.
    if !quiet {
        for o in &a.unapplied {
            eprintln!("qsh: warning: {o} is not supported by qsh and has no effect");
        }
    }
    if let Some(spec) = &a.stdio_forward {
        forward::stdio(&conn, spec).await?;
        conn.close().await;
        return Ok(0);
    }
    let forwarder = forward::Forwarder::new(conn.clone(), a.gateway_ports, target.permit_remote_open, target.loopback_fallback);
    // This run's own forwards, taken back before a master waits for others.
    let mut own: Vec<(char, String)> = Vec::new();
    for (kind, list) in [('L', locals), ('D', dynamics)] {
        for (f, required) in list {
            let spec = f.describe();
            match forwarder.local(kind, f).await {
                Ok(()) => own.push((kind, spec)),
                // Like ssh: a forward from the config that cannot bind is only a warning.
                Err(e) if !required && !target.exit_on_forward_failure => eprintln!("qsh: warning: forward {spec}: {e:#}"),
                Err(e) => return Err(e.context(format!("-{kind} {spec}"))),
            }
        }
    }
    if a.forward_agent == Some(true) && agent.is_none() && !quiet {
        eprintln!("qsh: warning: -A: no ssh-agent to forward (SSH_AUTH_SOCK is not set)");
    }
    // Remote forwards held by the master for this run: taken back when it ends.
    #[cfg(unix)]
    let mut held = Vec::new();
    for (f, required) in remotes {
        let spec = f.describe();
        #[cfg(unix)]
        let result = match (&target.sharing.path, conn.is_shared()) {
            (Some(path), true) => qsh::transport::shared::hold_forward(path, 'R', &spec).await.map(|(h, msg)| {
                held.push(h);
                forwarder.held_by_master(f.clone());
                msg.parse::<u16>().ok()
            }),
            _ => forwarder.remote(f.clone()).await.inspect(|_| own.push(('R', spec.clone()))),
        };
        #[cfg(not(unix))]
        let result = forwarder.remote(f.clone()).await.inspect(|_| own.push(('R', spec.clone())));
        match result {
            Ok(Some(port)) if matches!(f.listen, forward::Listen::Tcp { port: 0, .. }) && !quiet => {
                eprintln!("Allocated port {port} for remote forward {spec}");
            }
            Ok(_) => {}
            // As in ssh: a refused remote forward is a warning, unless ExitOnForwardFailure.
            // A forward from the config is only a warning too.
            Err(e) if !target.exit_on_forward_failure && (!required || e.is::<qsh::proto::Refused>()) => {
                eprintln!("qsh: warning: remote port forwarding failed for {spec}: {e:#}");
            }
            Err(e) => return Err(e.context(format!("remote forward {spec}"))),
        }
    }
    if let Some(path) = agent {
        forwarder.agent(path, quiet).await;
    }
    if let Some(ethernet) = target.tunnel {
        match forwarder.tunnel(ethernet, target.tunnel_units).await {
            Ok(name) => tracing::info!("tunnel device {name}"),
            Err(e) if !target.exit_on_forward_failure => eprintln!("qsh: warning: tunnel (-w): {e:#}"),
            Err(e) => return Err(e.context("tunnel (-w)")),
        }
    }
    if let Some(trusted) = target.forward_x11 {
        match std::env::var("DISPLAY").ok().filter(|d| !d.is_empty()) {
            None if !quiet => eprintln!("qsh: warning: X11 forwarding requested but DISPLAY is not set"),
            None => {}
            Some(display) => match qsh::client::x11::prepare(&display, trusted, &target.xauth, target.x11_timeout) {
                Ok(auth) => forwarder.x11(auth, quiet).await,
                Err(e) if !quiet => eprintln!("qsh: warning: X11 forwarding: {e:#}"),
                Err(_) => {}
            },
        }
    }
    if let Some(command) = &target.local_command {
        run_local_command(&target.expand_tokens(command)?);
    }
    #[cfg(unix)]
    let master = if private { None } else { start_master(&conn, &target, quiet, &forwarder) };
    #[cfg(unix)]
    if a.background {
        detach(DAEMON_FD, "ok", false)?;
    }

    // Logs in again by itself: `quiet`, and with no one to ask for anything.
    let reconnect = || -> session::Reconnect {
        let target = Target { batch_mode: true, quiet: true, ..target.clone() };
        let opts = opts.clone();
        Arc::new(move |token: Vec<u8>| {
            let (target, opts) = (target.clone(), ConnectOptions { resume: Some(token), ..opts.clone() });
            Box::pin(async move { client::connect(&target, &opts).await.map(Arc::new) }) as futures::future::BoxFuture<'static, _>
        })
    };
    if a.no_command {
        #[cfg(unix)]
        let exit_requested = async {
            match &master {
                Some(m) => m.exit_requested().await,
                None => std::future::pending().await,
            }
        };
        #[cfg(not(unix))]
        let exit_requested = std::future::pending::<()>();
        let signal = session::termination_signal(true);
        let end = async {
            tokio::select! {
                _ = signal => {}
                () = exit_requested => {}
            }
        };
        let back = (target.persist_session && !needs_this_connection).then(reconnect);
        let code = session::hold(conn.clone(), back, forwarder.clone(), target.server_alive, end).await?;
        forwarder.conn().close().await;
        return Ok(code);
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
        Some(e) => client::parse_escape(Some(e))?,
        None => target.escape_char,
    };
    // A terminal session survives lost connections (unless X11 or a tunnel
    // depends on this connection, or PersistSession is off): qsh logs in
    // again by itself.
    let reconnect = (pty && target.persist_session && !needs_this_connection).then(reconnect);
    let quit = Arc::new(tokio::sync::Notify::new());
    let session = session::run(
        conn.clone(),
        SessionOptions {
            command,
            subsystem,
            env: target.session_env(),
            pty,
            keystroke_interval: target.keystroke_interval,
            escape_char,
            escape_commandline: target.escape_commandline,
            stdin_null: a.stdin_null || a.background,
            reconnect,
            compress: a.compress || target.compress_output,
            left_behind,
            claim: claim.filter(|_| pty).map(Arc::new),
            server_alive: target.server_alive,
            predict: target.predict,
            quit: quit.clone(),
            forwarder: Some(forwarder.clone()),
        },
    );
    // `-O exit` ends a master that runs a session too, like ssh's.
    #[cfg(unix)]
    let code = match &master {
        Some(m) => {
            tokio::pin!(session);
            tokio::select! {
                code = &mut session => code?,
                () = m.exit_requested() => {
                    // Let the session end itself, so a persistent one is hung
                    // up on the server instead of left behind.
                    quit.notify_one();
                    let _ = tokio::time::timeout(Duration::from_secs(5), &mut session).await;
                    eprintln!("\r\nqsh: the shared connection was ended (-O exit)");
                    255
                }
            }
        }
        None => session.await?,
    };
    #[cfg(not(unix))]
    let code = session.await?;
    // A persistent session may have logged in again on the way.
    let conn = forwarder.conn();
    #[cfg(unix)]
    if let Some(m) = master {
        if m.active() > 0 {
            for (kind, spec) in &own {
                if let Err(e) = forwarder.request(*kind, spec, true).await {
                    tracing::debug!("taking back -{kind} {spec}: {e:#}");
                }
            }
        }
        wait_for_shared(m, &conn, quiet).await;
    }
    #[cfg(not(unix))]
    let _ = own;
    conn.close().await;
    Ok(code)
}

/// `LocalCommand` (with `PermitLocalCommand`): runs on this machine once
/// connected, through the user's shell, as in ssh.
fn run_local_command(line: &str) {
    #[cfg(unix)]
    let status = std::process::Command::new(std::env::var_os("SHELL").filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/sh".into()))
        .arg("-c")
        .arg(line)
        .status();
    #[cfg(not(unix))]
    let status = std::process::Command::new("cmd").arg("/C").arg(line).status();
    if let Err(e) = status {
        eprintln!("qsh: LocalCommand {line:?}: {e}");
    }
}

/// `ControlMaster`: offers this connection to later qsh runs.
#[cfg(unix)]
fn start_master(conn: &Arc<qsh::transport::Conn>, target: &Target, quiet: bool, forwarder: &Arc<forward::Forwarder>) -> Option<qsh::transport::shared::Master> {
    use qsh::client::control::ControlMaster;
    let path = target.sharing.path.as_ref()?;
    if conn.is_shared() || target.sharing.master == ControlMaster::No {
        return None;
    }
    let started = prepare_control_dir(path).and_then(|()| qsh::transport::shared::Master::start(forwarder.connections(), path, Some(forward_hook(forwarder)), forwarder.activity()));
    match started {
        Ok(m) => {
            tracing::debug!("sharing the connection at {}", path.display());
            Some(m)
        }
        Err(e) => {
            if target.sharing.master == ControlMaster::Yes && !quiet {
                eprintln!("qsh: not sharing the connection: {e:#}");
            }
            None
        }
    }
}

/// After the master's own session: other qsh runs may still use the
/// connection, so it stays until they are done (or the user gives up).
#[cfg(unix)]
async fn wait_for_shared(master: qsh::transport::shared::Master, conn: &qsh::transport::Conn, quiet: bool) {
    // Still listening: attached clients open new streams through the socket.
    if master.active() == 0 {
        return;
    }
    if !quiet {
        eprintln!("qsh: other qsh sessions still use this connection; waiting for them (Ctrl-C ends them)");
    }
    tokio::select! {
        () = master.wait_idle(conn, None) => {}
        _ = session::termination_signal(true) => {}
    }
}

/// When no qshd answered, points to `qsh doctor`, which finds out why.
fn with_doctor_hint(e: anyhow::Error, target: &Target) -> anyhow::Error {
    if e.is::<Unreachable>() && std::env::var_os("QSH_NO_DOCTOR_HINT").is_none() {
        let port = if target.port != qsh::DEFAULT_PORT { format!("-p {} ", target.port) } else { String::new() };
        anyhow!("{e:#}\n`qsh doctor {port}{}` checks each step and says what to fix", target.ssh_dest)
    } else {
        e
    }
}

/// The command line for ssh, without qsh's own long options, and with the
/// long ones ssh has short (`--port`) spelled as ssh knows them.
fn without_qsh_options(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "--" {
            out.push(arg.clone());
            out.extend(it.cloned());
            break;
        }
        let (name, value) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let short = match name {
            "--port" => "-p",
            "--identity" => "-i",
            "--login" => "-l",
            _ => "",
        };
        match name {
            "--full" | "--accept-new-host" | "--verbose" | "--force" => {}
            "--transport" | "--save" => {
                if value.is_none() {
                    it.next();
                }
            }
            _ if !short.is_empty() => {
                out.push(short.to_string());
                out.extend(value.or_else(|| it.next().cloned()));
            }
            _ => out.push(arg.clone()),
        }
    }
    out
}

fn ssh_args(a: &SshArgs, target: &Target) -> Vec<String> {
    let mut args = a.passthrough.clone();
    if let Some(p) = target.cli_port {
        args.push("-p".into());
        args.push(p.to_string());
    }
    for o in &target.ssh_options {
        args.extend(["-o".to_string(), o.clone()]);
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
    let file = if cfg!(windows) { format!("{tool}.exe") } else { tool.to_string() };
    std::env::split_paths(&path)
        .map(|dir| dir.join(&file))
        .find(|c| c.is_file() && c.canonicalize().ok() != me)
        .with_context(|| format!("OpenSSH's {tool} was not found in PATH"))
}

/// `--full`: replaces this process with OpenSSH's `tool` (ssh or scp); on
/// Windows, runs it and passes on its exit code.
fn exec_openssh(tool: &str, args: Vec<String>, reason: &str) -> Result<i32> {
    tracing::info!("using {tool}: {reason}");
    let program = find_openssh(tool)?;
    let mut cmd = std::process::Command::new(&program);
    cmd.args(args);
    #[cfg(not(unix))]
    {
        let status = cmd.status().with_context(|| format!("cannot run {}", program.display()))?;
        Ok(status.code().unwrap_or(255))
    }
    #[cfg(unix)]
    exec_unix(cmd, &program)
}

#[cfg(unix)]
fn exec_unix(mut cmd: std::process::Command, program: &Path) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    // In a `-f` child: ssh gets `-f` too and goes to the background by
    // itself; our parent then waits for ssh's own exit.
    cmd.env_remove(DAEMON_FD);
    Err(anyhow!("cannot run {}: {}", program.display(), cmd.exec()))
}

async fn speed_test(target: &Target, opts: &ConnectOptions, seconds: Duration) -> Result<i32> {
    use std::io::Write;
    use qsh::client::speed;
    let conn = client::connect(target, opts).await.map_err(|e| with_doctor_hint(e, target))?;
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

async fn cp(paths: &[String], (recursive, compress): (bool, bool), args: &ConnArgs) -> Result<i32> {
    enum Direction {
        Upload { local: PathBuf, remote: String },
        Download { remote: String, local: PathBuf },
    }
    let (srcs, dst) = paths.split_at(paths.len() - 1);
    let dst = &dst[0];
    let several = srcs.len() > 1;
    let mut host: Option<String> = None;
    let mut jobs = Vec::new();
    for src in srcs {
        let (dest, job) = match (Location::parse(src), Location::parse(dst)) {
            (Location::Local(local), Location::Remote { dest, mut path }) => {
                // Into the directory, never one file over another.
                if several && !path.is_empty() && !path.ends_with('/') {
                    path.push('/');
                }
                (dest, Direction::Upload { local, remote: path })
            }
            (Location::Remote { dest, path }, Location::Local(local)) => {
                if several && !local.is_dir() {
                    bail!("{}: not a directory (several sources need one)", local.display());
                }
                (dest, Direction::Download { remote: path, local })
            }
            (Location::Local(_), Location::Local(_)) => bail!("one of SRC/DST must be remote ([user@]host:path)"),
            (Location::Remote { .. }, Location::Remote { .. }) => bail!("remote-to-remote copies are not supported"),
        };
        if host.as_ref().is_some_and(|h| *h != dest) {
            bail!("all remote paths must be on one host");
        }
        host = Some(dest);
        jobs.push(job);
    }
    let dest = host.expect("at least one source");
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
        if compress {
            v.push("-C".into());
        }
        if args.verbose > 0 {
            v.push("-v".into());
        }
        for o in &target.ssh_options {
            v.extend(["-o".to_string(), o.clone()]);
        }
        v.push("--".to_string());
        v.extend(paths.iter().cloned());
        v
    };
    if args.full && target.needs_proxy {
        return exec_openssh("scp", scp_args(), "the ssh config uses ProxyJump/ProxyCommand");
    }
    let conn = match client::connect(&target, &args.options()).await {
        Ok(c) => c,
        Err(e) if args.full && e.is::<Unreachable>() => return exec_openssh("scp", scp_args(), &format!("{e:#}")),
        Err(e) => return Err(with_doctor_hint(e, &target)),
    };
    // `-C`, or `Compression yes` in the config (as for ssh).
    if compress && conn.server_version() < 5 {
        eprintln!("qsh: the server's qshd is too old for compression (-C); copying without it");
    }
    let compress = compress || target.compression;
    // Like scp: a source that fails does not stop the others.
    let mut failed = None;
    for job in jobs {
        let result = match (job, recursive) {
            (Direction::Upload { local, remote }, false) => copy::upload(&conn, &local, &remote, compress).await,
            (Direction::Upload { local, remote }, true) => copy::upload_tree(&conn, &local, &remote, compress).await,
            (Direction::Download { remote, local }, false) => copy::download(&conn, &remote, &local, compress).await,
            (Direction::Download { remote, local }, true) => copy::download_tree(&conn, &remote, &local, compress).await,
        };
        if let Err(e) = result {
            if several {
                eprintln!("qsh: {e:#}");
            }
            failed = Some(e);
        }
    }
    conn.close().await;
    match failed {
        None => Ok(0),
        Some(_) if several => Ok(1),
        Some(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(args: &str) -> bool {
        let v: Vec<String> = std::iter::once("qsh").chain(args.split_whitespace()).map(String::from).collect();
        is_tool_invocation(&v)
    }

    #[test]
    fn long_options_for_ssh() {
        let args = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        assert_eq!(
            without_qsh_options(&args("--full --port 2222 --login=bob --identity k --transport tcp --transport=quic -v host -- --port")),
            args("-p 2222 -l bob -i k -v host -- --port")
        );
    }

    #[test]
    fn tool_commands_only_in_first_position() {
        assert!(tool("cp a host:b"));
        assert!(tool("-p 2222 pair u@host code"));
        assert!(tool("--accept-new-host --transport tcp pair u@host code"));
        assert!(tool("-v keygen"));
        assert!(tool("--full cp a host:b"));
        assert!(tool("-oPort=1 speed h"));
        assert!(tool("update"));
        assert!(!tool("-f host"));
        assert!(!tool("host cp a b"));
        assert!(!tool("-p 22 host"));
        assert!(!tool("-L 8080:cp:80 host"));
        assert!(!tool("-tL 1:a:2 host pair"));
        assert!(!tool("-i cp host"));
        assert!(!tool("-o cp host"));
        assert!(!tool("-- cp"));
    }

    /// `-G` shows the settings that decide how strict qsh is, in a fixed order.
    #[test]
    fn printed_config() {
        let t = Target::parse_with("u@h", Some(1), None, false).unwrap();
        let t = Target { host_key_policy: client::HostKeyPolicy::Strict, forward_x11: Some(false), password_authentication: false, ..t };
        let text = config_lines(&t);
        let keys: Vec<&str> = text.lines().map(|l| l.split(' ').next().unwrap()).collect();
        let want = [
            "user", "hostname", "port", "batchmode", "stricthostkeychecking", "passwordauthentication", "numberofpasswordprompts",
            "userknownhostsfile", "globalknownhostsfile", "hashknownhosts", "addkeystoagent", "forwardagent", "forwardx11",
            "forwardx11trusted", "identitiesonly", "requesttty", "clearallforwardings",
        ];
        // Without a home directory there is no default known_hosts file to show.
        let keys: Vec<&str> = keys.into_iter().filter(|k| *k != "userknownhostsfile").collect();
        let want: Vec<&str> = want.into_iter().filter(|k| *k != "userknownhostsfile").collect();
        assert_eq!(keys, want, "{text}");
        for line in ["stricthostkeychecking true", "passwordauthentication no", "numberofpasswordprompts 3", "forwardx11 yes", "forwardx11trusted no"] {
            assert!(text.lines().any(|l| l == line), "{line} in {text}");
        }
        // Switches that win over the config show too.
        let a = SshArgs { forward_agent: Some(true), tty: 2, accept_new_host: true, ..Default::default() };
        let text = config_lines(&with_switches(t, &a));
        for line in ["forwardagent yes", "requesttty force", "stricthostkeychecking accept-new"] {
            assert!(text.lines().any(|l| l == line), "{line} in {text}");
        }
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
