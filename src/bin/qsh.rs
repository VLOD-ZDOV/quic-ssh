use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use clap::{Args, Parser, Subcommand};

use qsh::client::copy::{self, Location};
use qsh::client::forward::{self, Forward};
use qsh::client::{self, session, ConnectOptions, Target};
use qsh::keys::{home_dir, qsh_dir, Identity};
use qsh::transport::{Mode, Unreachable};

/// Secure shell over QUIC, with automatic fallback to TCP.
#[derive(Parser)]
#[command(
    name = "qsh",
    version,
    after_help = "Other commands (see `qsh <command> --help`):\n  \
                  qsh cp SRC DST                   copy a file, one side is [user@]host:path\n  \
                  qsh pair [user@]host CODE        pair with a server using a code from `qshd pair`\n  \
                  qsh keygen [FILE]                create a new key"
)]
struct Cli {
    #[command(flatten)]
    conn: ConnArgs,

    /// Forward a local port: [bind_address:]port:host:hostport (repeatable)
    #[arg(short = 'L', value_name = "SPEC")]
    local_forward: Vec<String>,

    /// Do not run a command or shell (just forward ports)
    #[arg(short = 'N')]
    no_command: bool,

    /// Force a pseudo-terminal
    #[arg(short = 't', conflicts_with = "no_tty")]
    tty: bool,

    /// Disable pseudo-terminal allocation
    #[arg(short = 'T')]
    no_tty: bool,

    /// [user@]host[:port]
    destination: Option<String>,

    /// Command to run instead of a login shell
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

/// `qsh cp|pair|keygen ...`
#[derive(Parser)]
#[command(name = "qsh", version)]
struct ToolCli {
    #[command(subcommand)]
    cmd: Cmd,

    #[command(flatten)]
    conn: ConnArgs,
}

const TOOLS: [&str; 3] = ["cp", "pair", "keygen"];

/// True when the first positional argument names a tool command. Only the
/// first position counts, so `qsh host cp a b` runs `cp a b` remotely.
fn is_tool_invocation(args: &[String]) -> bool {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--" {
            return false;
        }
        if let Some(long) = a.strip_prefix("--") {
            if matches!(long, "port" | "identity" | "transport") {
                it.next();
            }
        } else if let Some(short) = a.strip_prefix('-').filter(|s| !s.is_empty()) {
            // A value-taking flag at the end of a cluster consumes the next argument (`-p 22`, `-tL spec`).
            if short.find(['p', 'i', 'L']) == Some(short.len() - 1) {
                it.next();
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
    identity: Option<PathBuf>,

    /// Transport to use
    #[arg(long, value_enum, default_value = "auto", global = true)]
    transport: Mode,

    /// Trust an unknown host key without asking (a changed key is still refused)
    #[arg(long, global = true)]
    accept_new_host: bool,

    /// Verbose output
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    /// OpenSSH compatibility: also use Port, LocalForward and RequestTTY from
    /// ~/.ssh/config (default port 22), and if the host has no qshd on that
    /// UDP port (or needs ProxyJump/ProxyCommand), run ssh/scp instead
    #[arg(short = 'f', long, global = true)]
    full: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Copy a file: qsh cp SRC DST, where one side is [user@]host:path
    Cp { src: String, dst: String },
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
}

impl ConnArgs {
    fn options(&self) -> ConnectOptions {
        ConnectOptions {
            identity: self.identity.clone(),
            transport: self.transport,
            accept_new_host: self.accept_new_host,
            full: self.full,
        }
    }
}

enum Invocation {
    Session(Cli),
    Tool(ToolCli),
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let inv = if is_tool_invocation(&args) {
        Invocation::Tool(ToolCli::parse_from(args))
    } else {
        Invocation::Session(Cli::parse_from(args))
    };
    let verbose = match &inv {
        Invocation::Session(c) => c.conn.verbose,
        Invocation::Tool(c) => c.conn.verbose,
    };
    let filter = if verbose { "qsh=debug" } else { "qsh=warn" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .init();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let result = rt.block_on(async {
        match inv {
            Invocation::Session(cli) => session_main(cli).await,
            Invocation::Tool(cli) => tool_main(cli).await,
        }
    });
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

async fn tool_main(cli: ToolCli) -> Result<i32> {
    let opts = cli.conn.options();
    match cli.cmd {
        Cmd::Keygen { file } => keygen(file),
        Cmd::Pair { destination, code } => {
            let target = Target::parse(&destination, cli.conn.port, cli.conn.full)?;
            client::pair(&target, &opts, &code).await?;
            Ok(0)
        }
        Cmd::Cp { src, dst } => {
            cp(&src, &dst, &cli.conn).await
        }
    }
}

async fn session_main(cli: Cli) -> Result<i32> {
    let opts = cli.conn.options();
    let Some(dest) = cli.destination.as_deref() else {
        bail!("missing destination; usage: qsh [OPTIONS] [user@]host[:port] [COMMAND]...  (see --help)");
    };
    let target = Target::parse(dest, cli.conn.port, cli.conn.full)?;
    if cli.conn.full && target.needs_proxy {
        return exec_ssh(&cli, &target, "the config uses ProxyJump/ProxyCommand");
    }
    let mut forwards = Vec::new();
    for spec in &cli.local_forward {
        forwards.push((Forward::parse(spec)?, true));
    }
    for spec in &target.local_forwards {
        forwards.push((Forward::parse(spec)?, false));
    }
    let conn = match client::connect(&target, &opts).await {
        Ok(c) => Arc::new(c),
        Err(e) if cli.conn.full && e.is::<Unreachable>() => return exec_ssh(&cli, &target, &format!("{e:#}")),
        Err(e) => return Err(e),
    };
    for (f, required) in forwards {
        let spec = format!("{}:{}:{}", f.port, f.host, f.host_port);
        match forward::start(conn.clone(), f).await {
            Ok(()) => {}
            // Like ssh: a forward from the config that cannot bind is only a warning.
            Err(e) if !required => eprintln!("qsh: warning: LocalForward {spec}: {e:#}"),
            Err(e) => return Err(e),
        }
    }
    if cli.no_command {
        tokio::select! {
            _ = conn.closed() => bail!("connection closed"),
            _ = session::termination_signal(true) => {}
        }
        conn.close().await;
        return Ok(0);
    }
    let command = (!cli.command.is_empty()).then(|| cli.command.join(" "));
    let want_pty = if cli.tty {
        true
    } else if cli.no_tty {
        false
    } else {
        match target.request_tty.as_deref() {
            Some("yes" | "force") => true,
            Some("no") => false,
            _ => command.is_none() && std::io::stdin().is_terminal(),
        }
    };
    let code = session::run(&conn, command, want_pty).await?;
    conn.close().await;
    Ok(code)
}

/// `--full`: replaces this process with `ssh`, passing the same options.
/// ssh then applies its whole config (agent, ProxyJump, its own known_hosts...).
fn exec_ssh(cli: &Cli, target: &Target, reason: &str) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    tracing::info!("using ssh: {reason}");
    let mut cmd = std::process::Command::new("ssh");
    if let Some(p) = target.cli_port {
        cmd.arg("-p").arg(p.to_string());
    }
    if let Some(i) = &cli.conn.identity {
        cmd.arg("-i").arg(i);
    }
    for spec in &cli.local_forward {
        cmd.arg("-L").arg(spec);
    }
    for (set, flag) in [(cli.no_command, "-N"), (cli.tty, "-t"), (cli.no_tty, "-T"), (cli.conn.verbose, "-v")] {
        if set {
            cmd.arg(flag);
        }
    }
    // `--` so the destination can never be read as an option.
    cmd.arg("--").arg(&target.ssh_dest).args(&cli.command);
    Err(anyhow!("cannot run ssh: {}", cmd.exec()))
}

/// `--full` for `cp`: replaces this process with `scp`.
fn exec_scp(src: &str, dst: &str, conn: &ConnArgs, reason: &str) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    tracing::info!("using scp: {reason}");
    let mut cmd = std::process::Command::new("scp");
    if let Some(p) = conn.port {
        cmd.arg("-P").arg(p.to_string());
    }
    if let Some(i) = &conn.identity {
        cmd.arg("-i").arg(i);
    }
    if conn.verbose {
        cmd.arg("-v");
    }
    cmd.arg("--").arg(src).arg(dst);
    Err(anyhow!("cannot run scp: {}", cmd.exec()))
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

async fn cp(src: &str, dst: &str, args: &ConnArgs) -> Result<i32> {
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
    if args.full && target.needs_proxy {
        return exec_scp(src, dst, args, "the config uses ProxyJump/ProxyCommand");
    }
    let conn = match client::connect(&target, &args.options()).await {
        Ok(c) => c,
        Err(e) if args.full && e.is::<Unreachable>() => return exec_scp(src, dst, args, &format!("{e:#}")),
        Err(e) => return Err(e),
    };
    let result = match direction {
        Direction::Upload { local, remote } => copy::upload(&conn, &local, &remote).await,
        Direction::Download { remote, local } => copy::download(&conn, &remote, &local).await,
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
        assert!(tool("-f cp a host:b"));
        assert!(!tool("-f host"));
        assert!(!tool("host cp a b"));
        assert!(!tool("-p 22 host"));
        assert!(!tool("-L 8080:cp:80 host"));
        assert!(!tool("-tL 1:a:2 host pair"));
        assert!(!tool("-i cp host"));
        assert!(!tool("-- cp"));
    }

    #[test]
    fn both_parsers_are_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        ToolCli::command().debug_assert();
    }
}
