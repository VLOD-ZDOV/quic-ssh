use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};

use qsh::client::copy::{self, Location};
use qsh::client::forward::{self, Forward};
use qsh::client::{self, session, ConnectOptions, Target};
use qsh::keys::{home_dir, qsh_dir, Identity};
use qsh::transport::Mode;

/// Secure shell over QUIC, with automatic fallback to TCP.
#[derive(Parser)]
#[command(name = "qsh", version, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

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
    /// Create a new key at ~/.config/qsh/id_ed25519 (or -f FILE)
    Keygen {
        #[arg(short = 'f', value_name = "FILE")]
        file: Option<PathBuf>,
    },
}

impl ConnArgs {
    fn options(&self) -> ConnectOptions {
        ConnectOptions {
            identity: self.identity.clone(),
            transport: self.transport,
            accept_new_host: self.accept_new_host,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let filter = if cli.conn.verbose { "qsh=debug" } else { "qsh=warn" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .init();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = match rt.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("qsh: {e:#}");
            255
        }
    };
    // Exit right away: a blocked stdin reader thread must not keep the process alive.
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32> {
    let opts = cli.conn.options();
    match cli.cmd {
        Some(Cmd::Keygen { file }) => keygen(file),
        Some(Cmd::Pair { destination, code }) => {
            let target = Target::parse(&destination, cli.conn.port)?;
            client::pair(&target, &opts, &code).await?;
            Ok(0)
        }
        Some(Cmd::Cp { src, dst }) => {
            cp(&src, &dst, cli.conn.port, &opts).await?;
            Ok(0)
        }
        None => {
            let Some(dest) = cli.destination else {
                bail!("missing destination; usage: qsh [OPTIONS] [user@]host[:port] [COMMAND]...  (see --help)");
            };
            let target = Target::parse(&dest, cli.conn.port)?;
            let forwards = cli.local_forward.iter().map(|s| Forward::parse(s)).collect::<Result<Vec<_>>>()?;
            let conn = Arc::new(client::connect(&target, &opts).await?);
            for f in forwards {
                forward::start(conn.clone(), f).await?;
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
                command.is_none() && std::io::stdin().is_terminal()
            };
            let code = session::run(&conn, command, want_pty).await?;
            conn.close().await;
            Ok(code)
        }
    }
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

async fn cp(src: &str, dst: &str, port: Option<u16>, opts: &ConnectOptions) -> Result<()> {
    match (Location::parse(src), Location::parse(dst)) {
        (Location::Local(local), Location::Remote { dest, path }) => {
            let conn = client::connect(&Target::parse(&dest, port)?, opts).await?;
            let result = copy::upload(&conn, &local, &path).await;
            conn.close().await;
            result
        }
        (Location::Remote { dest, path }, Location::Local(local)) => {
            let conn = client::connect(&Target::parse(&dest, port)?, opts).await?;
            let result = copy::download(&conn, &path, &local).await;
            conn.close().await;
            result
        }
        (Location::Local(_), Location::Local(_)) => bail!("one of SRC/DST must be remote ([user@]host:path)"),
        (Location::Remote { .. }, Location::Remote { .. }) => bail!("remote-to-remote copies are not supported"),
    }
}
