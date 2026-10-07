use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use qsh::config::ServerConfig;
use qsh::keys::{home_dir, qsh_dir, Identity};
use qsh::server::{self, helpers};

/// qsh server: secure shell over QUIC (UDP) and TCP on the same port.
#[derive(Parser)]
#[command(name = "qshd", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Config file (default /etc/qsh/config.toml as root, ~/.config/qsh/qshd.toml otherwise)
    #[arg(short = 'c', long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server (default)
    Serve {
        /// Override the listen address, e.g. 0.0.0.0:4422
        #[arg(short, long)]
        listen: Option<std::net::SocketAddr>,
    },
    /// Create the host key if needed and print its fingerprint
    Init,
    /// Create a one-time pairing code for the current user
    Pair,
    #[command(hide = true)]
    InternalRecv { path: String, name: String, size: u64, mode: String },
    #[command(hide = true)]
    InternalSend { path: String },
    #[command(hide = true)]
    InternalPairTake,
    #[command(hide = true)]
    InternalAddKey { line: String },
    #[command(hide = true)]
    InternalConnect { host: String, port: u16 },
    #[command(hide = true)]
    InternalUntar { path: String, name: String },
    #[command(hide = true)]
    InternalTar { path: String },
}

fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

fn config_dir() -> Result<PathBuf> {
    Ok(if is_root() { PathBuf::from("/etc/qsh") } else { qsh_dir(&home_dir()?) })
}

fn load_config(path: Option<PathBuf>) -> Result<(ServerConfig, PathBuf)> {
    let dir = config_dir()?;
    let path = path.unwrap_or_else(|| dir.join(if is_root() { "config.toml" } else { "qshd.toml" }));
    let cfg = ServerConfig::load(&path)?;
    let key = cfg.host_key.clone().unwrap_or_else(|| dir.join("host_ed25519"));
    Ok((cfg, key))
}

fn host_key(path: &std::path::Path) -> Result<Identity> {
    let (id, created) = Identity::load_or_generate(path, "qshd host key")?;
    if created {
        eprintln!("Generated host key {}", path.display());
    }
    Ok(id)
}

fn main() {
    let cli = match std::env::args().nth(1).as_deref() {
        // A helper started through the user's shell: the real arguments are in the environment.
        Some(helpers::HELPER_FROM_ENV) => {
            let args = std::env::var(helpers::HELPER_ARGS).ok().and_then(|a| helpers::decode_args(&a));
            let Some(args) = args.filter(|a| a.first().is_some_and(|c| c.starts_with("internal-"))) else {
                eprintln!("qshd: bad helper arguments");
                std::process::exit(2);
            };
            Cli::parse_from(std::iter::once("qshd".to_string()).chain(args))
        }
        _ => Cli::parse(),
    };
    let result = match cli.cmd {
        Some(Cmd::InternalRecv { path, name, size, mode }) => helpers::recv(&path, &name, size, &mode),
        Some(Cmd::InternalSend { path }) => helpers::send(&path),
        Some(Cmd::InternalPairTake) => helpers::pair_take(),
        Some(Cmd::InternalAddKey { line }) => helpers::add_key(&line),
        Some(Cmd::InternalConnect { host, port }) => helpers::connect(&host, port),
        Some(Cmd::InternalUntar { path, name }) => helpers::untar(&path, &name),
        Some(Cmd::InternalTar { path }) => helpers::tar(&path),
        Some(Cmd::Init) => init(cli.config),
        Some(Cmd::Pair) => pair(cli.config),
        Some(Cmd::Serve { listen }) => serve(cli.config, listen),
        None => serve(cli.config, None),
    };
    if let Err(e) = result {
        eprintln!("qshd: {e:#}");
        std::process::exit(1);
    }
}

fn init(config: Option<PathBuf>) -> Result<()> {
    let (cfg, key_path) = load_config(config)?;
    let id = host_key(&key_path)?;
    println!("Host key:    {}", key_path.display());
    println!("Fingerprint: {}", id.public().fingerprint());
    println!("Listening:   {} ({})", cfg.listen, if cfg.tcp { "UDP + TCP" } else { "UDP only" });
    Ok(())
}

fn pair(config: Option<PathBuf>) -> Result<()> {
    let (cfg, _) = load_config(config)?;
    let code = qsh::pair::create_pending(&home_dir()?)?;
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())?.context("unknown user")?.name;
    let host = nix::unistd::gethostname()?.to_string_lossy().into_owned();
    let port = match cfg.listen.port() {
        qsh::DEFAULT_PORT => String::new(),
        p => format!(" -p {p}"),
    };
    println!("Pairing code: {code}  (single use, valid {} minutes)", qsh::pair::CODE_TTL.as_secs() / 60);
    println!("On the client run:");
    println!("  qsh pair{port} {user}@{host} {code}");
    Ok(())
}

fn serve(config: Option<PathBuf>, listen: Option<std::net::SocketAddr>) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("QSHD_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("qsh=info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let (mut cfg, key_path) = load_config(config)?;
    if let Some(l) = listen {
        cfg.listen = l;
    }
    let host = host_key(&key_path)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let listener = server::bind(&cfg, &host).await?;
        tracing::info!(
            "listening on {} ({}), host key {}",
            listener.local_addr()?,
            listener.transports(),
            host.public().fingerprint()
        );
        server::serve(listener, cfg, &host).await
    })
}
