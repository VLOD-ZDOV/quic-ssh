use std::os::unix::fs::OpenOptionsExt;
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

    /// Check the config file and the host key, then exit (like sshd -t)
    #[arg(short = 't', long = "test")]
    test: bool,

    /// Print the settings in effect and exit (like sshd -T); with -C, for one login
    #[arg(short = 'T', long = "print-config")]
    print_config: bool,

    /// The login -T shows settings for: user=NAME,addr=ADDRESS
    #[arg(short = 'C', value_name = "SPEC", requires = "print_config")]
    connection: Option<String>,
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
    Pair {
        /// Also show the client's command as a QR code (to scan with a phone)
        #[arg(long)]
        qr: bool,
        /// Address clients should use (default: this machine's host name)
        #[arg(long, value_name = "HOST")]
        host: Option<String>,
    },
    /// Set up one-time codes (TOTP) as a second factor for the current user
    Totp {
        /// Replace an existing secret
        #[arg(long)]
        force: bool,
        /// Turn one-time codes off again
        #[arg(long, conflicts_with = "force")]
        disable: bool,
    },
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
    let mut cfg = cfg;
    if cfg.host_certificate.is_none() {
        // OpenSSH's naming: the certificate for `key` is `key-cert.pub`.
        let default = PathBuf::from(format!("{}-cert.pub", key.display()));
        cfg.host_certificate = default.exists().then_some(default);
    }
    Ok((cfg, key))
}

fn host_key(path: &std::path::Path) -> Result<Identity> {
    let (id, created) = Identity::load_or_generate(path, "qshd host key")?;
    if created {
        eprintln!("Generated host key {}", path.display());
    }
    Ok(id)
}

pub fn main() {
    // Switching to a user before running their program (see `User::launch`).
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some(helpers::BECOME) {
        let Err(e) = helpers::become_user(&argv[2..]);
        eprintln!("qshd: {e:#}");
        std::process::exit(126);
    }
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
    if cli.test || cli.print_config {
        let result = check_config(cli.config, cli.print_config, cli.connection.as_deref());
        if let Err(e) = result {
            eprintln!("qshd: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    let result = match cli.cmd {
        Some(Cmd::InternalRecv { path, name, size, mode }) => helpers::recv(&path, &name, size, &mode),
        Some(Cmd::InternalSend { path }) => helpers::send(&path),
        Some(Cmd::InternalPairTake) => helpers::pair_take(),
        Some(Cmd::InternalAddKey { line }) => helpers::add_key(&line),
        Some(Cmd::InternalConnect { host, port }) => helpers::connect(&host, port),
        Some(Cmd::InternalUntar { path, name }) => helpers::untar(&path, &name),
        Some(Cmd::InternalTar { path }) => helpers::tar(&path),
        Some(Cmd::Init) => init(cli.config),
        Some(Cmd::Pair { qr, host }) => pair(cli.config, qr, host),
        Some(Cmd::Totp { force, disable }) => totp(force, disable),
        Some(Cmd::Serve { listen }) => serve(cli.config, listen),
        None => serve(cli.config, None),
    };
    if let Err(e) = result {
        eprintln!("qshd: {e:#}");
        std::process::exit(1);
    }
}

/// `qshd -t` / `-T`: loads the config (and host key) like the server would.
fn check_config(config: Option<PathBuf>, print: bool, connection: Option<&str>) -> Result<()> {
    let (cfg, key_path) = load_config(config)?;
    if key_path.exists() {
        Identity::load(&key_path).with_context(|| format!("host key {}", key_path.display()))?;
    }
    if !print {
        return Ok(());
    }
    let cfg = match connection {
        None => cfg,
        Some(spec) => {
            let (mut user, mut addr) = (None, None);
            for part in spec.split(',') {
                match part.split_once('=') {
                    Some(("user", v)) => user = Some(v.to_string()),
                    Some(("addr", v)) => addr = Some(v.parse::<std::net::IpAddr>().with_context(|| format!("bad address {v:?}"))?),
                    Some(("host" | "laddr" | "lport" | "rdomain", _)) => {}
                    _ => anyhow::bail!("bad -C {part:?} (user=NAME,addr=ADDRESS)"),
                }
            }
            let user = user.context("-C needs user=NAME")?;
            let groups = server::user_group_names(&user);
            let who = qsh::config::Login { user: &user, groups: &groups, addr: addr.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into()) };
            if let Some(reason) = cfg.login_refused(&who) {
                println!("# {user} may not log in: {reason}");
            }
            cfg.for_login(&who)
        }
    };
    print!("{}", cfg.dump()?);
    Ok(())
}

fn init(config: Option<PathBuf>) -> Result<()> {
    let (cfg, key_path) = load_config(config)?;
    let id = host_key(&key_path)?;
    println!("Host key:    {}", key_path.display());
    println!("Fingerprint: {}", id.public().fingerprint());
    println!("Listening:   {} ({})", cfg.listen, if cfg.tcp { "UDP + TCP" } else { "UDP only" });
    Ok(())
}

fn pair(config: Option<PathBuf>, qr: bool, host: Option<String>) -> Result<()> {
    let (cfg, _) = load_config(config)?;
    let given = host.is_some();
    let host = match host {
        // Only what a host name or address can contain: the command below is
        // meant to be pasted into a shell.
        Some(h) if h.is_empty() || h.starts_with('-') || !h.chars().all(|c| c.is_ascii_alphanumeric() || ".-:[]%".contains(c)) => {
            anyhow::bail!("invalid host {h:?} (a host name or IP address)")
        }
        Some(h) => h,
        None => nix::unistd::gethostname()?.to_string_lossy().into_owned(),
    };
    // An IPv6 address needs brackets, or its colons would read as a port.
    let host = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host };
    let code = qsh::pair::create_pending(&home_dir()?)?;
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())?.context("unknown user")?.name;
    let port = match cfg.listen.port() {
        qsh::DEFAULT_PORT => String::new(),
        p => format!(" -p {p}"),
    };
    let command = format!("qsh pair{port} {user}@{host} {code}");
    println!("Pairing code: {code}  (single use, valid {} minutes)", qsh::pair::CODE_TTL.as_secs() / 60);
    println!("On the client run:");
    println!("  {command}");
    if !given && (!host.contains('.') || host == "localhost") {
        println!("(If the client cannot find {host:?} by that name, use --host with this machine's address.)");
    }
    if qr {
        // The QR code holds just the command: a phone's camera shows it as
        // text to copy into a terminal (e.g. Termux).
        println!("\nOr scan this and paste the text into a terminal:\n");
        print!("{}", qsh::totp::qr_text(&command)?);
    }
    Ok(())
}

/// `qshd totp`: creates a secret, shows it as a QR code for an authenticator
/// app, and stores it once a code from the app has been typed back.
fn totp(force: bool, disable: bool) -> Result<()> {
    use std::io::{BufRead, Write};
    use qsh::totp;
    let home = home_dir()?;
    let path = totp::secret_path(&home);
    if disable {
        match std::fs::remove_file(&path) {
            Ok(()) => println!("One-time codes are turned off for this account."),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("One-time codes were not set up."),
            Err(e) => return Err(e).with_context(|| format!("cannot remove {}", path.display())),
        }
        return Ok(());
    }
    if path.exists() && !force {
        anyhow::bail!("one-time codes are already set up ({}); use --force to replace the secret or --disable to turn them off", path.display());
    }
    let mut secret = [0u8; 20];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())?.context("unknown user")?.name;
    let host = nix::unistd::gethostname()?.to_string_lossy().into_owned();
    let uri = totp::uri(&secret, &format!("{user}@{host}"));
    println!("Scan this with an authenticator app (or enter the key by hand):\n");
    print!("{}", totp::qr_text(&uri)?);
    let key = totp::base32_encode(&secret);
    let grouped: Vec<String> = key.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    println!("\nKey: {}\n{uri}\n", grouped.join(" "));
    let stdin = std::io::stdin();
    for _ in 0..3 {
        print!("Code from the app (to confirm): ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        if stdin.lock().read_line(&mut answer)? == 0 {
            anyhow::bail!("not confirmed; nothing was changed");
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        if totp::verify(&secret, &answer, now, None).is_some() {
            qsh::keys::create_private_dir(path.parent().context("bad path")?)?;
            let tmp = path.with_extension("new");
            let _ = std::fs::remove_file(&tmp);
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            writeln!(f, "{key}")?;
            drop(f);
            std::fs::rename(&tmp, &path)?;
            println!("Done: logins to this account now ask for a one-time code after the key.");
            return Ok(());
        }
        println!("That code does not match; check the clock on both devices and try again.");
    }
    anyhow::bail!("not confirmed; nothing was changed")
}

/// Lifts the soft limit on open files (often 1024) towards the hard one:
/// every connection, forwarded connection and helper holds descriptors.
/// Capped so that the users' programs, which inherit it, see a usual value.
fn raise_fd_limit() {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    const WANT: u64 = 8192;
    if let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) {
        let new = hard.min(WANT);
        if soft < new {
            let _ = setrlimit(Resource::RLIMIT_NOFILE, new, hard);
        }
    }
}

fn serve(config: Option<PathBuf>, listen: Option<std::net::SocketAddr>) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("QSHD_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("qsh=info")),
        )
        .with_writer(std::io::stderr)
        .init();
    raise_fd_limit();
    let (mut cfg, key_path) = load_config(config.clone())?;
    if let Some(l) = listen {
        cfg.listen = l;
    }
    let reload: server::Reload = Box::new(move || {
        let (mut cfg, _) = load_config(config.clone())?;
        if let Some(l) = listen {
            cfg.listen = l;
        }
        Ok(cfg)
    });
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
        server::serve(listener, cfg, &host, Some(reload)).await
    })
}
