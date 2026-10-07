//! The `qsh` client.

pub mod copy;
pub mod forward;
mod known_hosts;
pub mod session;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::keys::{home_dir, qsh_dir, Identity, PublicKey};
use crate::proto::{expect_ok, write_msg, Hello, VERSION};
use crate::transport::{self, Conn, Mode};
use known_hosts::{host_id, KnownHosts};

/// `[user@]host[:port]`; IPv6 literals go in brackets: `user@[::1]:4422`.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub user: String,
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn parse(s: &str, port: Option<u16>) -> Result<Target> {
        let (user, rest) = match s.rsplit_once('@') {
            Some((u, r)) if !u.is_empty() => (u.to_string(), r),
            Some(_) => bail!("empty user name in {s:?}"),
            None => (local_user()?, s),
        };
        let (host, parsed_port) = if let Some(r) = rest.strip_prefix('[') {
            let (h, after) = r.split_once(']').context("unclosed '[' in host")?;
            match after.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None if after.is_empty() => (h, None),
                None => bail!("unexpected text after ']' in {s:?}"),
            }
        } else {
            match rest.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (rest, None),
            }
        };
        if host.is_empty() {
            bail!("empty host in {s:?}");
        }
        let parsed_port = parsed_port.map(|p| p.parse::<u16>().context("invalid port")).transpose()?;
        Ok(Target {
            user,
            host: host.to_string(),
            port: port.or(parsed_port).unwrap_or(crate::DEFAULT_PORT),
        })
    }
}

fn local_user() -> Result<String> {
    let uid = nix::unistd::getuid();
    Ok(nix::unistd::User::from_uid(uid)?.context("cannot determine local user name")?.name)
}

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub identity: Option<PathBuf>,
    pub transport: Mode,
    /// Trust unknown host keys without asking (still refuses changed keys).
    pub accept_new_host: bool,
}

fn default_identity_paths() -> Result<[PathBuf; 2]> {
    let home = home_dir()?;
    Ok([home.join(".ssh").join("id_ed25519"), qsh_dir(&home).join("id_ed25519")])
}

/// Loads the client key: `-i path`, else `~/.ssh/id_ed25519`, else `~/.config/qsh/id_ed25519`.
/// With `create`, generates the latter when no key exists.
pub fn load_identity(explicit: Option<&Path>, create: bool) -> Result<Identity> {
    if let Some(p) = explicit {
        return Identity::load(p);
    }
    let paths = default_identity_paths()?;
    if let Some(p) = paths.iter().find(|p| p.exists()) {
        return Identity::load(p);
    }
    if create {
        let (id, _) = Identity::load_or_generate(&paths[1], "qsh")?;
        eprintln!("Generated new key {}", paths[1].display());
        return Ok(id);
    }
    bail!(
        "no key found ({} or {}); run `qsh keygen` or `qsh pair`",
        paths[0].display(),
        paths[1].display()
    )
}

fn known_hosts() -> Result<KnownHosts> {
    Ok(KnownHosts::new(qsh_dir(&home_dir()?).join("known_hosts")))
}

/// Asks on the terminal whether to trust an unknown host key.
fn confirm_new_host(id: &str, key: PublicKey) -> Result<bool> {
    let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").context(
        "host key is unknown and there is no terminal to confirm it; use --accept-new-host or `qsh pair`",
    )?;
    let mut out = &tty;
    write!(
        out,
        "The authenticity of host '{id}' can't be established.\n\
         ED25519 key fingerprint is {}.\n\
         Are you sure you want to continue connecting (yes/no)? ",
        key.fingerprint()
    )?;
    out.flush()?;
    let mut answer = String::new();
    std::io::BufReader::new(&tty).read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

async fn open(target: &Target, opts: &ConnectOptions, id: &Identity) -> Result<Conn> {
    let tls = crate::tls::client_config(id)?;
    let conn = transport::connect(&target.host, target.port, opts.transport, tls).await?;
    tracing::info!("connected to {} over {}", conn.remote_addr(), conn.transport_name());
    Ok(conn)
}

/// Connects, verifies the host key against known_hosts and logs in.
pub async fn connect(target: &Target, opts: &ConnectOptions) -> Result<Conn> {
    let id = load_identity(opts.identity.as_deref(), false)?;
    let conn = open(target, opts, &id).await?;

    let kh = known_hosts()?;
    let hid = host_id(&target.host, target.port);
    let key = conn.peer_key();
    match kh.lookup(&hid)? {
        Some(known) if known == key => {}
        Some(known) => {
            conn.close().await;
            bail!(
                "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n\
                 Someone could be eavesdropping on you right now (man-in-the-middle attack),\n\
                 or the host key has just been changed.\n\
                 Host '{hid}' now presents {}, expected {}.\n\
                 If the change is legitimate, remove the line for '{hid}' from {}.",
                key.fingerprint(),
                known.fingerprint(),
                qsh_dir(&home_dir()?).join("known_hosts").display()
            );
        }
        None => {
            let trusted = opts.accept_new_host || confirm_new_host(&hid, key)?;
            if !trusted {
                conn.close().await;
                bail!("host key verification failed");
            }
            kh.add(&hid, key)?;
            eprintln!("Permanently added '{hid}' (ED25519) to the list of known hosts.");
        }
    }

    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Hello::Login { version: VERSION, user: target.user.clone() }).await?;
    if let Err(e) = expect_ok(&mut recv).await {
        conn.close().await;
        bail!(
            "{e} for {}@{} (key {}).\nAdd the key on the server with `qsh pair` or to ~/.config/qsh/authorized_keys.",
            target.user,
            target.host,
            id.public().fingerprint()
        );
    }
    Ok(conn)
}

/// Pairs this client with the server using a one-time code from `qshd pair`.
pub async fn pair(target: &Target, opts: &ConnectOptions, code: &str) -> Result<()> {
    let id = load_identity(opts.identity.as_deref(), true)?;
    let conn = open(target, opts, &id).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_msg(&mut send, &Hello::Pair { version: VERSION, user: target.user.clone() }).await?;
    let result = async {
        expect_ok(&mut recv).await?;
        crate::pair::client(&mut send, &mut recv, code, &conn.exporter(), id.public(), conn.peer_key()).await
    }
    .await;
    conn.close().await;
    result?;

    // The server proved knowledge of the code inside this TLS session, so its key is authentic.
    let kh = known_hosts()?;
    let hid = host_id(&target.host, target.port);
    let key = conn.peer_key();
    match kh.lookup(&hid)? {
        Some(known) if known == key => {}
        Some(_) => bail!(
            "paired, but '{hid}' is in known_hosts with a different key; remove that line and pair again"
        ),
        None => kh.add(&hid, key)?,
    }
    eprintln!("Paired with {hid} as {} (host key {}).", target.user, key.fingerprint());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_targets() {
        let t = Target::parse("alice@example.com", None).unwrap();
        assert_eq!((t.user.as_str(), t.host.as_str(), t.port), ("alice", "example.com", crate::DEFAULT_PORT));
        let t = Target::parse("bob@example.com:2200", None).unwrap();
        assert_eq!(t.port, 2200);
        let t = Target::parse("bob@example.com:2200", Some(99)).unwrap();
        assert_eq!(t.port, 99);
        let t = Target::parse("c@[::1]:5", None).unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 5));
        let t = Target::parse("c@[::1]", None).unwrap();
        assert_eq!(t.host, "::1");
        assert!(Target::parse("@host", None).is_err());
        assert!(Target::parse("a@host:notaport", None).is_err());
    }
}
