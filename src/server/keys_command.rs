//! `authorized_keys_command`: keys from a program (like sshd's
//! `AuthorizedKeysCommand`), e.g. a directory service or a web API. Its
//! output is read like an authorized_keys file.
//!
//! The program must be given by an absolute path that only root (or, in user
//! mode, the server's own user) can change. As root it runs as
//! `authorized_keys_command_user`, never as root; without that setting it is
//! not run. Tokens in the arguments: `%u` user, `%h` home, `%U` uid, and for
//! the key being checked `%f` (SHA256 fingerprint), `%k` (base64 key), `%t`
//! (key type), `%%`. With a key token the program runs once per offered key,
//! otherwise once per login.

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ssh_key::public::KeyData;
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};

use super::users::User;
use crate::authkeys::{self, AuthorizedKey, Offered};
use crate::config::ServerConfig;

const TIMEOUT: Duration = Duration::from_secs(10);
/// Most output taken from the program.
const MAX_OUTPUT: u64 = 1 << 20;

/// Splits the configured command line: whitespace separates arguments,
/// double quotes keep spaces.
pub fn split(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut any) = (false, false);
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// Checks the configured command line (at startup).
pub fn validate(line: &str) -> Result<()> {
    let argv = split(line);
    let Some(program) = argv.first() else { bail!("authorized_keys_command is empty") };
    if !Path::new(program).is_absolute() {
        bail!("authorized_keys_command must be an absolute path, not {program:?}");
    }
    Ok(())
}

fn uses_key(argv: &[String]) -> bool {
    argv.iter().skip(1).any(|a| a.contains("%f") || a.contains("%k") || a.contains("%t"))
}

/// The program and every directory above it may only be writable by root
/// or `owner` (like sshd's checks of AuthorizedKeysCommand).
fn secure_path(program: &Path, owner: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(program).with_context(|| format!("{}", program.display()))?;
    if !meta.is_file() {
        bail!("{} is not a file", program.display());
    }
    let mut path = Some(program);
    while let Some(p) = path {
        let m = std::fs::metadata(p).with_context(|| format!("{}", p.display()))?;
        if (m.uid() != 0 && m.uid() != owner) || m.mode() & 0o022 != 0 {
            bail!("{} can be changed by other users", p.display());
        }
        path = p.parent();
    }
    Ok(())
}

fn expand(arg: &str, user: &User, key: Option<&KeyData>) -> Result<String> {
    let mut out = String::new();
    let mut chars = arg.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let k = || key.context("a key token outside a key check");
        match chars.next() {
            Some('u') => out.push_str(&user.name),
            Some('h') => out.push_str(&user.home.to_string_lossy()),
            Some('U') => out.push_str(&user.uid.to_string()),
            Some('f') => out.push_str(&k()?.fingerprint(ssh_key::HashAlg::Sha256).to_string()),
            Some('t') => out.push_str(k()?.algorithm().as_str()),
            Some('k') => {
                let line = ssh_key::PublicKey::from(k()?.clone()).to_openssh()?;
                out.push_str(line.split_whitespace().nth(1).unwrap_or_default());
            }
            Some('%') => out.push('%'),
            other => bail!("unknown token %{}", other.map(String::from).unwrap_or_default()),
        }
    }
    Ok(out)
}

/// Keys from the command for one login, cached per key.
pub struct KeysCommand<'a> {
    argv: Vec<String>,
    runner: User,
    user: &'a User,
    per_key: bool,
    cache: Mutex<HashMap<Vec<u8>, Vec<AuthorizedKey>>>,
}

impl<'a> KeysCommand<'a> {
    /// The command for logging in `user`, if one is configured and may run.
    pub fn new(cfg: &ServerConfig, user: &'a User) -> Option<KeysCommand<'a>> {
        let argv = split(cfg.authorized_keys_command.as_deref()?);
        let runner = if nix::unistd::geteuid().is_root() {
            let Some(name) = &cfg.authorized_keys_command_user else {
                warn!("authorized_keys_command is set but authorized_keys_command_user is not; not running it");
                return None;
            };
            match User::lookup(name) {
                Ok(u) if u.uid != 0 => u,
                Ok(_) => {
                    warn!("authorized_keys_command_user must not be root; not running the command");
                    return None;
                }
                Err(e) => {
                    warn!("authorized_keys_command_user {name:?}: {e:#}");
                    return None;
                }
            }
        } else {
            user.clone()
        };
        let per_key = uses_key(&argv);
        Some(KeysCommand { argv, runner, user, per_key, cache: Mutex::default() })
    }

    /// Entries for `offered` (or for any key, if the command takes no key).
    pub async fn entries(&self, offered: &Offered) -> Vec<AuthorizedKey> {
        let key = offered.signing_key();
        let cache_key = if self.per_key { ssh_key::PublicKey::from(key.clone()).to_bytes().unwrap_or_default() } else { Vec::new() };
        if let Some(e) = self.cache.lock().unwrap().get(&cache_key) {
            return e.clone();
        }
        let entries = match self.run(self.per_key.then_some(key)).await {
            Ok(e) => e,
            Err(e) => {
                warn!("authorized_keys_command for {}: {e:#}", self.user.name);
                Vec::new()
            }
        };
        self.cache.lock().unwrap().insert(cache_key, entries.clone());
        entries
    }

    async fn run(&self, key: Option<&KeyData>) -> Result<Vec<AuthorizedKey>> {
        let program = Path::new(&self.argv[0]);
        secure_path(program, nix::unistd::geteuid().as_raw())?;
        let args = self.argv[1..].iter().map(|a| expand(a, self.user, key)).collect::<Result<Vec<_>>>()?;
        let mut child = self
            .runner
            .command(program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("cannot run {}", program.display()))?;
        let mut out = Vec::new();
        let mut stdout = child.stdout.take().expect("piped");
        let finished = tokio::time::timeout(TIMEOUT, async {
            (&mut stdout).take(MAX_OUTPUT).read_to_end(&mut out).await?;
            child.wait().await
        })
        .await;
        let status = match finished {
            Ok(s) => s?,
            Err(_) => {
                let _ = child.kill().await;
                bail!("timed out after {TIMEOUT:?}");
            }
        };
        if !status.success() {
            let mut err = String::new();
            if let Some(e) = child.stderr.take() {
                let _ = e.take(512).read_to_string(&mut err).await;
            }
            bail!("{status}: {}", err.trim());
        }
        let text = String::from_utf8_lossy(&out);
        let entries = authkeys::parse_list(&text, |line, e| debug!("authorized_keys_command line {line} ignored: {e:#}"));
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines() {
        assert_eq!(split(r#"/usr/bin/keys  %u "two words" %f"#), ["/usr/bin/keys", "%u", "two words", "%f"]);
        assert_eq!(split(r#"/x """#), ["/x", ""]);
        assert!(validate("keys %u").is_err());
        assert!(validate("").is_err());
        assert!(validate("/usr/bin/keys %u").is_ok());
        assert!(uses_key(&split("/x %u %k")));
        assert!(!uses_key(&split("/x %u")));
    }

    #[test]
    fn tokens() {
        let user = User::lookup(&nix::unistd::User::from_uid(nix::unistd::getuid()).unwrap().unwrap().name).unwrap();
        let key = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([7; 32]));
        assert_eq!(expand("%u:%U:%%", &user, None).unwrap(), format!("{}:{}:%", user.name, user.uid));
        assert!(expand("%f", &user, Some(&key)).unwrap().starts_with("SHA256:"));
        assert_eq!(expand("%t", &user, Some(&key)).unwrap(), "ssh-ed25519");
        assert!(expand("%k", &user, None).is_err());
        assert!(expand("%z", &user, None).is_err());
    }

    #[test]
    fn insecure_programs_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let prog = dir.path().join("keys");
        std::fs::write(&prog, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o757)).unwrap();
        let me = nix::unistd::geteuid().as_raw();
        assert!(secure_path(&prog, me).is_err(), "world-writable program");
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
        // /tmp itself is world-writable (sticky), so a program below it is refused too.
        assert!(secure_path(&prog, me).is_err());
        assert!(secure_path(Path::new("/bin/sh"), me).is_ok());
    }
}
