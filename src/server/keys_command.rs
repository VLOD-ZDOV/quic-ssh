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
use std::sync::atomic::{AtomicU64, Ordering};
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
    // Unknown tokens are found now, not at the first login.
    let who = Who { name: "", home: "/", uid: 0 };
    let key = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([0; 32]));
    for arg in &argv[1..] {
        expand(arg, &who, Some(&key)).with_context(|| format!("authorized_keys_command argument {arg:?}"))?;
    }
    Ok(())
}

fn uses_key(argv: &[String]) -> bool {
    argv.iter().skip(1).any(|a| a.contains("%f") || a.contains("%k") || a.contains("%t"))
}

/// Resolves the program (symlinks too) and checks that it and every
/// directory above its real location may only be changed by root or
/// `owner`, like sshd's checks of AuthorizedKeysCommand. Returns the real
/// path, which is what then runs: nobody else can swap anything on it.
fn secure_path(program: &Path, owner: u32) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let real = std::fs::canonicalize(program).with_context(|| format!("{}", program.display()))?;
    let meta = std::fs::metadata(&real)?;
    if !meta.is_file() {
        bail!("{} is not a file", real.display());
    }
    for p in real.ancestors() {
        let m = std::fs::symlink_metadata(p).with_context(|| format!("{}", p.display()))?;
        if (m.uid() != 0 && m.uid() != owner) || m.mode() & 0o022 != 0 {
            bail!("{} can be changed by other users", p.display());
        }
    }
    Ok(real)
}

/// Whose keys are asked for (the `%u %h %U` tokens).
struct Who<'a> {
    name: &'a str,
    home: &'a str,
    uid: u32,
}

fn expand(arg: &str, user: &Who, key: Option<&KeyData>) -> Result<String> {
    let mut out = String::new();
    let mut chars = arg.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let k = || key.context("a key token outside a key check");
        match chars.next() {
            Some('u') => out.push_str(user.name),
            Some('h') => out.push_str(user.home),
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

/// How long the command's last run took (ms), for [`Mimic`].
static LAST_RUN_MS: AtomicU64 = AtomicU64::new(0);

fn cache_key(per_key: bool, offered: &Offered) -> Vec<u8> {
    if per_key { ssh_key::PublicKey::from(offered.signing_key().clone()).to_bytes().unwrap_or_default() } else { Vec::new() }
}

/// Stands in for the command where it is not run (an unknown user): waits
/// as long as its last run took, once per key as its cache would, so the
/// time does not tell which users exist.
pub struct Mimic {
    per_key: bool,
    waited: Mutex<std::collections::HashSet<Vec<u8>>>,
}

impl Mimic {
    pub fn new(cfg: &ServerConfig) -> Option<Mimic> {
        let argv = split(cfg.authorized_keys_command.as_deref()?);
        Some(Mimic { per_key: uses_key(&argv), waited: Mutex::default() })
    }

    pub async fn wait(&self, offered: &Offered) {
        if self.waited.lock().unwrap().insert(cache_key(self.per_key, offered)) {
            tokio::time::sleep(Duration::from_millis(LAST_RUN_MS.load(Ordering::Relaxed))).await;
        }
    }
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
    /// Who runs the command for logging in `user`, if one is configured and
    /// may run. Looks users up (NSS): call it where blocking is fine.
    pub fn runner(cfg: &ServerConfig, user: &User) -> Option<User> {
        cfg.authorized_keys_command.as_ref()?;
        if !nix::unistd::geteuid().is_root() {
            return Some(user.clone());
        }
        let Some(name) = &cfg.authorized_keys_command_user else {
            warn!("authorized_keys_command is set but authorized_keys_command_user is not; not running it");
            return None;
        };
        match User::lookup(name) {
            Ok(u) if u.uid != 0 => Some(u),
            Ok(_) => {
                warn!("authorized_keys_command_user must not be root; not running the command");
                None
            }
            Err(e) => {
                warn!("authorized_keys_command_user {name:?}: {e:#}");
                None
            }
        }
    }

    /// The command for logging in `user`, run by `runner` (see [`KeysCommand::runner`]).
    pub fn new(cfg: &ServerConfig, user: &'a User, runner: User) -> Option<KeysCommand<'a>> {
        let argv = split(cfg.authorized_keys_command.as_deref()?);
        let per_key = uses_key(&argv);
        Some(KeysCommand { argv, runner, user, per_key, cache: Mutex::default() })
    }

    /// Entries for `offered` (or for any key, if the command takes no key).
    pub async fn entries(&self, offered: &Offered) -> Vec<AuthorizedKey> {
        let key = offered.signing_key();
        let cache_key = cache_key(self.per_key, offered);
        if let Some(e) = self.cache.lock().unwrap().get(&cache_key) {
            return e.clone();
        }
        let started = std::time::Instant::now();
        let ran = self.run(self.per_key.then_some(key)).await;
        LAST_RUN_MS.store(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), Ordering::Relaxed);
        let entries = match ran {
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
        let program = secure_path(Path::new(&self.argv[0]), nix::unistd::geteuid().as_raw())?;
        let home = self.user.home.to_string_lossy();
        let who = Who { name: &self.user.name, home: &home, uid: self.user.uid };
        let args = self.argv[1..].iter().map(|a| expand(a, &who, key)).collect::<Result<Vec<_>>>()?;
        let mut child = self
            .runner
            .command(&program)
            .args(&args)
            // The runner's home may not exist (nobody's is /nonexistent).
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("cannot run {}", program.display()))?;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let finished = tokio::time::timeout(TIMEOUT, async {
            // Both at once, so a chatty stderr cannot block the program.
            let (mut out_done, mut err_done) = (false, false);
            let (mut a, mut b) = ([0u8; 8192], [0u8; 8192]);
            while !(out_done && err_done) {
                // Past the limit the program may still be writing, and would
                // wait for us forever: not waited for.
                if out.len() as u64 > MAX_OUTPUT || err.len() as u64 > MAX_OUTPUT {
                    return Ok(None);
                }
                tokio::select! {
                    n = stdout.read(&mut a), if !out_done => match n? {
                        0 => out_done = true,
                        n => out.extend_from_slice(&a[..n]),
                    },
                    n = stderr.read(&mut b), if !err_done => match n? {
                        0 => err_done = true,
                        n => err.extend_from_slice(&b[..n]),
                    },
                }
            }
            child.wait().await.map(Some)
        })
        .await;
        let status = match finished {
            Ok(Ok(Some(s))) => s,
            Ok(Ok(None)) => {
                let _ = child.kill().await;
                bail!("printed more than {MAX_OUTPUT} bytes");
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                let _ = child.kill().await;
                bail!("timed out after {TIMEOUT:?}");
            }
        };
        if !status.success() {
            let err = String::from_utf8_lossy(&err[..err.len().min(512)]).into_owned();
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
        assert!(validate("/usr/bin/keys %u %k %f %t %h %U %%").is_ok());
        assert!(validate("/usr/bin/keys %x").is_err(), "unknown token");
        assert!(uses_key(&split("/x %u %k")));
        assert!(!uses_key(&split("/x %u")));
    }

    #[test]
    fn tokens() {
        let user = Who { name: "alice", home: "/home/alice", uid: 1000 };
        let key = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([7; 32]));
        assert_eq!(expand("%u:%U:%h:%%", &user, None).unwrap(), "alice:1000:/home/alice:%");
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
        // A directory above it that others can write to (like /tmp) is refused too.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(secure_path(&prog, me).is_err());
        assert!(secure_path(Path::new("/bin/sh"), me).is_ok());
        // A symlink is judged by where it points.
        let safe = tempfile::tempdir().unwrap();
        let link = safe.path().join("link");
        std::os::unix::fs::symlink(&prog, &link).unwrap();
        assert!(secure_path(&link, me).is_err(), "through a symlink into an unsafe directory");
    }
}
