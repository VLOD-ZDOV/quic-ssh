//! The user on Windows: qshd serves only the account it runs as (no
//! switching users), and starts programs directly as that account.

use std::path::PathBuf;

use anyhow::{bail, Result};

/// What runs before a session's program on Unix (motd, `~/.ssh/rc`...).
/// Windows has none of it; kept so the server's settings read the same.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Prelude {
    pub rc: bool,
    pub user_rc: Option<String>,
    pub x11: Option<(String, String, String)>,
    pub xauth: Option<String>,
    pub motd: bool,
    pub last_login: Option<String>,
    pub chroot: Option<PathBuf>,
    pub pam: Option<(String, String)>,
}

/// The user sessions run as: the one qshd runs as.
#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    /// Not a Windows notion: never 0, so nothing counts as root.
    pub uid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
    pub chroot: Option<PathBuf>,
}

/// The account qshd runs as.
pub fn current_name() -> Option<String> {
    std::env::var("USERNAME").ok().filter(|n| !n.is_empty())
}

impl User {
    /// `name` must be the account qshd runs as. Windows compares names
    /// without case, but the account's own spelling is returned: policies
    /// match the name, and the caller refuses other spellings.
    pub fn lookup(name: &str) -> Result<User> {
        let me = current_name().ok_or_else(|| anyhow::anyhow!("cannot tell which user qshd runs as (USERNAME)"))?;
        if !me.eq_ignore_ascii_case(name) {
            bail!("qshd on Windows serves only the user it runs as ({me}), not {name:?}");
        }
        Ok(User { name: me, uid: 1000, home: crate::keys::home_dir()?, shell: shell(), chroot: None })
    }

    pub fn group_names(&self) -> Vec<String> {
        Vec::new()
    }

    pub fn switches(&self) -> bool {
        false
    }

    /// Base environment: the server's own, which is this user's.
    pub fn env(&self) -> Vec<(String, String)> {
        let mut env: Vec<(String, String)> = std::env::vars().collect();
        env.retain(|(k, _)| !k.eq_ignore_ascii_case("SSH_AUTH_SOCK"));
        env
    }

    pub fn login_arg0(&self) -> String {
        String::new()
    }

    /// A command as this user (directly: qshd is this user).
    pub fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> tokio::process::Command {
        self.command_as(program, None, &Prelude::default(), self.env(), false)
    }

    pub fn command_as(&self, program: impl AsRef<std::ffi::OsStr>, _arg0: Option<&str>, _prelude: &Prelude, env: Vec<(String, String)>, _scope: bool) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(program.as_ref());
        cmd.env_clear().envs(env).current_dir(&self.home).kill_on_drop(true);
        cmd
    }

    /// One of qshd's `internal-*` helpers (file transfers): qshd itself,
    /// already this user.
    pub fn helper(&self, args: &[&str]) -> Result<tokio::process::Command> {
        let mut cmd = self.command(exe_path()?);
        // After `--`, a path such as `-x` is not taken for an option.
        if let Some((sub, rest)) = args.split_first() {
            cmd.arg(sub).arg("--").args(rest);
        }
        Ok(cmd)
    }

    /// As [`User::helper`]: Windows has no login shell to go through.
    pub fn shell_helper(&self, args: &[&str]) -> Result<tokio::process::Command> {
        self.helper(args)
    }

    /// The flag that makes the shell run one command line.
    pub fn command_flag(&self) -> &'static str {
        if is_cmd(&self.shell) { "/c" } else { "-c" }
    }
}

fn is_cmd(shell: &std::path::Path) -> bool {
    shell.file_stem().is_some_and(|s| s.eq_ignore_ascii_case("cmd"))
}

/// The shell: `QSHD_SHELL` (say, `pwsh.exe`), else `%COMSPEC%` (cmd.exe),
/// as Win32-OpenSSH defaults to cmd.exe.
fn shell() -> PathBuf {
    std::env::var_os("QSHD_SHELL")
        .or_else(|| std::env::var_os("COMSPEC"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"))
}

pub fn exe_path() -> Result<PathBuf> {
    Ok(std::env::current_exe()?)
}

pub fn set_session_scope(_on: bool) {}

/// The command name of the built-in SFTP server (Unix only; on Windows the
/// name is still refused as a subsystem rather than run as a program).
pub const INTERNAL_SFTP: &str = "internal-sftp";
