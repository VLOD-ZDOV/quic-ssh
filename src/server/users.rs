//! Target-user lookup and privilege dropping for spawned processes.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use nix::unistd::{geteuid, Gid, User as PwUser};

/// Only Linux has the shadow database (Android has no other accounts to expire;
/// macOS keeps account policy in Directory Services, which PAM would consult).
#[cfg(not(target_os = "linux"))]
fn account_expired(_name: &str) -> bool {
    false
}

/// Whether the account's expiry date (`chage -E`, `usermod -e`) has passed,
/// checked the way pam_unix does: the shadow entry's expiry day is set and
/// today is on or after it. Without a readable entry the account counts as
/// not expired. (Read from /etc/shadow, as static builds' libc does too.)
#[cfg(target_os = "linux")]
fn account_expired(name: &str) -> bool {
    let Ok(text) = std::fs::read_to_string("/etc/shadow") else { return false };
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i64)
        .unwrap_or(0);
    shadow_expired(&text, name, today)
}

#[cfg(target_os = "linux")]
fn shadow_expired(shadow: &str, name: &str, today: i64) -> bool {
    shadow
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f.first() == Some(&name))
        .and_then(|f| f.get(7).and_then(|e| e.parse::<i64>().ok()))
        .is_some_and(|expire| expire >= 0 && today >= expire)
}

/// The user's groups, including `gid` (resolved before starting processes).
#[cfg(not(target_vendor = "apple"))]
fn group_list(name: &str, gid: Gid) -> Result<Vec<libc::gid_t>> {
    let cname = std::ffi::CString::new(name)?;
    Ok(nix::unistd::getgrouplist(&cname, gid)?.into_iter().map(Gid::as_raw).collect())
}

/// macOS resolves group membership dynamically (Directory Services): a
/// process does not need its supplementary groups for access checks.
#[cfg(target_vendor = "apple")]
fn group_list(_name: &str, _gid: Gid) -> Result<Vec<libc::gid_t>> {
    Ok(Vec::new())
}

/// A user sessions run as.
#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
    groups: Vec<libc::gid_t>,
    /// True when the server runs as root and must switch to this user.
    switch: bool,
}

impl User {
    /// Resolves `name`. A non-root server can only serve its own user.
    pub fn lookup(name: &str) -> Result<User> {
        let pw = PwUser::from_name(name)?.with_context(|| format!("no such user {name:?}"))?;
        let switch = geteuid().is_root();
        let home = if switch {
            pw.dir.clone()
        } else {
            if pw.uid != geteuid() {
                bail!("server runs unprivileged and cannot log in other users ({name:?})");
            }
            // Same home the rest of this process (and `qshd pair`) uses.
            crate::keys::home_dir()?
        };
        if switch && account_expired(name) {
            bail!("account {name:?} has expired");
        }
        let groups = if switch { group_list(name, pw.gid)? } else { Vec::new() };
        let shell = if pw.shell.as_os_str().is_empty() { PathBuf::from("/bin/sh") } else { pw.shell };
        Ok(User {
            name: pw.name,
            uid: pw.uid.as_raw(),
            gid: pw.gid.as_raw(),
            home,
            shell,
            groups,
            switch,
        })
    }

    /// True when the server runs as root and switches to this user.
    pub fn switches(&self) -> bool {
        self.switch
    }

    /// Base environment for the user's processes.
    pub fn env(&self) -> Vec<(String, String)> {
        let path = if self.uid == 0 {
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        } else {
            "/usr/local/bin:/usr/bin:/bin"
        };
        vec![
            ("HOME".into(), self.home.to_string_lossy().into_owned()),
            ("USER".into(), self.name.clone()),
            ("LOGNAME".into(), self.name.clone()),
            ("SHELL".into(), self.shell.to_string_lossy().into_owned()),
            ("PATH".into(), path.into()),
        ]
    }

    /// `-bash`-style argv[0] that makes the shell a login shell.
    pub fn login_arg0(&self) -> String {
        let base = self.shell.file_name().map(|s| s.to_string_lossy()).unwrap_or_default();
        format!("-{base}")
    }

    /// How to start `program` as this user: itself, or, when the server
    /// runs as root, through `qshd internal-become` (see
    /// [`super::helpers::become_user`]), which switches to the user in a
    /// process of its own and then runs it. `arg0` replaces the program's
    /// argv[0] (a login shell's `-bash`); `tty` hands the terminal on stdin
    /// to the user.
    fn launch(&self, program: &std::ffi::OsStr, arg0: Option<&str>, tty: bool) -> (std::ffi::OsString, Vec<std::ffi::OsString>) {
        if !self.switch {
            return (program.to_owned(), Vec::new());
        }
        let exe = self_program();
        let groups: Vec<String> = self.groups.iter().map(|g| g.to_string()).collect();
        let mut args: Vec<std::ffi::OsString> = vec![
            BECOME.into(),
            self.uid.to_string().into(),
            self.gid.to_string().into(),
            if groups.is_empty() { "-".into() } else { groups.join(",").into() },
            self.home.clone().into_os_string(),
            if tty { "tty" } else { "-" }.into(),
            arg0.unwrap_or("").into(),
            "--".into(),
        ];
        args.push(program.to_owned());
        (exe.into_os_string(), args)
    }

    /// A command that runs as this user with a clean environment in their home.
    pub fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> tokio::process::Command {
        self.command_as(program, None)
    }

    /// Like [`User::command`], with `arg0` as the program's argv[0].
    pub fn command_as(&self, program: impl AsRef<std::ffi::OsStr>, arg0: Option<&str>) -> tokio::process::Command {
        let (exe, args) = self.launch(program.as_ref(), arg0, false);
        let mut cmd = tokio::process::Command::new(exe);
        cmd.args(args).env_clear().envs(self.env()).kill_on_drop(true);
        if self.switch {
            name_self(&mut cmd);
        } else {
            cmd.current_dir(&self.home);
            if let Some(a) = arg0 {
                cmd.arg0(a);
            }
        }
        cmd
    }

    /// A command on a terminal, as this user (the terminal is handed to them).
    pub fn pty_command(&self, program: impl AsRef<std::ffi::OsStr>, arg0: Option<&str>, env: Vec<(String, String)>) -> pty_process::Command {
        let (exe, args) = self.launch(program.as_ref(), arg0, true);
        let mut cmd = pty_process::Command::new(exe).args(args).env_clear().envs(env).kill_on_drop(true);
        if self.switch {
            if let Ok(p) = exe_path() {
                cmd = cmd.arg0(p);
            }
        } else {
            cmd = cmd.current_dir(&self.home);
            if let Some(a) = arg0 {
                cmd = cmd.arg0(a);
            }
        }
        cmd
    }

    /// Runs one of `qshd`'s internal helper subcommands as this user, so all
    /// file access in the user's home happens with the user's own permissions.
    /// `args` is the subcommand followed by its positional arguments.
    pub fn helper(&self, args: &[&str]) -> Result<tokio::process::Command> {
        let mut cmd = self.command(self_program());
        if !self.switch {
            name_self(&mut cmd);
        }
        cmd.args(helper_argv(args));
        Ok(cmd)
    }

    /// Like [`User::helper`], but started through the user's shell
    /// (`$SHELL -c`), as sshd does for scp and sftp: a restricted shell
    /// (nologin, git-shell) then also restricts file transfers. The arguments
    /// travel in the environment, so the shell never parses client input.
    pub fn shell_helper(&self, args: &[&str]) -> Result<tokio::process::Command> {
        // Through a shell `/proc/self/exe` would be the shell: the path it is.
        let exe = exe_path()?;
        let exe = exe.to_str().context("qshd path is not UTF-8")?;
        let mut cmd = self.command(&self.shell);
        cmd.arg("-c").arg(format!("{} {HELPER_FROM_ENV}", shell_quote(exe)?));
        cmd.env(HELPER_ARGS, encode_args(&helper_argv(args)));
        Ok(cmd)
    }
}

/// qshd's own path, as found when first asked (call early: after an
/// upgrade replaced the file, the running binary's path reads
/// "... (deleted)").
pub fn exe_path() -> Result<PathBuf> {
    static PATH: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let p = std::env::current_exe().ok()?;
        let text = p.to_str()?.strip_suffix(" (deleted)").map(PathBuf::from);
        Some(text.unwrap_or(p))
    })
    .clone()
    .context("cannot locate the qshd binary")
}

/// What to run to start qshd itself (helpers, `internal-become`): on Linux
/// the running binary through `/proc/self/exe`, which works even after an
/// upgrade replaced the file (and keeps helpers at the server's version);
/// elsewhere (or without /proc) its path.
fn self_program() -> PathBuf {
    if cfg!(target_os = "linux") && std::path::Path::new("/proc/self/exe").exists() {
        PathBuf::from("/proc/self/exe")
    } else {
        exe_path().unwrap_or_else(|_| PathBuf::from("qshd"))
    }
}

/// Shows qshd's real path as argv[0] of a helper started as `/proc/self/exe`.
fn name_self(cmd: &mut tokio::process::Command) {
    if let Ok(p) = exe_path() {
        cmd.arg0(p);
    }
}

/// Subcommand that switches to a user and runs a program (see `User::launch`).
pub const BECOME: &str = "internal-become";
/// Subcommand that takes its arguments from [`HELPER_ARGS`].
pub const HELPER_FROM_ENV: &str = "internal-env";
/// Environment variable with a helper's arguments, hex-encoded and NUL-separated.
pub const HELPER_ARGS: &str = "QSHD_HELPER_ARGS";

/// `[subcommand, "--", args...]`, so arguments starting with `-` stay arguments.
fn helper_argv(args: &[&str]) -> Vec<String> {
    let mut argv: Vec<String> = args.iter().take(1).map(|s| s.to_string()).collect();
    argv.push("--".into());
    argv.extend(args.iter().skip(1).map(|s| s.to_string()));
    argv
}

fn encode_args(args: &[String]) -> String {
    args.join("\0").bytes().map(|b| format!("{b:02x}")).collect()
}

/// Decodes [`HELPER_ARGS`]; `None` if it is malformed.
pub fn decode_args(hex: &str) -> Option<Vec<String>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect();
    let text = String::from_utf8(bytes?).ok()?;
    Some(text.split('\0').map(String::from).collect())
}

/// Quotes a word for `sh -c` (and for fish and zsh, which read single quotes the
/// same way as long as there is no backslash).
fn shell_quote(word: &str) -> Result<String> {
    if word.contains(['\\', '\n', '\0']) {
        bail!("cannot quote {word:?} for the shell");
    }
    if word.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b)) {
        return Ok(word.to_string());
    }
    Ok(format!("'{}'", word.replace('\'', "'\\''")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn shadow_expiry() {
        let shadow = "root:*:19000:0:99999:7:::\nold:$6$x:19000:0:99999:7::19500:\nzero:x:1:::::0:\n";
        assert!(!shadow_expired(shadow, "root", 20000), "no expiry set");
        assert!(shadow_expired(shadow, "old", 19500));
        assert!(!shadow_expired(shadow, "old", 19499));
        assert!(shadow_expired(shadow, "zero", 1), "0 is a date too (1970-01-01)");
        assert!(!shadow_expired(shadow, "missing", 1));
    }

    #[test]
    fn helper_args_roundtrip() {
        let argv = helper_argv(&["internal-recv", "-dir/a b", "$(x)", ""]);
        assert_eq!(argv, ["internal-recv", "--", "-dir/a b", "$(x)", ""]);
        assert_eq!(decode_args(&encode_args(&argv)).unwrap(), argv);
        assert!(decode_args("zz").is_none() && decode_args("abc").is_none());
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("/usr/bin/qshd").unwrap(), "/usr/bin/qshd");
        assert_eq!(shell_quote("/opt/my qsh/it's").unwrap(), "'/opt/my qsh/it'\\''s'");
        assert!(shell_quote("a\\b").is_err());
    }
}
