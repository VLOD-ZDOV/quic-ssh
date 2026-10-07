//! Target-user lookup and privilege dropping for spawned processes.

use std::ffi::CString;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use nix::unistd::{geteuid, Gid, Group, User as PwUser};

/// Only Linux has the shadow database (Android has no other accounts to expire;
/// macOS keeps account policy in Directory Services, which PAM would consult).
#[cfg(not(target_os = "linux"))]
fn account_expired(_name: &str) -> bool {
    false
}

/// Whether the account's expiry date (`chage -E`, `usermod -e`) has passed,
/// checked the way pam_unix does: `sp_expire` is set and today is on or after
/// it. Without a readable shadow entry the account counts as not expired.
#[cfg(target_os = "linux")]
fn account_expired(name: &str) -> bool {
    let Ok(cname) = CString::new(name) else { return true };
    // SAFETY: getspnam_r fills `entry` using `buf`; both outlive the call and
    // `found` is checked before `entry` is used.
    let entry = unsafe {
        let mut entry: libc::spwd = std::mem::zeroed();
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut found: *mut libc::spwd = std::ptr::null_mut();
        let rc = libc::getspnam_r(cname.as_ptr(), &mut entry, buf.as_mut_ptr(), buf.len(), &mut found);
        if rc != 0 || found.is_null() {
            return false;
        }
        entry.sp_expire
    };
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(0) as libc::c_long;
    entry != -1 && today >= entry
}

/// The user's groups, including `gid` (resolved before forking).
#[cfg(not(target_vendor = "apple"))]
fn group_list(name: &str, gid: Gid) -> Result<Vec<libc::gid_t>> {
    let cname = CString::new(name)?;
    Ok(nix::unistd::getgrouplist(&cname, gid)?.into_iter().map(Gid::as_raw).collect())
}

/// macOS: `getgrouplist` takes `int` group IDs and nix does not wrap it.
#[cfg(target_vendor = "apple")]
fn group_list(name: &str, gid: Gid) -> Result<Vec<libc::gid_t>> {
    let cname = CString::new(name)?;
    let mut n: libc::c_int = 64;
    loop {
        let mut groups = vec![0 as libc::c_int; n as usize];
        // SAFETY: `groups` has room for `n` entries; libc updates `n` to the count.
        let rc = unsafe { libc::getgrouplist(cname.as_ptr(), gid.as_raw() as libc::c_int, groups.as_mut_ptr(), &mut n) };
        if rc >= 0 {
            groups.truncate(n as usize);
            return Ok(groups.into_iter().map(|g| g as libc::gid_t).collect());
        }
        if n >= 65536 {
            bail!("too many groups for {name}");
        }
        n *= 2;
    }
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

    /// Closure for `pre_exec` that switches to this user. Only calls
    /// async-signal-safe syscalls; the group list is resolved beforehand.
    /// With `own_tty`, the terminal on stdin is first handed to the user like
    /// sshd does: group `tty` with mode 0620 (only `write`/`wall` may write to
    /// it), or mode 0600 if there is no `tty` group.
    pub fn drop_privileges(&self, own_tty: bool) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
        let (switch, uid, gid, groups) = (self.switch, self.uid, self.gid, self.groups.clone());
        let (tty_gid, tty_mode) = match Group::from_name("tty").ok().flatten() {
            Some(g) => (g.gid.as_raw(), 0o620),
            None => (libc::gid_t::MAX, 0o600), // -1: keep the group
        };
        move || {
            if !switch {
                return Ok(());
            }
            // SAFETY: plain syscalls with valid pointers; no allocation happens here.
            unsafe {
                // Best effort: if the terminal cannot be chowned (e.g. a devpts
                // owned by another user namespace), it stays root-owned, which is
                // stricter; the session still works through its open descriptors.
                if own_tty && libc::fchown(0, uid, tty_gid) == 0 {
                    libc::fchmod(0, tty_mode);
                }
                if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                // Refuse to continue if root privileges could be regained.
                if uid != 0 && libc::setuid(0) == 0 {
                    return Err(std::io::Error::other("failed to drop privileges"));
                }
            }
            Ok(())
        }
    }

    /// A command that runs as this user with a clean environment in their home.
    pub fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(program);
        cmd.env_clear().envs(self.env()).current_dir(&self.home).kill_on_drop(true);
        // SAFETY: the closure only performs async-signal-safe syscalls.
        unsafe { cmd.pre_exec(self.drop_privileges(false)) };
        cmd
    }

    /// Runs one of `qshd`'s internal helper subcommands as this user, so all
    /// file access in the user's home happens with the user's own permissions.
    /// `args` is the subcommand followed by its positional arguments.
    pub fn helper(&self, args: &[&str]) -> Result<tokio::process::Command> {
        let exe = std::env::current_exe().context("cannot locate qshd binary")?;
        let mut cmd = self.command(exe);
        cmd.args(helper_argv(args));
        Ok(cmd)
    }

    /// Like [`User::helper`], but started through the user's shell
    /// (`$SHELL -c`), as sshd does for scp and sftp: a restricted shell
    /// (nologin, git-shell) then also restricts file transfers. The arguments
    /// travel in the environment, so the shell never parses client input.
    pub fn shell_helper(&self, args: &[&str]) -> Result<tokio::process::Command> {
        let exe = std::env::current_exe().context("cannot locate qshd binary")?;
        let exe = exe.to_str().context("qshd path is not UTF-8")?;
        let mut cmd = self.command(&self.shell);
        cmd.arg("-c").arg(format!("{} {HELPER_FROM_ENV}", shell_quote(exe)?));
        cmd.env(HELPER_ARGS, encode_args(&helper_argv(args)));
        Ok(cmd)
    }
}

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
