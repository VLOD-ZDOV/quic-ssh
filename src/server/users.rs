//! Target-user lookup and privilege dropping for spawned processes.

use std::ffi::CString;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use nix::unistd::{geteuid, getgrouplist, Gid, User as PwUser};

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
        let groups = if switch {
            let cname = CString::new(name)?;
            getgrouplist(&cname, pw.gid)?.into_iter().map(Gid::as_raw).collect()
        } else {
            Vec::new()
        };
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
    /// With `own_tty`, the terminal on stdin is handed to the user first (as sshd does).
    pub fn drop_privileges(&self, own_tty: bool) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
        let (switch, uid, gid, groups) = (self.switch, self.uid, self.gid, self.groups.clone());
        move || {
            if !switch {
                return Ok(());
            }
            // SAFETY: plain syscalls with valid pointers; no allocation happens here.
            unsafe {
                if own_tty && (libc::fchown(0, uid, gid) != 0 || libc::fchmod(0, 0o620) != 0) {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
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
    pub fn helper(&self, args: &[&str]) -> Result<tokio::process::Command> {
        let exe = std::env::current_exe().context("cannot locate qshd binary")?;
        let mut cmd = self.command(exe);
        cmd.args(args);
        Ok(cmd)
    }
}
