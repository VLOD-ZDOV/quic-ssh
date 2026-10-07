//! The few places where Unix and Windows differ for the client: file modes,
//! the local user name, and the terminal.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Creates a new file readable only by the owner (0600 on Unix). Fails if it exists.
pub fn create_private(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)
}

/// Sets Unix permission bits; Windows has no equivalent, so nothing happens there.
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    return std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode));
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// Unix permission bits of a file (on Windows: 0644, or 0444 if read-only, and 0755 for directories).
pub fn mode(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    return std::os::unix::fs::MetadataExt::mode(meta);
    #[cfg(not(unix))]
    match (meta.is_dir(), meta.permissions().readonly()) {
        (true, _) => 0o755,
        (false, true) => 0o444,
        (false, false) => 0o644,
    }
}

/// The local login name.
pub fn local_user() -> anyhow::Result<String> {
    #[cfg(unix)]
    {
        use anyhow::Context;
        let uid = nix::unistd::getuid();
        Ok(nix::unistd::User::from_uid(uid)?.context("cannot determine local user name")?.name)
    }
    #[cfg(not(unix))]
    std::env::var("USERNAME").map_err(|_| anyhow::anyhow!("cannot determine local user name (USERNAME is not set)"))
}

/// The controlling terminal for questions, as (input, output), even when
/// stdin/stdout are redirected.
pub fn terminal() -> io::Result<(File, File)> {
    #[cfg(unix)]
    {
        let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        Ok((tty.try_clone()?, tty))
    }
    #[cfg(not(unix))]
    {
        let input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
        let output = OpenOptions::new().read(true).write(true).open("CONOUT$")?;
        Ok((input, output))
    }
}
