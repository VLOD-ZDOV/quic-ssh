//! `qsh copy-id host`: sets a host up for qsh through an ssh login that
//! already works, as ssh-copy-id does for ssh: adds this computer's key to
//! qsh's authorized_keys there and pins qshd's host key here. The host key
//! is read over ssh (checked by ssh's own known_hosts), so the first qsh
//! connection can trust it without asking and without a pairing code.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use super::{ConnectOptions, Target};
use crate::keys::PublicKey;

/// Run by the remote shell: adds the key (`@KEY@`, whose data is `@DATA@`)
/// unless it is there, then prints qshd's host keys it can find: the
/// defaults of system and user mode, and a `host_key` set in their configs.
const SCRIPT: &str = r#"umask 077
d="$HOME/.config/qsh"
f="$d/authorized_keys"
mkdir -p "$d" || exit 1
if [ -f "$f" ] && grep -q '^ssh-ed25519 @DATA@' "$f"; then
    echo present
else
    printf '%s\n' '@KEY@' >> "$f" || exit 1
    echo added
fi
for p in /etc/qsh/host_ed25519 "$d/host_ed25519" $(sed -n 's/^[[:space:]]*host_key[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' /etc/qsh/config.toml "$d/qshd.toml" 2>/dev/null); do
    [ -r "$p.pub" ] && sed -n '1s/^/key /p' "$p.pub"
done
exit 0
"#;

/// What the script reported.
#[derive(Debug, PartialEq)]
struct Found {
    added: bool,
    host_keys: Vec<PublicKey>,
}

fn parse(out: &str) -> Result<Found> {
    let added = match out.lines().next() {
        Some("added") => true,
        Some("present") => false,
        _ => bail!("the key could not be added there"),
    };
    let mut host_keys = Vec::new();
    for key in out.lines().filter_map(|l| l.strip_prefix("key ")).filter_map(PublicKey::parse_openssh) {
        if !host_keys.contains(&key) {
            host_keys.push(key);
        }
    }
    Ok(Found { added, host_keys })
}

pub async fn run(target: &Target, opts: &ConnectOptions) -> Result<()> {
    let id = super::find_identity(&opts.identities, &target.identity_files, true, target.batch_mode)?
        .context("no Ed25519 key to copy (qsh uses Ed25519 keys)")?;
    let line = id.public().to_openssh("qsh-copy-id");
    let data = line.split_whitespace().nth(1).context("bad public key")?;
    let script = SCRIPT.replace("@KEY@", &line).replace("@DATA@", data);

    eprintln!("Adding your key on {} over ssh…", target.ssh_dest);
    let mut child = Command::new("ssh")
        .args(["-T", "--", &target.ssh_dest, "sh -s"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("cannot run ssh")?;
    child.stdin.take().expect("piped").write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("ssh to {} failed ({})", target.ssh_dest, out.status);
    }
    let found = parse(&String::from_utf8_lossy(&out.stdout))?;
    if found.host_keys.is_empty() {
        bail!("your key is there now, but no qshd host key was found on {} (is qshd installed and started there?)", target.ssh_dest);
    }
    // Logging in checks both: qshd's key against what ssh read, ours there.
    let opts = ConnectOptions { host_keys_from_ssh: found.host_keys, share: false, ..opts.clone() };
    let conn = super::connect(target, &opts).await.context("the key was copied, but logging in with qsh failed")?;
    conn.close().await;
    let what = if found.added { "added your key" } else { "your key was already there" };
    eprintln!("Done: {what}, and qshd's host key is pinned. `qsh {}` works now.", target.ssh_dest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Identity;

    #[test]
    fn script_output() {
        let (a, b) = (Identity::generate().public(), Identity::generate().public());
        let out = format!("added\nkey {}\nkey {}\nkey {}\n", a.to_openssh("x"), b.to_openssh(""), a.to_openssh("y"));
        assert_eq!(parse(&out).unwrap(), Found { added: true, host_keys: vec![a, b] });
        assert_eq!(parse("present\n").unwrap(), Found { added: false, host_keys: vec![] });
        assert!(parse("").is_err());
    }
}
