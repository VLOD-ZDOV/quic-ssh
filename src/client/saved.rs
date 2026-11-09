//! Connections saved from `qsh ui`, kept in `~/.config/qsh/ui-hosts` in
//! ssh_config syntax, so `qsh NAME` works from the command line too.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::config::UI_HOSTS;

/// One saved connection (a `Host` block).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Saved {
    pub name: String,
    pub host: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity: Option<String>,
    /// Further `Keyword value` lines (forwards and the like), in order.
    pub options: Vec<String>,
}

/// Keywords with fields of their own, or that would change the file's structure.
const OWN_KEYWORDS: [&str; 7] = ["host", "match", "include", "hostname", "user", "port", "identityfile"];

pub fn path(home: &Path) -> PathBuf {
    crate::keys::qsh_dir(home).join(UI_HOSTS)
}

fn plain(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"')
}

impl Saved {
    /// Checks the fields before they go into a config file.
    pub fn validate(&self) -> Result<()> {
        if !plain(&self.name) || self.name.starts_with('-') || self.name.contains(['*', '?', '!', ',', '@', ':']) {
            bail!("name: one word, no spaces or * ? ! , @ :");
        }
        if !plain(&self.host) || self.host.starts_with('-') {
            bail!("host: a host name or address, no spaces");
        }
        if let Some(u) = &self.user {
            if !crate::proto::valid_user_name(u) {
                bail!("user: letters, digits, . _ - only");
            }
        }
        if let Some(i) = &self.identity {
            if i.chars().any(|c| c.is_control() || c == '"') {
                bail!("key file: no quotes or control characters");
            }
        }
        for line in &self.options {
            let (key, value) = line.split_once(' ').unwrap_or((line, ""));
            if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) || OWN_KEYWORDS.contains(&key.to_ascii_lowercase().as_str()) {
                bail!("ssh options: {key:?} cannot be set here");
            }
            if value.trim().is_empty() || line.chars().any(|c| c.is_control()) {
                bail!("ssh options: {key} needs a value");
            }
        }
        Ok(())
    }

    fn block(&self) -> String {
        let mut out = format!("Host {}\n    HostName {}\n", self.name, self.host);
        if let Some(u) = &self.user {
            out += &format!("    User {u}\n");
        }
        if let Some(p) = self.port {
            out += &format!("    Port {p}\n");
        }
        if let Some(i) = &self.identity {
            let quoted = if i.contains(char::is_whitespace) { format!("\"{i}\"") } else { i.clone() };
            out += &format!("    IdentityFile {quoted}\n");
        }
        for line in &self.options {
            out += &format!("    {line}\n");
        }
        out
    }
}

/// Parses the file written by [`save`] (simple `Host` blocks only).
pub fn parse(text: &str) -> Vec<Saved> {
    let mut out: Vec<Saved> = Vec::new();
    // Lines under a hand-written Match belong to it, not to the Host above.
    let mut in_match = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k.to_ascii_lowercase(), v.trim().trim_matches('"').to_string()),
            None => continue,
        };
        match key.as_str() {
            "host" => {
                in_match = false;
                out.push(Saved { name: value, ..Default::default() });
            }
            "match" => in_match = true,
            _ if in_match => {}
            _ => {
                let Some(s) = out.last_mut() else { continue };
                match key.as_str() {
                    "hostname" => s.host = value,
                    "user" => s.user = Some(value),
                    "port" => s.port = value.parse().ok(),
                    "identityfile" => s.identity = Some(value),
                    "include" => {}
                    _ => s.options.push(line.split_once(char::is_whitespace).map(|(k, v)| format!("{k} {}", v.trim())).unwrap_or_default()),
                }
            }
        }
    }
    out
}

/// The saved connections; none if the file is not there. Another error is
/// one: read as none, the next save would drop them all.
pub fn load(home: &Path) -> Result<Vec<Saved>> {
    let file = path(home);
    match std::fs::read(&file) {
        Ok(bytes) => Ok(parse(&String::from_utf8_lossy(&bytes))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("cannot read {}", file.display()))),
    }
}

/// Whether the file has blocks that [`parse`] does not keep.
fn hand_written(text: &str) -> bool {
    text.lines().any(|l| {
        let key = l.trim().split(|c: char| c.is_whitespace() || c == '=').next().unwrap_or("");
        key.eq_ignore_ascii_case("match") || key.eq_ignore_ascii_case("include")
    })
}

/// Writes all saved connections (replacing the file atomically).
pub fn save(home: &Path, all: &[Saved]) -> Result<()> {
    for s in all {
        s.validate().with_context(|| format!("connection {:?}", s.name))?;
    }
    let file = path(home);
    if let Ok(old) = std::fs::read(&file) {
        if hand_written(&String::from_utf8_lossy(&old)) {
            bail!("{} has Match or Include lines, which `qsh ui` cannot keep: edit it by hand", file.display());
        }
    }
    let dir = file.parent().context("bad path")?;
    crate::keys::create_private_dir(dir)?;
    let mut text = String::from("# Connections saved in `qsh ui` (n new, e edit, d delete), in ssh_config syntax.\n# Read after ~/.config/qsh/config and ~/.ssh/config; names here are not used there.\n");
    for s in all {
        text.push('\n');
        text += &s.block();
    }
    crate::platform::replace_file(&file, text.as_bytes()).with_context(|| format!("cannot write {}", file.display()))?;
    Ok(())
}

/// Splits on spaces, keeping "double quoted" parts together.
fn words(text: &str) -> Result<Vec<String>> {
    let (mut out, mut word, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
    for c in text.chars() {
        match c {
            '"' => (quoted, any) = (!quoted, true),
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut word));
                    any = false;
                }
            }
            c => {
                word.push(c);
                any = true;
            }
        }
    }
    if quoted {
        bail!("unclosed quote");
    }
    if any {
        out.push(word);
    }
    Ok(out)
}

/// ssh's flags (`-L 8080:localhost:80 -D 1080 -A -o Key=value`) as config
/// lines for [`Saved::options`].
pub fn options_from_flags(text: &str) -> Result<Vec<String>> {
    use super::forward::Forward;
    let mut out = Vec::new();
    let mut it = words(text)?.into_iter();
    while let Some(word) = it.next() {
        let Some(flags) = word.strip_prefix('-').filter(|f| !f.is_empty()) else { bail!("{word:?}: expected an option such as -L") };
        for (i, c) in flags.char_indices() {
            if "LRDJo".contains(c) {
                let rest = &flags[i + 1..];
                let value = if rest.is_empty() { it.next().with_context(|| format!("-{c} needs a value"))? } else { rest.to_string() };
                let forward = |f: Forward, key: &str| match f.config_args() {
                    (listen, Some(dest)) => format!("{key} {listen} {dest}"),
                    (listen, None) => format!("{key} {listen}"),
                };
                out.push(match c {
                    'L' => forward(Forward::parse(&value)?, "LocalForward"),
                    'R' => forward(Forward::parse_remote(&value)?, "RemoteForward"),
                    'D' => forward(Forward::parse_dynamic(&value)?, "DynamicForward"),
                    'J' => format!("ProxyJump {value}"),
                    _ => {
                        let (key, v) = value.split_once(['=', ' ']).with_context(|| format!("-o {value}: expected Keyword=value"))?;
                        format!("{key} {}", v.trim())
                    }
                });
                break;
            }
            match c {
                'A' => out.push("ForwardAgent yes".into()),
                'a' => out.push("ForwardAgent no".into()),
                'X' => out.push("ForwardX11 yes".into()),
                'Y' => out.extend(["ForwardX11 yes".into(), "ForwardX11Trusted yes".into()]),
                'x' => out.push("ForwardX11 no".into()),
                'C' => out.push("Compression yes".into()),
                'N' => out.push("SessionType none".into()),
                'T' => out.push("RequestTTY no".into()),
                't' => out.push("RequestTTY yes".into()),
                'p' | 'l' | 'i' => bail!("-{c}: use the port, user or key file field"),
                _ => bail!("-{c} cannot be saved here; -o Keyword=value sets any option"),
            }
        }
    }
    Ok(out)
}

/// A connection from the command line (`qsh ... HOST --save NAME`), and
/// what of it a saved connection cannot hold (to warn about).
pub fn from_args(name: &str, dest: &str, a: &super::cli::SshArgs) -> Result<(Saved, Vec<String>)> {
    use super::forward::Forward;
    let (user, rest) = match dest.rsplit_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, dest),
    };
    let (host, port) = match rest.strip_prefix('[').and_then(|r| r.split_once(']')) {
        Some((h, p)) => (h, p.strip_prefix(':')),
        // An IPv6 address without brackets has no port.
        None if rest.matches(':').count() >= 2 => (rest, None),
        None => match rest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        },
    };
    let port = match port {
        Some(p) => Some(p.parse::<u16>().with_context(|| format!("invalid port in {dest:?}"))?),
        None => a.port,
    };
    if a.identities.len() > 1 {
        bail!("only one -i can be saved");
    }
    let mut options = Vec::new();
    let forward = |f: Forward, key: &str| match f.config_args() {
        (listen, Some(dest)) => format!("{key} {listen} {dest}"),
        (listen, None) => format!("{key} {listen}"),
    };
    for v in &a.local_forwards {
        options.push(forward(Forward::parse(v)?, "LocalForward"));
    }
    for v in &a.remote_forwards {
        options.push(forward(Forward::parse_remote(v)?, "RemoteForward"));
    }
    for v in &a.dynamic_forwards {
        options.push(forward(Forward::parse_dynamic(v)?, "DynamicForward"));
    }
    options.extend(a.jump.as_ref().map(|j| format!("ProxyJump {j}")));
    options.extend(a.forward_agent.map(|on| format!("ForwardAgent {}", if on { "yes" } else { "no" })));
    match a.x11 {
        Some(true) => options.push("ForwardX11 yes".into()),
        Some(false) => options.push("ForwardX11 no".into()),
        None => {}
    }
    if a.x11 == Some(true) && a.x11_trusted {
        options.push("ForwardX11Trusted yes".into());
    }
    let flags = [
        (a.compress, "Compression yes"),
        (a.no_command, "SessionType none"),
        (a.no_tty, "RequestTTY no"),
        (a.tty > 0, "RequestTTY yes"),
        (a.ipv4, "AddressFamily inet"),
        (a.ipv6, "AddressFamily inet6"),
        (a.stdin_null, "StdinNull yes"),
        (a.background, "ForkAfterAuthentication yes"),
    ];
    options.extend(flags.iter().filter(|(on, _)| *on).map(|(_, line)| line.to_string()));
    options.extend(a.escape_char.as_ref().map(|e| format!("EscapeChar {e}")));
    options.extend(a.options.iter().cloned());
    let mut left_out = Vec::new();
    if !a.command.is_empty() {
        left_out.push(format!("the command {:?}", a.command.join(" ")));
    }
    let more = [
        (a.stdio_forward.is_some(), "-W"),
        (a.subsystem, "-s"),
        (a.gateway_ports, "-g"),
        (a.config_file.is_some(), "-F"),
        (a.transport != crate::transport::Mode::Auto, "--transport (set it in qsh ui)"),
        (a.full, "--full"),
    ];
    left_out.extend(more.iter().filter(|(on, _)| *on).map(|(_, what)| what.to_string()));
    let saved = Saved {
        name: name.to_string(),
        host: host.to_string(),
        user: user.or_else(|| a.login.clone()),
        port,
        identity: a.identities.first().map(|i| i.display().to_string()),
        options,
    };
    saved.validate()?;
    Ok((saved, left_out))
}

/// [`Saved::options`] as ssh's flags, for editing ([`options_from_flags`] reads them back).
pub fn flags_from_options(options: &[String]) -> String {
    let quote = |s: String| if s.contains(char::is_whitespace) { format!("\"{s}\"") } else { s };
    let has = |line: &str| options.iter().any(|o| o.eq_ignore_ascii_case(line));
    let (trusted, x11) = (has("ForwardX11Trusted yes"), has("ForwardX11 yes"));
    let mut out = Vec::new();
    for line in options {
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        let args = value.split_whitespace();
        let flag = match (key.to_ascii_lowercase().as_str(), value.to_ascii_lowercase().as_str()) {
            ("localforward", _) if value.contains(' ') => format!("-L {}", args.collect::<Vec<_>>().join(":")),
            ("remoteforward", _) => format!("-R {}", args.collect::<Vec<_>>().join(":")),
            ("dynamicforward", _) => format!("-D {value}"),
            ("proxyjump", _) => format!("-J {value}"),
            ("forwardagent", "yes") => "-A".into(),
            ("forwardagent", "no") => "-a".into(),
            ("forwardx11", "yes") if trusted => "-Y".into(),
            ("forwardx11", "yes") => "-X".into(),
            ("forwardx11", "no") => "-x".into(),
            // -Y says both.
            ("forwardx11trusted", "yes") if x11 => continue,
            ("compression", "yes" | "auto") => "-C".into(),
            ("sessiontype", "none") => "-N".into(),
            ("requesttty", "no") => "-T".into(),
            ("requesttty", "yes") => "-t".into(),
            // A value saved in quotes as one word: they go, `quote` adds its
            // own. Several quoted words (`SendEnv "A" "B"`) stay as they are.
            _ => {
                let one = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).filter(|v| !v.contains('"'));
                format!("-o {}", quote(format!("{key}={}", one.unwrap_or(value))))
            }
        };
        out.push(flag);
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_lookup() {
        let home = tempfile::tempdir().unwrap();
        assert!(load(home.path()).unwrap().is_empty(), "no file yet");
        let a = Saved {
            name: "box".into(),
            host: "192.0.2.5".into(),
            user: Some("admin".into()),
            port: Some(2222),
            identity: Some("~/.ssh/my key".into()),
            options: vec!["LocalForward 8080 localhost:80".into(), "ForwardAgent yes".into()],
        };
        let b = Saved { name: "web".into(), host: "web.example.com".into(), ..Default::default() };
        save(home.path(), &[a.clone(), b.clone()]).unwrap();
        assert_eq!(load(home.path()).unwrap(), vec![a, b]);
        // qsh itself reads the file: `qsh box` resolves through it.
        let t = super::super::Target::parse_with("box", None, Some(home.path()), false).unwrap();
        assert_eq!((t.host.as_str(), t.user.as_str(), t.port), ("192.0.2.5", "admin", 2222));
        assert_eq!(t.local_forwards, ["8080:localhost:80"]);
        // And for ssh when it takes over (a host without qshd).
        assert!(t.ssh_options.iter().any(|o| o == "LocalForward=8080 localhost:80"), "{:?}", t.ssh_options);
        assert!(t.ssh_options.iter().any(|o| o == "ForwardAgent=yes"), "{:?}", t.ssh_options);
        assert!(super::super::config::host_aliases(home.path()).contains(&"web".to_string()));
        // A file that cannot be read is an error, not "nothing saved".
        let file = path(home.path());
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(load(home.path()).is_err());
    }

    #[test]
    fn hand_written_match_is_kept_apart() {
        let home = tempfile::tempdir().unwrap();
        let file = path(home.path());
        crate::keys::create_private_dir(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "Host a\n    HostName a.example\nMatch host x\n    ProxyJump j\n").unwrap();
        let all = load(home.path()).unwrap();
        assert!(all[0].options.is_empty(), "{:?}", all[0].options);
        assert!(save(home.path(), &all).is_err(), "the Match block would be lost");
        assert!(std::fs::read_to_string(&file).unwrap().contains("Match host x"));
    }

    #[test]
    fn bad_fields_are_refused() {
        let ok = Saved { name: "box".into(), host: "example.com".into(), ..Default::default() };
        assert!(ok.validate().is_ok());
        for bad in [
            Saved { name: "two words".into(), ..ok.clone() },
            Saved { name: "*".into(), ..ok.clone() },
            Saved { host: "-oProxyCommand=x".into(), ..ok.clone() },
            Saved { host: "a\nHost *".into(), ..ok.clone() },
            Saved { user: Some("ro ot".into()), ..ok.clone() },
            Saved { options: vec!["HostName evil".into()], ..ok.clone() },
            Saved { options: vec!["Match exec x".into()], ..ok.clone() },
            Saved { options: vec!["ForwardAgent".into()], ..ok.clone() },
            Saved { options: vec!["Bad-Key 1".into()], ..ok.clone() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn flags_and_config_lines() {
        let flags = "-L 8080:localhost:80 -L[::1]:5432:/run/pg.sock -R 9000 -R 2222:db:22 -D 1080 -NA -Y -C -o ServerAliveInterval=30 -o \"RemoteCommand=tmux new -A\" -J gw";
        let lines = options_from_flags(flags).unwrap();
        assert_eq!(
            lines,
            [
                "LocalForward 8080 localhost:80",
                "LocalForward [::1]:5432 /run/pg.sock",
                "RemoteForward 9000",
                "RemoteForward 2222 db:22",
                "DynamicForward 1080",
                "SessionType none",
                "ForwardAgent yes",
                "ForwardX11 yes",
                "ForwardX11Trusted yes",
                "Compression yes",
                "ServerAliveInterval 30",
                "RemoteCommand tmux new -A",
                "ProxyJump gw",
            ]
        );
        let back = flags_from_options(&lines);
        assert_eq!(
            back,
            "-L 8080:localhost:80 -L [::1]:5432:/run/pg.sock -R 9000 -R 2222:db:22 -D 1080 -N -A -Y -C -o ServerAliveInterval=30 -o \"RemoteCommand=tmux new -A\" -J gw"
        );
        assert_eq!(options_from_flags(&back).unwrap(), lines);
        // A value written in quotes in the file survives an edit.
        let quoted = vec!["RemoteCommand \"tmux new -A\"".to_string()];
        assert_eq!(options_from_flags(&flags_from_options(&quoted)).unwrap(), ["RemoteCommand tmux new -A"]);
        let words = vec!["SendEnv \"LANG\" \"LC_*\"".to_string()];
        assert_eq!(options_from_flags(&flags_from_options(&words)).unwrap(), ["SendEnv LANG LC_*"]);
        for bad in ["-p 22", "-L", "-L 80", "8080:x:80", "-o NoValue", "-K", "-o \"Unclosed=1"] {
            assert!(options_from_flags(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn saved_from_a_command_line() {
        let args = |s: &str| super::super::cli::SshArgs::parse(s.split_whitespace().map(String::from)).unwrap();
        let a = args("-N -R 2222:127.0.0.1:4422 -p 4422 -o ServerAliveInterval=15 qsh-tun@server --save tunnel");
        assert_eq!(a.save.as_deref(), Some("tunnel"));
        let (s, left_out) = from_args("tunnel", a.destination.as_deref().unwrap(), &a).unwrap();
        assert_eq!((s.host.as_str(), s.user.as_deref(), s.port), ("server", Some("qsh-tun"), Some(4422)));
        assert_eq!(s.options, ["RemoteForward 2222 127.0.0.1:4422", "SessionType none", "ServerAliveInterval 15"]);
        assert!(left_out.is_empty());
        // Read back as written, with the same flags for qsh ui's form.
        assert_eq!(parse(&s.block()), std::slice::from_ref(&s));
        assert_eq!(flags_from_options(&s.options), "-R 2222:127.0.0.1:4422 -N -o ServerAliveInterval=15");
        let a = args("-l bob -i k1 [2001:db8::1]:2200 uptime --save x");
        let (s, left_out) = from_args("x", a.destination.as_deref().unwrap(), &a).unwrap();
        assert_eq!((s.host.as_str(), s.user.as_deref(), s.port, s.identity.as_deref()), ("2001:db8::1", Some("bob"), Some(2200), Some("k1")));
        // `uptime --save x` is the command here: only options before it count.
        assert_eq!(a.save, None);
        assert_eq!(left_out, ["the command \"uptime --save x\""]);
        let a = args("-i a -i b host --save x");
        assert!(from_args("x", "host", &a).is_err());
    }
}
