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
            "host" => out.push(Saved { name: value, ..Default::default() }),
            _ => {
                let Some(s) = out.last_mut() else { continue };
                match key.as_str() {
                    "hostname" => s.host = value,
                    "user" => s.user = Some(value),
                    "port" => s.port = value.parse().ok(),
                    "identityfile" => s.identity = Some(value),
                    "match" | "include" => {}
                    _ => s.options.push(line.split_once(char::is_whitespace).map(|(k, v)| format!("{k} {}", v.trim())).unwrap_or_default()),
                }
            }
        }
    }
    out
}

pub fn load(home: &Path) -> Vec<Saved> {
    std::fs::read_to_string(path(home)).map(|t| parse(&t)).unwrap_or_default()
}

/// Writes all saved connections (replacing the file atomically).
pub fn save(home: &Path, all: &[Saved]) -> Result<()> {
    for s in all {
        s.validate().with_context(|| format!("connection {:?}", s.name))?;
    }
    let file = path(home);
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
            ("compression", "yes") => "-C".into(),
            ("sessiontype", "none") => "-N".into(),
            ("requesttty", "no") => "-T".into(),
            ("requesttty", "yes") => "-t".into(),
            _ => format!("-o {}", quote(format!("{key}={value}"))),
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
        assert_eq!(load(home.path()), vec![a, b]);
        // qsh itself reads the file: `qsh box` resolves through it.
        let t = super::super::Target::parse_with("box", None, Some(home.path()), false).unwrap();
        assert_eq!((t.host.as_str(), t.user.as_str(), t.port), ("192.0.2.5", "admin", 2222));
        assert_eq!(t.local_forwards, ["8080:localhost:80"]);
        // And for ssh when it takes over (a host without qshd).
        assert!(t.ssh_options.iter().any(|o| o == "LocalForward=8080 localhost:80"), "{:?}", t.ssh_options);
        assert!(t.ssh_options.iter().any(|o| o == "ForwardAgent=yes"), "{:?}", t.ssh_options);
        assert!(super::super::config::host_aliases(home.path()).contains(&"web".to_string()));
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
        for bad in ["-p 22", "-L", "-L 80", "8080:x:80", "-o NoValue", "-K", "-o \"Unclosed=1"] {
            assert!(options_from_flags(bad).is_err(), "{bad}");
        }
    }
}
