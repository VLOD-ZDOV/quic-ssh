//! Host aliases from `~/.config/qsh/config` and `~/.ssh/config` (ssh_config syntax).
//!
//! Supported: `Host` patterns (`*`, `?`, `!negation`), `HostName`, `User`,
//! `Port`, `IdentityFile`, `LocalForward`, `RequestTTY`,
//! `ObscureKeystrokeTiming`, `Include`,
//! `Match all`; the first value found wins (IdentityFile and LocalForward
//! accumulate). Other `Match` blocks are skipped because their conditions are
//! not evaluated. From `~/.ssh/config`, `Port`, `LocalForward` and
//! `RequestTTY` are only used in `--full` mode (they describe the ssh session),
//! and `ProxyJump`/`ProxyCommand` are noted so `--full` can hand such hosts to ssh.

use std::path::{Path, PathBuf};

const MAX_INCLUDE_DEPTH: usize = 16;

/// Settings collected for one host alias.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct HostConfig {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// `Port` from `~/.ssh/config` (only read in `--full` mode).
    pub ssh_port: Option<u16>,
    pub identity_files: Vec<String>,
    /// `LocalForward` entries as `-L` specs (`[bind:]port:host:hostport`).
    pub local_forwards: Vec<String>,
    /// `RequestTTY` (`yes`, `no`, `force`, `auto`).
    pub request_tty: Option<String>,
    /// The host goes through `ProxyJump`/`ProxyCommand`, which qsh cannot do.
    pub needs_proxy: bool,
    /// `ObscureKeystrokeTiming` (`yes`, `no`, `interval:MS`).
    pub obscure_keystrokes: Option<String>,
}

/// `fnmatch`-style match supporting `*` and `?`.
fn wildcard(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// A `Host` line matches if any positive pattern matches and no negated one does.
fn host_matches(patterns: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let mut matched = false;
    for p in patterns {
        let p = p.to_ascii_lowercase();
        if let Some(neg) = p.strip_prefix('!') {
            if wildcard(neg, &host) {
                return false;
            }
        } else if wildcard(&p, &host) {
            matched = true;
        }
    }
    matched
}

/// Splits `Keyword value`, `Keyword=value` and `Keyword "quoted value"` lines.
fn split_line(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(line.len());
    let keyword = line[..end].to_ascii_lowercase();
    let mut rest = line[end..].trim_start();
    if let Some(r) = rest.strip_prefix('=') {
        rest = r.trim_start();
    }
    let mut args = Vec::new();
    let mut chars = rest.chars().peekable();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let mut arg = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                arg.push(c);
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                arg.push(c);
                chars.next();
            }
        }
        if !arg.is_empty() {
            args.push(arg);
        }
    }
    Some((keyword, args))
}

struct Parser<'a> {
    host: &'a str,
    /// Directory relative `Include` paths are resolved against.
    base: &'a Path,
    /// Read the ssh-session settings (`Port`, `LocalForward`, `RequestTTY`).
    full: bool,
    out: HostConfig,
}

impl Parser<'_> {
    fn feed(&mut self, text: &str, depth: usize) {
        // Lines before the first Host/Match apply to every host.
        let mut active = true;
        for line in text.lines() {
            let Some((keyword, args)) = split_line(line) else { continue };
            match keyword.as_str() {
                "host" => active = host_matches(&args, self.host),
                "match" => active = args.len() == 1 && args[0].eq_ignore_ascii_case("all"),
                _ if !active => {}
                "include" if depth < MAX_INCLUDE_DEPTH => {
                    for pattern in &args {
                        for file in self.expand_include(pattern) {
                            if let Ok(t) = std::fs::read_to_string(&file) {
                                self.feed(&t, depth + 1);
                            }
                        }
                    }
                }
                "hostname" if self.out.hostname.is_none() => self.out.hostname = args.into_iter().next(),
                "user" if self.out.user.is_none() => self.out.user = args.into_iter().next(),
                "port" if self.full && self.out.port.is_none() => {
                    self.out.port = args.first().and_then(|p| p.parse().ok());
                }
                "identityfile" => self.out.identity_files.extend(args.into_iter().take(1)),
                // `LocalForward [bind:]port host:hostport` → `-L [bind:]port:host:hostport`.
                "localforward" if self.full && args.len() == 2 => {
                    self.out.local_forwards.push(format!("{}:{}", args[0], args[1]));
                }
                "requesttty" if self.full && self.out.request_tty.is_none() => {
                    self.out.request_tty = args.into_iter().next().map(|v| v.to_ascii_lowercase());
                }
                "obscurekeystroketiming" if self.out.obscure_keystrokes.is_none() => {
                    self.out.obscure_keystrokes = args.into_iter().next().map(|v| v.to_ascii_lowercase());
                }
                "proxyjump" | "proxycommand" if args.first().is_some_and(|v| !v.eq_ignore_ascii_case("none")) => {
                    self.out.needs_proxy = true;
                }
                _ => {}
            }
        }
    }

    fn expand_include(&self, pattern: &str) -> Vec<PathBuf> {
        expand_include(self.base, pattern)
    }
}

/// Resolves an `Include` argument (relative to the config dir, `~`, `*` in the file name).
fn expand_include(base: &Path, pattern: &str) -> Vec<PathBuf> {
    let path = match pattern.strip_prefix("~/") {
        Some(rest) => dirs::home_dir().unwrap_or_default().join(rest),
        None => base.join(pattern), // join keeps absolute paths as they are
    };
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if !name.contains(['*', '?']) {
        return vec![path];
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| wildcard(&name, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect();
    files.sort();
    files
}

/// Concrete host names (no patterns) declared with `Host` in a config text.
fn collect_aliases(text: &str, base: &Path, depth: usize, out: &mut Vec<String>) {
    for line in text.lines() {
        let Some((keyword, args)) = split_line(line) else { continue };
        match keyword.as_str() {
            "host" => {
                for a in args {
                    if !a.contains(['*', '?', '!']) && !out.contains(&a) {
                        out.push(a);
                    }
                }
            }
            "include" if depth < MAX_INCLUDE_DEPTH => {
                for pattern in &args {
                    for file in expand_include(base, pattern) {
                        if let Ok(t) = std::fs::read_to_string(&file) {
                            collect_aliases(&t, base, depth + 1, out);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Host aliases from `~/.config/qsh/config` and `~/.ssh/config`, in file order.
pub fn host_aliases(home: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for dir in [crate::keys::qsh_dir(home), home.join(".ssh")] {
        if let Ok(text) = std::fs::read_to_string(dir.join("config")) {
            collect_aliases(&text, &dir, 0, &mut out);
        }
    }
    out
}

/// Collects the settings for `host` from config `text`. `full` is false for
/// `~/.ssh/config` outside `--full`: its `Port`, `LocalForward` and
/// `RequestTTY` belong to the ssh session.
pub fn parse(text: &str, host: &str, base: &Path, full: bool) -> HostConfig {
    let mut p = Parser { host, base, full, out: HostConfig::default() };
    p.feed(text, 0);
    p.out
}

/// Parses `ObscureKeystrokeTiming`: `yes` (default 20 ms), `no`, `interval:MS`.
/// `None` (unset) means the default.
pub fn keystroke_interval(value: Option<&str>) -> Option<std::time::Duration> {
    let default = Some(crate::client::keystroke::DEFAULT_INTERVAL);
    match value {
        None | Some("yes") => default,
        Some("no") => None,
        Some(v) => match v.strip_prefix("interval:").and_then(|ms| ms.parse::<u64>().ok()) {
            Some(0) => None,
            Some(ms) => Some(std::time::Duration::from_millis(ms)),
            None => default,
        },
    }
}

/// Expands `~`, `%d` (home), `%h` (host name), `%r` (remote user), `%u` (local user), `%%`.
pub fn expand_path(s: &str, home: &Path, host: &str, remote_user: &str, local_user: &str) -> PathBuf {
    let s = match s.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", home.display()),
        None if s == "~" => home.display().to_string(),
        None => s.to_string(),
    };
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('d') => out.push_str(&home.display().to_string()),
            Some('h') => out.push_str(host),
            Some('r') => out.push_str(remote_user),
            Some('u') => out.push_str(local_user),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    PathBuf::from(out)
}

/// Settings for `host` from `~/.config/qsh/config` (first) and `~/.ssh/config`.
/// `full`: also take the ssh-session settings from `~/.ssh/config` (`qsh --full`).
pub fn lookup(home: &Path, host: &str, full: bool) -> HostConfig {
    let read = |p: PathBuf| std::fs::read_to_string(p).unwrap_or_default();
    let qsh_dir = crate::keys::qsh_dir(home);
    let ssh_dir = home.join(".ssh");
    let ours = parse(&read(qsh_dir.join("config")), host, &qsh_dir, true);
    let ssh = parse(&read(ssh_dir.join("config")), host, &ssh_dir, full);
    HostConfig {
        hostname: ours.hostname.or(ssh.hostname),
        user: ours.user.or(ssh.user),
        port: ours.port,
        ssh_port: ssh.port,
        identity_files: ours.identity_files.into_iter().chain(ssh.identity_files).collect(),
        local_forwards: ours.local_forwards.into_iter().chain(ssh.local_forwards).collect(),
        request_tty: ours.request_tty.or(ssh.request_tty),
        needs_proxy: ours.needs_proxy || ssh.needs_proxy,
        // A privacy preference, so ssh's setting applies to qsh sessions as well.
        obscure_keystrokes: ours.obscure_keystrokes.or(ssh.obscure_keystrokes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSH: &str = r#"
# global defaults come first only if placed before any Host
Host myserver
        Port 22
        User root
        HostName 192.0.2.10
        IdentityFile ~/.ssh/work_key
        LocalForward 8000 localhost:80

Host *.example.com !secret.example.com
    User=deploy
    IdentityFile "~/.ssh/my key"

Match host foo exec "false"
    User nope

Host *
    User fallback
    IdentityFile ~/.ssh/id_%h
"#;

    #[test]
    fn wildcards() {
        assert!(wildcard("*", "anything"));
        assert!(wildcard("web-?.example.com", "web-1.example.com"));
        assert!(!wildcard("web-?.example.com", "web-10.example.com"));
        assert!(wildcard("*.example.com", "a.b.example.com"));
        assert!(!wildcard("*.example.com", "example.com"));
    }

    #[test]
    fn alias_with_ssh_port_ignored() {
        let c = parse(SSH, "myserver", Path::new("/x"), false);
        assert_eq!(c.hostname.as_deref(), Some("192.0.2.10"));
        assert_eq!(c.user.as_deref(), Some("root"));
        assert_eq!(c.port, None);
        assert_eq!(c.identity_files, vec!["~/.ssh/work_key", "~/.ssh/id_%h"]);
        assert_eq!(parse(SSH, "myserver", Path::new("/x"), true).port, Some(22));
    }

    #[test]
    fn patterns_negation_and_first_value_wins() {
        let c = parse(SSH, "app.example.com", Path::new("/x"), false);
        assert_eq!(c.user.as_deref(), Some("deploy"));
        assert_eq!(c.identity_files[0], "~/.ssh/my key");
        let c = parse(SSH, "secret.example.com", Path::new("/x"), false);
        assert_eq!(c.user.as_deref(), Some("fallback"));
        // Unevaluated Match blocks never apply.
        assert_eq!(parse(SSH, "foo", Path::new("/x"), false).user.as_deref(), Some("fallback"));
    }

    #[test]
    fn full_mode_session_settings() {
        let text = "Host a\n LocalForward 8000 localhost:80\n LocalForward 127.0.0.1:9000 db:5432\n RequestTTY force\n\
                    Host b\n ProxyJump bastion\nHost c\n ProxyCommand none\n";
        let c = parse(text, "a", Path::new("/x"), true);
        assert_eq!(c.local_forwards, vec!["8000:localhost:80", "127.0.0.1:9000:db:5432"]);
        assert_eq!(c.request_tty.as_deref(), Some("force"));
        assert!(parse(text, "a", Path::new("/x"), false).local_forwards.is_empty());
        assert!(parse(text, "b", Path::new("/x"), false).needs_proxy);
        assert!(!parse(text, "c", Path::new("/x"), true).needs_proxy);
    }

    #[test]
    fn keystroke_setting() {
        use std::time::Duration;
        assert_eq!(keystroke_interval(None), Some(Duration::from_millis(20)));
        assert_eq!(keystroke_interval(Some("no")), None);
        assert_eq!(keystroke_interval(Some("interval:80")), Some(Duration::from_millis(80)));
        assert_eq!(keystroke_interval(Some("interval:0")), None);
        let c = parse("Host *\n ObscureKeystrokeTiming interval:50\n", "x", Path::new("/x"), false);
        assert_eq!(c.obscure_keystrokes.as_deref(), Some("interval:50"));
    }

    #[test]
    fn aliases_for_the_menu() {
        let home = tempfile::tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        std::fs::create_dir_all(ssh.join("conf.d")).unwrap();
        std::fs::write(ssh.join("config"), "Host a b *.x !c\n Port 1\nInclude conf.d/*\nHost *\n").unwrap();
        std::fs::write(ssh.join("conf.d/more"), "Host d a\n").unwrap();
        assert_eq!(host_aliases(home.path()), vec!["a", "b", "d"]);
    }

    #[test]
    fn includes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("conf.d")).unwrap();
        std::fs::write(dir.path().join("conf.d/a.conf"), "Host box\n  HostName 192.0.2.7\n").unwrap();
        std::fs::write(dir.path().join("conf.d/b.conf"), "Host box\n  HostName ignored\n  User u\n").unwrap();
        let c = parse("Include conf.d/*.conf\nHost box\n  Port 9\n", "box", dir.path(), true);
        assert_eq!(c.hostname.as_deref(), Some("192.0.2.7"));
        assert_eq!(c.user.as_deref(), Some("u"));
        assert_eq!(c.port, Some(9));
    }

    #[test]
    fn path_tokens() {
        let p = expand_path("~/.ssh/id_%h_%r%%", Path::new("/home/me"), "box", "root", "me");
        assert_eq!(p, PathBuf::from("/home/me/.ssh/id_box_root%"));
        assert_eq!(expand_path("%d/k", Path::new("/h"), "", "", ""), PathBuf::from("/h/k"));
    }

    #[test]
    fn qsh_config_overrides_ssh_config() {
        let home = tempfile::tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        let ours = crate::keys::qsh_dir(home.path());
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::create_dir_all(&ours).unwrap();
        std::fs::write(ssh.join("config"), "Host myserver\n HostName 192.0.2.1\n User root\n Port 22\n").unwrap();
        std::fs::write(ours.join("config"), "Host myserver\n Port 8080\n User admin\n").unwrap();
        let c = lookup(home.path(), "myserver", false);
        assert_eq!(c.hostname.as_deref(), Some("192.0.2.1"));
        assert_eq!(c.user.as_deref(), Some("admin"));
        assert_eq!(c.port, Some(8080));
        // --full: ssh's Port is used when qsh's config has none.
        std::fs::write(ours.join("config"), "Host other\n Port 1\n").unwrap();
        assert_eq!(lookup(home.path(), "myserver", true).ssh_port, Some(22));
        assert_eq!(lookup(home.path(), "myserver", false).ssh_port, None);
    }
}
