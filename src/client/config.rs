//! Host aliases from `~/.config/qsh/config` and `~/.ssh/config` (ssh_config syntax).
//!
//! Precedence: `-o` options, then `~/.config/qsh/config`, then `~/.ssh/config`
//! (or the `-F` file); within each the first value found wins (IdentityFile
//! and the forwards accumulate). Supported keywords: `Host` patterns (`*`,
//! `?`, `!`), `Match`, `Include`, `HostName`, `User`, `Port`,
//! `IdentityFile`, `LocalForward`, `RemoteForward`, `DynamicForward`,
//! `ProxyJump`, `RequestTTY`, `BatchMode`, `StrictHostKeyChecking`,
//! `UserKnownHostsFile`, `ClearAllForwardings`, `EscapeChar`,
//! `AddressFamily`, `LogLevel`, `ForwardAgent`, `ObscureKeystrokeTiming`,
//! `ControlMaster`, `ControlPath`, `ControlPersist`, and qsh's own
//! `PersistSession` and `PredictiveEcho`.
//! `Match` blocks are evaluated for `all`, `host`, `originalhost`, `user` and
//! `localuser`; a block whose conditions qsh cannot check (`exec`,
//! `localnetwork`, `canonical`...) is not used, except that a proxy in it
//! counts. Like ssh, `/etc/ssh/ssh_config` is read after `~/.ssh/config`
//! (not with `-F`), and `#` starts a comment anywhere on a line.
//!
//! From `~/.ssh/config`, settings that describe the ssh session itself (`Port`,
//! the forwards, `RequestTTY`) are only used in `--full` mode. Its
//! `ProxyJump`/`ProxyCommand` make `--full` hand the host to ssh, and its
//! `UserKnownHostsFile` is never used (that file holds ssh host keys, not qshd's).

use std::path::{Path, PathBuf};

const MAX_INCLUDE_DEPTH: usize = 16;
/// OpenSSH's system-wide client config (not read with `-F`, as by ssh).
const SYSTEM_SSH_CONFIG: &str = "/etc/ssh/ssh_config";

/// Settings collected for one host alias.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct HostConfig {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// `Port` from `~/.ssh/config` (only read in `--full` mode).
    pub ssh_port: Option<u16>,
    pub identity_files: Vec<String>,
    /// `-L` specs (`[bind:]port:host:hostport`).
    pub local_forwards: Vec<String>,
    /// `-R` specs (`[bind:]port:host:hostport`).
    pub remote_forwards: Vec<String>,
    /// `-D` specs (`[bind:]port`).
    pub dynamic_forwards: Vec<String>,
    /// Jump hosts for qsh (from qsh's config or `-o`).
    pub proxy_jump: Option<String>,
    /// `RequestTTY` (`yes`, `no`, `force`, `auto`).
    pub request_tty: Option<String>,
    /// ssh's config routes the host through ProxyJump/ProxyCommand (`--full` hands it to ssh).
    pub needs_proxy: bool,
    pub batch_mode: Option<bool>,
    /// `StrictHostKeyChecking` (`yes`, `ask`, `accept-new`, `no`).
    pub strict_host_key_checking: Option<String>,
    pub user_known_hosts_file: Option<String>,
    pub clear_all_forwardings: Option<bool>,
    pub escape_char: Option<String>,
    /// `AddressFamily` (`any`, `inet`, `inet6`).
    pub address_family: Option<String>,
    pub log_level: Option<String>,
    pub forward_agent: Option<bool>,
    /// `ObscureKeystrokeTiming` (`yes`, `no`, `interval:MS`).
    pub obscure_keystrokes: Option<String>,
    /// Only offer agent keys that match an IdentityFile.
    pub identities_only: Option<bool>,
    /// `IdentityAgent`: socket path, `SSH_AUTH_SOCK` or `none`.
    pub identity_agent: Option<String>,
    /// `CertificateFile`s, in order.
    pub certificate_files: Vec<String>,
    /// qsh's `PersistSession`: terminal sessions survive lost connections.
    pub persist_session: Option<bool>,
    /// `ServerAliveInterval` (seconds; 0 = off).
    pub server_alive_interval: Option<u64>,
    /// `ServerAliveCountMax`.
    pub server_alive_count_max: Option<u32>,
    /// `ControlMaster`, `ControlPath` (qsh's config and `-o` only), `ControlPersist`.
    pub control_master: Option<String>,
    pub control_path: Option<String>,
    pub control_persist: Option<String>,
    /// qsh's `PredictiveEcho` (`auto`, `yes`, `no`).
    pub predictive_echo: Option<String>,
    /// `Compression` (used by `qsh cp`).
    pub compression: Option<bool>,
    /// `BindAddress` and `BindInterface` (`-b`, `-B`).
    pub bind_address: Option<String>,
    pub bind_interface: Option<String>,
    /// `-o` options for ssh/scp when `--full` hands the host over: what only
    /// qsh's config says (a name only `qsh ui` saved, say), so that ssh
    /// reaches the same host.
    pub for_ssh: Vec<String>,
}

fn yes(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "on")
}

use crate::pattern::{host_matches, wildcard};

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
        // An unquoted word starting with `#` begins a comment (OpenSSH's argv_split).
        if chars.peek() == Some(&'#') {
            break;
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

/// Whether a `Host`/`Match` block applies.
#[derive(Clone, Copy, PartialEq)]
enum Applies {
    Yes,
    No,
    /// Depends on what qsh cannot check (`Match exec`, `localnetwork`...):
    /// its settings are not used, but a proxy in it counts (see `needs_proxy`).
    Maybe,
}

struct Parser<'a> {
    host: &'a str,
    /// Directory relative `Include` paths are resolved against.
    base: PathBuf,
    /// Read the ssh-session settings (`Port`, forwards, `RequestTTY`, `ProxyJump`).
    full: bool,
    /// qsh's own config or `-o` (as opposed to ssh's config).
    ours: bool,
    out: HostConfig,
    /// `CanonicalizeHostname` is on: blocks may match the canonical name,
    /// which qsh does not compute.
    canonicalize: bool,
    /// Some ProxyCommand/ProxyJump appears anywhere in the file.
    any_proxy: bool,
}

/// A proxy setting that is not `none`.
fn is_proxy(keyword: &str, first: Option<&str>) -> bool {
    matches!(keyword, "proxyjump" | "proxycommand") && first.is_some_and(|v| !v.eq_ignore_ascii_case("none"))
}

impl Parser<'_> {
    /// Evaluates `Match` criteria like OpenSSH, as far as qsh can.
    fn match_applies(&self, args: &[String]) -> Applies {
        let mut result = Applies::Yes;
        let mut words = args.iter();
        while let Some(word) = words.next() {
            let (negated, criterion) = match word.strip_prefix('!') {
                Some(c) => (true, c.to_ascii_lowercase()),
                None => (false, word.to_ascii_lowercase()),
            };
            let patterns = |arg: Option<&String>| -> Vec<String> { arg.map(|a| a.split(',').map(str::to_string).collect()).unwrap_or_default() };
            let this = match criterion.as_str() {
                "all" => Applies::Yes,
                "host" => {
                    let name = self.out.hostname.as_deref().unwrap_or(self.host);
                    if host_matches(&patterns(words.next()), name) { Applies::Yes } else { Applies::No }
                }
                "originalhost" => {
                    if host_matches(&patterns(words.next()), self.host) { Applies::Yes } else { Applies::No }
                }
                "localuser" => {
                    let me = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default();
                    if host_matches(&patterns(words.next()), &me) { Applies::Yes } else { Applies::No }
                }
                "user" => {
                    let pats = patterns(words.next());
                    match self.out.user.as_deref() {
                        Some(u) if host_matches(&pats, u) => Applies::Yes,
                        Some(_) => Applies::No,
                        None => Applies::Maybe,
                    }
                }
                // Evaluated on a second pass after canonicalization, which qsh does not do.
                "canonical" | "final" => Applies::Maybe,
                // `exec`, `localnetwork`, `tagged`, `version` and anything newer.
                _ => {
                    words.next();
                    Applies::Maybe
                }
            };
            let this = match (negated, this) {
                (true, Applies::Yes) => Applies::No,
                (true, Applies::No) => Applies::Yes,
                (_, x) => x,
            };
            result = match (result, this) {
                (Applies::No, _) | (_, Applies::No) => Applies::No,
                (Applies::Maybe, _) | (_, Applies::Maybe) => Applies::Maybe,
                _ => Applies::Yes,
            };
        }
        result
    }

    fn feed(&mut self, text: &str, depth: usize) {
        // Lines before the first Host/Match apply to every host.
        let mut active = Applies::Yes;
        for line in text.lines() {
            let Some((keyword, args)) = split_line(line) else { continue };
            let first = args.first().cloned();
            if is_proxy(&keyword, first.as_deref()) {
                self.any_proxy = true;
                // A proxy that may apply: do not connect around it.
                if active == Applies::Maybe {
                    self.out.needs_proxy = true;
                }
            }
            match keyword.as_str() {
                "host" => {
                    active = if host_matches(&args, self.host) { Applies::Yes } else { Applies::No };
                    continue;
                }
                "match" => {
                    active = self.match_applies(&args);
                    continue;
                }
                _ => {}
            }
            let o = &mut self.out;
            match keyword.as_str() {
                _ if active != Applies::Yes => {}
                "canonicalizehostname" => self.canonicalize |= first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("no")),
                "include" if depth < MAX_INCLUDE_DEPTH => {
                    for pattern in &args {
                        for file in self.expand_include(pattern) {
                            if let Ok(t) = std::fs::read_to_string(&file) {
                                self.feed(&t, depth + 1);
                            }
                        }
                    }
                }
                "hostname" if o.hostname.is_none() => o.hostname = first,
                "user" if o.user.is_none() => o.user = first,
                "port" if self.full && o.port.is_none() => o.port = first.and_then(|p| p.parse().ok()),
                "identityfile" => o.identity_files.extend(first),
                // `LocalForward [bind:]port host:hostport` → `-L [bind:]port:host:hostport`.
                "localforward" if self.full && args.len() == 2 => o.local_forwards.push(format!("{}:{}", args[0], args[1])),
                "remoteforward" if self.full && args.len() == 2 => o.remote_forwards.push(format!("{}:{}", args[0], args[1])),
                "dynamicforward" if self.full => o.dynamic_forwards.extend(first),
                "requesttty" if self.full && o.request_tty.is_none() => o.request_tty = first.map(|v| v.to_ascii_lowercase()),
                "proxyjump" if first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("none")) => {
                    if self.ours {
                        if o.proxy_jump.is_none() {
                            o.proxy_jump = first;
                        }
                    } else {
                        o.needs_proxy = true;
                    }
                }
                "proxycommand" if first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("none")) => o.needs_proxy = true,
                "batchmode" if o.batch_mode.is_none() => o.batch_mode = first.as_deref().map(yes),
                "stricthostkeychecking" if o.strict_host_key_checking.is_none() => {
                    o.strict_host_key_checking = first.map(|v| v.to_ascii_lowercase());
                }
                "userknownhostsfile" if self.ours && o.user_known_hosts_file.is_none() => o.user_known_hosts_file = first,
                "clearallforwardings" if o.clear_all_forwardings.is_none() => o.clear_all_forwardings = first.as_deref().map(yes),
                "escapechar" if o.escape_char.is_none() => o.escape_char = first,
                "addressfamily" if o.address_family.is_none() => o.address_family = first.map(|v| v.to_ascii_lowercase()),
                "loglevel" if o.log_level.is_none() => o.log_level = first.map(|v| v.to_ascii_lowercase()),
                "forwardagent" if o.forward_agent.is_none() => o.forward_agent = first.as_deref().map(yes),
                "identitiesonly" if o.identities_only.is_none() => o.identities_only = first.as_deref().map(yes),
                "identityagent" if o.identity_agent.is_none() => o.identity_agent = first,
                "certificatefile" => o.certificate_files.extend(first),
                "persistsession" if o.persist_session.is_none() => o.persist_session = first.as_deref().map(yes),
                "serveraliveinterval" if o.server_alive_interval.is_none() => o.server_alive_interval = first.and_then(|v| v.parse().ok()),
                "serveralivecountmax" if o.server_alive_count_max.is_none() => o.server_alive_count_max = first.and_then(|v| v.parse().ok()),
                "controlmaster" if o.control_master.is_none() => o.control_master = first,
                "controlpath" if self.ours && o.control_path.is_none() => o.control_path = first,
                "controlpersist" if o.control_persist.is_none() => o.control_persist = first,
                "predictiveecho" if o.predictive_echo.is_none() => o.predictive_echo = first,
                "compression" if o.compression.is_none() => o.compression = first.as_deref().map(yes),
                "bindaddress" if o.bind_address.is_none() => o.bind_address = first,
                "bindinterface" if o.bind_interface.is_none() => o.bind_interface = first,
                "obscurekeystroketiming" if o.obscure_keystrokes.is_none() => {
                    o.obscure_keystrokes = first.map(|v| v.to_ascii_lowercase());
                }
                _ => {}
            }
        }
    }

    fn expand_include(&self, pattern: &str) -> Vec<PathBuf> {
        expand_include(&self.base, pattern)
    }

    fn new<'h>(host: &'h str, base: &Path, full: bool, ours: bool) -> Parser<'h> {
        Parser { host, base: base.to_path_buf(), full, ours, out: HostConfig::default(), canonicalize: false, any_proxy: false }
    }

    /// Feeds another file, with its own directory for `Include`.
    fn feed_file(&mut self, text: &str, base: &Path) {
        self.base = base.to_path_buf();
        // Blocks do not continue into the next file.
        self.feed(&format!("{text}\nMatch all\n"), 0);
    }

    fn finish(mut self) -> HostConfig {
        // Blocks may match a canonical name qsh does not know: any proxy then counts.
        if self.canonicalize && self.any_proxy {
            self.out.needs_proxy = true;
        }
        self.out
    }

    fn run(mut self, text: &str) -> HostConfig {
        self.feed(text, 0);
        self.finish()
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
        // Like glob(3): a leading dot must be matched explicitly.
        .filter(|e| {
            let file = e.file_name().to_string_lossy().into_owned();
            (!file.starts_with('.') || name.starts_with('.')) && wildcard(&name, &file)
        })
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
    let qsh_dir = crate::keys::qsh_dir(home);
    for (dir, file) in [(qsh_dir.clone(), "config"), (home.join(".ssh"), "config"), (qsh_dir, UI_HOSTS)] {
        if let Ok(text) = std::fs::read_to_string(dir.join(file)) {
            collect_aliases(&text, &dir, 0, &mut out);
        }
    }
    out
}

/// Connections saved from `qsh ui` (ssh_config syntax), in `~/.config/qsh`.
/// Read after the user's own config files, and the menu only saves names
/// that are not in them, so it never overrides what the user wrote.
pub const UI_HOSTS: &str = "ui-hosts";

/// Collects the settings for `host` from config `text`. `full` is false for
/// `~/.ssh/config` outside `--full`: its `Port`, `LocalForward` and
/// `RequestTTY` belong to the ssh session.
pub fn parse(text: &str, host: &str, base: &Path, full: bool) -> HostConfig {
    Parser::new(host, base, full, full).run(text)
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

/// Where settings come from besides the default files.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Sources {
    /// `qsh --full`: also take the ssh-session settings from ssh's config.
    pub full: bool,
    /// Config lines from `-o` (and `-l`), highest precedence.
    pub overrides: Vec<String>,
    /// `-F`: use this file instead of `~/.ssh/config`.
    pub ssh_config: Option<PathBuf>,
}

/// Settings for `host`: `-o` overrides, then `~/.config/qsh/config`, then
/// `~/.ssh/config` (or the `-F` file).
pub fn lookup(home: &Path, host: &str, sources: &Sources) -> HostConfig {
    let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
    let qsh_dir = crate::keys::qsh_dir(home);
    let ssh_file = sources.ssh_config.clone().unwrap_or_else(|| home.join(".ssh").join("config"));
    // Relative Includes in the user's file are in ~/.ssh, even with -F (as in ssh).
    let ssh_dir = home.join(".ssh");
    // -o lines come first: before any `Host` they apply to every host and win.
    // `Match all` ends the last `Host` block of each part, so settings in the
    // next one are not taken as part of it.
    let ours_text = format!(
        "{}\nMatch all\n{}\nMatch all\n{}",
        sources.overrides.join("\n"),
        read(&qsh_dir.join("config")),
        read(&qsh_dir.join(UI_HOSTS))
    );
    let ours = Parser::new(host, &qsh_dir, true, true).run(&ours_text);
    // ssh's own files: the user's, then (without -F) the system-wide one,
    // as ssh reads them; first value wins across both.
    let mut ssh = Parser::new(host, &ssh_dir, sources.full, false);
    ssh.feed_file(&read(&ssh_file), &ssh_dir);
    if sources.ssh_config.is_none() {
        let system = Path::new(SYSTEM_SSH_CONFIG);
        ssh.feed_file(&read(system), system.parent().unwrap_or(Path::new("/")));
    }
    let ssh = ssh.finish();
    let needs_proxy = ours.needs_proxy || (ssh.needs_proxy && ours.proxy_jump.is_none());
    let mut for_ssh = Vec::new();
    if let (Some(h), None) = (&ours.hostname, &ssh.hostname) {
        for_ssh.push(format!("HostName={h}"));
    }
    if let (Some(u), None) = (&ours.user, &ssh.user) {
        for_ssh.push(format!("User={u}"));
    }
    for f in &ours.identity_files {
        for_ssh.push(format!("IdentityFile={f}"));
    }
    HostConfig {
        hostname: ours.hostname.or(ssh.hostname),
        user: ours.user.or(ssh.user),
        port: ours.port,
        ssh_port: ssh.port,
        identity_files: ours.identity_files.into_iter().chain(ssh.identity_files).collect(),
        local_forwards: ours.local_forwards.into_iter().chain(ssh.local_forwards).collect(),
        remote_forwards: ours.remote_forwards.into_iter().chain(ssh.remote_forwards).collect(),
        dynamic_forwards: ours.dynamic_forwards.into_iter().chain(ssh.dynamic_forwards).collect(),
        proxy_jump: ours.proxy_jump,
        request_tty: ours.request_tty.or(ssh.request_tty),
        // A ProxyJump in qsh's own config (or -J) is how to reach a host that
        // ssh reaches through a proxy, so it takes care of ssh's.
        needs_proxy,
        batch_mode: ours.batch_mode.or(ssh.batch_mode),
        strict_host_key_checking: ours.strict_host_key_checking.or(ssh.strict_host_key_checking),
        user_known_hosts_file: ours.user_known_hosts_file,
        clear_all_forwardings: ours.clear_all_forwardings.or(ssh.clear_all_forwardings),
        escape_char: ours.escape_char.or(ssh.escape_char),
        address_family: ours.address_family.or(ssh.address_family),
        log_level: ours.log_level.or(ssh.log_level),
        forward_agent: ours.forward_agent.or(ssh.forward_agent),
        // A privacy preference, so ssh's setting applies to qsh sessions as well.
        obscure_keystrokes: ours.obscure_keystrokes.or(ssh.obscure_keystrokes),
        identities_only: ours.identities_only.or(ssh.identities_only),
        identity_agent: ours.identity_agent.or(ssh.identity_agent),
        certificate_files: ours.certificate_files.into_iter().chain(ssh.certificate_files).collect(),
        persist_session: ours.persist_session.or(ssh.persist_session),
        server_alive_interval: ours.server_alive_interval.or(ssh.server_alive_interval),
        server_alive_count_max: ours.server_alive_count_max.or(ssh.server_alive_count_max),
        control_master: ours.control_master.or(ssh.control_master),
        control_path: ours.control_path,
        control_persist: ours.control_persist.or(ssh.control_persist),
        predictive_echo: ours.predictive_echo.or(ssh.predictive_echo),
        compression: ours.compression.or(ssh.compression),
        bind_address: ours.bind_address.or(ssh.bind_address),
        bind_interface: ours.bind_interface.or(ssh.bind_interface),
        for_ssh,
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
        assert_eq!(parse(text, "b", Path::new("/x"), true).proxy_jump.as_deref(), Some("bastion"));
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
        let c = lookup(home.path(), "myserver", &Sources::default());
        assert_eq!(c.hostname.as_deref(), Some("192.0.2.1"));
        assert_eq!(c.user.as_deref(), Some("admin"));
        assert_eq!(c.port, Some(8080));
        // --full: ssh's Port is used when qsh's config has none.
        std::fs::write(ours.join("config"), "Host other\n Port 1\n").unwrap();
        let full = Sources { full: true, ..Default::default() };
        assert_eq!(lookup(home.path(), "myserver", &full).ssh_port, Some(22));
        assert_eq!(lookup(home.path(), "myserver", &Sources::default()).ssh_port, None);
        // -o wins over both files; ssh's known_hosts file is never used.
        std::fs::write(ssh.join("config"), "Host myserver\n UserKnownHostsFile /x\n User root\n").unwrap();
        let o = Sources { overrides: vec!["User override".into(), "UserKnownHostsFile ~/kh".into()], ..Default::default() };
        let c = lookup(home.path(), "myserver", &o);
        assert_eq!(c.user.as_deref(), Some("override"));
        assert_eq!(c.user_known_hosts_file.as_deref(), Some("~/kh"));
        assert_eq!(lookup(home.path(), "myserver", &Sources::default()).user_known_hosts_file, None);
    }
}

#[cfg(test)]
mod match_tests {
    use super::*;

    fn cfg(text: &str, host: &str) -> HostConfig {
        parse(text, host, Path::new("/nonexistent"), true)
    }

    #[test]
    fn comments_end_lines() {
        let c = cfg("Host alpha   # was: beta\n    HostName 192.0.2.10   # the office box\n", "beta");
        assert_eq!(c.hostname, None, "a comment is not a host pattern");
        let c = cfg("Host alpha   # was: beta\n    HostName 192.0.2.10   # the office box\n", "alpha");
        assert_eq!(c.hostname.as_deref(), Some("192.0.2.10"));
        let c = cfg("Match all   # everything\n    ProxyCommand nc -x 127.0.0.1:9050 %h %p\n", "any");
        assert!(c.needs_proxy, "Match all with a comment still applies");
    }

    #[test]
    fn match_blocks_are_evaluated() {
        let text = "Host m2\n    HostName 192.0.2.5\nMatch originalhost m2\n    ProxyCommand nc %h %p\n    User via\n";
        let c = cfg(text, "m2");
        assert!(c.needs_proxy);
        assert_eq!(c.user.as_deref(), Some("via"));
        assert!(!cfg(text, "other").needs_proxy);
        let c = cfg("Match host 192.0.2.*\n    User ops\n", "192.0.2.7");
        assert_eq!(c.user.as_deref(), Some("ops"));
        let c = cfg("Match !host 192.0.2.*\n    User ops\n", "192.0.2.7");
        assert_eq!(c.user, None);
    }

    /// What qsh cannot check: settings are not used, but a proxy counts.
    #[test]
    fn unknown_conditions_with_a_proxy() {
        let c = cfg("Match exec \"test -e /tmp/vpn\"\n    ProxyJump bastion\n    User other\n", "h");
        assert!(c.needs_proxy);
        assert_eq!(c.user, None);
        let c = cfg("Match exec \"true\"\n    User other\n", "h");
        assert!(!c.needs_proxy);
        let c = cfg("CanonicalizeHostname yes\nHost *.corp.example\n    ProxyJump bastion\n", "box");
        assert!(c.needs_proxy, "the canonical name could match");
    }
}
