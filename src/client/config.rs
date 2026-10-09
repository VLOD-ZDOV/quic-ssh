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
//! `ControlMaster`, `ControlPath`, `ControlPersist`, `ProxyCommand`,
//! `SendEnv`, `SetEnv`, `RemoteCommand`, `SessionType`, `StdinNull`,
//! `ForkAfterAuthentication`, `ExitOnForwardFailure`, `LocalCommand`,
//! `PermitLocalCommand`, `HostKeyAlias`, `ConnectTimeout`,
//! `ConnectionAttempts`, and qsh's own `PersistSession` and `PredictiveEcho`.
//! `Match` blocks are evaluated for `all`, `host`, `originalhost`, `user`,
//! `localuser`, `exec`, `localnetwork`, `tagged`, `canonical` and `final`
//! (with `CanonicalizeHostname`, the configs are read again for the
//! canonical name); a block whose conditions qsh cannot check (`version`...)
//! is not used, except that a proxy in it counts. Like ssh, `/etc/ssh/ssh_config` is read after `~/.ssh/config`
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
    /// More `UserKnownHostsFile`s (read, not written).
    pub more_known_hosts_files: Vec<String>,
    /// `GlobalKnownHostsFile`s (qsh's config only; `none` for none).
    pub global_known_hosts_files: Option<Vec<String>>,
    pub hash_known_hosts: Option<bool>,
    /// `KnownHostsCommand` (qsh's config only).
    pub known_hosts_command: Option<String>,
    /// `Tag` (or `-P`), for `Match tagged`.
    pub tag: Option<String>,
    /// `CanonicalizeHostname` (`no`, `yes`, `always`), `CanonicalDomains`,
    /// `CanonicalizeMaxDots`, `CanonicalizeFallbackLocal`.
    pub canonicalize_hostname: Option<String>,
    pub canonical_domains: Option<Vec<String>>,
    pub canonicalize_max_dots: Option<usize>,
    pub canonicalize_fallback_local: Option<bool>,
    /// `AddKeysToAgent` (`no`, `yes`, `ask`, `confirm`, a time).
    pub add_keys_to_agent: Option<String>,
    /// A `Match final` block exists (read the config once more at the end).
    pub wants_final: bool,
    /// `CanonicalizeFallbackLocal no` and the name could not be canonicalized.
    pub canonicalize_failed: Option<String>,
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
    /// `ProxyCommand` from qsh's config or `-o`: TLS over its stdin/stdout.
    pub proxy_command: Option<String>,
    /// `SendEnv` patterns (`-NAME` removes) and `SetEnv NAME=VALUE`s.
    pub send_env: Vec<String>,
    pub set_env: Vec<String>,
    pub remote_command: Option<String>,
    /// `SessionType` (`none`, `subsystem`, `default`).
    pub session_type: Option<String>,
    pub stdin_null: Option<bool>,
    pub fork_after_authentication: Option<bool>,
    pub exit_on_forward_failure: Option<bool>,
    pub local_command: Option<String>,
    pub permit_local_command: Option<bool>,
    /// `HostKeyAlias`: the name to look the host key up under.
    pub host_key_alias: Option<String>,
    /// `ConnectTimeout` (seconds) and `ConnectionAttempts`.
    pub connect_timeout: Option<u64>,
    pub connection_attempts: Option<u32>,
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
    split_line_raw(line).map(|(k, a, _)| (k, a))
}

/// Like [`split_line`], also returning the value as written (for commands,
/// which ssh keeps verbatim).
fn split_line_raw(line: &str) -> Option<(String, Vec<String>, String)> {
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
    let raw = rest.trim_end().to_string();
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
        // Like OpenSSH's argv_split: quotes may start anywhere in a word,
        // and a backslash escapes a quote, a backslash or a space.
        let mut arg = String::new();
        let mut quote: Option<char> = None;
        while let Some(&c) = chars.peek() {
            chars.next();
            match (c, quote) {
                ('\\', _) if chars.peek().is_some_and(|n| matches!(n, '"' | '\'' | '\\') || n.is_whitespace()) => {
                    arg.push(chars.next().unwrap());
                }
                ('"' | '\'', None) => quote = Some(c),
                (q, Some(open)) if q == open => quote = None,
                (w, None) if w.is_whitespace() => break,
                (other, _) => arg.push(other),
            }
        }
        if !arg.is_empty() {
            args.push(arg);
        }
    }
    Some((keyword, args, raw))
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
    /// The host as given (`Match originalhost`, `%n`), when `host` is its
    /// canonical name.
    original: String,
    /// Reading again after canonicalization (`Match canonical`), and the
    /// last pass (`Match final`).
    canonical: bool,
    final_pass: bool,
    /// A `Match final` was seen: the config is read once more at the end.
    wants_final: bool,
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
                    if host_matches(&patterns(words.next()), &self.original) { Applies::Yes } else { Applies::No }
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
                "canonical" => if self.canonical { Applies::Yes } else { Applies::No },
                "final" => if self.final_pass { Applies::Yes } else { Applies::No },
                "exec" => match words.next() {
                    Some(cmd) => if self.exec_succeeds(cmd) { Applies::Yes } else { Applies::No },
                    None => Applies::No,
                },
                "localnetwork" => match local_networks_match(&patterns(words.next())) {
                    Some(true) => Applies::Yes,
                    Some(false) => Applies::No,
                    None => Applies::Maybe,
                },
                "tagged" => {
                    let pats = patterns(words.next());
                    let tag = self.out.tag.as_deref().unwrap_or("");
                    if crate::pattern::name_matches(&pats, tag) || (tag.is_empty() && pats.iter().any(|p| p.is_empty())) { Applies::Yes } else { Applies::No }
                }
                // `version`, `sessiontype`, `command` and anything newer.
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
            let Some((keyword, args, raw)) = split_line_raw(line) else { continue };
            let first = args.first().cloned();
            if keyword == "match" && args.iter().any(|a| a.trim_start_matches('!').eq_ignore_ascii_case("final")) {
                self.wants_final = true;
            }
            if is_proxy(&keyword, first.as_deref()) && !self.ours {
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
                // ProxyJump and ProxyCommand compete: the first one found wins (as in ssh).
                "proxyjump" if first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("none")) => {
                    if self.ours {
                        if o.proxy_jump.is_none() && o.proxy_command.is_none() {
                            o.proxy_jump = first;
                        }
                    } else {
                        o.needs_proxy = true;
                    }
                }
                "proxycommand" if first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("none")) => {
                    if self.ours {
                        if o.proxy_jump.is_none() && o.proxy_command.is_none() {
                            o.proxy_command = Some(raw);
                        }
                    } else {
                        o.needs_proxy = true;
                    }
                }
                "sendenv" if self.full => o.send_env.extend(args.iter().cloned()),
                "setenv" if self.full => {
                    for a in &args {
                        let name = a.split('=').next().unwrap_or("");
                        if a.contains('=') && !o.set_env.iter().any(|e| e.split('=').next() == Some(name)) {
                            o.set_env.push(a.clone());
                        }
                    }
                }
                "remotecommand" if self.full && o.remote_command.is_none() && !raw.is_empty() => {
                    o.remote_command = (!raw.eq_ignore_ascii_case("none")).then_some(raw);
                }
                "sessiontype" if self.full && o.session_type.is_none() => o.session_type = first.map(|v| v.to_ascii_lowercase()),
                "stdinnull" if self.full && o.stdin_null.is_none() => o.stdin_null = first.as_deref().map(yes),
                "forkafterauthentication" if self.full && o.fork_after_authentication.is_none() => {
                    o.fork_after_authentication = first.as_deref().map(yes);
                }
                "exitonforwardfailure" if self.full && o.exit_on_forward_failure.is_none() => {
                    o.exit_on_forward_failure = first.as_deref().map(yes);
                }
                "localcommand" if self.full && o.local_command.is_none() && !raw.is_empty() => o.local_command = Some(raw),
                "permitlocalcommand" if self.full && o.permit_local_command.is_none() => o.permit_local_command = first.as_deref().map(yes),
                "hostkeyalias" if o.host_key_alias.is_none() => o.host_key_alias = first,
                "connecttimeout" if o.connect_timeout.is_none() => o.connect_timeout = first.and_then(|v| v.parse().ok()),
                "connectionattempts" if o.connection_attempts.is_none() => o.connection_attempts = first.and_then(|v| v.parse().ok()),
                "batchmode" if o.batch_mode.is_none() => o.batch_mode = first.as_deref().map(yes),
                "stricthostkeychecking" if o.strict_host_key_checking.is_none() => {
                    o.strict_host_key_checking = first.map(|v| v.to_ascii_lowercase());
                }
                "userknownhostsfile" if self.ours && o.user_known_hosts_file.is_none() => {
                    o.user_known_hosts_file = first;
                    o.more_known_hosts_files = args.iter().skip(1).cloned().collect();
                }
                "globalknownhostsfile" if self.ours && o.global_known_hosts_files.is_none() => o.global_known_hosts_files = Some(args.clone()),
                // qsh's own: distributions turn it on in ssh_config for ssh's file.
                "hashknownhosts" if self.ours && o.hash_known_hosts.is_none() => o.hash_known_hosts = first.as_deref().map(yes),
                "knownhostscommand" if self.ours && o.known_hosts_command.is_none() && !raw.is_empty() => {
                    o.known_hosts_command = (!raw.eq_ignore_ascii_case("none")).then_some(raw);
                }
                "tag" if o.tag.is_none() => o.tag = first,
                "canonicalizehostname" if o.canonicalize_hostname.is_none() => {
                    o.canonicalize_hostname = first.map(|v| v.to_ascii_lowercase());
                }
                "canonicaldomains" if o.canonical_domains.is_none() => o.canonical_domains = Some(args.clone()),
                "canonicalizemaxdots" if o.canonicalize_max_dots.is_none() => o.canonicalize_max_dots = first.and_then(|v| v.parse().ok()),
                "canonicalizefallbacklocal" if o.canonicalize_fallback_local.is_none() => {
                    o.canonicalize_fallback_local = first.as_deref().map(yes);
                }
                "addkeystoagent" if o.add_keys_to_agent.is_none() && !args.is_empty() => o.add_keys_to_agent = Some(args.join(" ").to_ascii_lowercase()),
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
        Parser {
            host,
            base: base.to_path_buf(),
            full,
            ours,
            out: HostConfig::default(),
            original: host.to_string(),
            canonical: false,
            final_pass: false,
            wants_final: false,
        }
    }

    /// `Match exec`: runs the command (with ssh's tokens) through /bin/sh;
    /// it applies if the command succeeds.
    fn exec_succeeds(&self, command: &str) -> bool {
        let host = self.out.hostname.as_deref().unwrap_or(self.host);
        let port = self.out.port.unwrap_or(if self.ours { crate::DEFAULT_PORT } else { 22 });
        let local = crate::platform::local_user().unwrap_or_default();
        let user = self.out.user.clone().unwrap_or_else(|| local.clone());
        let home = dirs::home_dir().unwrap_or_default();
        let mut line = String::new();
        let mut chars = command.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                line.push(c);
                continue;
            }
            match chars.next() {
                Some('%') => line.push('%'),
                Some('C') => line.push_str(&crate::client::control::connection_hash(host, port, &user)),
                Some('d') => line.push_str(&home.to_string_lossy()),
                Some('h') => line.push_str(host),
                Some('i') => line.push_str(&crate::platform::uid().to_string()),
                Some('L') => line.push_str(crate::platform::hostname().split('.').next().unwrap_or("")),
                Some('l') => line.push_str(&crate::platform::hostname()),
                Some('n') => line.push_str(&self.original),
                Some('p') => line.push_str(&port.to_string()),
                Some('r') => line.push_str(&user),
                Some('u') => line.push_str(&local),
                // Unknown tokens make the condition fail, as in ssh.
                _ => return false,
            }
        }
        #[cfg(unix)]
        let status = std::process::Command::new("/bin/sh").arg("-c").arg(&line).stdin(std::process::Stdio::null()).status();
        #[cfg(not(unix))]
        let status = std::process::Command::new("cmd").arg("/C").arg(&line).stdin(std::process::Stdio::null()).status();
        status.is_ok_and(|s| s.success())
    }

    /// Feeds another file, with its own directory for `Include`.
    fn feed_file(&mut self, text: &str, base: &Path) {
        self.base = base.to_path_buf();
        // Blocks do not continue into the next file.
        self.feed(&format!("{text}\nMatch all\n"), 0);
    }

    fn finish(mut self) -> HostConfig {
        self.out.wants_final |= self.wants_final;
        self.out
    }

    fn run(mut self, text: &str) -> HostConfig {
        self.feed(text, 0);
        self.finish()
    }
}

/// `Match localnetwork`: whether an address of this machine's interfaces is
/// in one of the CIDR ranges (`!` excludes); `None` where qsh cannot tell.
fn local_networks_match(patterns: &[String]) -> Option<bool> {
    #[cfg(unix)]
    {
        let addrs: Vec<std::net::IpAddr> = nix::ifaddrs::getifaddrs()
            .ok()?
            .filter_map(|i| {
                let a = i.address?;
                a.as_sockaddr_in().map(|v4| std::net::IpAddr::V4(v4.ip())).or_else(|| a.as_sockaddr_in6().map(|v6| std::net::IpAddr::V6(v6.ip())))
            })
            .collect();
        let list = patterns.join(",");
        Some(addrs.iter().any(|ip| crate::pattern::source_address_list_matches(&list, *ip)))
    }
    #[cfg(not(unix))]
    {
        let _ = patterns;
        None
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
/// `~/.ssh/config` (or the `-F` file). Like ssh, with `CanonicalizeHostname`
/// the configs are read again for the canonical name (`Match canonical`),
/// and once more at the end if a `Match final` asks for it.
pub fn lookup(home: &Path, host: &str, sources: &Sources) -> HostConfig {
    let first = lookup_pass(home, host, host, sources, false, false);
    let mode = first.canonicalize_hostname.clone().unwrap_or_default();
    let direct = first.proxy_jump.is_none() && first.proxy_command.is_none() && !first.needs_proxy;
    let mut canonical = None;
    if mode == "always" || (mode == "yes" && direct) {
        let name = first.hostname.clone().unwrap_or_else(|| host.to_string());
        let domains = first.canonical_domains.clone().unwrap_or_default();
        canonical = canonicalize(&name, &domains, first.canonicalize_max_dots.unwrap_or(1));
        if canonical.is_none() && first.canonicalize_fallback_local == Some(false) && !domains.is_empty() {
            let mut failed = first;
            failed.canonicalize_failed = Some(format!("could not canonicalize {name:?} with CanonicalDomains {}", domains.join(" ")));
            return failed;
        }
    }
    match &canonical {
        Some(name) => {
            let mut again = lookup_pass(home, name, host, sources, true, true);
            if again.hostname.is_none() {
                again.hostname = Some(name.clone());
            }
            again
        }
        None if first.wants_final => lookup_pass(home, host, host, sources, false, true),
        None => first,
    }
}

/// `CanonicalizeHostname`: `name` with the first of `domains` under which it
/// resolves, if it has at most `max_dots` dots and is not an address.
/// A trailing dot means the name is canonical already.
fn canonicalize(name: &str, domains: &[String], max_dots: usize) -> Option<String> {
    use std::net::ToSocketAddrs;
    if let Some(n) = name.strip_suffix('.') {
        return Some(n.to_string());
    }
    if name.parse::<std::net::IpAddr>().is_ok() || name.matches('.').count() > max_dots {
        return None;
    }
    domains.iter().find_map(|d| {
        let fqdn = format!("{name}.{}.", d.trim_end_matches('.'));
        (fqdn.as_str(), 0).to_socket_addrs().ok()?.next()?;
        Some(fqdn.trim_end_matches('.').to_string())
    })
}

/// One reading of the configs (see [`lookup`]); `original` is the host as given.
fn lookup_pass(home: &Path, host: &str, original: &str, sources: &Sources, canonical: bool, final_pass: bool) -> HostConfig {
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
    let mut ours = Parser::new(host, &qsh_dir, true, true);
    (ours.original, ours.canonical, ours.final_pass) = (original.to_string(), canonical, final_pass);
    let ours = ours.run(&ours_text);
    // ssh's own files: the user's, then (without -F) the system-wide one,
    // as ssh reads them; first value wins across both.
    let mut ssh = Parser::new(host, &ssh_dir, sources.full, false);
    (ssh.original, ssh.canonical, ssh.final_pass) = (original.to_string(), canonical, final_pass);
    // A tag set by -P or qsh's config is the tag for ssh's `Match tagged` too.
    ssh.out.tag = ours.tag.clone();
    ssh.feed_file(&read(&ssh_file), &ssh_dir);
    if sources.ssh_config.is_none() {
        let system = Path::new(SYSTEM_SSH_CONFIG);
        ssh.feed_file(&read(system), system.parent().unwrap_or(Path::new("/")));
    }
    let ssh = ssh.finish();
    let needs_proxy = ours.needs_proxy || (ssh.needs_proxy && ours.proxy_jump.is_none() && ours.proxy_command.is_none());
    let mut set_env = ours.set_env.clone();
    for e in &ssh.set_env {
        let name = e.split('=').next();
        if !set_env.iter().any(|o| o.split('=').next() == name) {
            set_env.push(e.clone());
        }
    }
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
        more_known_hosts_files: ours.more_known_hosts_files,
        global_known_hosts_files: ours.global_known_hosts_files,
        hash_known_hosts: ours.hash_known_hosts,
        known_hosts_command: ours.known_hosts_command,
        tag: ours.tag.or(ssh.tag),
        canonicalize_hostname: ours.canonicalize_hostname.or(ssh.canonicalize_hostname),
        canonical_domains: ours.canonical_domains.or(ssh.canonical_domains),
        canonicalize_max_dots: ours.canonicalize_max_dots.or(ssh.canonicalize_max_dots),
        canonicalize_fallback_local: ours.canonicalize_fallback_local.or(ssh.canonicalize_fallback_local),
        add_keys_to_agent: ours.add_keys_to_agent.or(ssh.add_keys_to_agent),
        wants_final: ours.wants_final || ssh.wants_final,
        canonicalize_failed: None,
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
        proxy_command: ours.proxy_command,
        send_env: ours.send_env.into_iter().chain(ssh.send_env).collect(),
        set_env,
        remote_command: ours.remote_command.or(ssh.remote_command),
        session_type: ours.session_type.or(ssh.session_type),
        stdin_null: ours.stdin_null.or(ssh.stdin_null),
        fork_after_authentication: ours.fork_after_authentication.or(ssh.fork_after_authentication),
        exit_on_forward_failure: ours.exit_on_forward_failure.or(ssh.exit_on_forward_failure),
        local_command: ours.local_command.or(ssh.local_command),
        permit_local_command: ours.permit_local_command.or(ssh.permit_local_command),
        host_key_alias: ours.host_key_alias.or(ssh.host_key_alias),
        connect_timeout: ours.connect_timeout.or(ssh.connect_timeout),
        connection_attempts: ours.connection_attempts.or(ssh.connection_attempts),
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
    fn commands_env_and_session_keywords() {
        let text = "Host a\n ProxyCommand sh -c \"nc %h %p\"  # comment stays\n ProxyJump later\n SendEnv GIT_* -LC_*\n \
                    SetEnv A=1 B=\"two words\"\n SetEnv A=ignored\n RemoteCommand tmux new -A -s main\n SessionType none\n \
                    StdinNull yes\n ExitOnForwardFailure yes\n LocalCommand echo %n\n PermitLocalCommand yes\n \
                    HostKeyAlias shared\n ConnectTimeout 7\n ConnectionAttempts 3\n";
        let c = parse(text, "a", Path::new("/x"), true);
        assert_eq!(c.proxy_command.as_deref(), Some("sh -c \"nc %h %p\"  # comment stays"));
        assert_eq!(c.proxy_jump, None, "ProxyCommand came first");
        assert_eq!(c.send_env, vec!["GIT_*", "-LC_*"]);
        assert_eq!(c.set_env, vec!["A=1", "B=two words"]);
        assert_eq!(c.remote_command.as_deref(), Some("tmux new -A -s main"));
        assert_eq!(c.session_type.as_deref(), Some("none"));
        assert_eq!((c.stdin_null, c.exit_on_forward_failure, c.permit_local_command), (Some(true), Some(true), Some(true)));
        assert_eq!(c.local_command.as_deref(), Some("echo %n"));
        assert_eq!(c.host_key_alias.as_deref(), Some("shared"));
        assert_eq!((c.connect_timeout, c.connection_attempts), (Some(7), Some(3)));
        // From ssh's config outside --full: the session settings are ssh's.
        let c = parse(text, "a", Path::new("/x"), false);
        assert!(c.proxy_command.is_none() && c.needs_proxy && c.remote_command.is_none() && c.send_env.is_empty());
        assert_eq!(c.host_key_alias.as_deref(), Some("shared"));
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

    /// ssh's config, read in `--full` mode.
    fn cfg(text: &str, host: &str) -> HostConfig {
        Parser::new(host, Path::new("/nonexistent"), true, false).run(text)
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
        let c = cfg("Match version OpenSSH_9*\n    ProxyJump bastion\n    User other\n", "h");
        assert!(c.needs_proxy);
        assert_eq!(c.user, None);
    }

    #[cfg(unix)]
    #[test]
    fn exec_localnetwork_and_tagged() {
        let c = cfg("Match exec \"test %h = h && test %n = h\"\n    User yes-exec\nMatch exec false\n    User no-exec\n", "h");
        assert_eq!(c.user.as_deref(), Some("yes-exec"));
        let c = cfg("Match exec false\n    User no-exec\n", "h");
        assert_eq!(c.user, None);
        let c = cfg("Match localnetwork 127.0.0.0/8\n    User lo\n", "h");
        assert_eq!(c.user.as_deref(), Some("lo"));
        let c = cfg("Match localnetwork 192.0.2.0/24,!127.0.0.0/8\n    User doc\n", "h");
        assert_eq!(c.user, None);
        let c = cfg("Tag work\nMatch tagged work\n    User tagged\n", "h");
        assert_eq!(c.user.as_deref(), Some("tagged"));
        let c = cfg("Match tagged work\n    User tagged\n", "h");
        assert_eq!(c.user, None);
    }

    #[test]
    fn canonical_and_final_passes() {
        assert_eq!(canonicalize("host.example.", &[], 1), Some("host.example".into()));
        assert_eq!(canonicalize("192.0.2.1", &["example.com".into()], 1), None);
        assert_eq!(canonicalize("a.b.c", &["example.com".into()], 1), None, "too many dots");
        assert_eq!(canonicalize("localhost", &["invalid".into()], 1), None, ".invalid never resolves");
        let home = tempfile::tempdir().unwrap();
        let dir = crate::keys::qsh_dir(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        let text = "Host h\n  HostName real.\nMatch canonical host real\n  User canon\nMatch final\n  Port 2200\n";
        std::fs::write(dir.join("config"), text).unwrap();
        let c = lookup(home.path(), "h", &Sources::default());
        assert_eq!(c.user, None, "no canonicalization asked for");
        std::fs::write(dir.join("config"), format!("CanonicalizeHostname yes\n{text}")).unwrap();
        let c = lookup(home.path(), "h", &Sources::default());
        assert_eq!(c.user.as_deref(), Some("canon"));
        assert_eq!(c.hostname.as_deref(), Some("real"));
        let c = lookup(home.path(), "other", &Sources::default());
        assert_eq!(c.port, Some(2200), "Match final applies on the last pass");
    }
}
