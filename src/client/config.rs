//! Host aliases from `~/.config/qsh/config` and `~/.ssh/config` (ssh_config syntax).
//!
//! Precedence: `-o` options, then `~/.config/qsh/config`, then
//! `~/.ssh/config` (or the `-F` file), then what `qsh ui` saved; within each
//! the first value found wins (IdentityFile and the forwards accumulate).
//! Supported keywords: `Host` patterns (`*`, `?`, `!`), `Match`, `Include`,
//! `HostName`, `User`, `Port`, `IdentityFile`, `LocalForward`,
//! `RemoteForward`, `DynamicForward`, `ProxyJump`, `RequestTTY`,
//! `BatchMode`, `StrictHostKeyChecking`, `UserKnownHostsFile`,
//! `ClearAllForwardings`, `EscapeChar`, `AddressFamily`, `LogLevel`,
//! `ForwardAgent`, `ObscureKeystrokeTiming`, `ControlMaster`, `ControlPath`,
//! `ControlPersist`, `ProxyCommand`, `SendEnv`, `SetEnv`, `RemoteCommand`,
//! `SessionType`, `StdinNull`, `ForkAfterAuthentication`,
//! `ExitOnForwardFailure`, `LocalCommand`, `PermitLocalCommand`,
//! `HostKeyAlias`, `ConnectTimeout`, `ConnectionAttempts`,
//! `RefuseConnection`, `IgnoreUnknown`, and qsh's own `PersistSession` and
//! `PredictiveEcho`. `Match` blocks are evaluated for `all`, `host`,
//! `originalhost`, `user`, `localuser`, `exec`, `localnetwork`, `tagged`,
//! `canonical` and `final` (with `CanonicalizeHostname`, the configs are read
//! again for the canonical name); a block whose conditions qsh cannot check
//! (`version`...) is not used, except that a proxy or a refusal
//! (`RevokedHostKeys`, `RefuseConnection`, `PermitRemoteOpen`) in it counts.
//! Like ssh, `/etc/ssh/ssh_config` is read after `~/.ssh/config` (not with
//! `-F`), and `#` starts a comment anywhere on a line. In qsh's own config,
//! a keyword nobody knows is an error and one qsh does not carry out a warning.
//!
//! From `~/.ssh/config`, settings that describe the ssh session itself
//! (`Port`, `RequestTTY`...) are only used in `--full` mode. Its
//! `ProxyJump`/`ProxyCommand` make `--full` hand the host to ssh, and its
//! `UserKnownHostsFile` is never used (that file holds ssh host keys, not qshd's).

use std::path::{Path, PathBuf};

const MAX_INCLUDE_DEPTH: usize = 16;
/// OpenSSH's system-wide client config (not read with `-F`, as by ssh).
const SYSTEM_SSH_CONFIG: &str = "/etc/ssh/ssh_config";

/// What `~/.config/qsh/config` starts as: every setting commented out at
/// its default.
const CONFIG_TEMPLATE: &str = include_str!("../../contrib/qsh_config");

/// Creates `~/.config/qsh/config` from the template if there is none, so
/// there is a file to look at and change (it changes nothing). Best effort:
/// qsh works without it.
pub fn create_template(home: &Path) {
    use std::io::Write;
    let dir = crate::keys::qsh_dir(home);
    let file = dir.join("config");
    // Not into someone else's home (`sudo -E`): the file would be root's.
    #[cfg(unix)]
    if std::fs::metadata(home).map_or(true, |m| std::os::unix::fs::MetadataExt::uid(&m) != nix::unistd::geteuid().as_raw()) {
        return;
    }
    if file.exists() || crate::keys::create_private_dir(&dir).is_err() {
        return;
    }
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
    if let Ok(mut f) = open.open(&file) {
        let _ = f.write_all(CONFIG_TEMPLATE.as_bytes());
    }
}

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
    /// A keyword qsh cannot carry out and would be less strict without
    /// (`RevokedHostKeys`): such a host is ssh's.
    pub refused: Option<String>,
    /// `RefuseConnection`: ssh's message, with the file and line. Also a
    /// refusal in qsh's own config, which `--full` must not hand to ssh
    /// (ssh does not read that file).
    pub refuse_connection: Option<String>,
    /// A keyword in qsh's own config that neither qsh nor ssh knows.
    pub bad_option: Option<String>,
    /// Keywords in qsh's own config that qsh does not carry out (`FILE line N: Keyword`).
    pub unapplied: Vec<String>,
    /// `PermitRemoteOpen` other than `any`: qsh cannot check it, so it
    /// refuses dynamic remote forwards (`-R port`).
    pub permit_remote_open: bool,
    /// `StrictHostKeyChecking` (`yes`/`true`, `ask`, `accept-new`, `no`/`false`).
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
    /// `ForwardX11`, `ForwardX11Trusted`, `ForwardX11Timeout`, `XAuthLocation`.
    pub forward_x11: Option<bool>,
    pub forward_x11_trusted: Option<bool>,
    pub forward_x11_timeout: Option<String>,
    pub xauth_location: Option<String>,
    /// `Tunnel` (`yes`, `point-to-point`, `ethernet`, `no`) and `TunnelDevice`.
    pub tunnel: Option<String>,
    pub tunnel_device: Option<String>,
    /// `EnableEscapeCommandline` (qsh: on unless turned off).
    pub escape_commandline: Option<bool>,
    /// `PasswordAuthentication` and `NumberOfPasswordPrompts`.
    pub password_authentication: Option<bool>,
    pub password_prompts: Option<u32>,
    /// A `Match final` block exists (read the config once more at the end).
    pub wants_final: bool,
    /// `CanonicalizeFallbackLocal no` and the name could not be canonicalized.
    pub canonicalize_failed: Option<String>,
    /// A config file (or one it includes) that others could have written
    /// (ssh refuses to go on then too).
    pub bad_file: Option<String>,
    pub clear_all_forwardings: Option<bool>,
    pub escape_char: Option<String>,
    /// `AddressFamily` (`any`, `inet`, `inet6`).
    pub address_family: Option<String>,
    pub log_level: Option<String>,
    pub forward_agent: Option<bool>,
    /// `ForwardAgent` given a socket (a path or `$VARIABLE`) instead of yes.
    pub forward_agent_socket: Option<String>,
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
    pub restore_session: Option<bool>,
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
    /// `Compression`: output and `qsh cp` (`auto` means yes).
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
    /// Keywords set to `none` (`proxy` for ProxyJump/ProxyCommand): later
    /// values of them do not count, as in ssh.
    pub none_set: Vec<String>,
}

/// Adds `v` to `list` unless it is there already.
fn push_new(list: &mut Vec<String>, v: Option<String>) {
    if let Some(v) = v.filter(|v| !list.contains(v)) {
        list.push(v);
    }
}

fn yes(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "on")
}

use crate::pattern::{host_matches, wildcard};
use super::forward::Forward;

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
    /// The file being read, for messages (`None` for `-o` lines).
    file: Option<String>,
    /// Report keywords qsh does not carry out or know (qsh's own config:
    /// ssh's files are ssh's to judge).
    check: bool,
    /// `IgnoreUnknown` patterns (lowercase).
    ignore_unknown: Option<Vec<String>>,
    /// Reading a file included from a block that only may apply: nothing in
    /// it applies for sure, but its proxies and refusals still count.
    maybe_only: bool,
}

/// A proxy setting that is not `none`.
fn is_proxy(keyword: &str, first: Option<&str>) -> bool {
    matches!(keyword, "proxyjump" | "proxycommand") && first.is_some_and(|v| !v.eq_ignore_ascii_case("none"))
}

/// `FILE line N: ` for messages, as ssh writes it.
fn at(file: &Option<String>, n: usize) -> String {
    file.as_ref().map(|f| format!("{f} line {n}: ")).unwrap_or_default()
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
                    let name = self.out.hostname.as_deref().map_or(self.host.to_string(), |h| h.replace("%h", self.host));
                    if host_matches(&patterns(words.next()), &name) { Applies::Yes } else { Applies::No }
                }
                "originalhost" => {
                    if host_matches(&patterns(words.next()), &self.original) { Applies::Yes } else { Applies::No }
                }
                "localuser" => {
                    let me = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default();
                    if host_matches(&patterns(words.next()), &me) { Applies::Yes } else { Applies::No }
                }
                "user" => {
                    // Like ssh: the user so far (command line, earlier `User`), else the local one.
                    let user = self.out.user.clone().unwrap_or_else(|| crate::platform::local_user().unwrap_or_default());
                    if crate::pattern::name_matches(&patterns(words.next()), &user) { Applies::Yes } else { Applies::No }
                }
                "canonical" => if self.canonical { Applies::Yes } else { Applies::No },
                "final" => if self.final_pass { Applies::Yes } else { Applies::No },
                // Not run once the line cannot apply anyway (as in ssh).
                "exec" => match words.next() {
                    Some(_) if result == Applies::No => Applies::No,
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
        let maybe_only = self.maybe_only;
        let cap = |a: Applies| if maybe_only && a == Applies::Yes { Applies::Maybe } else { a };
        let mut active = cap(Applies::Yes);
        for (n, line) in text.lines().enumerate() {
            let Some((keyword, args, raw)) = split_line_raw(line) else { continue };
            let first = args.first().cloned();
            let n = n + 1;
            if keyword == "match" && args.iter().any(|a| a.trim_start_matches('!').eq_ignore_ascii_case("final")) {
                self.wants_final = true;
            }
            // `none` decides these, like any first value: later ones are ignored.
            let slot = match keyword.as_str() {
                "proxyjump" | "proxycommand" => Some("proxy"),
                "remotecommand" | "knownhostscommand" => Some(keyword.as_str()),
                _ => None,
            };
            if let Some(slot) = slot {
                if self.out.none_set.iter().any(|n| n == slot) {
                    continue;
                }
                if active == Applies::Yes && first.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("none")) {
                    self.out.none_set.push(slot.to_string());
                    continue;
                }
            }
            if is_proxy(&keyword, first.as_deref()) && !self.ours {
                // A proxy that may apply: do not connect around it.
                if active == Applies::Maybe {
                    self.out.needs_proxy = true;
                }
            }
            // Likewise a refusal that may apply: fail closed.
            if active == Applies::Maybe {
                let where_ = at(&self.file, n);
                let o = &mut self.out;
                match keyword.as_str() {
                    "revokedhostkeys" if self.ours && first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("none")) => {
                        o.refuse_connection.get_or_insert_with(|| format!("{where_}RevokedHostKeys is not supported by qsh"));
                    }
                    "revokedhostkeys" if first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("none")) => {
                        o.refused.get_or_insert_with(|| "RevokedHostKeys".into());
                    }
                    "refuseconnection" if self.ours && !args.is_empty() => {
                        o.refuse_connection.get_or_insert_with(|| format!("{where_}RefuseConnection (in a Match block qsh cannot evaluate): {}", args.join(" ")));
                    }
                    // Not a sure refusal: --full lets ssh evaluate the block in its own files.
                    "refuseconnection" if !args.is_empty() => {
                        o.refused.get_or_insert_with(|| "RefuseConnection (in a Match block qsh cannot evaluate)".into());
                    }
                    "permitremoteopen" if first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("any")) => o.permit_remote_open = true,
                    _ => {}
                }
            }
            if self.check {
                // As ssh: a keyword it does not know is an error anywhere in the file.
                let name = &line.trim_start()[..keyword.len()];
                match super::cli::keyword_kind(&keyword) {
                    super::cli::Keyword::Unknown if !self.ignore_unknown.as_ref().is_some_and(|p| crate::pattern::name_matches(p, &keyword)) => {
                        self.out.bad_option.get_or_insert_with(|| format!("{}Bad configuration option: {name}", at(&self.file, n)));
                    }
                    super::cli::Keyword::Unapplied if active == Applies::Yes => {
                        push_new(&mut self.out.unapplied, Some(format!("{}{name}", at(&self.file, n))));
                    }
                    _ => {}
                }
            }
            match keyword.as_str() {
                "host" => {
                    active = cap(if host_matches(&args, self.host) { Applies::Yes } else { Applies::No });
                    continue;
                }
                "match" => {
                    active = cap(self.match_applies(&args));
                    continue;
                }
                _ => {}
            }
            let o = &mut self.out;
            match keyword.as_str() {
                _ if active == Applies::No => {}
                "include" if depth < MAX_INCLUDE_DEPTH => {
                    let outer_maybe = self.maybe_only;
                    self.maybe_only |= active == Applies::Maybe;
                    for pattern in &args {
                        for file in self.expand_include(pattern) {
                            // Every included file is checked, those the system config includes too (as by ssh).
                            match read_config(&file) {
                                Ok(t) => {
                                    let outer = self.file.replace(file.display().to_string());
                                    self.feed(&t, depth + 1);
                                    self.file = outer;
                                }
                                Err(why) => {
                                    self.out.bad_file.get_or_insert(why);
                                }
                            }
                        }
                    }
                    self.maybe_only = outer_maybe;
                }
                _ if active != Applies::Yes => {}
                "hostname" if o.hostname.is_none() => o.hostname = first,
                "user" if o.user.is_none() => o.user = first,
                "port" if self.full && o.port.is_none() => o.port = first.and_then(|p| p.parse().ok()),
                // Accumulated, without repeats (a later pass reads the same lines again).
                "identityfile" => push_new(&mut o.identity_files, first),
                // `LocalForward [bind:]port host:hostport` → `-L [bind:]port:host:hostport`.
                // Forwards mean the same whichever server answers: also without --full.
                "localforward" if args.len() == 2 => push_new(&mut o.local_forwards, Some(format!("{}:{}", args[0], args[1]))),
                "remoteforward" if args.len() == 2 => push_new(&mut o.remote_forwards, Some(format!("{}:{}", args[0], args[1]))),
                // `RemoteForward [bind:]port` alone: a SOCKS proxy on the server.
                "remoteforward" if args.len() == 1 => push_new(&mut o.remote_forwards, first),
                "dynamicforward" => push_new(&mut o.dynamic_forwards, first),
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
                "tunnel" if self.full && o.tunnel.is_none() => o.tunnel = first.map(|v| v.to_ascii_lowercase()),
                "tunneldevice" if self.full && o.tunnel_device.is_none() => o.tunnel_device = first,
                "enableescapecommandline" if o.escape_commandline.is_none() => o.escape_commandline = first.as_deref().map(yes),
                "passwordauthentication" if o.password_authentication.is_none() => o.password_authentication = first.as_deref().map(yes),
                "numberofpasswordprompts" if o.password_prompts.is_none() => o.password_prompts = first.and_then(|v| v.parse().ok()),
                "forwardx11" if o.forward_x11.is_none() => o.forward_x11 = first.as_deref().map(yes),
                "forwardx11trusted" if o.forward_x11_trusted.is_none() => o.forward_x11_trusted = first.as_deref().map(yes),
                "forwardx11timeout" if o.forward_x11_timeout.is_none() => o.forward_x11_timeout = first,
                "xauthlocation" if o.xauth_location.is_none() => o.xauth_location = first,
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
                "forwardagent" if o.forward_agent.is_none() => match first.as_deref().map(str::to_ascii_lowercase).as_deref() {
                    Some("yes" | "true" | "on" | "no" | "false" | "off") | None => o.forward_agent = first.as_deref().map(yes),
                    // A path or $VARIABLE: forward that agent.
                    Some(_) => (o.forward_agent, o.forward_agent_socket) = (Some(true), first),
                },
                "identitiesonly" if o.identities_only.is_none() => o.identities_only = first.as_deref().map(yes),
                "identityagent" if o.identity_agent.is_none() => o.identity_agent = first,
                "certificatefile" => push_new(&mut o.certificate_files, first),
                "persistsession" if o.persist_session.is_none() => o.persist_session = first.as_deref().map(yes),
                "restoresession" if o.restore_session.is_none() => o.restore_session = first.as_deref().map(yes),
                "serveraliveinterval" if o.server_alive_interval.is_none() => o.server_alive_interval = first.and_then(|v| v.parse().ok()),
                "serveralivecountmax" if o.server_alive_count_max.is_none() => o.server_alive_count_max = first.and_then(|v| v.parse().ok()),
                "controlmaster" if o.control_master.is_none() => o.control_master = first,
                "controlpath" if self.ours && o.control_path.is_none() => o.control_path = first,
                "controlpersist" if o.control_persist.is_none() => o.control_persist = first,
                "predictiveecho" if o.predictive_echo.is_none() => o.predictive_echo = first,
                "compression" if o.compression.is_none() => o.compression = first.as_deref().map(|v| yes(v) || v.eq_ignore_ascii_case("auto")),
                "bindaddress" if o.bind_address.is_none() => o.bind_address = first,
                "bindinterface" if o.bind_interface.is_none() => o.bind_interface = first,
                "revokedhostkeys" if self.ours && o.refuse_connection.is_none() && first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("none")) => {
                    o.refuse_connection = Some(format!("{}RevokedHostKeys is not supported by qsh", at(&self.file, n)));
                }
                "revokedhostkeys" if o.refused.is_none() && first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("none")) => {
                    o.refused = Some("RevokedHostKeys".into());
                }
                "permitremoteopen" if first.as_deref().is_some_and(|v| !v.eq_ignore_ascii_case("any")) => o.permit_remote_open = true,
                // Its argument is a message, not yes/no: any one refuses (as in ssh).
                "refuseconnection" if o.refuse_connection.is_none() && !args.is_empty() => {
                    o.refuse_connection = Some(format!("{}RefuseConnection: {}", at(&self.file, n), args.join(" ")));
                }
                "ignoreunknown" if self.ignore_unknown.is_none() => {
                    self.ignore_unknown = Some(args.iter().flat_map(|a| a.split(',')).map(str::to_ascii_lowercase).collect());
                }
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
            file: None,
            check: false,
            ignore_unknown: None,
            maybe_only: false,
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
    fn feed_file(&mut self, text: &str, base: &Path, file: Option<&Path>) {
        self.base = base.to_path_buf();
        self.file = file.map(|f| f.display().to_string());
        // Blocks do not continue into the next file.
        self.feed(&format!("{text}\nMatch all\n"), 0);
    }

    /// The system-wide ssh config. Stricter than ssh, which does not check
    /// this file itself: one others could have written is refused like its
    /// includes, rather than run.
    fn feed_system(&mut self, system: &Path) {
        match read_config(system) {
            Ok(t) => self.feed_file(&t, system.parent().unwrap_or(Path::new("/")), Some(system)),
            Err(why) => {
                self.out.bad_file.get_or_insert(why);
            }
        }
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
        // Interfaces that are up, as ssh counts them.
        let addrs: Vec<std::net::IpAddr> = nix::ifaddrs::getifaddrs()
            .ok()?
            .filter(|i| i.flags.contains(nix::net::if_::InterfaceFlags::IFF_UP))
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

/// Reads a config file; `Err` says why it cannot be trusted: owned by
/// someone but the user or root, or writable by others (as ssh checks them).
/// A missing or unreadable file reads as empty.
fn read_config(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else { return Ok(String::new()) };
    // The open file is checked, not the name: it could be swapped in between.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let me = crate::platform::uid();
        if f.metadata().is_ok_and(|m| (m.uid() != 0 && m.uid() != me) || m.mode() & 0o022 != 0) {
            return Err(format!("Bad owner or permissions on {}", path.display()));
        }
    }
    let mut text = String::new();
    Ok(f.read_to_string(&mut text).map(|_| text).unwrap_or_default())
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
    /// The user from the command line (`-l`, `user@host`): ahead of any
    /// `User`, and what `Match user` and `%r` see.
    pub user: Option<String>,
}

/// Settings for `host`: `-o` overrides, then `~/.config/qsh/config`, then
/// `~/.ssh/config` (or the `-F` file). Like ssh, with `CanonicalizeHostname`
/// the configs are read again for the canonical name (`Match canonical`),
/// and once more at the end if a `Match final` asks for it.
pub fn lookup(home: &Path, host: &str, sources: &Sources) -> HostConfig {
    let seed = HostConfig { user: sources.user.clone(), ..Default::default() };
    let first_pass = lookup_pass(home, host, host, sources, (false, false), [seed.clone(), seed.clone(), seed]);
    let first = merge(first_pass.clone());
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
    // Later passes add to what the first one found (the first value still
    // wins, as in ssh), so settings of the original name's blocks stay.
    let mut parts = first_pass;
    match &canonical {
        Some(name) => {
            for part in &mut parts {
                part.hostname = Some(name.clone());
            }
            merge(lookup_pass(home, name, host, sources, (true, true), parts))
        }
        None if first.wants_final => merge(lookup_pass(home, host, host, sources, (false, true), parts)),
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

/// One reading of the configs (see [`lookup`]) on top of what `seeds` (qsh's
/// part, ssh's part, `qsh ui`'s part) have: those parts. `original` is the
/// host as given; `pass` is (canonical, final).
fn lookup_pass(
    home: &Path,
    host: &str,
    original: &str,
    sources: &Sources,
    (canonical, final_pass): (bool, bool),
    [ours_seed, ssh_seed, ui_seed]: [HostConfig; 3],
) -> [HostConfig; 3] {
    let qsh_dir = crate::keys::qsh_dir(home);
    let ssh_file = sources.ssh_config.clone().unwrap_or_else(|| home.join(".ssh").join("config"));
    // A file others could change is not read at all (as by ssh): its
    // `Match exec` would run before the connection is refused.
    let [qsh_config, ui_hosts, ssh_config] = [qsh_dir.join("config"), qsh_dir.join(UI_HOSTS), ssh_file.clone()].map(|f| read_config(&f));
    let bad_file = [&qsh_config, &ui_hosts, &ssh_config].into_iter().find_map(|r| r.clone().err());
    let read = |r: Result<String, String>| r.unwrap_or_default();
    // Relative Includes in the user's file are in ~/.ssh, even with -F (as in ssh).
    let ssh_dir = home.join(".ssh");
    let parser = |full, ours, seed| {
        let mut p = Parser::new(host, &qsh_dir, full, ours);
        (p.original, p.canonical, p.final_pass, p.out) = (original.to_string(), canonical, final_pass, seed);
        p
    };
    // -o lines come first: before any `Host` they apply to every host and win.
    let mut ours = parser(true, true, ours_seed);
    ours.feed_file(&sources.overrides.join("\n"), &qsh_dir, None);
    ours.check = true;
    let qsh_file = qsh_dir.join("config");
    ours.feed_file(&read(qsh_config), &qsh_dir, Some(&qsh_file));
    let mut ours = ours.finish();
    if bad_file.is_some() {
        ours.bad_file = bad_file;
    }
    // What `qsh ui` saved comes last of all (see `merge`).
    let ui = parser(true, true, ui_seed).run(&read(ui_hosts));
    // ssh's own files: the user's, then (without -F) the system-wide one,
    // as ssh reads them; first value wins across both.
    let mut ssh = parser(sources.full, false, ssh_seed);
    // A tag set by -P or qsh's config is the tag for ssh's `Match tagged` too.
    if ssh.out.tag.is_none() {
        ssh.out.tag = ours.tag.clone();
    }
    ssh.feed_file(&read(ssh_config), &ssh_dir, Some(&ssh_file));
    if sources.ssh_config.is_none() {
        ssh.feed_system(Path::new(SYSTEM_SSH_CONFIG));
    }
    [ours, ssh.finish(), ui]
}

/// `SetEnv`s of `high`, then those of `low` for other variables.
fn merge_set_env(high: &[String], low: &[String]) -> Vec<String> {
    let mut set_env = high.to_vec();
    for e in low {
        let name = e.split('=').next();
        if !set_env.iter().any(|o| o.split('=').next() == name) {
            set_env.push(e.clone());
        }
    }
    set_env
}

/// One host's settings from qsh's part, ssh's part and `qsh ui`'s part of
/// the configs, in this order of precedence: what `qsh ui` saved never
/// overrides what the user wrote.
fn merge([ours, ssh, ui]: [HostConfig; 3]) -> HostConfig {
    under(merge_ssh(ours, ssh), ui)
}

/// `-o` options for ssh from qsh's part `c` (see `HostConfig::for_ssh`):
/// what ssh would not get from `over`, the part that ssh reads or that
/// takes precedence. `wins`: `c` takes precedence over `over`.
fn ssh_options(c: &HostConfig, over: &HostConfig, wins: bool) -> Vec<String> {
    let mut for_ssh = Vec::new();
    if let (Some(h), None) = (&c.hostname, &over.hostname) {
        for_ssh.push(format!("HostName={h}"));
    }
    if let (Some(u), None) = (&c.user, &over.user) {
        for_ssh.push(format!("User={u}"));
    }
    for f in &c.identity_files {
        for_ssh.push(format!("IdentityFile={f}"));
    }
    // Forwards and the like from qsh's own files (`qsh ui` writes them) are
    // wanted when ssh takes over too.
    for (key, specs) in [("LocalForward", &c.local_forwards), ("RemoteForward", &c.remote_forwards)] {
        for spec in specs {
            let parsed = if key == "LocalForward" { Forward::parse(spec) } else { Forward::parse_remote(spec) };
            match parsed.map(|f| f.config_args()) {
                Ok((listen, Some(dest))) => for_ssh.push(format!("{key}={listen} {dest}")),
                Ok((listen, None)) => for_ssh.push(format!("{key}={listen}")),
                Err(_) => {}
            }
        }
    }
    for d in &c.dynamic_forwards {
        for_ssh.push(format!("DynamicForward={d}"));
    }
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    match (c.forward_agent, &c.forward_agent_socket) {
        _ if !wins && over.forward_agent.is_some() => {}
        (Some(true), Some(socket)) => for_ssh.push(format!("ForwardAgent={socket}")),
        (Some(on), _) => for_ssh.push(format!("ForwardAgent={}", yes_no(on))),
        (None, _) => {}
    }
    for (key, value, theirs) in [
        ("ForwardX11", c.forward_x11, over.forward_x11),
        ("ForwardX11Trusted", c.forward_x11_trusted, over.forward_x11_trusted),
        ("Compression", c.compression, over.compression),
    ] {
        if let Some(v) = value.filter(|_| wins || theirs.is_none()) {
            for_ssh.push(format!("{key}={}", yes_no(v)));
        }
    }
    for_ssh
}

/// qsh's part and ssh's part (see [`merge`]).
fn merge_ssh(ours: HostConfig, ssh: HostConfig) -> HostConfig {
    // A proxy (or `none`) in qsh's config or -o takes care of ssh's.
    let ours_decides = ours.proxy_jump.is_some() || ours.proxy_command.is_some() || ours.none_set.iter().any(|n| n == "proxy");
    let needs_proxy = ours.needs_proxy || (ssh.needs_proxy && !ours_decides);
    let set_env = merge_set_env(&ours.set_env, &ssh.set_env);
    let for_ssh = ssh_options(&ours, &ssh, true);
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
        refused: ours.refused.or(ssh.refused),
        refuse_connection: ours.refuse_connection.or(ssh.refuse_connection),
        bad_option: ours.bad_option.or(ssh.bad_option),
        unapplied: ours.unapplied.into_iter().chain(ssh.unapplied).collect(),
        permit_remote_open: ours.permit_remote_open || ssh.permit_remote_open,
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
        forward_x11: ours.forward_x11.or(ssh.forward_x11),
        forward_x11_trusted: ours.forward_x11_trusted.or(ssh.forward_x11_trusted),
        forward_x11_timeout: ours.forward_x11_timeout.or(ssh.forward_x11_timeout),
        xauth_location: ours.xauth_location.or(ssh.xauth_location),
        tunnel: ours.tunnel.or(ssh.tunnel),
        tunnel_device: ours.tunnel_device.or(ssh.tunnel_device),
        escape_commandline: ours.escape_commandline.or(ssh.escape_commandline),
        password_authentication: ours.password_authentication.or(ssh.password_authentication),
        password_prompts: ours.password_prompts.or(ssh.password_prompts),
        wants_final: ours.wants_final || ssh.wants_final,
        canonicalize_failed: None,
        bad_file: ours.bad_file.or(ssh.bad_file),
        clear_all_forwardings: ours.clear_all_forwardings.or(ssh.clear_all_forwardings),
        escape_char: ours.escape_char.or(ssh.escape_char),
        address_family: ours.address_family.or(ssh.address_family),
        log_level: ours.log_level.or(ssh.log_level),
        forward_agent_socket: if ours.forward_agent.is_some() { ours.forward_agent_socket } else { ssh.forward_agent_socket },
        forward_agent: ours.forward_agent.or(ssh.forward_agent),
        // A privacy preference, so ssh's setting applies to qsh sessions as well.
        obscure_keystrokes: ours.obscure_keystrokes.or(ssh.obscure_keystrokes),
        identities_only: ours.identities_only.or(ssh.identities_only),
        identity_agent: ours.identity_agent.or(ssh.identity_agent),
        certificate_files: ours.certificate_files.into_iter().chain(ssh.certificate_files).collect(),
        persist_session: ours.persist_session.or(ssh.persist_session),
        restore_session: ours.restore_session,
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
        none_set: ours.none_set.into_iter().chain(ssh.none_set).collect(),
    }
}

/// `low` (qsh ui's part) under `high`: only what `high` leaves unset, its
/// lists after `high`'s.
fn under(mut high: HostConfig, low: HostConfig) -> HostConfig {
    let for_ssh = ssh_options(&low, &high, false);
    let proxy_decided = high.needs_proxy || high.proxy_jump.is_some() || high.proxy_command.is_some() || high.none_set.iter().any(|n| n == "proxy");
    // Every field by name, so a new one cannot be forgotten here.
    let HostConfig {
        hostname, user, port, ssh_port, identity_files, local_forwards, remote_forwards, dynamic_forwards, proxy_jump,
        request_tty, needs_proxy, batch_mode, refused, refuse_connection, bad_option, unapplied, permit_remote_open,
        strict_host_key_checking, user_known_hosts_file, more_known_hosts_files, global_known_hosts_files, hash_known_hosts,
        known_hosts_command, tag, canonicalize_hostname, canonical_domains, canonicalize_max_dots, canonicalize_fallback_local,
        add_keys_to_agent, forward_x11, forward_x11_trusted, forward_x11_timeout, xauth_location, tunnel, tunnel_device,
        escape_commandline, password_authentication, password_prompts, wants_final, canonicalize_failed: _, bad_file,
        clear_all_forwardings, escape_char, address_family, log_level, forward_agent, forward_agent_socket, obscure_keystrokes,
        identities_only, identity_agent, certificate_files, persist_session, restore_session, server_alive_interval,
        server_alive_count_max, control_master, control_path, control_persist, predictive_echo, compression, bind_address,
        bind_interface, proxy_command, send_env, set_env, remote_command, session_type, stdin_null, fork_after_authentication,
        exit_on_forward_failure, local_command, permit_local_command, host_key_alias, connect_timeout, connection_attempts,
        for_ssh: _, none_set,
    } = low;
    macro_rules! fill {
        ($($f:ident)*) => { $(high.$f = high.$f.take().or($f);)* };
    }
    macro_rules! append {
        ($($f:ident)*) => { $(high.$f.extend($f);)* };
    }
    fill!(hostname user port ssh_port request_tty batch_mode refused refuse_connection bad_option strict_host_key_checking
        global_known_hosts_files hash_known_hosts known_hosts_command tag canonicalize_hostname canonical_domains
        canonicalize_max_dots canonicalize_fallback_local add_keys_to_agent forward_x11 forward_x11_trusted forward_x11_timeout
        xauth_location tunnel tunnel_device escape_commandline password_authentication password_prompts bad_file
        clear_all_forwardings escape_char address_family log_level obscure_keystrokes identities_only identity_agent
        persist_session restore_session server_alive_interval server_alive_count_max control_master control_path
        control_persist predictive_echo compression bind_address bind_interface remote_command session_type stdin_null
        fork_after_authentication exit_on_forward_failure local_command permit_local_command host_key_alias connect_timeout
        connection_attempts);
    append!(identity_files local_forwards remote_forwards dynamic_forwards unapplied certificate_files send_env none_set);
    if high.user_known_hosts_file.is_none() {
        (high.user_known_hosts_file, high.more_known_hosts_files) = (user_known_hosts_file, more_known_hosts_files);
    }
    if high.forward_agent.is_none() {
        (high.forward_agent, high.forward_agent_socket) = (forward_agent, forward_agent_socket);
    }
    if !proxy_decided {
        (high.proxy_jump, high.proxy_command) = (proxy_jump, proxy_command);
    }
    high.set_env = merge_set_env(&high.set_env, &set_env);
    high.needs_proxy |= needs_proxy;
    high.permit_remote_open |= permit_remote_open;
    high.wants_final |= wants_final;
    high.for_ssh.extend(for_ssh);
    high
}

/// Writes a test config file not writable by others, whatever the umask
/// (002 would make it group-writable, and so refused).
#[cfg(test)]
fn write_config(path: impl AsRef<Path>, text: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(&path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
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
    fn config_template() {
        assert_eq!(parse(CONFIG_TEMPLATE, "h", Path::new("/x"), false), HostConfig::default());
        // Uncommented, the "Host *" settings are all ones qsh reads.
        let all = CONFIG_TEMPLATE.split("# Host *").nth(1).unwrap();
        let on: String = all.lines().filter_map(|l| l.strip_prefix("#     ")).filter(|l| l.starts_with(|c: char| c.is_ascii_uppercase())).map(|l| format!("{l}\n")).collect();
        let c = parse(&on, "h", Path::new("/x"), true);
        assert_eq!((c.persist_session, c.predictive_echo.as_deref(), c.control_master.as_deref()), (Some(true), Some("auto"), Some("no")));
        assert_eq!((c.batch_mode, c.compression, c.exit_on_forward_failure), (Some(false), Some(false), Some(false)));
        assert_eq!((c.strict_host_key_checking.as_deref(), c.escape_char.as_deref(), c.server_alive_count_max), (Some("ask"), Some("~"), Some(3)));
        assert_eq!((c.port, c.connect_timeout, c.obscure_keystrokes.as_deref()), (Some(4422), Some(0), Some("yes")));
        assert_eq!(c.refused, None);
    }

    #[test]
    fn keywords_qsh_would_be_less_strict_without() {
        let refused = |text: &str| parse(text, "h", Path::new("/x"), false).refused;
        assert_eq!(refused("RevokedHostKeys /etc/ssh/revoked\n").as_deref(), Some("RevokedHostKeys"));
        assert!(parse("Host h\n PermitRemoteOpen localhost:8080\n", "h", Path::new("/x"), false).permit_remote_open);
        assert!(!parse("PermitRemoteOpen any\n", "h", Path::new("/x"), false).permit_remote_open);
        assert_eq!(refused("RevokedHostKeys none\n"), None);
    }

    /// `RefuseConnection MESSAGE` refuses the host, in its block only.
    #[test]
    fn refuse_connection() {
        let text = "Host old\n RefuseConnection \"use new.example\"\nHost *\n RefuseConnection later\n";
        let refuse = |host: &str| parse(text, host, Path::new("/x"), false).refuse_connection;
        assert_eq!(refuse("old").as_deref(), Some("RefuseConnection: use new.example"), "the first value wins");
        assert_eq!(refuse("h").as_deref(), Some("RefuseConnection: later"));
        assert_eq!(parse("Host old\n RefuseConnection x\n", "h", Path::new("/x"), false).refuse_connection, None);
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
        write_config(home.path().join(".ssh/config"), "Host old\n RefuseConnection gone\n").unwrap();
        let c = lookup(home.path(), "old", &Sources::default());
        let why = c.refuse_connection.unwrap();
        assert!(why.ends_with(".ssh/config line 2: RefuseConnection: gone"), "{why}");
    }

    /// Keywords in qsh's own config that qsh does not carry out are warned
    /// about, unknown ones are an error (as in ssh); ssh's files are ssh's.
    #[test]
    fn keywords_qsh_does_not_carry_out() {
        let home = tempfile::tempdir().unwrap();
        let dir = crate::keys::qsh_dir(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
        let file = dir.join("config").display().to_string();
        let ours = |text: &str| {
            write_config(dir.join("config"), text).unwrap();
            lookup(home.path(), "h", &Sources::default())
        };
        let c = ours("Ciphers aes\nHost h\n PubkeyAuthentication no\nHost other\n VerifyHostKeyDNS yes\n");
        assert_eq!((c.unapplied, c.bad_option), (vec![format!("{file} line 3: PubkeyAuthentication")], None));
        // A typo is an error even in a block for another host.
        let c = ours("Host other\n StrictHostKeyCheking yes\n");
        assert_eq!(c.bad_option, Some(format!("{file} line 2: Bad configuration option: StrictHostKeyCheking")));
        assert_eq!(ours("IgnoreUnknown Strict*,foo\nHost other\n StrictHostKeyCheking yes\n").bad_option, None);
        // In an included file: that file's name and line.
        write_config(dir.join("extra"), "\nBogus 1\n").unwrap();
        let c = ours("Include extra\n");
        assert_eq!(c.bad_option, Some(format!("{} line 2: Bad configuration option: Bogus", dir.join("extra").display())));
        // A second pass (canonical name) does not repeat the warning.
        let c = ours("CanonicalizeHostname always\nPubkeyAuthentication no\nHost h\n HostName real.\n");
        assert_eq!((c.hostname.as_deref(), c.unapplied.len()), (Some("real"), 1), "{:?}", c.unapplied);
        // -o lines are checked by the command line; ssh's own files are not checked.
        ours("");
        write_config(home.path().join(".ssh/config"), "Bogus 1\nPubkeyAuthentication no\n").unwrap();
        let o = Sources { overrides: vec!["PubkeyAuthentication no".into()], ..Default::default() };
        let c = lookup(home.path(), "h", &o);
        assert_eq!((c.unapplied, c.bad_option), (vec![], None));
    }

    /// What `qsh ui` saved never overrides the user's ssh config, but its own
    /// settings (Port, forwards) still count.
    #[test]
    fn ui_hosts_come_last() {
        let home = tempfile::tempdir().unwrap();
        let dir = crate::keys::qsh_dir(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
        write_config(dir.join(UI_HOSTS), "Host web\n    HostName 192.0.2.1\n    User olduser\n    Port 5000\n    LocalForward 8000 localhost:80\n    ForwardAgent yes\n").unwrap();
        let c = lookup(home.path(), "web", &Sources::default());
        assert_eq!((c.hostname.as_deref(), c.user.as_deref(), c.port), (Some("192.0.2.1"), Some("olduser"), Some(5000)));
        assert!(c.for_ssh.contains(&"HostName=192.0.2.1".to_string()) && c.for_ssh.contains(&"ForwardAgent=yes".to_string()), "{:?}", c.for_ssh);
        write_config(home.path().join(".ssh/config"), "Host web\n HostName 192.0.2.2\n User deploy\n ForwardAgent no\n").unwrap();
        let c = lookup(home.path(), "web", &Sources::default());
        assert_eq!((c.hostname.as_deref(), c.user.as_deref(), c.forward_agent), (Some("192.0.2.2"), Some("deploy"), Some(false)));
        assert_eq!((c.port, c.local_forwards.as_slice()), (Some(5000), &["8000:localhost:80".to_string()][..]));
        assert_eq!(c.for_ssh, ["LocalForward=8000 localhost:80"], "nothing that would override ssh's config");
        // qsh's own config still comes first.
        write_config(dir.join("config"), "Host web\n Port 6000\n").unwrap();
        assert_eq!(lookup(home.path(), "web", &Sources::default()).port, Some(6000));
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
        // Forwards also without --full; the terminal request only with it.
        let plain = parse(text, "a", Path::new("/x"), false);
        assert_eq!(plain.local_forwards, c.local_forwards);
        assert_eq!(plain.request_tty, None);
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
        write_config(ssh.join("config"), "Host a b *.x !c\n Port 1\nInclude conf.d/*\nHost *\n").unwrap();
        write_config(ssh.join("conf.d/more"), "Host d a\n").unwrap();
        assert_eq!(host_aliases(home.path()), vec!["a", "b", "d"]);
    }

    #[test]
    fn includes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("conf.d")).unwrap();
        write_config(dir.path().join("conf.d/a.conf"), "Host box\n  HostName 192.0.2.7\n").unwrap();
        write_config(dir.path().join("conf.d/b.conf"), "Host box\n  HostName ignored\n  User u\n").unwrap();
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
        write_config(ssh.join("config"), "Host myserver\n HostName 192.0.2.1\n User root\n Port 22\n").unwrap();
        write_config(ours.join("config"), "Host myserver\n Port 8080\n User admin\n").unwrap();
        let c = lookup(home.path(), "myserver", &Sources::default());
        assert_eq!(c.hostname.as_deref(), Some("192.0.2.1"));
        assert_eq!(c.user.as_deref(), Some("admin"));
        assert_eq!(c.port, Some(8080));
        // --full: ssh's Port is used when qsh's config has none.
        write_config(ours.join("config"), "Host other\n Port 1\n").unwrap();
        let full = Sources { full: true, ..Default::default() };
        assert_eq!(lookup(home.path(), "myserver", &full).ssh_port, Some(22));
        assert_eq!(lookup(home.path(), "myserver", &Sources::default()).ssh_port, None);
        // -o wins over both files; ssh's known_hosts file is never used.
        write_config(ssh.join("config"), "Host myserver\n UserKnownHostsFile /x\n User root\n").unwrap();
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

    /// So do refusals: qsh does not connect around them either.
    #[test]
    fn unknown_conditions_with_a_refusal() {
        let c = cfg("Match host h sessiontype shell\n    RevokedHostKeys /x\n    PermitRemoteOpen localhost:80\n    StrictHostKeyChecking yes\n", "h");
        assert_eq!((c.refused.as_deref(), c.permit_remote_open, c.strict_host_key_checking), (Some("RevokedHostKeys"), true, None));
        // Only maybe: a refusal ssh may lift (`--full`), not a sure one.
        let c = cfg("Match version OpenSSH_9*\n    RefuseConnection old\n", "h");
        assert_eq!((c.refused.as_deref(), c.refuse_connection), (Some("RefuseConnection (in a Match block qsh cannot evaluate)"), None));
        let c = cfg("Match version OpenSSH_9*\n    RevokedHostKeys none\n    PermitRemoteOpen any\n", "h");
        assert_eq!((c.refused, c.permit_remote_open), (None, false));
        let c = cfg("Match host other version OpenSSH_9*\n    RefuseConnection old\n", "h");
        assert_eq!((c.refused, c.refuse_connection), (None, None), "a block that cannot apply");
        // The same in a file such a block includes; nothing else there applies.
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path().join("policy"), "User other\nHost *\n  RefuseConnection old\n  ProxyJump gate\n").unwrap();
        let c = Parser::new("h", dir.path(), true, false).run("Match version OpenSSH_9*\n    Include policy\n");
        assert_eq!((c.refused.as_deref(), c.needs_proxy, c.user), (Some("RefuseConnection (in a Match block qsh cannot evaluate)"), true, None));
        // In qsh's own config ssh never sees them: they stop qsh, also with --full.
        let ours = |text: &str| Parser::new("h", Path::new("/nonexistent"), true, true).run(text);
        for text in ["Match version OpenSSH_9*\n    RefuseConnection old\n", "Match version OpenSSH_9*\n    RevokedHostKeys /x\n", "RevokedHostKeys /x\n"] {
            let c = ours(text);
            assert!(c.refused.is_none() && c.refuse_connection.is_some(), "{text:?}: {c:?}");
        }
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
        write_config(dir.join("config"), text).unwrap();
        let c = lookup(home.path(), "h", &Sources::default());
        assert_eq!(c.user, None, "no canonicalization asked for");
        write_config(dir.join("config"), format!("CanonicalizeHostname yes\n{text}")).unwrap();
        let c = lookup(home.path(), "h", &Sources::default());
        assert_eq!(c.user.as_deref(), Some("canon"));
        assert_eq!(c.hostname.as_deref(), Some("real"));
        let c = lookup(home.path(), "other", &Sources::default());
        assert_eq!(c.port, Some(2200), "Match final applies on the last pass");

        // The later pass keeps what the first found for the original name.
        let text = "CanonicalizeHostname always\nHost h\n  HostName real.\n  ProxyJump gate\n  IdentityFile ~/k\nHost *\n  IdentityFile ~/all\n";
        write_config(dir.join("config"), text).unwrap();
        let c = lookup(home.path(), "h", &Sources::default());
        assert_eq!((c.hostname.as_deref(), c.proxy_jump.as_deref()), (Some("real"), Some("gate")));
        assert_eq!(c.identity_files, ["~/k", "~/all"], "no repeats from the second pass");
    }

    /// Config files others could write are refused, as by ssh.
    #[cfg(unix)]
    #[test]
    fn writable_config_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let dir = crate::keys::qsh_dir(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        write_config(dir.join("config"), "Include extra\n").unwrap();
        write_config(dir.join("extra"), "Host h\n  ProxyCommand evil\n").unwrap();
        let c = lookup(home.path(), "h", &Sources::default());
        assert!(c.bad_file.is_none());
        std::fs::set_permissions(dir.join("extra"), std::fs::Permissions::from_mode(0o666)).unwrap();
        let c = lookup(home.path(), "h", &Sources::default());
        assert!(c.bad_file.as_deref().is_some_and(|b| b.contains("extra")), "{c:?}");
        std::fs::set_permissions(dir.join("config"), std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(lookup(home.path(), "x", &Sources::default()).bad_file.is_some());
        // Such a file is not read at all: its `Match exec` does not run.
        let marker = home.path().join("ran");
        write_config(dir.join("config"), format!("Match exec \"touch {}\"\n  User x\n", marker.display())).unwrap();
        std::fs::set_permissions(dir.join("config"), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(lookup(home.path(), "x", &Sources::default()).bad_file.is_some());
        assert!(!marker.exists(), "Match exec ran");
        std::fs::set_permissions(dir.join("config"), std::fs::Permissions::from_mode(0o600)).unwrap();
        lookup(home.path(), "x", &Sources::default());
        assert!(marker.exists(), "the test's Match exec works");
    }

    /// The system config and the files it includes are checked too.
    #[cfg(unix)]
    #[test]
    fn writable_system_config_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (system, extra) = (dir.path().join("ssh_config"), dir.path().join("extra"));
        write_config(&system, "Include extra\n").unwrap();
        write_config(&extra, "Host h\n  ProxyCommand evil\n").unwrap();
        let mode = |f: &Path, m| std::fs::set_permissions(f, std::fs::Permissions::from_mode(m)).unwrap();
        let read = || {
            let mut p = Parser::new("h", dir.path(), true, false);
            p.feed_system(&system);
            p.finish()
        };
        let c = read();
        assert!(c.bad_file.is_none() && c.needs_proxy, "{c:?}");
        for (file, other) in [(&extra, &system), (&system, &extra)] {
            mode(file, 0o666);
            mode(other, 0o644);
            let c = read();
            assert!(c.bad_file.as_deref().is_some_and(|b| b.contains(&*file.to_string_lossy())), "{c:?}");
            assert!(!c.needs_proxy, "{c:?}");
        }
    }

    /// `none` is a first value like any other: later ones do not count.
    #[test]
    fn none_decides() {
        let home = tempfile::tempdir().unwrap();
        let dir = crate::keys::qsh_dir(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        write_config(dir.join("config"), "Host h\n  ProxyJump gate\n  RemoteCommand top\n").unwrap();
        std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
        write_config(home.path().join(".ssh/config"), "Host h\n  ProxyCommand nc %h %p\n").unwrap();
        let o = Sources { overrides: vec!["ProxyJump none".into(), "RemoteCommand none".into()], ssh_config: Some(home.path().join(".ssh/config")), ..Default::default() };
        let c = lookup(home.path(), "h", &o);
        assert_eq!((c.proxy_jump, c.remote_command, c.needs_proxy), (None, None, false));
        let c = lookup(home.path(), "h", &Sources { ssh_config: Some(home.path().join(".ssh/config")), ..Default::default() });
        assert_eq!(c.proxy_jump.as_deref(), Some("gate"));
    }

    /// The command line's user is what `Match user` and `%r` see, ahead of `User`.
    #[test]
    fn command_line_user() {
        let home = tempfile::tempdir().unwrap();
        let dir = crate::keys::qsh_dir(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        write_config(dir.join("config"), "Host h\n  User other\nMatch user deploy\n  ProxyJump gate\n").unwrap();
        let deploy = Sources { user: Some("deploy".into()), ..Default::default() };
        let c = lookup(home.path(), "h", &deploy);
        assert_eq!((c.user.as_deref(), c.proxy_jump.as_deref()), (Some("deploy"), Some("gate")));
        let c = lookup(home.path(), "h", &Sources::default());
        assert_eq!((c.user.as_deref(), c.proxy_jump.as_deref()), (Some("other"), None));
    }

    /// `Match exec` does not run once an earlier criterion of the line failed.
    #[cfg(unix)]
    #[test]
    fn exec_after_failed_criterion() {
        let home = tempfile::tempdir().unwrap();
        let marker = home.path().join("ran");
        let c = cfg(&format!("Match host nope exec \"touch {}\"\n  User x\n", marker.display()), "h");
        assert_eq!(c.user, None);
        assert!(!marker.exists(), "Match exec ran for a line that cannot apply");
    }
}
