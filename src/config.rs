//! Server configuration (`config.toml`).
//!
//! The settings follow sshd_config(5) where qshd has the same feature, with
//! snake_case names (`AllowUsers` is `allow_users`). `[[match]]` blocks
//! replace settings for some logins, like sshd's `Match`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::pattern::{address_allowed, cidr_contains, name_matches, wildcard};

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address for both UDP (QUIC) and TCP.
    pub listen: SocketAddr,
    /// Also accept the TLS-over-TCP fallback. With `false` qshd listens on UDP
    /// only, so it can share a port number with sshd (e.g. 22) for `qsh --full`.
    pub tcp: bool,
    /// Host key path; defaults to `host_ed25519` next to the config file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key: Option<PathBuf>,
    /// Also accept keys from `~/.ssh/authorized_keys` (the files in
    /// `authorized_keys_file`).
    pub use_ssh_authorized_keys: bool,
    /// The OpenSSH key files read with `use_ssh_authorized_keys` (like
    /// AuthorizedKeysFile): relative to the home, `%h` home, `%u` user,
    /// `%U` uid, `%%`. qsh's own `~/.config/qsh/authorized_keys` is always read.
    #[serde(deserialize_with = "names")]
    pub authorized_keys_file: Vec<String>,
    /// Principals that certificates from `trusted_user_ca_keys` must name,
    /// one per line with optional authorized_keys options (like
    /// AuthorizedPrincipalsFile); without it, the user name. Same tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_principals_file: Option<String>,
    /// Port forwarding (`-L`/`-D`/`-W` and `-R`): `true`/`"yes"`/`"all"`,
    /// `false`/`"no"`, `"local"` or `"remote"` (like AllowTcpForwarding).
    pub allow_tcp_forwarding: Forwarding,
    /// Turns all forwarding off: ports, Unix sockets, agent (like DisableForwarding).
    pub disable_forwarding: bool,
    /// Unix socket forwarding (`-L`/`-R` with paths), like
    /// AllowStreamLocalForwarding: `yes`, `no`, `local`, `remote`.
    pub allow_stream_local_forwarding: Forwarding,
    /// Permissions taken away from `-R` sockets on the server (octal, like
    /// StreamLocalBindMask): "0177" leaves them to their owner.
    pub stream_local_bind_mask: String,
    /// Remove a stale socket file before listening on it (StreamLocalBindUnlink).
    pub stream_local_bind_unlink: bool,
    /// Allow `qsh -X`/`-Y` (like X11Forwarding).
    pub x11_forwarding: bool,
    /// The first display number used (like X11DisplayOffset).
    pub x11_display_offset: u32,
    /// Displays listen on loopback only (like X11UseLocalhost).
    pub x11_use_localhost: bool,
    /// The xauth program (like XAuthLocation).
    pub xauth_location: PathBuf,
    /// Destinations `-L`/`-D`/`-W` may connect to: `host:port` patterns with
    /// `*` (like PermitOpen). Empty or `["any"]`: any; `["none"]`: none.
    #[serde(deserialize_with = "names")]
    pub permit_open: Vec<String>,
    /// Addresses `-R` may listen on: `port`, `host:port` (like PermitListen).
    #[serde(deserialize_with = "names")]
    pub permit_listen: Vec<String>,
    /// Maximum simultaneous connections.
    pub max_connections: usize,
    /// Maximum connections that have not authenticated yet (like sshd's MaxStartups).
    pub max_startups: usize,
    /// Maximum unauthenticated connections from one IP address.
    pub max_startups_per_ip: usize,
    /// Who may connect to `-R` listeners: loopback only (`no`), everyone (`yes`),
    /// or whatever address the client asks for (`clientspecified`).
    pub gateway_ports: GatewayPorts,
    /// Subsystems (`qsh -s host NAME`): name → command line, run like sshd as
    /// `$SHELL -c command`. `sftp` is found automatically if OpenSSH's
    /// sftp-server is installed.
    pub subsystems: BTreeMap<String, String>,
    /// File with CA public keys trusted to sign user certificates for any
    /// user (the certificate must name the user as a principal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_user_ca_keys: Option<PathBuf>,
    /// Failed key proofs allowed per connection (like sshd's MaxAuthTries).
    pub max_auth_tries: u32,
    /// Allow `qsh -A` (ssh-agent forwarding).
    pub allow_agent_forwarding: bool,
    /// One-time codes (TOTP) as a second factor after the key.
    pub totp: Totp,
    /// OpenSSH host certificate for the host key; defaults to
    /// `<host_key>-cert.pub` if that exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_certificate: Option<PathBuf>,
    /// Keys and certificates that may not log in: a list of public keys or a
    /// KRL from `ssh-keygen -k` (like sshd's RevokedKeys). If the file
    /// cannot be read, no key is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_keys: Option<PathBuf>,
    /// A program that prints more authorized keys for a user (like sshd's
    /// AuthorizedKeysCommand); see `server::keys_command`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_keys_command: Option<String>,
    /// The user it runs as when qshd runs as root (required then; not root).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_keys_command_user: Option<String>,
    /// How long an interactive session survives without its client (seconds),
    /// so it can be resumed after a network outage. 0 turns this off.
    pub session_timeout: u64,
    /// Only these users may log in: name patterns, or `user@address` with a
    /// pattern or CIDR for the client address (like AllowUsers).
    #[serde(deserialize_with = "names")]
    pub allow_users: Vec<String>,
    /// These users may not log in (like DenyUsers; checked first).
    #[serde(deserialize_with = "names")]
    pub deny_users: Vec<String>,
    /// Only members of these groups may log in (like AllowGroups).
    #[serde(deserialize_with = "names")]
    pub allow_groups: Vec<String>,
    /// Members of these groups may not log in (like DenyGroups).
    #[serde(deserialize_with = "names")]
    pub deny_groups: Vec<String>,
    /// `yes`, `prohibit-password` (the same: qshd has no passwords), `no`,
    /// or `forced-commands-only` (like PermitRootLogin).
    pub permit_root_login: PermitRootLogin,
    /// Seconds a client has to log in (like LoginGraceTime; 0 = no limit).
    pub login_grace_time: u64,
    /// Text file shown to clients before they log in (like Banner).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<PathBuf>,
    /// Show /etc/motd when a login shell starts (like PrintMotd);
    /// `~/.hushlogin` turns this and the last login off.
    pub print_motd: bool,
    /// Show when and from where the user last logged in (like PrintLastLog).
    pub print_last_log: bool,
    /// Run `~/.ssh/rc` (or else /etc/ssh/sshrc) before a session's program,
    /// as sshd does (like PermitUserRC).
    pub permit_user_rc: bool,
    /// Commands, shells and subsystems at once per connection (like MaxSessions).
    pub max_sessions: usize,
    /// Allow terminals (like PermitTTY).
    pub permit_tty: bool,
    /// Client variables a session gets: name patterns (like AcceptEnv).
    #[serde(deserialize_with = "names")]
    pub accept_env: Vec<String>,
    /// Variables every session gets (like SetEnv); they replace the client's.
    pub set_env: BTreeMap<String, String>,
    /// Runs instead of whatever the client asks for, which is passed in
    /// `SSH_ORIGINAL_COMMAND` (like ForceCommand).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_command: Option<String>,
    /// Confine sessions and file transfers to this directory (like
    /// ChrootDirectory; `%h` home, `%u` user, `%U` uid, `%%`). It and every
    /// directory above it must belong to root and be writable only by root.
    /// Usually with `force_command = "internal-sftp"`. System mode only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chroot_directory: Option<String>,
    /// Probe a silent client every this many seconds and drop it after
    /// `client_alive_count_max` probes go unanswered (like
    /// ClientAliveInterval). 0: the transports' own defaults (about a minute).
    pub client_alive_interval: u64,
    pub client_alive_count_max: u32,
    /// Refuse the connection (like RefuseConnection; for `[[match]]`).
    pub refuse_connection: bool,
    /// Drop connections from addresses that keep failing to log in (like
    /// PerSourcePenalties): `true`, `false`, or sshd's settings, e.g.
    /// `"authfail:5s noauth:1s grace-exceeded:10s min:15s max:10m"`.
    pub per_source_penalties: Penalties,
    /// Addresses (patterns or CIDR) that never get penalties.
    #[serde(deserialize_with = "names")]
    pub per_source_penalty_exempt_list: Vec<String>,
    /// Settings for some logins only.
    #[serde(rename = "match", skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<MatchBlock>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Totp {
    /// Never ask.
    Off,
    /// Ask users who set it up with `qshd totp`.
    #[default]
    Optional,
    /// Ask everyone; users without a TOTP secret cannot log in.
    Required,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GatewayPorts {
    #[default]
    No,
    Yes,
    ClientSpecified,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PermitRootLogin {
    Yes,
    #[default]
    #[serde(alias = "without-password")]
    ProhibitPassword,
    ForcedCommandsOnly,
    No,
}

/// Which way forwarding may go (sshd's `yes`/`all`, `no`, `local`, `remote`).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Forwarding {
    #[default]
    All,
    Local,
    Remote,
    No,
}

impl Forwarding {
    pub fn local(self) -> bool {
        matches!(self, Forwarding::All | Forwarding::Local)
    }
    pub fn remote(self) -> bool {
        matches!(self, Forwarding::All | Forwarding::Remote)
    }
}

impl<'de> Deserialize<'de> for Forwarding {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Text(String),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Bool(true) => Forwarding::All,
            Raw::Bool(false) => Forwarding::No,
            Raw::Text(t) => match t.to_ascii_lowercase().as_str() {
                "yes" | "all" => Forwarding::All,
                "no" => Forwarding::No,
                "local" => Forwarding::Local,
                "remote" => Forwarding::Remote,
                _ => return Err(serde::de::Error::custom(format!("unknown forwarding {t:?} (yes, no, local, remote)"))),
            },
        })
    }
}

impl Serialize for Forwarding {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            Forwarding::All => "yes",
            Forwarding::Local => "local",
            Forwarding::Remote => "remote",
            Forwarding::No => "no",
        })
    }
}

/// `per_source_penalties` (sshd's defaults).
#[derive(Debug, Clone, PartialEq)]
pub struct Penalties {
    pub enabled: bool,
    pub authfail: Duration,
    pub noauth: Duration,
    pub grace_exceeded: Duration,
    /// Penalty a source must collect before its connections are dropped.
    pub min: Duration,
    pub max: Duration,
    /// Sources remembered at most (more are not penalized).
    pub max_sources: usize,
    /// `per_source_penalty_exempt_list` (filled in from the config).
    pub exempt: Vec<String>,
}

impl Default for Penalties {
    fn default() -> Self {
        Penalties {
            enabled: true,
            authfail: Duration::from_secs(5),
            noauth: Duration::from_secs(1),
            grace_exceeded: Duration::from_secs(10),
            min: Duration::from_secs(15),
            max: Duration::from_secs(600),
            max_sources: 65536,
            exempt: Vec::new(),
        }
    }
}

/// `30`, `30s`, `5m`, `1h` (sshd's time format, without combinations).
fn seconds(v: &str) -> Option<Duration> {
    let (n, unit) = match v.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => v.split_at(i),
        None => (v, "s"),
    };
    let n: u64 = n.parse().ok()?;
    let mult = match unit.to_ascii_lowercase().as_str() {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return None,
    };
    Some(Duration::from_secs(n.checked_mul(mult)?))
}

impl Penalties {
    fn parse(text: &str) -> Result<Penalties, String> {
        let mut p = Penalties::default();
        match text.trim().to_ascii_lowercase().as_str() {
            "yes" => return Ok(p),
            "no" => return Ok(Penalties { enabled: false, ..p }),
            _ => {}
        }
        for word in text.split_whitespace() {
            let (key, value) = word.split_once(':').ok_or_else(|| format!("bad per_source_penalties item {word:?}"))?;
            if key == "max-sources4" || key == "max-sources6" || key == "max-sources" {
                p.max_sources = value.parse().map_err(|_| format!("bad {key} {value:?}"))?;
                continue;
            }
            let d = seconds(value).ok_or_else(|| format!("bad time {value:?} for {key}"))?;
            match key {
                "authfail" => p.authfail = d,
                "noauth" => p.noauth = d,
                "grace-exceeded" => p.grace_exceeded = d,
                "min" => p.min = d,
                "max" => p.max = d,
                // Penalties for events qshd does not have.
                "crash" | "refuseconnection" => {}
                _ => return Err(format!("unknown per_source_penalties item {key:?}")),
            }
        }
        Ok(p)
    }
}

impl<'de> Deserialize<'de> for Penalties {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Bool(enabled) => Ok(Penalties { enabled, ..Penalties::default() }),
            Raw::Text(t) => Penalties::parse(&t).map_err(serde::de::Error::custom),
        }
    }
}

impl Serialize for Penalties {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if !self.enabled {
            return s.serialize_bool(false);
        }
        s.serialize_str(&format!(
            "authfail:{}s noauth:{}s grace-exceeded:{}s min:{}s max:{}s max-sources:{}",
            self.authfail.as_secs(),
            self.noauth.as_secs(),
            self.grace_exceeded.as_secs(),
            self.min.as_secs(),
            self.max.as_secs(),
            self.max_sources
        ))
    }
}

/// A list given as an array or as one string of comma- or space-separated words.
fn names<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        One(String),
        Many(Vec<String>),
    }
    let words = match Raw::deserialize(d)? {
        Raw::One(s) => vec![s],
        Raw::Many(v) => v,
    };
    Ok(words.iter().flat_map(|w| w.split([',', ' ', '\t'])).filter(|w| !w.is_empty()).map(str::to_string).collect())
}

fn opt_names<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    names(d).map(Some)
}

/// `[[match]]` settings that replace the global ones.
macro_rules! overrides {
    (
        plain { $($(#[$pa:meta])* $p:ident: $pt:ty,)* }
        optional { $($o:ident: $ot:ty,)* }
    ) => {
        /// A `[[match]]` block: conditions (all given ones must hold; none:
        /// every login) and settings that replace the global ones for
        /// logins that meet them. Like in sshd, if several blocks match, the
        /// first one that sets a setting wins.
        #[derive(Deserialize, Serialize, Debug, Clone, Default)]
        #[serde(default, deny_unknown_fields)]
        pub struct MatchBlock {
            /// User name patterns (`!` excludes).
            #[serde(deserialize_with = "names", skip_serializing_if = "Vec::is_empty")]
            pub user: Vec<String>,
            /// Group name patterns: any of the user's groups.
            #[serde(deserialize_with = "names", skip_serializing_if = "Vec::is_empty")]
            pub group: Vec<String>,
            /// Client address patterns or CIDR ranges.
            #[serde(deserialize_with = "names", skip_serializing_if = "Vec::is_empty")]
            pub address: Vec<String>,
            $($(#[$pa])* #[serde(skip_serializing_if = "Option::is_none")] pub $p: Option<$pt>,)*
            /// `"none"` removes a global value.
            $(#[serde(skip_serializing_if = "Option::is_none")] pub $o: Option<$ot>,)*
        }

        impl MatchBlock {
            fn apply(&self, cfg: &mut ServerConfig) {
                $(if let Some(v) = &self.$p { cfg.$p = v.clone(); })*
                $(if let Some(v) = &self.$o { cfg.$o = (!is_none(v)).then(|| v.clone()); })*
            }
        }
    };
}

overrides! {
    plain {
        #[serde(deserialize_with = "opt_names")]
        accept_env: Vec<String>,
        allow_agent_forwarding: bool,
        #[serde(deserialize_with = "opt_names")]
        allow_groups: Vec<String>,
        allow_tcp_forwarding: Forwarding,
        allow_stream_local_forwarding: Forwarding,
        stream_local_bind_mask: String,
        stream_local_bind_unlink: bool,
        #[serde(deserialize_with = "opt_names")]
        allow_users: Vec<String>,
        #[serde(deserialize_with = "opt_names")]
        authorized_keys_file: Vec<String>,
        #[serde(deserialize_with = "opt_names")]
        deny_groups: Vec<String>,
        #[serde(deserialize_with = "opt_names")]
        deny_users: Vec<String>,
        disable_forwarding: bool,
        gateway_ports: GatewayPorts,
        max_auth_tries: u32,
        max_sessions: usize,
        #[serde(deserialize_with = "opt_names")]
        permit_listen: Vec<String>,
        #[serde(deserialize_with = "opt_names")]
        permit_open: Vec<String>,
        permit_root_login: PermitRootLogin,
        permit_tty: bool,
        permit_user_rc: bool,
        refuse_connection: bool,
        set_env: BTreeMap<String, String>,
        totp: Totp,
        use_ssh_authorized_keys: bool,
        x11_display_offset: u32,
        x11_forwarding: bool,
        x11_use_localhost: bool,
    }
    optional {
        authorized_keys_command: String,
        authorized_keys_command_user: String,
        authorized_principals_file: String,
        banner: PathBuf,
        chroot_directory: String,
        force_command: String,
        revoked_keys: PathBuf,
        trusted_user_ca_keys: PathBuf,
    }
}

/// sshd's `none` for "no value".
fn is_none(v: &impl AsRef<std::ffi::OsStr>) -> bool {
    v.as_ref() == "none"
}

/// Who logs in, for `[[match]]` and the allow/deny lists.
pub struct Login<'a> {
    pub user: &'a str,
    /// The user's group names (empty for an unknown user).
    pub groups: &'a [String],
    pub addr: IpAddr,
}

impl MatchBlock {
    fn matches(&self, who: &Login) -> bool {
        (self.user.is_empty() || name_matches(&self.user, who.user))
            && (self.group.is_empty() || groups_match(&self.group, who.groups))
            && (self.address.is_empty() || address_allowed(&self.address.join(","), who.addr))
    }
}

/// Like sshd: a group matching an excluded pattern fails, any group matching a pattern passes.
fn groups_match(patterns: &[String], groups: &[String]) -> bool {
    let excluded = patterns.iter().filter_map(|p| p.strip_prefix('!')).any(|p| groups.iter().any(|g| wildcard(p, g)));
    !excluded && groups.iter().any(|g| name_matches(patterns, g))
}

/// `user` or `user@address` (address: wildcard pattern or CIDR) from AllowUsers/DenyUsers.
fn user_entry_matches(entry: &str, who: &Login) -> bool {
    let (user, host) = match entry.rsplit_once('@') {
        Some((u, h)) => (u, Some(h)),
        None => (entry, None),
    };
    wildcard(user, who.user)
        && host.is_none_or(|h| {
            if h.contains('/') { cidr_contains(h, who.addr).unwrap_or(false) } else { wildcard(h, &who.addr.to_canonical().to_string()) }
        })
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: SocketAddr::from(([0u16; 8], crate::DEFAULT_PORT)),
            tcp: true,
            host_key: None,
            use_ssh_authorized_keys: true,
            authorized_keys_file: vec![".ssh/authorized_keys".into()],
            authorized_principals_file: None,
            allow_tcp_forwarding: Forwarding::All,
            disable_forwarding: false,
            allow_stream_local_forwarding: Forwarding::All,
            stream_local_bind_mask: "0177".into(),
            stream_local_bind_unlink: false,
            x11_forwarding: false,
            x11_display_offset: 10,
            x11_use_localhost: true,
            xauth_location: PathBuf::from("/usr/bin/xauth"),
            permit_open: Vec::new(),
            permit_listen: Vec::new(),
            max_connections: 256,
            max_startups: 64,
            max_startups_per_ip: 8,
            gateway_ports: GatewayPorts::No,
            subsystems: BTreeMap::new(),
            trusted_user_ca_keys: None,
            max_auth_tries: 6,
            allow_agent_forwarding: true,
            totp: Totp::Optional,
            host_certificate: None,
            revoked_keys: None,
            authorized_keys_command: None,
            authorized_keys_command_user: None,
            session_timeout: 3600,
            allow_users: Vec::new(),
            deny_users: Vec::new(),
            allow_groups: Vec::new(),
            deny_groups: Vec::new(),
            permit_root_login: PermitRootLogin::ProhibitPassword,
            login_grace_time: 120,
            banner: None,
            print_motd: true,
            print_last_log: true,
            permit_user_rc: true,
            max_sessions: 10,
            permit_tty: true,
            accept_env: vec!["LANG".into(), "LC_*".into(), "COLORTERM".into()],
            set_env: BTreeMap::new(),
            force_command: None,
            chroot_directory: None,
            client_alive_interval: 0,
            client_alive_count_max: 3,
            refuse_connection: false,
            per_source_penalties: Penalties::default(),
            per_source_penalty_exempt_list: Vec::new(),
            matches: Vec::new(),
        }
    }
}

impl ServerConfig {
    /// Loads `path` if it exists, otherwise returns defaults.
    pub fn load(path: &Path) -> Result<ServerConfig> {
        let cfg: ServerConfig = match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ServerConfig::default(),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        cfg.validate().with_context(|| format!("invalid {}", path.display()))?;
        Ok(cfg)
    }

    /// Limits of 0 would silently refuse every connection or login.
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("max_connections", self.max_connections),
            ("max_startups", self.max_startups),
            ("max_startups_per_ip", self.max_startups_per_ip),
            ("max_auth_tries", self.max_auth_tries as usize),
        ] {
            if value == 0 {
                bail!("{name} must be at least 1");
            }
        }
        for mask in std::iter::once(&self.stream_local_bind_mask).chain(self.matches.iter().flat_map(|m| &m.stream_local_bind_mask)) {
            if u32::from_str_radix(mask, 8).map_or(true, |m| m > 0o777) {
                bail!("stream_local_bind_mask: {mask:?} is not an octal mask like \"0177\"");
            }
        }
        for (i, m) in self.matches.iter().enumerate() {
            if m.max_auth_tries == Some(0) {
                bail!("match block {}: max_auth_tries must be at least 1", i + 1);
            }
            for cidr in m.address.iter().map(|a| a.trim_start_matches('!')).filter(|a| a.contains('/')) {
                if cidr_contains(cidr, IpAddr::from([0u8; 4])).is_none() {
                    bail!("match block {}: bad address range {cidr:?}", i + 1);
                }
            }
        }
        for name in self.set_env.keys().chain(self.matches.iter().flat_map(|m| m.set_env.iter().flat_map(|e| e.keys()))) {
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                bail!("set_env: bad variable name {name:?}");
            }
        }
        #[cfg(unix)]
        for cmd in std::iter::once(&self.authorized_keys_command)
            .chain(self.matches.iter().map(|m| &m.authorized_keys_command))
            .flatten()
            .filter(|c| !is_none(c))
        {
            crate::server::keys_command::validate(cmd)?;
        }
        Ok(())
    }

    /// Whether `[[match]]` or the allow/deny lists look at groups (then
    /// the user's groups must be looked up).
    pub fn needs_groups(&self) -> bool {
        !self.allow_groups.is_empty()
            || !self.deny_groups.is_empty()
            || self.matches.iter().any(|m| !m.group.is_empty() || m.allow_groups.is_some() || m.deny_groups.is_some())
    }

    /// The settings for one login: the global ones with matching
    /// `[[match]]` blocks applied.
    pub fn for_login(&self, who: &Login) -> ServerConfig {
        let mut cfg = self.clone();
        // The first block that sets something wins: apply in reverse.
        for m in self.matches.iter().rev().filter(|m| m.matches(who)) {
            m.apply(&mut cfg);
        }
        cfg.matches.clear();
        cfg
    }

    /// Why the allow/deny lists keep this user out, checked in sshd's order.
    pub fn login_refused(&self, who: &Login) -> Option<String> {
        if self.refuse_connection {
            return Some("refuse_connection is set".into());
        }
        if self.deny_users.iter().any(|e| user_entry_matches(e, who)) {
            return Some("listed in deny_users".into());
        }
        if !self.allow_users.is_empty() && !self.allow_users.iter().any(|e| user_entry_matches(e, who)) {
            return Some("not listed in allow_users".into());
        }
        if let Some(g) = who.groups.iter().find(|g| self.deny_groups.iter().any(|p| wildcard(p, g))) {
            return Some(format!("group {g:?} is listed in deny_groups"));
        }
        if !self.allow_groups.is_empty() && !who.groups.iter().any(|g| self.allow_groups.iter().any(|p| wildcard(p, g))) {
            return Some("in none of the allow_groups".into());
        }
        None
    }

    /// `-L`/`-D`/`-W` allowed at all.
    pub fn local_forwarding(&self) -> bool {
        !self.disable_forwarding && self.allow_tcp_forwarding.local()
    }

    /// `-R` allowed at all.
    pub fn remote_forwarding(&self) -> bool {
        !self.disable_forwarding && self.allow_tcp_forwarding.remote()
    }

    /// `-L` to a Unix socket on the server.
    pub fn local_stream_forwarding(&self) -> bool {
        !self.disable_forwarding && self.allow_stream_local_forwarding.local()
    }

    /// `-R` from a Unix socket on the server.
    pub fn remote_stream_forwarding(&self) -> bool {
        !self.disable_forwarding && self.allow_stream_local_forwarding.remote()
    }

    /// `stream_local_bind_mask` as a number.
    pub fn bind_mask(&self) -> u32 {
        u32::from_str_radix(&self.stream_local_bind_mask, 8).unwrap_or(0o177) & 0o777
    }

    pub fn x11(&self) -> bool {
        !self.disable_forwarding && self.x11_forwarding
    }

    pub fn agent_forwarding(&self) -> bool {
        !self.disable_forwarding && self.allow_agent_forwarding
    }

    /// `permit_open` allows `host:port`.
    pub fn may_open(&self, host: &str, port: u16) -> bool {
        endpoint_list_allows(&self.permit_open, |p| crate::pattern::endpoint_matches(p, host, port, false))
    }

    /// `permit_listen` allows `bind:port`.
    pub fn may_listen(&self, bind: &str, port: u16) -> bool {
        endpoint_list_allows(&self.permit_listen, |p| crate::pattern::endpoint_matches(p, bind, port, true))
    }

    /// Whether a client may set variable `name` (`accept_env`). Only plain
    /// names: no `=`, NUL or other tricks (compare CVE-2014-2532).
    pub fn accepts_env(&self, name: &str) -> bool {
        let plain = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        plain && name_matches(&self.accept_env, name)
    }

    /// `chroot_directory` for a user, with its tokens replaced.
    pub fn chroot_for(&self, user: &str, uid: u32, home: &Path) -> Result<Option<PathBuf>> {
        let Some(dir) = &self.chroot_directory else { return Ok(None) };
        expand_user_path(dir, user, uid, home).map(Some)
    }

    /// The authorized_keys files to read for a user (`none` reads none).
    pub fn authorized_keys_files(&self, user: &str, uid: u32, home: &Path) -> Vec<Result<PathBuf>> {
        self.authorized_keys_file
            .iter()
            .filter(|f| f.as_str() != "none")
            .map(|f| expand_user_path(f, user, uid, home).map(|p| home.join(p)))
            .collect()
    }

    /// The text for `qshd -T`.
    /// The text for `qshd -T`.
    pub fn dump(&self) -> Result<String> {
        Ok(toml::to_string(self)?)
    }
}

/// Replaces sshd's path tokens: `%h` home, `%u` user, `%U` uid, `%%`.
pub fn expand_user_path(text: &str, user: &str, uid: u32, home: &Path) -> Result<PathBuf> {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(&home.to_string_lossy()),
            Some('u') => out.push_str(user),
            Some('U') => out.push_str(&uid.to_string()),
            Some('%') => out.push('%'),
            other => bail!("unknown token %{} in {text:?}", other.map(String::from).unwrap_or_default()),
        }
    }
    Ok(PathBuf::from(out))
}

/// PermitOpen/PermitListen lists: empty or `any` allows all, `none` nothing.
fn endpoint_list_allows(list: &[String], matches: impl Fn(&str) -> bool) -> bool {
    match list {
        [] => true,
        [one] if one == "any" => true,
        [one] if one == "none" => false,
        _ => list.iter().any(|p| matches(p)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ServerConfig {
        let cfg: ServerConfig = toml::from_str(text).unwrap();
        cfg.validate().unwrap();
        cfg
    }

    fn who<'a>(user: &'a str, groups: &'a [String], addr: &str) -> Login<'a> {
        Login { user, groups, addr: addr.parse().unwrap() }
    }

    #[test]
    fn zero_limits_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qshd.toml");
        std::fs::write(&path, "max_startups = 0\n").unwrap();
        assert!(format!("{:#}", ServerConfig::load(&path).unwrap_err()).contains("max_startups must be at least 1"));
        std::fs::write(&path, "max_startups = 1\n").unwrap();
        assert!(ServerConfig::load(&path).is_ok());
        assert!(ServerConfig::load(&dir.path().join("missing.toml")).is_ok());
    }

    #[test]
    fn allow_and_deny_lists() {
        let cfg = parse("allow_users = \"alice bob@192.0.2.0/24 carol@10.*\"\ndeny_users = [\"bob@192.0.2.66\"]\n");
        let none: &[String] = &[];
        assert!(cfg.login_refused(&who("alice", none, "203.0.113.1")).is_none());
        assert!(cfg.login_refused(&who("bob", none, "192.0.2.1")).is_none());
        assert!(cfg.login_refused(&who("bob", none, "203.0.113.1")).is_some(), "wrong address");
        assert!(cfg.login_refused(&who("bob", none, "192.0.2.66")).is_some(), "denied first");
        assert!(cfg.login_refused(&who("carol", none, "10.1.2.3")).is_none());
        assert!(cfg.login_refused(&who("mallory", none, "10.1.2.3")).is_some());

        let cfg = parse("allow_groups = [\"staff\"]\ndeny_groups = \"guests\"\n");
        let staff = ["users".to_string(), "staff".to_string()];
        let both = ["staff".to_string(), "guests".to_string()];
        assert!(cfg.login_refused(&who("a", &staff, "192.0.2.1")).is_none());
        assert!(cfg.login_refused(&who("a", &both, "192.0.2.1")).is_some());
        assert!(cfg.login_refused(&who("a", none, "192.0.2.1")).is_some());
    }

    #[test]
    fn match_blocks() {
        let cfg = parse(
            r#"
            allow_tcp_forwarding = true
            force_command = "/bin/global"

            [[match]]
            group = "sftponly"
            force_command = "internal-sftp"
            allow_tcp_forwarding = "no"
            permit_tty = false

            [[match]]
            address = "192.0.2.0/24"
            force_command = "none"
            allow_tcp_forwarding = "local"
            max_sessions = 2
            "#,
        );
        let sftp = ["sftponly".to_string()];
        let none: &[String] = &[];
        let a = cfg.for_login(&who("u", &sftp, "192.0.2.9"));
        assert_eq!(a.force_command.as_deref(), Some("internal-sftp"), "the first block wins");
        assert_eq!(a.allow_tcp_forwarding, Forwarding::No);
        assert!(!a.permit_tty);
        assert_eq!(a.max_sessions, 2, "settings only the second block has still apply");
        let b = cfg.for_login(&who("u", none, "192.0.2.9"));
        assert_eq!(b.force_command, None, "none removes the global value");
        assert!(b.local_forwarding() && !b.remote_forwarding());
        let c = cfg.for_login(&who("u", none, "203.0.113.9"));
        assert_eq!(c.force_command.as_deref(), Some("/bin/global"));
        assert_eq!(c.max_sessions, 10);
    }

    #[test]
    fn bad_values_are_rejected() {
        for bad in [
            "allow_tcp_forwarding = \"sometimes\"",
            "permit_root_login = \"maybe\"",
            "[[match]]\nuser = \"x\"\nlisten = \"0.0.0.0:1\"",
            "[[match]]\naddress = \"10.0.0.0/40\"",
            "[set_env]\n\"A=B\" = \"x\"",
        ] {
            let parsed = toml::from_str::<ServerConfig>(bad).map_err(anyhow::Error::from).and_then(|c| c.validate().map(|_| c));
            assert!(parsed.is_err(), "{bad}");
        }
        assert_eq!(parse("permit_root_login = \"without-password\"").permit_root_login, PermitRootLogin::ProhibitPassword);
    }

    #[test]
    fn penalties() {
        assert_eq!(parse("").per_source_penalties, Penalties::default());
        assert!(!parse("per_source_penalties = false").per_source_penalties.enabled);
        let p = parse("per_source_penalties = \"authfail:30s min:1m max:2h crash:90\"").per_source_penalties;
        assert_eq!((p.authfail, p.min, p.max), (Duration::from_secs(30), Duration::from_secs(60), Duration::from_secs(7200)));
        assert!(toml::from_str::<ServerConfig>("per_source_penalties = \"authfail:x\"").is_err());
        assert!(toml::from_str::<ServerConfig>("per_source_penalties = \"bogus:1\"").is_err());
    }

    #[test]
    fn env_and_endpoints() {
        let cfg = ServerConfig::default();
        assert!(cfg.accepts_env("LANG") && cfg.accepts_env("LC_ALL") && cfg.accepts_env("COLORTERM"));
        for bad in ["LD_PRELOAD", "PATH", "LC_X=LD_PRELOAD", "LC_\0", "LC_ ", "", "BASH_ENV"] {
            assert!(!cfg.accepts_env(bad), "{bad:?}");
        }
        let cfg = parse("accept_env = [\"GIT_*\"]\npermit_open = [\"db:5432\", \"*:443\"]\npermit_listen = \"8080\"");
        assert!(cfg.accepts_env("GIT_PROTOCOL") && !cfg.accepts_env("LANG"));
        assert!(cfg.may_open("db", 5432) && cfg.may_open("example.com", 443) && !cfg.may_open("db", 22));
        assert!(cfg.may_listen("localhost", 8080) && !cfg.may_listen("localhost", 8081));
        assert!(!parse("permit_open = \"none\"").may_open("db", 1));
        assert!(ServerConfig::default().may_open("db", 1));
    }

    #[test]
    fn dump_reads_back() {
        let cfg = parse("[set_env]\nA = \"1\"\n[[match]]\nuser = \"x\"\nbanner = \"/etc/issue.net\"\n");
        let text = cfg.dump().unwrap();
        let again: ServerConfig = toml::from_str(&text).unwrap();
        assert_eq!(again.dump().unwrap(), text);
        assert_eq!(again.matches.len(), 1);
    }
}
