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

use crate::pattern::{address_allowed, address_matches, cidr_contains, name_matches, wildcard};

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address for both UDP (QUIC) and TCP.
    pub listen: SocketAddr,
    /// Also accept the TLS-over-TCP fallback. With `false` qshd listens on UDP
    /// only, so it can share a port number with sshd (e.g. 22) for `qsh --full`.
    #[serde(deserialize_with = "flag")]
    pub tcp: bool,
    /// Host key path; defaults to `host_ed25519` in qshd's config dir
    /// (`/etc/qsh` or `~/.config/qsh`), even with `--config` elsewhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key: Option<PathBuf>,
    /// Also accept keys from `~/.ssh/authorized_keys` (the files in
    /// `authorized_keys_file`).
    #[serde(deserialize_with = "flag")]
    pub use_ssh_authorized_keys: bool,
    /// Accept keys from qsh's own `~/.config/qsh/authorized_keys` (where
    /// `qsh pair` puts them). Off where keys are managed
    /// centrally (`authorized_keys_file`, `authorized_keys_command`).
    #[serde(deserialize_with = "flag")]
    pub use_qsh_authorized_keys: bool,
    /// The OpenSSH key files read with `use_ssh_authorized_keys` (like
    /// AuthorizedKeysFile): relative to the home, `%h` home, `%u` user,
    /// `%U` uid, `%%`.
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
    #[serde(deserialize_with = "flag")]
    pub disable_forwarding: bool,
    /// Unix socket forwarding (`-L`/`-R` with paths), like
    /// AllowStreamLocalForwarding: `yes`, `no`, `local`, `remote`.
    pub allow_stream_local_forwarding: Forwarding,
    /// Permissions taken away from `-R` sockets on the server (octal, like
    /// StreamLocalBindMask): "0177" leaves them to their owner.
    pub stream_local_bind_mask: String,
    /// Remove a stale socket file before listening on it (StreamLocalBindUnlink).
    #[serde(deserialize_with = "flag")]
    pub stream_local_bind_unlink: bool,
    /// Allow `qsh -X`/`-Y` (like X11Forwarding).
    #[serde(deserialize_with = "flag")]
    pub x11_forwarding: bool,
    /// The first display number used (like X11DisplayOffset).
    pub x11_display_offset: u32,
    /// Displays listen on loopback only (like X11UseLocalhost).
    #[serde(deserialize_with = "flag")]
    pub x11_use_localhost: bool,
    /// The xauth program (like XAuthLocation).
    pub xauth_location: PathBuf,
    /// Tunnel devices (`qsh -w`, like PermitTunnel): `no`, `yes`,
    /// `point-to-point` (TUN only) or `ethernet` (TAP only). Other users than
    /// root only get a device made for them, as in sshd.
    pub permit_tunnel: PermitTunnel,
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
    /// Data from a client that qshd may hold before the program it is for
    /// reads it, per connection, in MiB. Normally little is held; it fills
    /// when forwards stop reading (a stuck service), and then the whole
    /// connection waits. A stream may hold an eighth of it (8 MiB at most),
    /// so 7 stuck forwards cannot fill it. Worst case RAM: `max_connections`
    /// times this.
    pub connection_buffer_mb: u32,
    /// As root under systemd: each session in a scope of its own in the
    /// user's slice (`user-UID.slice/qsh-UID-ID.scope`), so its programs count
    /// against the user and not qshd's service, and restarting qshd leaves
    /// them running (tmux). Off, or without systemd, they stay in qshd's.
    #[serde(deserialize_with = "flag")]
    pub session_scope: bool,
    /// Who may connect to `-R` listeners: loopback only (`no`), everyone (`yes`),
    /// or whatever address the client asks for (`clientspecified`).
    pub gateway_ports: GatewayPorts,
    /// A `-L`/`-D` connection refused on 127.0.0.1 tries ::1, and back.
    /// Off: while the service is down, another local user may listen there.
    #[serde(deserialize_with = "flag")]
    pub loopback_fallback: bool,
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
    /// Seconds a one-time code lasts on its connection: after them, it
    /// starts no session or copy (a shared one, `ControlMaster`, then logs
    /// in with a code again; what is under way goes on, forwards included);
    /// 0 = as long as the connection.
    pub totp_valid_for: u64,
    /// Allow `qsh -A` (ssh-agent forwarding).
    #[serde(deserialize_with = "flag")]
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
    /// Only these users may log in: name patterns, or `user@address` with
    /// patterns or CIDRs for the client address, comma-separated (like AllowUsers).
    #[serde(deserialize_with = "user_entries")]
    pub allow_users: Vec<String>,
    /// These users may not log in (like DenyUsers; checked first).
    #[serde(deserialize_with = "user_entries")]
    pub deny_users: Vec<String>,
    /// Only members of these groups may log in (like AllowGroups).
    #[serde(deserialize_with = "names")]
    pub allow_groups: Vec<String>,
    /// Members of these groups may not log in (like DenyGroups).
    #[serde(deserialize_with = "names")]
    pub deny_groups: Vec<String>,
    /// `yes` (keys, and passwords with `password_authentication`),
    /// `prohibit-password` (keys only), `no`, or `forced-commands-only`
    /// (keys with a forced command only), like PermitRootLogin.
    pub permit_root_login: PermitRootLogin,
    /// Seconds a client has to log in (like LoginGraceTime; 0 = no limit).
    pub login_grace_time: u64,
    /// Text file shown to clients before they log in (like Banner).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<PathBuf>,
    /// Show /etc/motd when a login shell starts (like PrintMotd);
    /// `~/.hushlogin` turns this and the last login off.
    #[serde(deserialize_with = "flag")]
    pub print_motd: bool,
    /// Show when and from where the user last logged in (like PrintLastLog).
    #[serde(deserialize_with = "flag")]
    pub print_last_log: bool,
    /// Run `~/.ssh/rc` (or else /etc/ssh/sshrc) before a session's program,
    /// as sshd does (like PermitUserRC).
    #[serde(deserialize_with = "flag")]
    pub permit_user_rc: bool,
    /// Commands, shells and subsystems at once per connection (like MaxSessions).
    pub max_sessions: usize,
    /// Allow terminals (like PermitTTY).
    #[serde(deserialize_with = "flag")]
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
    #[serde(deserialize_with = "flag")]
    pub refuse_connection: bool,
    /// Accept passwords from /etc/shadow when no key works (like
    /// PasswordAuthentication; off by default). System mode on Linux only;
    /// yescrypt and SHA-crypt hashes.
    #[serde(deserialize_with = "flag")]
    pub password_authentication: bool,
    /// Accept an empty password for accounts that have none (PermitEmptyPasswords).
    #[serde(deserialize_with = "flag")]
    pub permit_empty_passwords: bool,
    /// Use PAM (like UsePAM; qshd built with the `pam` feature, Linux, as
    /// root): every login passes the account check (`pam_acct_mgmt`),
    /// passwords are checked by `pam_authenticate`, and each session's
    /// program runs in a PAM session (pam_limits, pam_systemd, pam_env).
    #[serde(deserialize_with = "flag")]
    pub use_pam: bool,
    /// The PAM service: its file in /etc/pam.d.
    pub pam_service: String,
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

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PermitTunnel {
    #[default]
    No,
    Yes,
    PointToPoint,
    Ethernet,
}

impl PermitTunnel {
    /// Whether a tunnel of this kind (TAP with `ethernet`) is allowed.
    pub fn allows(self, ethernet: bool) -> bool {
        match self {
            PermitTunnel::No => false,
            PermitTunnel::Yes => true,
            PermitTunnel::PointToPoint => !ethernet,
            PermitTunnel::Ethernet => ethernet,
        }
    }
}

/// A yes/no setting: TOML's `true`/`false`, or as sshd and people write
/// them, `yes`/`no`, `on`/`off`, `1`/`0`.
fn flag<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Bool(bool),
        Int(i64),
        Text(String),
    }
    let bad = |v: String| serde::de::Error::custom(format!("{v} is not yes or no (true/false, yes/no, on/off, 1/0)"));
    match Raw::deserialize(d)? {
        Raw::Bool(b) => Ok(b),
        Raw::Int(1) => Ok(true),
        Raw::Int(0) => Ok(false),
        Raw::Int(n) => Err(bad(n.to_string())),
        Raw::Text(t) => match t.to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" | "1" => Ok(true),
            "no" | "false" | "off" | "0" => Ok(false),
            _ => Err(bad(format!("{t:?}"))),
        },
    }
}

fn opt_flag<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    flag(d).map(Some)
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
    /// Items given that qshd does not use as written, for `qshd -t`.
    pub notes: Vec<String>,
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
            notes: Vec::new(),
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
            "yes" | "true" | "on" | "1" => return Ok(p),
            "no" | "false" | "off" | "0" => return Ok(Penalties { enabled: false, ..p }),
            _ => {}
        }
        // sshd's per-family limits, each at the default until set.
        let (mut v4, mut v6) = (p.max_sources, p.max_sources);
        for word in text.split_whitespace() {
            let (key, value) = word.split_once(':').ok_or_else(|| format!("bad per_source_penalties item {word:?}"))?;
            if key == "max-sources4" || key == "max-sources6" || key == "max-sources" {
                let n = value.parse().ok().filter(|&n: &usize| n > 0).ok_or_else(|| format!("bad {key} {value:?}"))?;
                if key != "max-sources6" {
                    v4 = n;
                }
                if key != "max-sources4" {
                    v6 = n;
                }
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
                "crash" | "refuseconnection" => p.notes.push(format!("per_source_penalties: {key} has no effect in qshd")),
                _ => return Err(format!("unknown per_source_penalties item {key:?}")),
            }
        }
        // One shared table, and a full one penalizes no new source: the
        // larger limit is the stricter one, not whichever came last.
        p.max_sources = v4.max(v6);
        if v4 != v6 {
            p.notes.push(format!("per_source_penalties: qshd has one limit for IPv4 and IPv6 sources together; using max-sources {}", p.max_sources));
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
            Int(i64),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Bool(enabled) => Ok(Penalties { enabled, ..Penalties::default() }),
            Raw::Int(n @ (0 | 1)) => Ok(Penalties { enabled: n == 1, ..Penalties::default() }),
            Raw::Int(n) => Err(serde::de::Error::custom(format!("per_source_penalties: {n} is not 1 or 0"))),
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

/// `allow_users`/`deny_users`: like [`names`], but the address part of
/// `user@address` may be a comma-separated list. Commas between users still
/// separate them (`"alice,bob"`, `"alice,bob@192.0.2.0/24"`), as before v1.0.1.
fn user_entries<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
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
    let mut out = Vec::new();
    for word in words.iter().flat_map(|w| w.split([' ', '\t'])) {
        let (users, addresses) = match word.find('@') {
            Some(at) => word.split_at(at),
            None => (word, ""),
        };
        let mut users: Vec<&str> = users.split(',').collect();
        let last = users.pop().unwrap_or_default();
        out.extend(users.into_iter().map(str::to_string));
        out.push(format!("{last}{addresses}"));
    }
    out.retain(|w| !w.is_empty());
    Ok(out)
}

fn opt_user_entries<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    user_entries(d).map(Some)
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
            /// User name patterns (`!` excludes). Given but empty is an
            /// error (not "every login").
            #[serde(deserialize_with = "opt_names", skip_serializing_if = "Option::is_none")]
            pub user: Option<Vec<String>>,
            /// Group name patterns: any of the user's groups.
            #[serde(deserialize_with = "opt_names", skip_serializing_if = "Option::is_none")]
            pub group: Option<Vec<String>>,
            /// Client address patterns or CIDR ranges.
            #[serde(deserialize_with = "opt_names", skip_serializing_if = "Option::is_none")]
            pub address: Option<Vec<String>>,
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
        #[serde(deserialize_with = "opt_flag")]
        allow_agent_forwarding: bool,
        #[serde(deserialize_with = "opt_names")]
        allow_groups: Vec<String>,
        allow_tcp_forwarding: Forwarding,
        allow_stream_local_forwarding: Forwarding,
        stream_local_bind_mask: String,
        #[serde(deserialize_with = "opt_flag")]
        stream_local_bind_unlink: bool,
        #[serde(deserialize_with = "opt_user_entries")]
        allow_users: Vec<String>,
        #[serde(deserialize_with = "opt_names")]
        authorized_keys_file: Vec<String>,
        #[serde(deserialize_with = "opt_names")]
        deny_groups: Vec<String>,
        #[serde(deserialize_with = "opt_user_entries")]
        deny_users: Vec<String>,
        #[serde(deserialize_with = "opt_flag")]
        disable_forwarding: bool,
        gateway_ports: GatewayPorts,
        #[serde(deserialize_with = "opt_flag")]
        loopback_fallback: bool,
        max_auth_tries: u32,
        max_sessions: usize,
        #[serde(deserialize_with = "opt_flag")]
        password_authentication: bool,
        #[serde(deserialize_with = "opt_flag")]
        permit_empty_passwords: bool,
        #[serde(deserialize_with = "opt_names")]
        permit_listen: Vec<String>,
        #[serde(deserialize_with = "opt_names")]
        permit_open: Vec<String>,
        permit_root_login: PermitRootLogin,
        #[serde(deserialize_with = "opt_flag")]
        permit_tty: bool,
        permit_tunnel: PermitTunnel,
        #[serde(deserialize_with = "opt_flag")]
        permit_user_rc: bool,
        #[serde(deserialize_with = "opt_flag")]
        refuse_connection: bool,
        set_env: BTreeMap<String, String>,
        totp: Totp,
        totp_valid_for: u64,
        #[serde(deserialize_with = "opt_flag")]
        use_qsh_authorized_keys: bool,
        #[serde(deserialize_with = "opt_flag")]
        use_ssh_authorized_keys: bool,
        x11_display_offset: u32,
        #[serde(deserialize_with = "opt_flag")]
        x11_forwarding: bool,
        #[serde(deserialize_with = "opt_flag")]
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
        self.user.as_ref().is_none_or(|u| name_matches(u, who.user))
            && self.group.as_ref().is_none_or(|g| groups_match(g, who.groups))
            && self.address.as_ref().is_none_or(|a| address_allowed(&a.join(","), who.addr))
    }

    fn conditions(&self) -> [(&'static str, &Option<Vec<String>>); 3] {
        [("user", &self.user), ("group", &self.group), ("address", &self.address)]
    }

    /// `user = backup, address = 10.0.0.0/8`, for messages.
    fn describe(&self) -> String {
        let given: Vec<String> = self.conditions().iter().filter_map(|(n, v)| v.as_ref().map(|v| format!("{n} = {}", v.join(",")))).collect();
        if given.is_empty() { "every login".into() } else { given.join(", ") }
    }
}

/// Every top-level setting, to catch one that TOML put inside a table
/// (`[set_env]`, `[subsystems]`) because it came after the table's header.
/// The test `setting_names_are_complete` keeps it in sync.
const SETTING_NAMES: &[&str] = &[
    "listen", "tcp", "host_key", "use_ssh_authorized_keys", "use_qsh_authorized_keys", "authorized_keys_file",
    "authorized_principals_file", "allow_tcp_forwarding", "disable_forwarding", "allow_stream_local_forwarding",
    "stream_local_bind_mask", "stream_local_bind_unlink", "x11_forwarding", "x11_display_offset", "x11_use_localhost",
    "xauth_location", "permit_tunnel", "permit_open", "permit_listen", "max_connections", "max_startups",
    "max_startups_per_ip", "connection_buffer_mb", "session_scope", "gateway_ports", "loopback_fallback", "subsystems", "trusted_user_ca_keys",
    "max_auth_tries", "totp_valid_for", "allow_agent_forwarding", "totp", "host_certificate", "revoked_keys",
    "authorized_keys_command", "authorized_keys_command_user", "session_timeout", "allow_users", "deny_users",
    "allow_groups", "deny_groups", "permit_root_login", "login_grace_time", "banner", "print_motd", "print_last_log",
    "permit_user_rc", "max_sessions", "permit_tty", "accept_env", "set_env", "force_command", "chroot_directory",
    "client_alive_interval", "client_alive_count_max", "refuse_connection", "password_authentication",
    "permit_empty_passwords", "use_pam", "pam_service", "per_source_penalties", "per_source_penalty_exempt_list", "match",
];

/// `[[match]]` settings that change who may log in, how, and what they may
/// do: [`ServerConfig::match_overrides`] reports blocks that change them.
const ACCESS_SETTINGS: &[&str] = &[
    "password_authentication", "permit_empty_passwords", "permit_root_login", "totp", "totp_valid_for",
    "refuse_connection", "allow_users", "deny_users", "allow_groups", "deny_groups", "force_command",
    "chroot_directory", "authorized_keys_file", "authorized_keys_command", "authorized_keys_command_user",
    "authorized_principals_file", "trusted_user_ca_keys", "revoked_keys", "use_ssh_authorized_keys",
    "use_qsh_authorized_keys", "max_auth_tries", "disable_forwarding", "allow_tcp_forwarding",
    "allow_stream_local_forwarding", "allow_agent_forwarding", "x11_forwarding", "x11_use_localhost", "permit_tunnel",
    "permit_open", "permit_listen", "gateway_ports", "loopback_fallback", "permit_tty", "permit_user_rc", "accept_env", "set_env",
    "stream_local_bind_mask", "stream_local_bind_unlink",
];

/// A host name where only addresses work (qshd does no DNS lookups): not
/// an address, range or pattern of one (IPv6 has hex letters, so not just
/// "has letters").
fn is_host_name(pattern: &str) -> bool {
    let p = pattern.trim_start_matches('!');
    !p.is_empty() && p.parse::<IpAddr>().is_err() && !cidr_valid(p) && !p.bytes().all(|b| b.is_ascii_hexdigit() || b":.*?/".contains(&b))
}

/// A list of `!` patterns only: like in sshd, it matches no one.
fn only_negations(list: &[String]) -> bool {
    !list.is_empty() && list.iter().all(|p| p.starts_with('!'))
}

/// Problems with `allow_users`/`deny_users` entries that make them match
/// no one: a `!` user, only `!` addresses, a host name.
fn user_entry_warnings(what: &str, entries: &[String], out: &mut Vec<String>) {
    for entry in entries {
        let (user, host) = match entry.rsplit_once('@') {
            Some((u, h)) => (u, Some(h)),
            None => (entry.as_str(), None),
        };
        if user.starts_with('!') {
            out.push(format!("{what}: {entry:?}: '!' does not exclude here, so it matches no one"));
        }
        let Some(host) = host else { continue };
        let hosts: Vec<String> = host.split(',').map(str::to_string).collect();
        if only_negations(&hosts) {
            out.push(format!("{what}: {entry:?} has only excluded addresses, so it matches no one, as in sshd; write \"{user}@*,{host}\""));
        }
        if let Some(h) = hosts.iter().find(|h| is_host_name(h)) {
            out.push(format!("{what}: {entry:?}: {h:?} is a host name; qshd matches addresses only, so it never matches"));
        }
    }
}

/// Like sshd: a group matching an excluded pattern fails, any group matching a pattern passes.
fn groups_match(patterns: &[String], groups: &[String]) -> bool {
    let excluded = patterns.iter().filter_map(|p| p.strip_prefix('!')).any(|p| groups.iter().any(|g| wildcard(p, g)));
    !excluded && groups.iter().any(|g| name_matches(patterns, g))
}

/// `user` or `user@addresses` from AllowUsers/DenyUsers. The addresses are
/// a comma-separated list of wildcard patterns and CIDRs, `!` negating (a
/// negated match rules the entry out), as in sshd.
fn user_entry_matches(entry: &str, who: &Login) -> bool {
    let (user, host) = match entry.rsplit_once('@') {
        Some((u, h)) => (u, Some(h)),
        None => (entry, None),
    };
    let addr = who.addr.to_canonical();
    let one = |p: &str| if p.contains('/') { cidr_contains(p, addr).unwrap_or(false) } else { address_matches(p, addr) };
    wildcard(user, who.user)
        && host.is_none_or(|h| {
            let mut found = false;
            for p in h.split(',') {
                match p.strip_prefix('!') {
                    Some(neg) if one(neg) => return false,
                    Some(_) => {}
                    None => found |= one(p),
                }
            }
            found
        })
}

/// Whether `cidr` is a range of either family (an IPv6 one is only checked
/// against an IPv6 address).
fn cidr_valid(cidr: &str) -> bool {
    cidr_contains(cidr, IpAddr::from([0u8; 4])).is_some() && cidr_contains(cidr, IpAddr::from([0u16; 8])).is_some()
}

/// Checks the address ranges of AllowUsers/DenyUsers entries: a broken one
/// would never match, which for deny_users means letting users in.
fn check_user_entries(what: &str, entries: &[String]) -> Result<()> {
    for entry in entries {
        let Some((_, host)) = entry.rsplit_once('@') else { continue };
        for cidr in host.split(',').map(|p| p.trim_start_matches('!')).filter(|p| p.contains('/')) {
            if !cidr_valid(cidr) {
                bail!("{what}: bad address range {cidr:?} in {entry:?}");
            }
        }
    }
    Ok(())
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: SocketAddr::from(([0u16; 8], crate::DEFAULT_PORT)),
            tcp: true,
            host_key: None,
            use_ssh_authorized_keys: true,
            use_qsh_authorized_keys: true,
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
            permit_tunnel: PermitTunnel::No,
            permit_open: Vec::new(),
            permit_listen: Vec::new(),
            max_connections: 256,
            connection_buffer_mb: 32,
            session_scope: true,
            max_startups: 64,
            max_startups_per_ip: 8,
            gateway_ports: GatewayPorts::No,
            loopback_fallback: false,
            subsystems: BTreeMap::new(),
            trusted_user_ca_keys: None,
            max_auth_tries: 6,
            totp_valid_for: 3600,
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
            password_authentication: false,
            permit_empty_passwords: false,
            use_pam: false,
            pam_service: "qshd".into(),
            per_source_penalties: Penalties::default(),
            per_source_penalty_exempt_list: Vec::new(),
            matches: Vec::new(),
        }
    }
}

impl ServerConfig {
    /// Loads `path`; a missing file is an error.
    pub fn load(path: &Path) -> Result<ServerConfig> {
        Self::load_optional(path)?.with_context(|| format!("config file {} not found", path.display()))
    }

    /// Loads `path`, or `None` if it does not exist.
    pub fn load_optional(path: &Path) -> Result<Option<ServerConfig>> {
        let cfg: ServerConfig = match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        cfg.validate().with_context(|| format!("invalid {}", path.display()))?;
        Ok(Some(cfg))
    }

    /// Limits of 0 would silently refuse every connection or login.
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("max_connections", self.max_connections),
            ("max_startups", self.max_startups),
            ("max_startups_per_ip", self.max_startups_per_ip),
            ("max_auth_tries", self.max_auth_tries as usize),
            ("connection_buffer_mb", self.connection_buffer_mb as usize),
        ] {
            if value == 0 {
                bail!("{name} must be at least 1");
            }
        }
        if self.connection_buffer_mb > 4000 {
            bail!("connection_buffer_mb must be at most 4000");
        }
        for mask in std::iter::once(&self.stream_local_bind_mask).chain(self.matches.iter().flat_map(|m| &m.stream_local_bind_mask)) {
            if u32::from_str_radix(mask, 8).map_or(true, |m| m > 0o777) {
                bail!("stream_local_bind_mask: {mask:?} is not an octal mask like \"0177\"");
            }
        }
        if self.use_pam && !cfg!(all(feature = "pam", target_os = "linux")) {
            bail!("use_pam: this qshd was built without PAM (build it on Linux with `cargo build --features pam`)");
        }
        if self.pam_service.is_empty() || !self.pam_service.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
            bail!("pam_service: {:?} is not a file name in /etc/pam.d", self.pam_service);
        }
        let penalties = &self.per_source_penalties;
        if penalties.enabled && penalties.min > penalties.max {
            bail!("per_source_penalties: min is above max, so no source would ever be dropped");
        }
        if penalties.enabled && penalties.max_sources == 0 {
            bail!("per_source_penalties: max_sources must be at least 1 (or turn penalties off)");
        }
        for entry in self.per_source_penalty_exempt_list.iter().filter(|e| e.contains('/')) {
            if !cidr_valid(entry) {
                bail!("per_source_penalty_exempt_list: bad address range {entry:?}");
            }
        }
        check_user_entries("allow_users", &self.allow_users)?;
        check_user_entries("deny_users", &self.deny_users)?;
        for (i, m) in self.matches.iter().enumerate() {
            check_user_entries(&format!("match block {}: allow_users", i + 1), m.allow_users.as_deref().unwrap_or_default())?;
            check_user_entries(&format!("match block {}: deny_users", i + 1), m.deny_users.as_deref().unwrap_or_default())?;
            if m.max_auth_tries == Some(0) {
                bail!("match block {}: max_auth_tries must be at least 1", i + 1);
            }
            if let Some((name, _)) = m.conditions().into_iter().find(|(_, v)| v.as_ref().is_some_and(Vec::is_empty)) {
                bail!("[[match]] #{}: {name} is empty, it would match every login", i + 1);
            }
            for cidr in m.address.iter().flatten().map(|a| a.trim_start_matches('!')).filter(|a| a.contains('/')) {
                if !cidr_valid(cidr) {
                    bail!("match block {}: bad address range {cidr:?}", i + 1);
                }
            }
        }
        let env_tables = std::iter::once(("[set_env]", &self.set_env))
            .chain(self.matches.iter().filter_map(|m| m.set_env.as_ref().map(|e| ("[match.set_env]", e))));
        for (table, env) in env_tables.chain([("[subsystems]", &self.subsystems)]) {
            // In [match.set_env], a block's condition too: lost, the block would match every login.
            let conditions: &[&str] = if table == "[match.set_env]" { &["user", "group", "address"] } else { &[] };
            if let Some(name) = env.keys().find(|k| SETTING_NAMES.contains(&k.as_str()) || conditions.contains(&k.as_str())) {
                bail!("'{name}' is inside {table}: settings must come before the first [table]");
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
            || self.matches.iter().any(|m| m.group.is_some() || m.allow_groups.is_some() || m.deny_groups.is_some())
    }

    /// The first setting that depends on the client's address: a
    /// `[[match]]` address condition or a `user@host` entry.
    pub fn needs_address(&self) -> Option<String> {
        let has_host = |list: &[String]| list.iter().any(|e| e.contains('@'));
        if has_host(&self.allow_users) || has_host(&self.deny_users) {
            return Some(if has_host(&self.deny_users) { "deny_users" } else { "allow_users" }.into());
        }
        self.matches.iter().enumerate().find_map(|(i, m)| {
            let what = if m.address.is_some() {
                "address"
            } else if has_host(m.deny_users.as_deref().unwrap_or_default()) {
                "deny_users"
            } else if has_host(m.allow_users.as_deref().unwrap_or_default()) {
                "allow_users"
            } else {
                return None;
            };
            Some(format!("[[match]] #{} {what}", i + 1))
        })
    }

    /// Settings that load but do not do what they seem to, for `qshd -t`
    /// and the log.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = self.per_source_penalties.notes.clone();
        user_entry_warnings("allow_users", &self.allow_users, &mut out);
        user_entry_warnings("deny_users", &self.deny_users, &mut out);
        for (i, m) in self.matches.iter().enumerate() {
            let n = i + 1;
            for (name, list) in m.conditions() {
                let Some(list) = list else { continue };
                if only_negations(list) {
                    out.push(format!("[[match]] #{n}: {name} = {:?} matches no one, as in sshd; write \"*,{}\"", list.join(","), list.join(",")));
                }
                if name == "address" {
                    if let Some(h) = list.iter().find(|a| is_host_name(a)) {
                        out.push(format!("[[match]] #{n}: address {h:?} is a host name; qshd matches addresses only, so it never matches"));
                    }
                }
            }
            user_entry_warnings(&format!("[[match]] #{n}: allow_users"), m.allow_users.as_deref().unwrap_or_default(), &mut out);
            user_entry_warnings(&format!("[[match]] #{n}: deny_users"), m.deny_users.as_deref().unwrap_or_default(), &mut out);
        }
        out
    }

    /// `[[match]]` blocks that change who may log in or how, against the
    /// global value: `[[match]] #2 (user = backup) changes
    /// password_authentication: false -> true`. This shows a global setting
    /// that ended up under a `[[match]]` header by mistake.
    pub fn match_overrides(&self) -> Vec<String> {
        fn table(v: &impl Serialize) -> toml::Table {
            toml::Table::try_from(v).unwrap_or_default()
        }
        let unset = |v: Option<&toml::Value>| v.is_none_or(|v| v.as_str() == Some("none"));
        // permit_open/permit_listen: `[]` and `["any"]` both allow any.
        let any = toml::Value::Array(vec!["any".into()]);
        let plain = |name: &str, v: Option<&toml::Value>| match v {
            Some(v) if v == &any && matches!(name, "permit_open" | "permit_listen") => Some(toml::Value::Array(Vec::new())),
            v => v.cloned(),
        };
        let show = |v: Option<&toml::Value>| v.map_or("unset".to_string(), toml::Value::to_string);
        let global = table(self);
        let mut out = Vec::new();
        for (i, m) in self.matches.iter().enumerate() {
            let local = table(m);
            for name in ACCESS_SETTINGS {
                let Some(new) = local.get(*name) else { continue };
                let old = global.get(*name);
                if plain(name, old) == plain(name, Some(new)) || (unset(old) && unset(Some(new))) {
                    continue;
                }
                out.push(format!("[[match]] #{} ({}) changes {name}: {} -> {}", i + 1, m.describe(), show(old), show(Some(new))));
            }
        }
        out
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

    /// `permit_open` / `permit_listen` limit forwarding to some addresses:
    /// then Unix sockets, which they cannot name, are not forwarded either
    /// (a limit must not leave a way around it).
    pub fn limits_open(&self) -> bool {
        !(self.permit_open.is_empty() || self.permit_open == ["any"])
    }

    pub fn limits_listen(&self) -> bool {
        !(self.permit_listen.is_empty() || self.permit_listen == ["any"])
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

    #[test]
    fn penalties_that_cannot_work_are_refused() {
        for bad in ["per_source_penalties = \"min:100 max:10\"\n", "per_source_penalties = \"max-sources:0\"\n", "per_source_penalty_exempt_list = [\"10.0.0.0/99\"]\n"] {
            let parsed = toml::from_str::<ServerConfig>(bad).map_err(anyhow::Error::from).and_then(|c| c.validate());
            assert!(parsed.is_err(), "{bad}");
        }
    }

    /// The template qshd writes (contrib/qshd.toml) changes nothing as it
    /// is, and every setting in it parses once uncommented.
    #[test]
    fn yes_no_settings() {
        let cfg: ServerConfig = toml::from_str("tcp = \"no\"\nprint_motd = 0\npermit_tty = \"Off\"\nx11_forwarding = \"yes\"\nper_source_penalties = \"off\"\n[[match]]\nuser = \"a\"\npermit_tty = \"on\"\n").unwrap();
        assert!(!cfg.tcp && !cfg.print_motd && !cfg.permit_tty && cfg.x11_forwarding && !cfg.per_source_penalties.enabled);
        assert_eq!(cfg.matches[0].permit_tty, Some(true));
        let err = toml::from_str::<ServerConfig>("tcp = \"maybe\"\n").unwrap_err().to_string();
        assert!(err.contains("yes or no"), "{err}");
        assert!(toml::from_str::<ServerConfig>("tcp = 2\n").is_err());
    }

    #[test]
    fn config_template() {
        let template = include_str!("../contrib/qshd.toml");
        let as_is: ServerConfig = toml::from_str(template).unwrap();
        assert_eq!(toml::to_string(&as_is).unwrap(), toml::to_string(&ServerConfig::default()).unwrap());
        fn setting(l: &str) -> Option<&str> {
            l.strip_prefix("# ").filter(|r| r.starts_with('[') || r.split_once(" = ").is_some_and(|(k, _)| !k.contains(' ')))
        }
        let uncommented: String = template.lines().map(|l| setting(l).unwrap_or(l)).collect::<Vec<_>>().join("\n");
        let cfg: ServerConfig = toml::from_str(&uncommented).unwrap_or_else(|e| panic!("{e}\n{uncommented}"));
        cfg.validate().unwrap();
        assert_eq!(cfg.totp, Totp::Optional);
    }

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
    }

    /// A typo in `-c` or a file moved away before SIGHUP is not "defaults".
    #[test]
    fn missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.toml");
        assert!(format!("{:#}", ServerConfig::load(&missing).unwrap_err()).contains("not found"));
        assert!(ServerConfig::load_optional(&missing).unwrap().is_none());
    }

    /// The names serde knows, from its "unknown field" error.
    fn known_fields<T: serde::de::DeserializeOwned + std::fmt::Debug>() -> Vec<String> {
        let err = toml::from_str::<T>("not_a_setting_x = 1").unwrap_err().to_string();
        let list = err.split("expected one of").nth(1).unwrap_or_else(|| panic!("{err}"));
        list.split(',').map(|w| w.trim().trim_matches(|c: char| c == '`' || c.is_whitespace()).to_string()).filter(|w| !w.is_empty()).collect()
    }

    #[test]
    fn setting_names_are_complete() {
        let mut known = known_fields::<ServerConfig>();
        let mut ours: Vec<String> = SETTING_NAMES.iter().map(|s| s.to_string()).collect();
        known.sort();
        ours.sort();
        assert_eq!(ours, known);
        let block = known_fields::<MatchBlock>();
        for name in ACCESS_SETTINGS {
            assert!(block.iter().any(|b| b == name), "{name} is no [[match]] setting");
        }
    }

    /// A global setting after `[set_env]`/`[subsystems]` is TOML's key of
    /// that table: refused rather than silently an env var.
    #[test]
    fn setting_inside_a_table() {
        for (text, table) in [
            ("[set_env]\nTZ = \"UTC\"\npermit_root_login = \"no\"\n", "[set_env]"),
            ("[subsystems]\nsftp = \"internal-sftp\"\nallow_users = \"alice\"\n", "[subsystems]"),
            ("[[match]]\nuser = \"a\"\n[match.set_env]\npassword_authentication = \"no\"\n", "[match.set_env]"),
            // A condition after the table would be lost: the block would match every login.
            ("[[match]]\npassword_authentication = true\n[match.set_env]\nFOO = \"1\"\nuser = \"backup\"\n", "'user' is inside [match.set_env]"),
            ("[[match]]\nuser = \"a\"\n[match.set_env]\naddress = \"10.0.0.0/8\"\n", "'address' is inside [match.set_env]"),
        ] {
            let err = toml::from_str::<ServerConfig>(text).unwrap().validate().unwrap_err().to_string();
            assert!(err.contains(table) && err.contains("must come before the first [table]"), "{err}");
        }
        parse("[set_env]\nTZ = \"UTC\"\nPERMIT_ROOT_LOGIN = \"x\"\nuser = \"x\"\n");
    }

    #[test]
    fn empty_match_condition() {
        for (text, what) in [
            ("[[match]]\nuser = \"\"\npermit_tty = false\n", "user is empty"),
            ("[[match]]\ngroup = []\n", "group is empty"),
            ("[[match]]\nuser = \"a\"\n[[match]]\naddress = \" , \"\n", "#2: address is empty"),
        ] {
            let err = toml::from_str::<ServerConfig>(text).unwrap().validate().unwrap_err().to_string();
            assert!(err.contains(what) && err.contains("every login"), "{err}");
        }
        // Not given at all: every login, as documented.
        let cfg = parse("[[match]]\npermit_tty = false\n");
        assert!(!cfg.for_login(&who("u", &[], "192.0.2.1")).permit_tty);
    }

    #[test]
    fn match_warnings() {
        let cfg = parse(
            "allow_users = \"!root alice@!10.0.0.0/8 bob@office.example.com carol@2001:db8::1,10.*\"\n\
             [[match]]\nuser = \"!root\"\naddress = \"!192.0.2.0/24\"\n\
             [[match]]\naddress = \"vpn.example.com,fe80::/10\"\ndeny_users = \"x@!1.2.3.4\"\n\
             [[match]]\nuser = \"*,!root\"\naddress = \"10.*,::1,cafe::/16\"\n",
        );
        let w = cfg.warnings();
        let has = |s: &str| w.iter().any(|l| l.contains(s));
        assert!(has("allow_users: \"!root\": '!' does not exclude"), "{w:#?}");
        assert!(has("allow_users: \"alice@!10.0.0.0/8\" has only excluded"), "{w:#?}");
        assert!(has("\"office.example.com\" is a host name"), "{w:#?}");
        assert!(has("[[match]] #1: user = \"!root\" matches no one"), "{w:#?}");
        assert!(has("[[match]] #1: address = \"!192.0.2.0/24\" matches no one"), "{w:#?}");
        assert!(has("[[match]] #2: address \"vpn.example.com\" is a host name"), "{w:#?}");
        assert!(has("[[match]] #2: deny_users: \"x@!1.2.3.4\""), "{w:#?}");
        assert!(!w.iter().any(|l| l.contains("#3") || l.contains("carol")), "{w:#?}");
        assert!(parse("").warnings().is_empty());
        assert_eq!(parse("[[match]]\naddress = \"10.0.0.0/8\"\n[[match]]\naddress = \"::1\"\n").needs_address().as_deref(), Some("[[match]] #1 address"));
        assert_eq!(parse("[[match]]\nuser = \"a\"\nallow_users = \"a\"\n").needs_address(), None);
        // user@host entries test the address too.
        assert_eq!(parse("deny_users = \"alice@10.*\"\n").needs_address().as_deref(), Some("deny_users"));
        assert_eq!(parse("allow_users = \"alice@10.0.0.0/8 bob\"\n").needs_address().as_deref(), Some("allow_users"));
        let cfg = parse("[[match]]\nuser = \"a\"\n[[match]]\nuser = \"b\"\nallow_users = \"b@::1\"\n");
        assert_eq!(cfg.needs_address().as_deref(), Some("[[match]] #2 allow_users"));
    }

    #[test]
    fn match_overrides() {
        let cfg = parse(
            "password_authentication = false\nforce_command = \"/bin/global\"\n\
             [[match]]\nuser = \"admin\"\npermit_tty = false\nmax_sessions = 2\n\
             [[match]]\nuser = \"backup\"\npassword_authentication = true\npermit_root_login = \"prohibit-password\"\n\
             deny_users = \"mallory\"\nforce_command = \"none\"\nchroot_directory = \"none\"\n",
        );
        assert_eq!(
            cfg.match_overrides(),
            [
                "[[match]] #1 (user = admin) changes permit_tty: true -> false",
                "[[match]] #2 (user = backup) changes password_authentication: false -> true",
                "[[match]] #2 (user = backup) changes deny_users: [] -> [\"mallory\"]",
                "[[match]] #2 (user = backup) changes force_command: \"/bin/global\" -> \"none\"",
            ]
        );
        assert_eq!(parse("[[match]]\npermit_tty = false\n").match_overrides(), ["[[match]] #1 (every login) changes permit_tty: true -> false"]);
        // `["any"]` is the default `[]`; `["none"]` is not.
        let cfg = parse("[[match]]\nuser = \"a\"\npermit_open = \"any\"\npermit_listen = \"any\"\n[[match]]\nuser = \"b\"\npermit_open = \"none\"\n");
        assert_eq!(cfg.match_overrides(), ["[[match]] #2 (user = b) changes permit_open: [] -> [\"none\"]"]);
        let cfg = parse("[[match]]\nuser = \"a\"\naccept_env = \"LD_PRELOAD\"\nx11_use_localhost = false\n");
        assert_eq!(cfg.match_overrides().len(), 2, "{:?}", cfg.match_overrides());
        assert!(parse("").match_overrides().is_empty());
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
        // Address lists, with negation.
        let cfg = parse("allow_users = \"dave@192.0.2.0/24,!192.0.2.9,198.51.100.*\"\n");
        assert!(cfg.login_refused(&who("dave", none, "192.0.2.1")).is_none());
        assert!(cfg.login_refused(&who("dave", none, "198.51.100.7")).is_none());
        assert!(cfg.login_refused(&who("dave", none, "192.0.2.9")).is_some(), "negated");
        // Commas between users separate them, as before v1.0.1.
        let cfg = parse("deny_users = \"alice,bob, carol,erin@192.0.2.0/24,!192.0.2.9\"\n");
        for user in ["alice", "bob", "carol"] {
            assert!(cfg.login_refused(&who(user, none, "203.0.113.1")).is_some(), "{user}");
        }
        assert!(cfg.login_refused(&who("erin", none, "192.0.2.1")).is_some());
        assert!(cfg.login_refused(&who("erin", none, "192.0.2.9")).is_none(), "the address list stays one");
        assert!(cfg.login_refused(&who("dave", none, "192.0.2.1")).is_none());
        // A broken range is an error, not an entry that never matches.
        let text = "deny_users = \"bob@192.0.2.0/99\"\n";
        let parsed: ServerConfig = toml::from_str(text).unwrap();
        assert!(parsed.validate().is_err());

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
            "[[match]]\naddress = \"2001:db8::/200\"",
            "deny_users = [\"*@2001:db8::/129\"]",
            "[set_env]\n\"A=B\" = \"x\"",
            "pam_service = \"../sshd\"",
            "pam_service = \"\"",
        ] {
            let parsed = toml::from_str::<ServerConfig>(bad).map_err(anyhow::Error::from).and_then(|c| c.validate().map(|_| c));
            assert!(parsed.is_err(), "{bad}");
        }
        assert_eq!(parse("permit_root_login = \"without-password\"").permit_root_login, PermitRootLogin::ProhibitPassword);
    }

    /// `use_pam` is refused, not ignored, by a qshd built without PAM.
    #[test]
    fn use_pam_needs_the_feature() {
        assert!(!parse("").use_pam);
        assert_eq!(parse("").pam_service, "qshd");
        let c = toml::from_str::<ServerConfig>("use_pam = true\npam_service = \"sshd\"").unwrap();
        assert_eq!(c.validate().is_ok(), cfg!(all(feature = "pam", target_os = "linux")));
    }

    #[test]
    fn penalties() {
        assert_eq!(parse("").per_source_penalties, Penalties::default());
        assert!(!parse("per_source_penalties = false").per_source_penalties.enabled);
        let p = parse("per_source_penalties = \"authfail:30s min:1m max:2h crash:90\"").per_source_penalties;
        assert_eq!((p.authfail, p.min, p.max), (Duration::from_secs(30), Duration::from_secs(60), Duration::from_secs(7200)));
        assert!(toml::from_str::<ServerConfig>("per_source_penalties = \"authfail:x\"").is_err());
        assert!(toml::from_str::<ServerConfig>("per_source_penalties = \"bogus:1\"").is_err());
        assert!(p.notes.iter().any(|n| n.contains("crash has no effect")), "{:?}", p.notes);
        // One shared limit: the larger one (a full table penalizes no new source), whatever the order.
        let p = parse("per_source_penalties = \"max-sources4:1000 max-sources6:65536\"").per_source_penalties;
        assert_eq!(p.max_sources, 65536);
        assert_eq!(parse("per_source_penalties = \"max-sources6:65536 max-sources4:1000\"").per_source_penalties.max_sources, 65536);
        assert!(p.notes.iter().any(|n| n.contains("one limit for IPv4 and IPv6")));
        let cfg = parse("per_source_penalties = \"max-sources6:500 max-sources4:500 refuseconnection:10s\"");
        assert_eq!(cfg.per_source_penalties.max_sources, 500);
        assert_eq!(cfg.warnings(), ["per_source_penalties: refuseconnection has no effect in qshd"]);
        // A later shared value sets both; a family left out keeps the default.
        assert_eq!(parse("per_source_penalties = \"max-sources4:100 max-sources6:200 max-sources:50\"").per_source_penalties.max_sources, 50);
        let p = parse("per_source_penalties = \"max-sources6:1000\"").per_source_penalties;
        assert_eq!(p.max_sources, Penalties::default().max_sources);
        assert!(p.notes.iter().any(|n| n.contains("one limit for IPv4 and IPv6")));
        assert!(toml::from_str::<ServerConfig>("per_source_penalties = \"max-sources4:0\"").is_err());
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
