//! Server configuration (`config.toml`).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address for both UDP (QUIC) and TCP.
    pub listen: SocketAddr,
    /// Also accept the TLS-over-TCP fallback. With `false` qshd listens on UDP
    /// only, so it can share a port number with sshd (e.g. 22) for `qsh --full`.
    pub tcp: bool,
    /// Host key path; defaults to `host_ed25519` next to the config file.
    pub host_key: Option<PathBuf>,
    /// Also accept keys from `~/.ssh/authorized_keys`.
    pub use_ssh_authorized_keys: bool,
    /// Allow `-L` port forwarding.
    pub allow_tcp_forwarding: bool,
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
    pub trusted_user_ca_keys: Option<PathBuf>,
    /// Failed key proofs allowed per connection (like sshd's MaxAuthTries).
    pub max_auth_tries: u32,
    /// Allow `qsh -A` (ssh-agent forwarding).
    pub allow_agent_forwarding: bool,
    /// One-time codes (TOTP) as a second factor after the key.
    pub totp: Totp,
    /// OpenSSH host certificate for the host key; defaults to
    /// `<host_key>-cert.pub` if that exists.
    pub host_certificate: Option<PathBuf>,
    /// Keys and certificates that may not log in: a list of public keys or a
    /// KRL from `ssh-keygen -k` (like sshd's RevokedKeys). If the file
    /// cannot be read, no key is accepted.
    pub revoked_keys: Option<PathBuf>,
    /// A program that prints more authorized keys for a user (like sshd's
    /// AuthorizedKeysCommand); see `server::keys_command`.
    pub authorized_keys_command: Option<String>,
    /// The user it runs as when qshd runs as root (required then; not root).
    pub authorized_keys_command_user: Option<String>,
    /// How long an interactive session survives without its client (seconds),
    /// so it can be resumed after a network outage. 0 turns this off.
    pub session_timeout: u64,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Default)]
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

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GatewayPorts {
    #[default]
    No,
    Yes,
    ClientSpecified,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: SocketAddr::from(([0u16; 8], crate::DEFAULT_PORT)),
            tcp: true,
            host_key: None,
            use_ssh_authorized_keys: true,
            allow_tcp_forwarding: true,
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
                anyhow::bail!("{name} must be at least 1");
            }
        }
        #[cfg(unix)]
        if let Some(cmd) = &self.authorized_keys_command {
            crate::server::keys_command::validate(cmd)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
