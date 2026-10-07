//! Server configuration (`config.toml`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address for both UDP (QUIC) and TCP.
    pub listen: SocketAddr,
    /// Host key path; defaults to `host_ed25519` next to the config file.
    pub host_key: Option<PathBuf>,
    /// Also accept keys from `~/.ssh/authorized_keys`.
    pub use_ssh_authorized_keys: bool,
    /// Allow `-L` port forwarding.
    pub allow_tcp_forwarding: bool,
    /// Maximum simultaneous connections.
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: SocketAddr::from(([0u16; 8], crate::DEFAULT_PORT)),
            host_key: None,
            use_ssh_authorized_keys: true,
            allow_tcp_forwarding: true,
            max_connections: 256,
        }
    }
}

impl ServerConfig {
    /// Loads `path` if it exists, otherwise returns defaults.
    pub fn load(path: &Path) -> Result<ServerConfig> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).with_context(|| format!("invalid {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ServerConfig::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }
}
