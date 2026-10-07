//! qsh — secure shell over QUIC with automatic TCP fallback.

pub mod agent;
#[cfg(unix)]
pub mod authkeys;
pub mod client;
pub mod config;
pub mod keys;
pub mod pair;
pub mod pattern;
pub mod platform;
pub mod prompt;
pub mod proto;
#[cfg(unix)]
pub mod server;
pub mod tls;
pub mod totp;
pub mod transport;
pub mod tree;

/// Default port for both UDP (QUIC) and TCP (fallback).
pub const DEFAULT_PORT: u16 = 4422;
