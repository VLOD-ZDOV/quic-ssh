//! qsh — secure shell over QUIC with automatic TCP fallback.

pub mod agent;
pub mod authkeys;
pub mod client;
pub mod config;
pub mod keys;
pub mod pair;
pub mod pattern;
pub mod proto;
pub mod server;
pub mod tls;
pub mod transport;
pub mod tree;

/// Default port for both UDP (QUIC) and TCP (fallback).
pub const DEFAULT_PORT: u16 = 4422;
