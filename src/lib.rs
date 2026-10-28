//! qsh — secure shell over QUIC with automatic TCP fallback.
#![cfg_attr(not(feature = "pam"), forbid(unsafe_code))]
// The `pam` feature brings the one module that calls C (libpam); nothing else may.
#![cfg_attr(feature = "pam", deny(unsafe_code))]

pub mod agent;
pub mod authkeys;
pub mod client;
pub mod config;
pub mod keys;
pub mod pair;
pub mod pattern;
pub mod platform;
pub mod prompt;
pub mod proto;
pub mod punch;
pub mod server;
pub mod tls;
pub mod totp;
pub mod transport;
pub mod tree;
pub mod tunnel;

/// Default port for both UDP (QUIC) and TCP (fallback).
pub const DEFAULT_PORT: u16 = 4422;
