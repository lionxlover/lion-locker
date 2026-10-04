//! `lion-locker` — LionOS secure screen lock (spec 03).
//!
//! Takes exclusive input through `ext-session-lock-v1` (the compositor
//! itself guarantees nothing but the lock surface is visible or focusable,
//! and keeps the screen locked if this process dies), verifies credentials
//! with PAM, and drives the `lion-lockscreen` UI over a local socket. Bus
//! service `os.lionos.Locker1`.
//!
//! Unsafe policy (spec 03 §8): every module carries
//! `#![forbid(unsafe_code)]` EXCEPT the two audited FFI modules —
//! `sysffi` (uid/pidfd/getpwuid_r) and `pam::sys` (dlopen'd libpam) —
//! mirroring lion-greeter and lion-session.

pub mod auth;
pub mod authz;
pub mod backends;
pub mod cli;
pub mod codec;
pub mod config;
pub mod core;
pub mod error;
pub mod mocks;
pub mod notify;
pub mod pam;
pub mod ports;
pub mod proto;
pub mod secret;
pub mod sysffi;
pub mod throttle;
pub mod uisock;

#[cfg(feature = "real-bus")]
pub mod bus;
#[cfg(feature = "real-wayland")]
pub mod wayland;

pub use config::{Config, DEFAULT_CONFIG_PATH, SCHEMA_JSON};
pub use error::{Error, Result};

/// Crate version (reported by `--version`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Spec number this crate implements.
pub const SPEC: &str = "03";
