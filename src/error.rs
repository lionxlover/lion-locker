#![forbid(unsafe_code)]
//! Unified error type for `lion-locker`.
//!
//! Variants stay data-only and never carry secret material (spec 03 §8:
//! secrets never reach logs or error strings). PAM detail codes are logged
//! server-side only and mapped to non-revealing reasons before they reach
//! the UI.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Configuration could not be loaded or failed validation (fail closed).
    Config(String),
    /// An I/O error with context.
    Io(String, std::io::Error),
    /// Lock-UI socket protocol violation (bad frame, oversized, bad UTF-8).
    Protocol(String),
    /// PAM transaction failure (generic text only).
    Pam(String),
    /// Wayland / ext-session-lock-v1 failure.
    Wayland(String),
    /// logind backend failure.
    Logind(String),
    /// D-Bus service layer failure (name lost, marshalling, bus gone).
    Bus(String),
    /// Request denied by policy (not authenticated, not owner, rate limit).
    Denied(String),
    /// Transient overload — retry later (bounded waiter queue, busy core).
    /// Deliberately distinct from `Denied` so the bus can answer
    /// `LimitsExceeded` instead of `AccessDenied`.
    Busy(String),
    /// Refusing to lock into an un-unlockable state (spec 03 §6) or lock
    /// engine failure.
    Lock(String),
    /// Invalid input from a caller.
    InvalidParams(String),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) => write!(f, "config error: {m}"),
            Error::Io(ctx, e) => write!(f, "io error ({ctx}): {e}"),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::Pam(m) => write!(f, "pam error: {m}"),
            Error::Wayland(m) => write!(f, "wayland error: {m}"),
            Error::Logind(m) => write!(f, "logind backend error: {m}"),
            Error::Bus(m) => write!(f, "dbus error: {m}"),
            Error::Denied(m) => write!(f, "denied: {m}"),
            Error::Busy(m) => write!(f, "busy: {m}"),
            Error::Lock(m) => write!(f, "lock error: {m}"),
            Error::InvalidParams(m) => write!(f, "invalid params: {m}"),
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io("unspecified".into(), e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
