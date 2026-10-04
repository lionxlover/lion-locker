#![forbid(unsafe_code)]
//! Secret (password) carrier.
//!
//! Spec 03 §8: "Passwords live only in `Zeroizing<String>` buffers and are
//! wiped immediately after the PAM call; never logged, never serialised."
//!
//! [`Secret`] is the *only* type allowed to hold password material:
//! - it wraps `Zeroizing<String>` (zeroed on drop / move),
//! - its `Debug`/`Display` impls are redacted,
//! - it implements `Deserialize` so answers arriving from the UI socket are
//!   moved into a zeroizing buffer immediately after decode,
//! - it deliberately does *not* implement `Serialize` (never serialised).
//!
//! The raw bytes of the incoming JSON line are additionally wiped by the
//! frame codec (`crate::codec`) after the message has been extracted.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use std::fmt;
use zeroize::Zeroizing;

/// A zeroizing, redacted, non-serialisable secret string.
#[derive(Default)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap an existing string. The source string should be dropped right
    /// after this call (it is *not* zeroised by this constructor).
    pub fn new(s: String) -> Self {
        Secret(Zeroizing::new(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<redacted, {} bytes>)", self.0.len())
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted>")
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Secret(Zeroizing::new(self.0.as_str().to_owned()))
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        // Length-bound secrets at the decode boundary (spec §8 "validate and
        // bound every input"): a sane PAM conversation answer never exceeds
        // 1 KiB (PAM itself caps messages at PAM_MAX_MSG_SIZE = 1024).
        if s.len() > 1024 {
            return Err(D::Error::custom("secret too long (max 1024 bytes)"));
        }
        Ok(Secret::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new("hunter2".into());
        assert!(!format!("{s:?}").contains("hunter2"));
        assert_eq!(format!("{s}"), "<redacted>");
    }

    #[test]
    fn deserializes_and_bounds() {
        let ok: Secret = serde_json::from_str("\"pw\"").unwrap();
        assert_eq!(ok.as_str(), "pw");
        let too_long = "x".repeat(1025);
        let err: Result<Secret, _> =
            serde_json::from_str(&serde_json::to_string(&too_long).unwrap());
        assert!(err.is_err());
    }
}
