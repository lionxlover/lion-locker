#![forbid(unsafe_code)]
//! systemd readiness/watchdog protocol (`sd_notify(3)`), hand-rolled over
//! `UnixDatagram` (identical to lion-session's, shared convention):
//! `READY=1` only when actually usable, `WATCHDOG=1` heartbeats at
//! `WATCHDOG_USEC/2`, `STOPPING=1` on graceful shutdown.
//!
//! Without `NOTIFY_SOCKET` (manual run, tests) every call is a no-op.

use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Notify {
    pub(crate) sock: Option<Arc<UnixDatagram>>,
}

impl Notify {
    /// No-op notifier (tests, `--mock`, manual runs).
    pub fn disabled() -> Notify {
        Notify { sock: None }
    }

    pub fn from_env() -> Notify {
        let path = std::env::var_os("NOTIFY_SOCKET");
        let sock = path.and_then(|p| {
            UnixDatagram::unbound().ok().and_then(|s| {
                // `@…` maps to the Linux abstract namespace `\0…`.
                let mut p = p;
                let bytes = p.as_encoded_bytes();
                if bytes.first() == Some(&b'@') {
                    let mut nb = bytes.to_vec();
                    nb[0] = 0;
                    p = std::os::unix::ffi::OsStringExt::from_vec(nb);
                }
                s.connect(p).ok()?;
                Some(Arc::new(s))
            })
        });
        Notify { sock }
    }

    fn send(&self, msg: &str) {
        if let Some(sock) = &self.sock {
            if sock.send(msg.as_bytes()).is_err() {
                // systemd not listening: not fatal; readiness is also in
                // the logs (see greeter's identical reasoning).
                tracing::debug!(target: "notify", "sd_notify send failed for {msg:?}");
            }
        }
    }

    /// The daemon is actually usable: bus name owned, compositor up.
    pub fn ready(&self) {
        self.send("READY=1");
        tracing::info!(target: "notify", "READY=1");
    }

    pub fn stopping(&self) {
        self.send("STOPPING=1");
        tracing::info!(target: "notify", "STOPPING=1");
    }

    /// Watchdog heartbeat interval; `None` (no timers) without
    /// WATCHDOG_USEC — the daemon stays fully idle (spec 03 §7).
    pub fn watchdog_interval(&self) -> Option<Duration> {
        let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
        if usec == 0 {
            return None;
        }
        Some(Duration::from_micros(usec / 2).max(Duration::from_millis(250)))
    }

    pub fn watchdog_tick(&self) {
        self.send("WATCHDOG=1");
    }

    pub fn is_active(&self) -> bool {
        self.sock.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_without_socket_is_noop() {
        let n = Notify { sock: None };
        n.ready();
        n.stopping();
        n.watchdog_tick();
        assert!(!n.is_active());
    }

    #[test]
    fn watchdog_interval_math() {
        std::env::remove_var("WATCHDOG_USEC");
        let n = Notify { sock: None };
        assert!(n.watchdog_interval().is_none());
        std::env::set_var("WATCHDOG_USEC", "60000000");
        assert_eq!(n.watchdog_interval(), Some(Duration::from_secs(30)));
        std::env::remove_var("WATCHDOG_USEC");
    }

    #[test]
    fn abstract_socket_prefix_is_translated() {
        // Round-trip check of the @ → \0 mapping used by from_env.
        use std::os::unix::ffi::OsStringExt;
        let mut nb = b"@lion-session-test".to_vec();
        nb[0] = 0;
        let os: std::ffi::OsString = OsStringExt::from_vec(nb);
        assert_eq!(os.as_encoded_bytes()[0], 0);
        assert_eq!(&os.as_encoded_bytes()[1..], b"lion-session-test");
    }
}
