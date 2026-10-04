#![forbid(unsafe_code)]
//! Port seams (hexagonal architecture, same convention as lion-greeter and
//! lion-session): the core in `core.rs` talks only to these traits. Real
//! backends live in `wayland.rs` / `logind.rs` / `bus.rs`, fakes in
//! `mocks.rs`, so the *same* core runs against a real compositor, a real
//! D-Bus, or fully scripted fakes (chaos tests kill the lock UI 100 times
//! without a display server).

use crate::config::Config;
use crate::error::Result;
use async_trait::async_trait;

/// What the compositor-facing backend reports (ext-session-lock-v1 events,
/// translated). Delivered to the core over a channel supplied at
/// construction of the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendEvent {
    /// `ext_session_lock_v1.locked`: the compositor guarantees nothing but
    /// lock surfaces is visible/focusable. The screen is covered.
    Locked,
    /// `ext_session_lock_v1.finished`: the compositor refused the lock
    /// (another locker holds it) or destroyed it.
    Finished,
    /// Output coverage changed (hotplug): `covered` of `total` outputs have
    /// a lock surface with a committed buffer.
    Outputs { covered: u32, total: u32 },
    /// The compositor connection is gone; the backend cannot recover.
    Fatal(String),
}

/// ext-session-lock-v1 client. Results of `lock()` arrive as
/// [`BackendEvent`]s; the call itself only submits the request.
#[async_trait]
pub trait LockBackend: Send + Sync {
    /// Request the lock and cover every output (including ones that appear
    /// later — new monitors come up locked immediately).
    async fn lock(&self) -> Result<()>;
    /// `unlock_and_destroy` followed by a display round trip, so the
    /// compositor has processed the request when this returns.
    async fn unlock(&self) -> Result<()>;
}

/// logind events the core cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogindEvent {
    /// Per-session `Lock` signal (`loginctl lock-session`). The matching
    /// `Unlock` signal is deliberately never forwarded (fail closed).
    Lock,
    /// Manager `PrepareForSleep(start)`.
    PrepareForSleep(bool),
    /// Manager `LidClosed` property changed.
    LidClosed(bool),
}

/// RAII handle for a logind delay inhibitor (an fd in the real backend):
/// dropping it releases the inhibitor.
pub struct InhibitorGuard(#[allow(dead_code)] Option<Box<dyn std::any::Any + Send + Sync>>);

impl InhibitorGuard {
    pub fn new<T: std::any::Any + Send + Sync>(token: T) -> Self {
        InhibitorGuard(Some(Box::new(token)))
    }
    pub fn none() -> Self {
        InhibitorGuard(None)
    }
}

impl std::fmt::Debug for InhibitorGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InhibitorGuard")
    }
}

/// org.freedesktop.login1 (spec 03 §3 "lock before sleep via logind
/// PrepareForSleep inhibitor"; "switch user, shut down" quick actions).
#[async_trait]
pub trait Logind: Send + Sync {
    /// `Session.SetLockedHint` on our own session.
    async fn set_locked_hint(&self, locked: bool) -> Result<()>;
    /// `Manager.Inhibit("sleep", …, "delay")`.
    async fn take_sleep_inhibitor(&self) -> Result<InhibitorGuard>;
    async fn power_off(&self) -> Result<()>;
    /// `Manager.ActivateSession(id)` — the switch-user target (greeter).
    async fn activate_session(&self, id: &str) -> Result<()>;
}

/// User-visible notifications for locker failures (never session content).
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn notify(&self, summary: &str, body: &str) -> Result<()>;
}

/// Tells the notification daemon to hide notification content while locked
/// (spec 03 §3 "Notification privacy"). Best effort: the lock UI receives
/// the same flag in `Show`, so a missing daemon never leaks content
/// through *this* component.
#[async_trait]
pub trait Privacy: Send + Sync {
    async fn set_lock_state(&self, locked: bool, hide_content: bool) -> Result<()>;
}

/// "Refuse to lock into an un-unlockable state" (spec 03 §6): verifies an
/// unlock path exists *before* the screen is taken.
pub trait Preflight: Send + Sync {
    fn check(&self, cfg: &Config) -> Result<()>;
}

/// A running supervised process (the lock UI).
#[async_trait]
pub trait ChildProcess: Send + Sync {
    fn pid(&self) -> u32;
    /// Wait for exit (idempotent). `true` = exited normally with status 0.
    async fn wait(&self) -> bool;
    /// Best-effort SIGKILL.
    fn kill(&self);
}

/// Spawns the lock-screen UI process.
#[async_trait]
pub trait UiLauncher: Send + Sync {
    async fn spawn(&self, argv: &[String]) -> Result<Box<dyn ChildProcess>>;
}
