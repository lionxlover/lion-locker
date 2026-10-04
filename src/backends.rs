#![forbid(unsafe_code)]
//! Real backends for the ports that are not Wayland.
//!
//! * [`DirectLauncher`] — spawns `lion-lockscreen` with `tokio::process`.
//!   The child is an unprivileged same-uid process; `kill_on_drop` bounds
//!   leaks. Its environment is *cleared* except for what a Wayland/Slint UI
//!   needs, so nothing sensitive in the locker's environment leaks.
//! * `zbus_backends` (feature `real-bus`) — org.freedesktop.login1,
//!   org.freedesktop.Notifications and the lion-notifications privacy hook.

use crate::error::{Error, Result};
use crate::ports::{ChildProcess, UiLauncher};
use async_trait::async_trait;

/// Environment variables a lock UI legitimately needs.
const PASS_ENV: &[&str] = &[
    "XDG_RUNTIME_DIR",
    "WAYLAND_DISPLAY",
    "XDG_SESSION_ID",
    "XDG_SEAT",
    "LANG",
    "LC_ALL",
    "LC_MESSAGES",
    "HOME",
    "PATH",
    "DBUS_SESSION_BUS_ADDRESS",
    "LION_LOCKER_SOCKET",
];

pub struct DirectLauncher {
    /// Exported to the child as `LION_LOCKER_SOCKET`.
    pub socket_path: std::path::PathBuf,
}

struct DirectChild {
    pid: u32,
    inner: tokio::sync::Mutex<Option<tokio::process::Child>>,
    done: std::sync::Mutex<Option<bool>>,
}

#[async_trait]
impl ChildProcess for DirectChild {
    fn pid(&self) -> u32 {
        self.pid
    }

    async fn wait(&self) -> bool {
        let mut slot = self.inner.lock().await;
        if let Some(mut child) = slot.take() {
            let ok = child.wait().await.map(|s| s.success()).unwrap_or(false);
            *self.done.lock().unwrap() = Some(ok);
            return ok;
        }
        drop(slot);
        // Already reaped by a previous wait().
        self.done.lock().unwrap().unwrap_or(false)
    }

    fn kill(&self) {
        // The pid is only signalled while the waiter still owns the child
        // (kill_on_drop covers the rest), so reuse cannot hit a stranger.
        if self.done.lock().unwrap().is_none() {
            crate::sysffi::kill_pid(self.pid);
        }
    }
}

#[async_trait]
impl UiLauncher for DirectLauncher {
    async fn spawn(&self, argv: &[String]) -> Result<Box<dyn ChildProcess>> {
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| Error::Lock("empty lock UI argv".into()))?;
        let mut cmd = tokio::process::Command::new(prog);
        cmd.args(args)
            .env_clear()
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null());
        for k in PASS_ENV {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
        cmd.env("LION_LOCKER_SOCKET", &self.socket_path);
        let child = cmd
            .spawn()
            .map_err(|e| Error::Io(format!("spawn {prog}"), e))?;
        let pid = child
            .id()
            .ok_or_else(|| Error::Lock("lock UI exited immediately".into()))?;
        Ok(Box::new(DirectChild {
            pid,
            inner: tokio::sync::Mutex::new(Some(child)),
            done: std::sync::Mutex::new(None),
        }))
    }
}

#[cfg(feature = "real-bus")]
pub mod zbus_backends {
    use super::*;
    use crate::ports::{InhibitorGuard, Logind, LogindEvent, Notifier, Privacy};
    use futures_util::StreamExt;
    use tokio::sync::mpsc;
    use zbus::zvariant::OwnedFd;

    fn map_err(what: &str, e: impl std::fmt::Display) -> Error {
        Error::Bus(format!("{what}: {e}"))
    }

    /// Which bus carries `org.freedesktop.login1` (the system bus in
    /// production; the session bus in the private-bus acceptance tests).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LogindBus {
        System,
        Session,
    }

    async fn connect(which: LogindBus) -> Result<zbus::Connection> {
        let b = match which {
            LogindBus::System => zbus::connection::Builder::system(),
            LogindBus::Session => zbus::connection::Builder::session(),
        };
        b.map_err(|e| map_err("bus", e))?
            .build()
            .await
            .map_err(|e| map_err("bus connect", e))
    }

    async fn manager(conn: &zbus::Connection) -> Result<zbus::Proxy<'static>> {
        zbus::Proxy::new_owned(
            conn.clone(),
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await
        .map_err(|e| map_err("login1 manager proxy", e))
    }

    #[derive(Clone)]
    pub struct ZbusLogind {
        conn: zbus::Connection,
        session_path: zbus::zvariant::OwnedObjectPath,
    }

    impl ZbusLogind {
        pub async fn connect(which: LogindBus) -> Result<Self> {
            let conn = connect(which).await?;
            let session_path = resolve_session(&conn).await?;
            tracing::info!(target: "logind", path = %session_path, "own logind session resolved");
            Ok(ZbusLogind { conn, session_path })
        }

        pub fn session_path(&self) -> &zbus::zvariant::OwnedObjectPath {
            &self.session_path
        }

        /// Spawn watchers for `Lock`, `PrepareForSleep` and `LidClosed`.
        /// The per-session `Unlock` signal is deliberately *not* watched:
        /// anything able to emit it must not be able to unlock the screen
        /// (fail closed, spec 03 §8).
        pub fn watch(&self, tx: mpsc::UnboundedSender<LogindEvent>) {
            let conn = self.conn.clone();
            let path = self.session_path.clone();
            let t = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = watch_session_lock(conn, path, t).await {
                    tracing::warn!(target: "logind", "Lock signal watch ended: {e}");
                }
            });
            let conn = self.conn.clone();
            let t = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = watch_sleep(conn, t).await {
                    tracing::warn!(target: "logind", "PrepareForSleep watch ended: {e}");
                }
            });
            let conn = self.conn.clone();
            tokio::spawn(async move {
                if let Err(e) = watch_lid(conn, tx).await {
                    tracing::debug!(target: "logind", "LidClosed watch ended: {e}");
                }
            });
        }
    }

    /// `XDG_SESSION_ID` when set, else the session of our own pid.
    async fn resolve_session(conn: &zbus::Connection) -> Result<zbus::zvariant::OwnedObjectPath> {
        let m = manager(conn).await?;
        if let Ok(id) = std::env::var("XDG_SESSION_ID") {
            if !id.is_empty() {
                if let Ok(p) = m
                    .call::<_, _, zbus::zvariant::OwnedObjectPath>("GetSession", &(id.as_str(),))
                    .await
                {
                    return Ok(p);
                }
            }
        }
        m.call::<_, _, zbus::zvariant::OwnedObjectPath>("GetSessionByPID", &(std::process::id(),))
            .await
            .map_err(|e| map_err("GetSessionByPID", e))
    }

    async fn watch_session_lock(
        conn: zbus::Connection,
        path: zbus::zvariant::OwnedObjectPath,
        tx: mpsc::UnboundedSender<LogindEvent>,
    ) -> Result<()> {
        let p = zbus::Proxy::new(
            &conn,
            "org.freedesktop.login1",
            path.as_str().to_owned(),
            "org.freedesktop.login1.Session",
        )
        .await
        .map_err(|e| map_err("session proxy", e))?;
        let mut s = p
            .receive_signal("Lock")
            .await
            .map_err(|e| map_err("subscribe Lock", e))?;
        while s.next().await.is_some() {
            if tx.send(LogindEvent::Lock).is_err() {
                break;
            }
        }
        Ok(())
    }

    async fn watch_sleep(
        conn: zbus::Connection,
        tx: mpsc::UnboundedSender<LogindEvent>,
    ) -> Result<()> {
        let m = manager(&conn).await?;
        let mut s = m
            .receive_signal("PrepareForSleep")
            .await
            .map_err(|e| map_err("subscribe PrepareForSleep", e))?;
        while let Some(msg) = s.next().await {
            let start: bool = msg
                .body()
                .deserialize()
                .map_err(|e| map_err("PrepareForSleep body", e))?;
            if tx.send(LogindEvent::PrepareForSleep(start)).is_err() {
                break;
            }
        }
        Ok(())
    }

    async fn watch_lid(
        conn: zbus::Connection,
        tx: mpsc::UnboundedSender<LogindEvent>,
    ) -> Result<()> {
        let m = manager(&conn).await?;
        let mut s = m.receive_property_changed::<bool>("LidClosed").await;
        while let Some(change) = s.next().await {
            if let Ok(v) = change.get().await {
                if tx.send(LogindEvent::LidClosed(v)).is_err() {
                    break;
                }
            }
        }
        Ok(())
    }

    #[async_trait]
    impl Logind for ZbusLogind {
        async fn set_locked_hint(&self, locked: bool) -> Result<()> {
            let p = zbus::Proxy::new(
                &self.conn,
                "org.freedesktop.login1",
                self.session_path.as_str().to_owned(),
                "org.freedesktop.login1.Session",
            )
            .await
            .map_err(|e| map_err("session proxy", e))?;
            p.call_method("SetLockedHint", &(locked,))
                .await
                .map(|_| ())
                .map_err(|e| map_err("SetLockedHint", e))
        }

        async fn take_sleep_inhibitor(&self) -> Result<InhibitorGuard> {
            let m = manager(&self.conn).await?;
            let fd: OwnedFd = m
                .call(
                    "Inhibit",
                    &(
                        "sleep",
                        "LionOS Locker",
                        "Locking the screen before suspend",
                        "delay",
                    ),
                )
                .await
                .map_err(|e| map_err("Inhibit", e))?;
            Ok(InhibitorGuard::new(fd))
        }

        async fn power_off(&self) -> Result<()> {
            let m = manager(&self.conn).await?;
            match m.call_method("PowerOff", &(false,)).await {
                Ok(_) => Ok(()),
                Err(_) => m
                    .call_method("PowerOff", &())
                    .await
                    .map(|_| ())
                    .map_err(|e| map_err("PowerOff", e)),
            }
        }

        async fn activate_session(&self, id: &str) -> Result<()> {
            manager(&self.conn)
                .await?
                .call_method("ActivateSession", &(id,))
                .await
                .map(|_| ())
                .map_err(|e| map_err("ActivateSession", e))
        }
    }

    /// org.freedesktop.Notifications (locker failures only; never session
    /// content). Best effort.
    pub struct NotificationsNotifier {
        conn: zbus::Connection,
    }

    impl NotificationsNotifier {
        pub async fn connect() -> Result<Self> {
            Ok(NotificationsNotifier {
                conn: connect(LogindBus::Session).await?,
            })
        }
    }

    #[async_trait]
    impl Notifier for NotificationsNotifier {
        async fn notify(&self, summary: &str, body: &str) -> Result<()> {
            let p = zbus::Proxy::new(
                &self.conn,
                "org.freedesktop.Notifications",
                "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications",
            )
            .await
            .map_err(|e| map_err("notifications proxy", e))?;
            let hints: std::collections::HashMap<&str, zbus::zvariant::Value<'_>> =
                std::collections::HashMap::new();
            p.call_method(
                "Notify",
                &(
                    "lion-locker",
                    0u32,
                    "changes-prevent-symbolic",
                    summary,
                    body,
                    Vec::<&str>::new(),
                    hints,
                    10_000i32,
                ),
            )
            .await
            .map(|_| ())
            .map_err(|e| map_err("Notify", e))
        }
    }

    /// lion-notifications privacy hook (`os.lionos.Notifications1`, spec
    /// 44; documented in MIGRATION.md): `SetLockState(locked, hide_content)`.
    /// Best effort — the lock UI is told the same flag in `Show`.
    pub struct NotificationPrivacy {
        conn: zbus::Connection,
    }

    impl NotificationPrivacy {
        pub async fn connect() -> Result<Self> {
            Ok(NotificationPrivacy {
                conn: connect(LogindBus::Session).await?,
            })
        }
    }

    #[async_trait]
    impl Privacy for NotificationPrivacy {
        async fn set_lock_state(&self, locked: bool, hide_content: bool) -> Result<()> {
            let p = zbus::Proxy::new(
                &self.conn,
                "os.lionos.Notifications1",
                "/os/lionos/Notifications1",
                "os.lionos.Notifications1",
            )
            .await
            .map_err(|e| map_err("notifications1 proxy", e))?;
            p.call_method("SetLockState", &(locked, hide_content))
                .await
                .map(|_| ())
                .map_err(|e| map_err("SetLockState", e))
        }
    }

    /// No-op privacy hook when the notification daemon is absent.
    pub struct NoPrivacy;

    #[async_trait]
    impl Privacy for NoPrivacy {
        async fn set_lock_state(&self, _: bool, _: bool) -> Result<()> {
            Ok(())
        }
    }
}

use crate::ports::{InhibitorGuard, Logind, Notifier, Privacy};

/// Used when logind is unreachable: the lock still works (the compositor
/// does the real work); suspend-lock and quick actions are unavailable and
/// the daemon says so loudly at startup.
pub struct NullLogind;

#[async_trait]
impl Logind for NullLogind {
    async fn set_locked_hint(&self, _: bool) -> Result<()> {
        Ok(())
    }
    async fn take_sleep_inhibitor(&self) -> Result<InhibitorGuard> {
        Err(Error::Logind("logind unavailable".into()))
    }
    async fn power_off(&self) -> Result<()> {
        Err(Error::Logind("logind unavailable".into()))
    }
    async fn activate_session(&self, _: &str) -> Result<()> {
        Err(Error::Logind("logind unavailable".into()))
    }
}

/// Log-only notifier fallback.
pub struct LogNotifier;

#[async_trait]
impl Notifier for LogNotifier {
    async fn notify(&self, summary: &str, body: &str) -> Result<()> {
        tracing::warn!(target: "notify", "{summary}: {body}");
        Ok(())
    }
}

/// No-op privacy hook (no notification daemon).
pub struct NoopPrivacy;

#[async_trait]
impl Privacy for NoopPrivacy {
    async fn set_lock_state(&self, _: bool, _: bool) -> Result<()> {
        Ok(())
    }
}
