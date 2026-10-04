#![forbid(unsafe_code)]
//! The `os.lionos.Locker1` D-Bus service (spec 03 §4), feature `real-bus`.
//!
//! Methods: `Lock()`, `Unlock()` (only valid after local PAM auth).
//! Properties: `IsLocked`, plus the documented extensions `State` and
//! `Failures`. Signals: `Locked`, `Unlocked`, `AuthFailed(count)`.
//!
//! Every caller is untrusted (spec 03 §8): its identity comes from the bus
//! daemon (`GetConnectionUnixUser/ProcessID` — kernel-mediated), the pid is
//! pinned with a pidfd and its cgroup logged for audit, authorization is
//! owner-only, and calls are rate-limited per bus unique name. `Unlock`
//! never unlocks by itself: the core requires a live, single-use,
//! PAM-verified grant (see `core.rs` invariant 1).

use crate::authz::{actions, Policy};
use crate::config::Config;
use crate::core::{Event, Handle, LockSource, Signal};
use crate::sysffi;
use crate::throttle::RateLimiter;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use zbus::object_server::SignalEmitter;

pub const PATH: &str = "/os/lionos/Locker1";
pub const IFACE: &str = "os.lionos.Locker1";
pub const DEFAULT_NAME: &str = "os.lionos.Locker1";

/// Core call deadline: a wedged core must not wedge the bus.
const CORE_TIMEOUT: Duration = Duration::from_secs(5);

struct Identity {
    uid: u32,
    pid: u32,
    pinned_pidfd: bool,
    cgroup: Option<String>,
}

struct LockerIface {
    ev: mpsc::UnboundedSender<Event>,
    snapshot: tokio::sync::watch::Receiver<crate::core::Snapshot>,
    policy: Policy,
    limiter: Mutex<RateLimiter>,
}

impl LockerIface {
    async fn identity_of(
        &self,
        conn: &zbus::Connection,
        sender: Option<&zbus::names::UniqueName<'_>>,
    ) -> zbus::fdo::Result<(Identity, String)> {
        let sender =
            sender.ok_or_else(|| zbus::fdo::Error::Failed("anonymous caller refused".into()))?;
        let dbus = zbus::fdo::DBusProxy::new(conn).await?;
        let bus_name = zbus::names::BusName::from(sender.to_owned());
        let uid = dbus
            .get_connection_unix_user(bus_name.clone())
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("caller uid resolution failed: {e}")))?;
        let pid = dbus
            .get_connection_unix_process_id(bus_name)
            .await
            .unwrap_or(0);
        let pinned_pidfd = pid > 0 && sysffi::pidfd_open(pid).is_some();
        let cgroup = if pid > 0 {
            sysffi::cgroup_of_pid(pid)
        } else {
            None
        };
        Ok((
            Identity {
                uid,
                pid,
                pinned_pidfd,
                cgroup,
            },
            sender.to_string(),
        ))
    }

    /// Identify, rate-limit, authorize. Returns the caller identity.
    async fn gate(
        &self,
        conn: &zbus::Connection,
        sender: Option<&zbus::names::UniqueName<'_>>,
        action: &str,
    ) -> zbus::fdo::Result<Identity> {
        let (id, key) = self.identity_of(conn, sender).await?;
        if !self
            .limiter
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("limiter poisoned".into()))?
            .allow(&key, Instant::now())
        {
            tracing::warn!(target: "bus", uid = id.uid, pid = id.pid, action, "rate limited");
            return Err(zbus::fdo::Error::LimitsExceeded("too many calls".into()));
        }
        if !self.policy.allows(action, id.uid) {
            tracing::warn!(
                target: "bus",
                uid = id.uid, pid = id.pid, action,
                cgroup = id.cgroup.as_deref().unwrap_or("?"),
                "denied: caller is not the session owner"
            );
            return Err(zbus::fdo::Error::AccessDenied(
                "not the session owner".into(),
            ));
        }
        tracing::info!(
            target: "bus",
            action, uid = id.uid, pid = id.pid, pidfd = id.pinned_pidfd,
            cgroup = id.cgroup.as_deref().unwrap_or("?"),
            "request"
        );
        Ok(id)
    }

    async fn ask_core(
        &self,
        make: impl FnOnce(oneshot::Sender<crate::Result<()>>) -> Event,
    ) -> zbus::fdo::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.ev
            .send(make(tx))
            .map_err(|_| zbus::fdo::Error::Failed("locker core gone".into()))?;
        match tokio::time::timeout(CORE_TIMEOUT, rx).await {
            Err(_) => Err(zbus::fdo::Error::Timeout(
                "locker core did not answer".into(),
            )),
            Ok(Err(_)) => Err(zbus::fdo::Error::Failed("core dropped reply".into())),
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(crate::Error::Denied(m)))) => Err(zbus::fdo::Error::AccessDenied(m)),
            // Bounded waiter queue full (stalled compositor): distinct from
            // a policy denial so well-behaved callers can retry instead of
            // treating it as "not allowed".
            Ok(Ok(Err(crate::Error::Busy(m)))) => Err(zbus::fdo::Error::LimitsExceeded(m)),
            Ok(Ok(Err(e))) => Err(zbus::fdo::Error::Failed(e.to_string())),
        }
    }
}

#[zbus::interface(name = "os.lionos.Locker1")]
impl LockerIface {
    /// Lock the screen. Returns once the compositor has confirmed the lock
    /// (screen covered) or the attempt failed.
    async fn lock(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        self.gate(conn, hdr.sender(), actions::LOCK).await?;
        self.ask_core(|reply| Event::Lock {
            source: LockSource::Bus,
            reply: Some(reply),
        })
        .await
    }

    /// Unlock — valid only right after a successful local PAM
    /// authentication (`locker.explicit_unlock = true` mode). Without a
    /// live grant this is denied, whoever calls it.
    async fn unlock(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        self.gate(conn, hdr.sender(), actions::UNLOCK).await?;
        self.ask_core(|reply| Event::Unlock { reply }).await
    }

    #[zbus(property)]
    async fn is_locked(&self) -> bool {
        self.snapshot.borrow().locked
    }

    /// Extension: "unlocked" | "locking" | "locked" | "unlocking".
    #[zbus(property)]
    async fn state(&self) -> String {
        self.snapshot.borrow().state.to_string()
    }

    /// Extension: consecutive failed unlock attempts.
    #[zbus(property)]
    async fn failures(&self) -> u32 {
        self.snapshot.borrow().failures
    }

    #[zbus(signal)]
    async fn locked(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn unlocked(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn auth_failed(emitter: &SignalEmitter<'_>, count: u32) -> zbus::Result<()>;
}

/// Serve the interface and own the bus name. Interface first, name second.
pub async fn serve(
    cfg: &Config,
    name: &str,
    handle: &Handle,
    sig_rx: mpsc::UnboundedReceiver<Signal>,
) -> crate::Result<Arc<zbus::Connection>> {
    let iface = LockerIface {
        ev: handle.ev_tx.clone(),
        snapshot: handle.snapshot.clone(),
        policy: Policy::new(cfg.owner()),
        limiter: Mutex::new(RateLimiter::new(
            Duration::from_millis(cfg.rate_limit.window_ms),
            cfg.rate_limit.max_calls,
        )),
    };
    let conn = zbus::connection::Builder::session()
        .map_err(|e| crate::Error::Bus(format!("session bus: {e}")))?
        .serve_at(PATH, iface)
        .map_err(|e| crate::Error::Bus(format!("serve_at: {e}")))?
        .name(name)
        .map_err(|e| crate::Error::Bus(format!("name {name}: {e}")))?
        .build()
        .await
        .map_err(|e| crate::Error::Bus(format!("connection: {e}")))?;
    let conn = Arc::new(conn);
    tracing::info!(target: "bus", "owning {name} at {PATH}");
    tokio::spawn(emitter_loop(conn.clone(), handle.snapshot.clone(), sig_rx));
    Ok(conn)
}

/// One task emits both PropertiesChanged and signals so their order is
/// deterministic: the core publishes the snapshot *before* sending a
/// signal, and the biased select drains snapshot changes first, so a
/// client that wakes on `Locked` can read `IsLocked == true` immediately.
async fn emitter_loop(
    conn: Arc<zbus::Connection>,
    mut snap: tokio::sync::watch::Receiver<crate::core::Snapshot>,
    mut rx: mpsc::UnboundedReceiver<Signal>,
) {
    let emitter = match SignalEmitter::new(conn.as_ref(), PATH) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(target: "bus", "emitter: {e}");
            return;
        }
    };
    let mut snap_open = true;
    loop {
        tokio::select! {
            biased;
            r = snap.changed(), if snap_open => {
                if r.is_err() { snap_open = false; continue; }
                let s = snap.borrow_and_update().clone();
                emit_props(&emitter, &s).await;
            }
            sig = rx.recv() => {
                let Some(sig) = sig else { return };
                // Make sure a pending snapshot change goes out first.
                if snap.has_changed().unwrap_or(false) {
                    let s = snap.borrow_and_update().clone();
                    emit_props(&emitter, &s).await;
                }
                let r = match sig {
                    Signal::Locked => LockerIface::locked(&emitter).await,
                    Signal::Unlocked => LockerIface::unlocked(&emitter).await,
                    Signal::AuthFailed(n) => LockerIface::auth_failed(&emitter, n).await,
                };
                if let Err(e) = r {
                    tracing::warn!(target: "bus", "signal emit failed: {e}");
                }
            }
        }
    }
}

async fn emit_props(emitter: &SignalEmitter<'_>, s: &crate::core::Snapshot) {
    let changed: std::collections::HashMap<&str, zbus::zvariant::Value<'_>> = [
        ("IsLocked", zbus::zvariant::Value::new(s.locked)),
        ("State", zbus::zvariant::Value::new(s.state.to_string())),
        ("Failures", zbus::zvariant::Value::new(s.failures)),
    ]
    .into_iter()
    .collect();
    let invalidated: Vec<&str> = vec![];
    let body = (IFACE, changed, invalidated);
    if let Err(e) = emitter
        .emit(
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &body,
        )
        .await
    {
        tracing::warn!(target: "bus", "properties-changed emit failed: {e}");
    }
}
