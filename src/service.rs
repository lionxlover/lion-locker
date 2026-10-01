//! The public `os.lionos.Locker` D-Bus service, and the state machine that
//! runs one lock episode from `Lock()` through to unlock.
//!
//! Bus name    : os.lionos.Locker
//! Object path : /os/lionos/Locker
//! Interface   : os.lionos.Locker1
//!
//!   Lock() -> b   Grab input and start the lock episode. Returns true
//!                 only after the compositor's `locked` *confirmation*
//!                 (bounded by a 3 s timeout — see wayland.rs), so a
//!                 caller can distinguish "locked" from "lock request
//!                 failed" and escalate. Idempotent: a second call while
//!                 already locked is a no-op returning true.
//!   GetState() -> s   "idle" | "locking" | "locked"
//!   GetMetrics() -> s JSON counters (same schema family as lion-greeter)
//!   ResetMetrics()    Zero the counters (not uptime)
//!
//!   Properties: Version (s), Capabilities (s, JSON array),
//!               Locked (b)
//!   Signal:     LockStateChanged(s state)  "idle" | "locking" | "locked"
//!
//! There is deliberately **no `Unlock()` method** — nothing but a
//! credential verified by PAM ends a lock episode (logind's `Unlock`
//! signal is refused and logged; see logind.rs). That asymmetry is the
//! whole point of a lock screen.
//!
//! This same connection also serves `os.lionos.Locker.Render1`
//! (lockscreen.rs), which is how `lion-lockscreen` hands over rendered
//! frames — one bus name, one object path, two interfaces.
//!
//! # Crash-relock
//!
//! If the durable episode marker (`state.rs`) is present at startup, a
//! previous instance died while locked; we re-acquire the lock
//! immediately (systemd restarts us with `Restart=always`,
//! `RestartSec=0`), which collapses the Wayland locker's classic
//! "crash = exposed session" window to one process restart.

use crate::{
    auth,
    lockscreen::{Frame, LockscreenClient, RenderService},
    metrics,
    password::PasswordBuffer,
    state,
    throttle::Throttle,
    wayland::{WlEvent, WlHandle},
};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use zbus::{interface, object_server::SignalContext};
use zeroize::Zeroizing;

const LOCKER_BUS: &str = "os.lionos.Locker";
const LOCKER_PATH: &str = "/os/lionos/Locker";

/// Live lock state, shared between the interface and the episode loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockPhase {
    Idle,
    Locking,
    Locked,
}

impl LockPhase {
    fn as_str(self) -> &'static str {
        match self {
            LockPhase::Idle => "idle",
            LockPhase::Locking => "locking",
            LockPhase::Locked => "locked",
        }
    }
}

/// Shared references the episode event handler needs, bundled so the
/// handler signature stays readable (and clippy-happy). `chatter_tx` is
/// an owned channel handle (cheap Arc clone) so `submit` can move it
/// into the auth thread without borrow gymnastics.
struct EpisodeCtx<'a> {
    wl: &'a WlHandle,
    lockscreen: &'a Arc<LockscreenClient>,
    phase: &'a Arc<std::sync::Mutex<LockPhase>>,
    ctxt: &'a SignalContext<'a>,
    chatter_tx: mpsc::UnboundedSender<crate::pam_ffi::Chatter>,
}

struct Locker1 {
    wl: WlHandle,
    phase: Arc<std::sync::Mutex<LockPhase>>,
    lock_requests: mpsc::UnboundedSender<()>,
}

#[interface(name = "os.lionos.Locker1")]
impl Locker1 {
    /// Start a lock episode. `true` = compositor confirmed the grab.
    async fn lock(&self) -> bool {
        {
            let mut g = self.phase.lock().unwrap_or_else(|e| e.into_inner());
            if *g == LockPhase::Locked {
                tracing::debug!("Lock() while already locked, ignoring");
                return true;
            }
            *g = LockPhase::Locking;
        }
        match self.wl.lock().await {
            Ok(()) => {
                let _ = self.lock_requests.send(());
                true
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to grab Wayland session lock");
                let mut g = self.phase.lock().unwrap_or_else(|e| e.into_inner());
                *g = LockPhase::Idle;
                false
            }
        }
    }

    async fn get_state(&self) -> String {
        self.phase
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_str()
            .to_owned()
    }

    async fn get_metrics(&self) -> String {
        metrics::to_json()
    }

    async fn reset_metrics(&self) {
        metrics::reset();
    }

    #[zbus(property)]
    async fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    /// JSON array of features the desktop can rely on; `mlock` appears
    /// only when memory is actually locked (auditable posture).
    #[zbus(property)]
    async fn capabilities(&self) -> String {
        let mut caps = vec![
            "session-lock-v1",
            "pam",
            "chatter",
            "crash-relock",
            "logind",
            "metrics",
            "capslock-indicator",
        ];
        if crate::mlock::is_locked() {
            caps.push("mlock");
        }
        serde_json::to_string(&caps).unwrap_or_else(|_| "[]".into())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) == LockPhase::Locked
    }

    #[zbus(signal)]
    async fn lock_state_changed(ctxt: &SignalContext<'_>, state: &str) -> zbus::Result<()>;
}

pub async fn serve(wl: WlHandle, mut wl_events: mpsc::UnboundedReceiver<WlEvent>) -> Result<()> {
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<Frame>();
    let (ready_tx, mut ready_rx) = mpsc::unbounded_channel::<Vec<String>>();
    let render = RenderService::new(frame_tx, ready_tx);

    let conn = zbus::connection::Builder::session()?
        .name(LOCKER_BUS)?
        .serve_at(LOCKER_PATH, render)?
        .build()
        .await?;

    let phase = Arc::new(std::sync::Mutex::new(LockPhase::Idle));
    let (lock_req_tx, mut lock_req_rx) = mpsc::unbounded_channel::<()>();
    let iface = Locker1 {
        wl: wl.clone(),
        phase: phase.clone(),
        lock_requests: lock_req_tx.clone(),
    };
    conn.object_server().at(LOCKER_PATH, iface).await?;
    tracing::info!(bus = LOCKER_BUS, path = LOCKER_PATH, "public IPC ready");

    // Signal context for state changes emitted from the episode loop.
    let ctxt = SignalContext::new(&conn, LOCKER_PATH)?;

    // logind compatibility: `loginctl lock-session` starts episodes; the
    // logind Unlock signal is refused (see logind.rs).
    tokio::spawn(crate::logind::watch(conn.clone(), lock_req_tx.clone()));

    let lockscreen = Arc::new(LockscreenClient::new(conn.clone()));
    let mut throttle = Throttle::default();
    let mut password = PasswordBuffer::default();

    // PAM chatter (fingerprint prompts, 2FA instructions, lockout text)
    // flows from the auth thread to the lock screen as it happens.
    let (chatter_tx, mut chatter_rx) = mpsc::unbounded_channel::<crate::pam_ffi::Chatter>();

    // Crash-relock: a marker left behind means the previous instance
    // died mid-episode. Read *before* any new episode can create it.
    if state::was_locked_at_start() {
        metrics::inc_crash_relock();
        tracing::warn!("previous locker instance died while locked; re-acquiring the session lock");
        {
            // Scoped so the sync guard is gone before the await below.
            let mut g = phase.lock().unwrap_or_else(|e| e.into_inner());
            *g = LockPhase::Locking;
        }
        match wl.lock().await {
            Ok(()) => {
                let _ = lock_req_tx.send(());
            }
            Err(e) => {
                tracing::error!(error = %e, "crash-relock failed; screen may be exposed");
                *phase.lock().unwrap_or_else(|e| e.into_inner()) = LockPhase::Idle;
            }
        }
    }

    // One long-running loop, since a lock episode is inherently
    // sequential (only one can be in flight -- Lock() already guards
    // that) but must react to several event sources at once: Wayland
    // input/lifecycle events, frames and readiness from lion-lockscreen,
    // PAM chatter, and fresh Lock() requests (including logind's).
    loop {
        tokio::select! {
            Some(()) = lock_req_rx.recv() => {
                throttle.reset();
                password = PasswordBuffer::default();
                metrics::inc_episodes();
                tracing::info!("lock episode starting");
            }

            Some(event) = wl_events.recv() => {
                let ctx = EpisodeCtx {
                    wl: &wl,
                    lockscreen: &lockscreen,
                    phase: &phase,
                    ctxt: &ctxt,
                    chatter_tx: chatter_tx.clone(),
                };
                handle_wl_event(event, &ctx, &mut throttle, &mut password).await;
            }

            Some(outputs) = ready_rx.recv() => {
                tracing::debug!(?outputs, "lion-lockscreen ready");
            }

            Some(frame) = frame_rx.recv() => {
                // Coalesce: keep only the newest frame per output so a
                // crashed/hot render loop cannot queue unbounded shared
                // memory in our channel (each Frame owns an fd!).
                let mut batch = vec![frame];
                while let Ok(more) = frame_rx.try_recv() {
                    batch.push(more);
                }
                for frame in coalesce_frames(batch) {
                    metrics::inc_frames();
                    wl.present(frame);
                }
            }

            Some(msg) = chatter_rx.recv() => {
                metrics::inc_chatter();
                lockscreen.display_message(&msg.text, msg.style.as_u32()).await;
            }
        }
    }
}

async fn handle_wl_event(
    event: WlEvent,
    ctx: &EpisodeCtx<'_>,
    throttle: &mut Throttle,
    password: &mut PasswordBuffer,
) {
    let EpisodeCtx {
        lockscreen,
        phase,
        ctxt,
        ..
    } = ctx;
    match event {
        WlEvent::Locked => {
            tracing::info!("Wayland lock confirmed; input grabbed");
            state::mark_locked();
            *phase.lock().unwrap_or_else(|e| e.into_inner()) = LockPhase::Locked;
            let _ = Locker1::lock_state_changed(ctxt, LockPhase::Locked.as_str()).await;
        }
        WlEvent::Finished => {
            // The compositor ended the lock out from under us (e.g. a
            // VT switch, or another client somehow took it). Whatever the
            // cause, the session is no longer protected -- reflect that
            // loudly rather than pretending we're still locked.
            tracing::warn!("Wayland session lock ended unexpectedly");
            state::mark_unlocked();
            *phase.lock().unwrap_or_else(|e| e.into_inner()) = LockPhase::Idle;
            let _ = Locker1::lock_state_changed(ctxt, LockPhase::Idle.as_str()).await;
            lockscreen.hide().await;
        }
        WlEvent::OutputReady(name) => {
            lockscreen.show(vec![name]).await;
        }
        WlEvent::KeyChar(c) => {
            password.push(c);
            lockscreen.key_activity().await;
        }
        WlEvent::KeyBackspace => {
            password.backspace();
            lockscreen.key_activity().await;
        }
        WlEvent::KeyCancel => {
            *password = PasswordBuffer::default();
        }
        WlEvent::KeySubmit => {
            if password.is_empty() {
                return;
            }
            if let Some(wait) = throttle.remaining() {
                metrics::add_throttled_ms(wait.as_millis() as u64);
                lockscreen
                    .auth_state(
                        "retry",
                        &format!("Too many attempts. Wait {}s.", wait.as_secs().max(1)),
                    )
                    .await;
                *password = PasswordBuffer::default();
                return;
            }
            submit(ctx, throttle, password).await;
        }
        WlEvent::PointerMotion { output, x, y } => {
            lockscreen.pointer_motion(&output, x, y).await;
        }
        WlEvent::PointerButton {
            output,
            button,
            pressed,
        } => {
            lockscreen.pointer_button(&output, button, pressed).await;
        }
        WlEvent::CapsLock(on) => {
            lockscreen.caps_lock(on).await;
        }
    }
}

async fn submit(ctx: &EpisodeCtx<'_>, throttle: &mut Throttle, password: &mut PasswordBuffer) {
    let EpisodeCtx {
        wl,
        lockscreen,
        phase,
        ctxt,
        chatter_tx,
    } = ctx;
    lockscreen.auth_state("verifying", "").await;
    metrics::inc_attempts();

    let username = whoami();
    let plaintext = Zeroizing::new(password.take());
    let rx = auth::spawn_check(username, plaintext, chatter_tx.clone());

    match rx.await {
        Ok(Ok(())) => {
            throttle.reset();
            metrics::inc_success();
            lockscreen.auth_state("unlocking", "").await;
            wl.unlock();
            lockscreen.hide().await;
            state::mark_unlocked();
            *phase.lock().unwrap_or_else(|e| e.into_inner()) = LockPhase::Idle;
            let _ = Locker1::lock_state_changed(ctxt, LockPhase::Idle.as_str()).await;
            tracing::info!("lock episode ended: unlocked");
        }
        Ok(Err(e)) => {
            let wait = throttle.record_failure();
            metrics::inc_failure();
            let msg = if wait.is_zero() {
                e.to_string()
            } else {
                metrics::add_throttled_ms(wait.as_millis() as u64);
                format!("{e}. Wait {}s.", wait.as_secs())
            };
            lockscreen.auth_state("retry", &msg).await;
        }
        Err(_) => {
            // The auth thread died without answering (spawn failure);
            // treat as transient, do NOT count as a password failure.
            lockscreen
                .auth_state("retry", "Sign-in is temporarily unavailable")
                .await;
        }
    }
}

/// Keep only the newest frame per output, preserving the order of each
/// output's last frame. Pure so it is unit-testable.
fn coalesce_frames(frames: Vec<Frame>) -> Vec<Frame> {
    // Index of the last frame seen for each output name.
    let mut last: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, f) in frames.iter().enumerate() {
        last.insert(f.output.clone(), i);
    }
    let mut keep: Vec<usize> = last.into_values().collect();
    keep.sort_unstable();

    // Single ownership pass: emit frame i iff i is a keeper (the sorted
    // `keep` cursor and the iteration advance together, so this is O(n)).
    let mut keep_iter = keep.into_iter().peekable();
    let mut result = Vec::with_capacity(keep_iter.len());
    for (i, f) in frames.into_iter().enumerate() {
        if keep_iter.peek() == Some(&i) {
            keep_iter.next();
            result.push(f);
        }
    }
    result
}

/// The user this lock episode concerns is always whoever this process is
/// running as -- lion-session drops privileges to that user before
/// starting the session, and lion-locker is one of its autostart apps.
fn whoami() -> String {
    let uid = unsafe { libc::getuid() };
    users::get_user_by_uid(uid)
        .map(|u| u.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| uid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frames with the *same* output name but distinguishable content
    /// (width carries the sequence number), as the coalescer requires:
    /// it deduplicates by output and keeps the newest.
    fn frame_for(output: &str, seq: u32) -> Frame {
        use std::os::fd::FromRawFd;
        // SAFETY(test): dup(0) returns a valid owned fd or -1; on the
        // (impossible in practice) -1 path the assert fails loudly
        // rather than silently misbehave. Nothing in the coalescer
        // reads or maps it.
        let raw = unsafe { libc::dup(0) };
        assert!(raw >= 0);
        Frame {
            output: output.to_owned(),
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) },
            width: seq as i32,
            height: 1,
            stride: 4,
            format: "xrgb8888".into(),
        }
    }

    #[test]
    fn coalesce_keeps_newest_per_output_in_order() {
        // Three frames for "hdmi", two for "dp": only the last of each
        // survives, in last-occurrence order.
        let frames = vec![
            frame_for("hdmi", 1),
            frame_for("dp", 1),
            frame_for("hdmi", 2),
            frame_for("hdmi", 3),
            frame_for("dp", 2),
        ];
        let kept = coalesce_frames(frames);
        let ids: Vec<(String, i32)> = kept.iter().map(|f| (f.output.clone(), f.width)).collect();
        // hdmi's last occurrence (seq 3) comes before dp's (seq 2).
        assert_eq!(ids, vec![("hdmi".into(), 3), ("dp".into(), 2)]);
    }

    #[test]
    fn coalesce_single_frame_passthrough() {
        let frames = vec![frame_for("hdmi", 1)];
        let kept = coalesce_frames(frames);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].output, "hdmi");
        assert_eq!(kept[0].width, 1);
    }

    #[test]
    fn coalesce_interleaved_keeps_only_last() {
        let frames = vec![
            frame_for("a", 1),
            frame_for("b", 1),
            frame_for("a", 2),
            frame_for("c", 1),
            frame_for("b", 2),
            frame_for("a", 3),
        ];
        let kept = coalesce_frames(frames);
        let ids: Vec<(String, i32)> = kept.iter().map(|f| (f.output.clone(), f.width)).collect();
        assert_eq!(ids, vec![("c".into(), 1), ("b".into(), 2), ("a".into(), 3)]);
    }

    #[test]
    fn phase_strings_are_stable_api() {
        assert_eq!(LockPhase::Idle.as_str(), "idle");
        assert_eq!(LockPhase::Locking.as_str(), "locking");
        assert_eq!(LockPhase::Locked.as_str(), "locked");
    }
}
