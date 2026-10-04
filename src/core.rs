#![forbid(unsafe_code)]
//! The locker core: one task, one event channel, all mutable state.
//!
//! Same architecture as lion-session's core. Bus methods, compositor
//! events, logind signals, UI-socket requests, PAM worker events, child
//! exits and timers all arrive as [`Event`]s on a single channel. That
//! gives deterministic ordering (tests drive the core without a bus or a
//! compositor), no lock contention, and true idleness: every wait is
//! `select!`-ed, so there are **no timers or wakeups unless there is work**
//! (a watchdog tick only when systemd configured one).
//!
//! ## Safety invariants (spec 03 §3, §6, §8)
//!
//! 1. **Never fall back to unlocked.** The only transition into
//!    `Unlocked` is [`LockerCore::finish_unlock`], reachable only from
//!    [`LockerCore::do_unlock`], which is called from exactly three places:
//!    successful PAM verdict, a consumed PAM-verified grant (explicit mode)
//!    and the opt-in grace window. UI crashes, UI-socket garbage, compositor
//!    `finished` events, SIGTERM and logind `Unlock` signals never unlock.
//! 2. The lock is taken before the unlock path is verified only when the
//!    compositor is *already* locked (restore after a crash, relock).
//! 3. PAM runs for the session owner only; no caller supplies a username.
//! 4. A lock marker in the runtime dir makes a restarted daemon re-lock
//!    before it reports ready.

use crate::auth::{AuthEvent, Txn};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::notify::Notify;
use crate::pam::{AuthFailReason, AuthOutcome, PamServiceFactory};
use crate::ports::*;
use crate::proto::{self, codes, Event as UiEvent, Request, ShowInfo, UiAction};
use crate::throttle::{AuthThrottle, RateLimiter};
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Upper bound on coalesced lock waiters. Without it, a compositor that
/// never confirms the lock would let waiters (each holding a oneshot)
/// accumulate without limit; the bus rate limiter bounds the *rate*, not
/// the total. Excess callers get `Error::Busy` (surfaced on the bus as
/// `LimitsExceeded`) and must retry.
///
/// Public so tests, `lionctl` diagnostics and docs can assert the exact
/// bound; changing it is a compatibility-visible decision.
pub const MAX_WAITERS: usize = 128;

/// Why a lock was requested (typed, never caller-supplied text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockSource {
    Bus,
    Logind,
    Sleep,
    Lid,
    /// Restored from the runtime marker after a daemon restart.
    Startup,
    /// The compositor destroyed our lock object while locked.
    Relock,
}

impl LockSource {
    /// Sources where the compositor may already be locked, so refusing to
    /// lock would strand the user behind a lock nobody owns.
    fn skips_preflight(self) -> bool {
        matches!(self, LockSource::Startup | LockSource::Relock)
    }
    fn retries_on_error(self) -> bool {
        self.skips_preflight()
    }
}

/// Bus-facing signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    Locked,
    Unlocked,
    AuthFailed(u32),
}

/// Output toward one UI connection.
#[derive(Debug)]
pub enum UiOut {
    Line(String),
    Close,
}

pub type Reply = oneshot::Sender<Result<()>>;

#[derive(Debug)]
pub enum Event {
    Lock {
        source: LockSource,
        reply: Option<Reply>,
    },
    Unlock {
        reply: Reply,
    },
    Backend(BackendEvent),
    Logind(LogindEvent),
    UiConnected {
        conn: u64,
        tx: mpsc::UnboundedSender<UiOut>,
    },
    UiRequest {
        conn: u64,
        req: Request,
    },
    UiDisconnected {
        conn: u64,
    },
    Auth {
        gen: u64,
        evt: AuthEvent,
    },
    UiChildExited {
        gen: u64,
        ok: bool,
    },
    UiRespawn {
        gen: u64,
    },
    SleepTimeout {
        gen: u64,
    },
    GrantExpired {
        gen: u64,
    },
    RelockRetry {
        gen: u64,
    },
    Reload(Box<Config>),
    SigTerm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Unlocked,
    /// Lock requested, compositor has not confirmed yet.
    Locking,
    Locked,
    /// `unlock_and_destroy` in flight.
    Unlocking,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Unlocked => "unlocked",
            State::Locking => "locking",
            State::Locked => "locked",
            State::Unlocking => "unlocking",
        }
    }
}

/// Read-only view for bus properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub state: &'static str,
    /// `IsLocked`: true once the screen is covered, until unlock completes.
    pub locked: bool,
    pub failures: u32,
    pub outputs_covered: u32,
    pub outputs_total: u32,
}

/// Everything the core depends on.
pub struct Deps {
    pub backend: Arc<dyn LockBackend>,
    pub logind: Arc<dyn Logind>,
    pub notifier: Arc<dyn Notifier>,
    pub privacy: Arc<dyn Privacy>,
    pub preflight: Arc<dyn Preflight>,
    pub ui_launcher: Arc<dyn UiLauncher>,
    pub pam: Arc<dyn PamServiceFactory>,
    pub notify: Notify,
    /// Login name of the session owner (the only user PAM is opened for).
    pub user: String,
}

/// Handles handed to the surrounding runtime.
#[derive(Clone)]
pub struct Handle {
    pub ev_tx: mpsc::UnboundedSender<Event>,
    pub snapshot: watch::Receiver<Snapshot>,
    /// Pid of the supervised lock-UI child (0 = none running). The UI
    /// socket accepts only this peer when the locker spawns the UI itself,
    /// so a stray same-uid process cannot kick the real UI off the socket.
    pub ui_pid: Arc<AtomicU32>,
}

struct ActiveAuth {
    gen: u64,
    req_id: u64,
    txn: Txn,
}

struct UiConn {
    id: u64,
    tx: mpsc::UnboundedSender<UiOut>,
}

struct UiChild {
    gen: u64,
    child: Arc<dyn ChildProcess>,
    started: Instant,
}

pub struct LockerCore {
    cfg: Config,
    deps: Deps,
    rx: mpsc::UnboundedReceiver<Event>,
    ev_tx: mpsc::UnboundedSender<Event>,
    sig_tx: mpsc::UnboundedSender<Signal>,
    snap_tx: watch::Sender<Snapshot>,
    ui_pid: Arc<AtomicU32>,

    state: State,
    waiters: Vec<Reply>,
    lock_requested_at: Option<Instant>,
    locked_at: Option<Instant>,
    lock_source: LockSource,
    relock_pending: bool,
    relock_gen: u64,
    relock_backoff_ms: u64,
    outputs: (u32, u32),

    throttle: AuthThrottle,
    auth: Option<ActiveAuth>,
    auth_gen: u64,
    grant: Option<(u64, Instant)>,
    grant_gen: u64,

    ui: Option<UiConn>,
    ui_child: Option<UiChild>,
    ui_gen: u64,
    ui_failures: u32,
    ui_respawn: Option<JoinHandle<()>>,
    ui_limiter: RateLimiter,

    inhibitor: Option<InhibitorGuard>,
    pending_sleep: bool,
    sleep_gen: u64,
}

const BACKEND_CALL_TIMEOUT: Duration = Duration::from_secs(3);
const BUS_CALL_TIMEOUT: Duration = Duration::from_millis(750);

impl LockerCore {
    pub fn new(
        cfg: Config,
        deps: Deps,
        sig_tx: mpsc::UnboundedSender<Signal>,
    ) -> (LockerCore, Handle) {
        let (ev_tx, rx) = mpsc::unbounded_channel();
        let snap = Snapshot {
            state: State::Unlocked.as_str(),
            locked: false,
            failures: 0,
            outputs_covered: 0,
            outputs_total: 0,
        };
        let (snap_tx, snap_rx) = watch::channel(snap);
        let throttle = AuthThrottle::new(cfg.throttle.clone());
        let ui_limiter = RateLimiter::new(
            Duration::from_millis(cfg.rate_limit.window_ms),
            cfg.rate_limit.max_calls,
        );
        let ui_pid = Arc::new(AtomicU32::new(0));
        let core = LockerCore {
            ui_pid: ui_pid.clone(),
            cfg,
            deps,
            rx,
            ev_tx: ev_tx.clone(),
            sig_tx,
            snap_tx,
            state: State::Unlocked,
            waiters: vec![],
            lock_requested_at: None,
            locked_at: None,
            lock_source: LockSource::Bus,
            relock_pending: false,
            relock_gen: 0,
            relock_backoff_ms: 250,
            outputs: (0, 0),
            throttle,
            auth: None,
            auth_gen: 0,
            grant: None,
            grant_gen: 0,
            ui: None,
            ui_child: None,
            ui_gen: 0,
            ui_failures: 0,
            ui_respawn: None,
            ui_limiter,
            inhibitor: None,
            pending_sleep: false,
            sleep_gen: 0,
        };
        (
            core,
            Handle {
                ev_tx,
                snapshot: snap_rx,
                ui_pid,
            },
        )
    }

    pub fn state(&self) -> State {
        self.state
    }

    // ── main loop ───────────────────────────────────────────────────

    /// Run until SIGTERM or an unrecoverable backend failure. Returns the
    /// process exit code. **Never unlocks on the way out**: dropping the
    /// compositor connection leaves ext-session-lock-v1 locked.
    pub async fn run(mut self) -> i32 {
        self.init().await;
        self.deps.notify.ready();

        let mut watchdog = self.deps.notify.watchdog_interval().map(|d| {
            let mut i = tokio::time::interval(d);
            i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            i
        });

        let code = loop {
            let ev = tokio::select! {
                ev = self.rx.recv() => match ev {
                    Some(ev) => ev,
                    None => break 0,
                },
                _ = async {
                    match watchdog.as_mut() {
                        Some(i) => { i.tick().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    self.deps.notify.watchdog_tick();
                    continue;
                }
            };
            if let Some(code) = self.handle(ev).await {
                break code;
            }
            self.publish();
        };

        self.deps.notify.stopping();
        self.stop_ui();
        self.inhibitor = None;
        code
    }

    async fn init(&mut self) {
        if let Err(e) = ensure_state_dir(&self.cfg) {
            tracing::error!(target: "locker", "cannot create state dir: {e}");
        }
        if self.cfg.lock_on_suspend {
            self.retake_inhibitor().await;
        }
        if marker_exists(&self.cfg) {
            tracing::warn!(target: "locker", "lock marker found: restoring the lock before ready");
            self.do_lock(LockSource::Startup, None).await;
        }
        self.publish();
    }

    async fn handle(&mut self, ev: Event) -> Option<i32> {
        match ev {
            Event::Lock { source, reply } => self.do_lock(source, reply).await,
            Event::Unlock { reply } => self.on_bus_unlock(reply).await,
            Event::Backend(b) => return self.on_backend(b).await,
            Event::Logind(l) => self.on_logind(l).await,
            Event::UiConnected { conn, tx } => self.on_ui_connected(conn, tx),
            Event::UiRequest { conn, req } => self.on_ui_request(conn, req).await,
            Event::UiDisconnected { conn } => self.on_ui_disconnected(conn),
            Event::Auth { gen, evt } => self.on_auth(gen, evt).await,
            Event::UiChildExited { gen, ok } => self.on_ui_child_exited(gen, ok),
            Event::UiRespawn { gen } => {
                if gen == self.ui_gen && self.state == State::Locked {
                    self.spawn_ui().await;
                }
            }
            Event::SleepTimeout { gen } => {
                if gen == self.sleep_gen && self.pending_sleep {
                    tracing::error!(target: "locker", "lock did not engage before the sleep deadline; releasing the inhibitor");
                    self.pending_sleep = false;
                    self.inhibitor = None;
                }
            }
            Event::GrantExpired { gen } => {
                if self.grant.map(|(g, _)| g) == Some(gen) {
                    self.grant = None;
                    tracing::info!(target: "locker", "unlock grant expired");
                }
            }
            Event::RelockRetry { gen } => {
                if gen == self.relock_gen && self.state == State::Locking {
                    self.submit_lock(self.lock_source).await;
                }
            }
            Event::Reload(cfg) => self.on_reload(*cfg).await,
            Event::SigTerm => {
                tracing::info!(target: "locker", "SIGTERM: stopping (the compositor keeps the screen locked)");
                return Some(0);
            }
        }
        None
    }

    // ── locking ─────────────────────────────────────────────────────

    async fn do_lock(&mut self, source: LockSource, reply: Option<Reply>) {
        match self.state {
            State::Locked => {
                if let Some(r) = reply {
                    let _ = r.send(Ok(()));
                }
                return;
            }
            State::Locking => {
                if let Some(r) = reply {
                    self.push_waiter(r);
                }
                return;
            }
            State::Unlocking => {
                self.relock_pending = true;
                if let Some(r) = reply {
                    self.push_waiter(r);
                }
                return;
            }
            State::Unlocked => {}
        }

        if self.cfg.preflight && !source.skips_preflight() {
            if let Err(e) = self.deps.preflight.check(&self.cfg) {
                tracing::error!(target: "locker", "refusing to lock into an un-unlockable state: {e}");
                self.notify_user("Screen lock unavailable", &format!("{e}"))
                    .await;
                self.release_sleep_hold();
                if let Some(r) = reply {
                    let _ = r.send(Err(e));
                }
                return;
            }
        }

        if let Some(r) = reply {
            self.push_waiter(r);
        }
        self.write_marker();
        self.state = State::Locking;
        self.lock_source = source;
        self.lock_requested_at = Some(Instant::now());
        self.relock_backoff_ms = 250;
        tracing::info!(target: "locker", ?source, "lock requested");
        self.submit_lock(source).await;
    }

    /// Queue a lock waiter, rejecting excess callers (`Error::Busy`) so a
    /// stalled compositor can never grow the queue without bound.
    fn push_waiter(&mut self, r: Reply) {
        if self.waiters.len() >= MAX_WAITERS {
            tracing::warn!(target: "locker", waiters = self.waiters.len(), "lock queue full");
            let _ = r.send(Err(Error::Busy("too many pending lock requests".into())));
        } else {
            self.waiters.push(r);
        }
    }

    /// Submit `lock()` to the backend; on error either retry (restore
    /// paths) or abort the attempt.
    async fn submit_lock(&mut self, source: LockSource) {
        let r = tokio::time::timeout(BACKEND_CALL_TIMEOUT, self.deps.backend.lock()).await;
        let err = match r {
            Ok(Ok(())) => return,
            Ok(Err(e)) => e,
            Err(_) => Error::Wayland("lock request timed out".into()),
        };
        tracing::error!(target: "locker", "lock request failed: {err}");
        if source.retries_on_error() {
            self.relock_gen += 1;
            let gen = self.relock_gen;
            let d = Duration::from_millis(self.relock_backoff_ms);
            self.relock_backoff_ms = (self.relock_backoff_ms * 2).min(5_000);
            self.after(d, Event::RelockRetry { gen });
        } else {
            self.abort_lock(err).await;
        }
    }

    async fn abort_lock(&mut self, err: Error) {
        self.remove_marker();
        self.state = State::Unlocked;
        self.release_sleep_hold();
        let msg = format!("{err}");
        for w in self.waiters.drain(..) {
            let _ = w.send(Err(Error::Lock(msg.clone())));
        }
        self.notify_user(
            "Screen lock failed",
            "The compositor did not accept the lock.",
        )
        .await;
    }

    async fn on_backend(&mut self, ev: BackendEvent) -> Option<i32> {
        match ev {
            BackendEvent::Locked => {
                if self.state == State::Locking {
                    self.state = State::Locked;
                    self.locked_at = Some(Instant::now());
                    self.finish_lock().await;
                }
            }
            BackendEvent::Finished => match self.state {
                State::Locking if self.lock_source.retries_on_error() => {
                    // Restore/re-lock paths: the compositor may already be
                    // locked (previous holder died), so aborting to
                    // "unlocked" would disagree with reality. Retry with
                    // backoff until a lock request is accepted.
                    tracing::warn!(target: "locker", "lock request finished early during restore; retrying");
                    self.relock_gen += 1;
                    let gen = self.relock_gen;
                    let d = Duration::from_millis(self.relock_backoff_ms);
                    self.relock_backoff_ms = (self.relock_backoff_ms * 2).min(5_000);
                    self.after(d, Event::RelockRetry { gen });
                }
                State::Locking => {
                    tracing::error!(target: "locker", "compositor refused the lock (finished before locked)");
                    self.abort_lock(Error::Wayland("compositor refused the lock".into()))
                        .await;
                }
                State::Locked => {
                    // The compositor stays locked on its own; take the
                    // lock over again. Never claim "unlocked".
                    tracing::error!(target: "locker", "lock object destroyed while locked: re-locking");
                    self.state = State::Locking;
                    self.lock_source = LockSource::Relock;
                    self.lock_requested_at = Some(Instant::now());
                    self.relock_backoff_ms = 250;
                    self.submit_lock(LockSource::Relock).await;
                }
                State::Unlocking | State::Unlocked => {}
            },
            BackendEvent::Outputs { covered, total } => {
                self.outputs = (covered, total);
            }
            BackendEvent::Fatal(msg) => {
                tracing::error!(target: "locker", "compositor connection lost: {msg}");
                // Keep the marker (if locked): systemd restarts us and the
                // restarted daemon re-locks before it reports ready.
                return Some(1);
            }
        }
        None
    }

    async fn finish_lock(&mut self) {
        let latency = self
            .lock_requested_at
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);
        tracing::info!(target: "locker", latency_ms = latency, source = ?self.lock_source, "screen locked");
        for w in self.waiters.drain(..) {
            let _ = w.send(Ok(()));
        }
        self.publish(); // properties first, so clients never see a signal ahead of its state
        let _ = self.sig_tx.send(Signal::Locked);
        self.release_sleep_hold();
        self.bus_call_hint(true).await;
        self.bus_call_privacy(true).await;
        self.spawn_ui().await;
        self.send_show();
    }

    // ── unlocking ───────────────────────────────────────────────────

    async fn on_bus_unlock(&mut self, reply: Reply) {
        if self.state != State::Locked {
            let _ = reply.send(Err(Error::Lock("not locked".into())));
            return;
        }
        let ttl = self.cfg.grant_ttl();
        match self.grant {
            Some((_, t)) if t.elapsed() <= ttl => {
                self.grant = None;
                let _ = reply.send(Ok(()));
                self.do_unlock("grant").await;
            }
            _ => {
                tracing::warn!(target: "locker", "Unlock() without a PAM-verified grant: denied");
                let _ = reply.send(Err(Error::Denied("not authenticated".into())));
            }
        }
    }

    /// The single gate to `Unlocked`. See the module invariants.
    async fn do_unlock(&mut self, why: &'static str) {
        if self.state != State::Locked {
            return;
        }
        self.state = State::Unlocking;
        self.cancel_auth();
        self.grant = None;
        self.send_ui(UiEvent::Hide);
        let r = tokio::time::timeout(BACKEND_CALL_TIMEOUT, self.deps.backend.unlock()).await;
        match r {
            Ok(Ok(())) => self.finish_unlock(why).await,
            other => {
                let why_not = match other {
                    Ok(Err(e)) => format!("{e}"),
                    _ => "timed out".into(),
                };
                tracing::error!(target: "locker", "unlock failed ({why_not}); staying locked");
                self.state = State::Locked;
                self.send_show();
                self.notify_user("Unlock failed", "The compositor did not release the lock.")
                    .await;
            }
        }
    }

    async fn finish_unlock(&mut self, why: &'static str) {
        self.remove_marker();
        self.state = State::Unlocked;
        self.locked_at = None;
        self.throttle.reset();
        self.stop_ui();
        tracing::info!(target: "locker", via = why, "screen unlocked");
        self.publish();
        let _ = self.sig_tx.send(Signal::Unlocked);
        self.bus_call_hint(false).await;
        self.bus_call_privacy(false).await;
        if self.relock_pending {
            self.relock_pending = false;
            self.do_lock(LockSource::Relock, None).await;
        }
    }

    // ── lock UI process & socket ───────────────────────────────────

    async fn spawn_ui(&mut self) {
        if self.cfg.ui.exec.is_empty() || self.state != State::Locked || self.ui_child.is_some() {
            return;
        }
        self.ui_gen += 1;
        let gen = self.ui_gen;
        let argv = self.cfg.ui.exec.clone();
        match self.deps.ui_launcher.spawn(&argv).await {
            Ok(child) => {
                let child: Arc<dyn ChildProcess> = Arc::from(child);
                let waiter = child.clone();
                let tx = self.ev_tx.clone();
                tokio::spawn(async move {
                    let ok = waiter.wait().await;
                    let _ = tx.send(Event::UiChildExited { gen, ok });
                });
                tracing::info!(target: "locker", pid = child.pid(), "lock UI started");
                self.ui_pid.store(child.pid(), Ordering::SeqCst);
                self.ui_child = Some(UiChild {
                    gen,
                    child,
                    started: Instant::now(),
                });
            }
            Err(e) => {
                tracing::error!(target: "locker", "cannot start the lock UI: {e}");
                self.schedule_ui_respawn();
            }
        }
    }

    fn on_ui_child_exited(&mut self, gen: u64, ok: bool) {
        match &self.ui_child {
            Some(c) if c.gen == gen => {}
            _ => return, // stale (we killed it, or a newer one runs)
        }
        self.ui_pid.store(0, Ordering::SeqCst);
        let ran = self.ui_child.take().map(|c| c.started.elapsed());
        if ran.map(|d| d > Duration::from_secs(10)).unwrap_or(false) {
            self.ui_failures = 0;
        }
        // The auth conversation died with the UI: abort it (no penalty).
        self.cancel_auth();
        self.ui = None;
        if self.state == State::Locked {
            tracing::error!(target: "locker", clean_exit = ok, "lock UI exited while locked: staying locked, respawning");
            self.schedule_ui_respawn();
        }
    }

    fn schedule_ui_respawn(&mut self) {
        if let Some(h) = self.ui_respawn.take() {
            h.abort();
        }
        let base = self.cfg.ui.respawn_backoff_ms;
        let d = base
            .saturating_mul(
                1u64.checked_shl(self.ui_failures.min(20))
                    .unwrap_or(u64::MAX),
            )
            .min(self.cfg.ui.respawn_backoff_max_ms);
        self.ui_failures = self.ui_failures.saturating_add(1);
        self.ui_gen += 1;
        let gen = self.ui_gen;
        self.ui_respawn = Some(self.after(Duration::from_millis(d), Event::UiRespawn { gen }));
    }

    fn stop_ui(&mut self) {
        if let Some(h) = self.ui_respawn.take() {
            h.abort();
        }
        self.ui_gen += 1; // invalidates pending exit/respawn events
        self.ui_pid.store(0, Ordering::SeqCst);
        if let Some(c) = self.ui_child.take() {
            c.child.kill();
        }
        if let Some(u) = self.ui.take() {
            let _ = u.tx.send(UiOut::Close);
        }
        self.ui_failures = 0;
    }

    fn on_ui_connected(&mut self, conn: u64, tx: mpsc::UnboundedSender<UiOut>) {
        if let Some(old) = self.ui.take() {
            let _ = old.tx.send(UiOut::Close);
            self.cancel_auth();
        }
        self.ui = Some(UiConn { id: conn, tx });
        if self.state == State::Locked {
            self.send_show();
        }
    }

    fn on_ui_disconnected(&mut self, conn: u64) {
        if self.ui.as_ref().map(|u| u.id) == Some(conn) {
            self.ui = None;
            // UI gone mid-conversation: abort PAM, no failure penalty.
            self.cancel_auth();
        }
    }

    fn show_info(&self) -> ShowInfo {
        let grace = self
            .locked_at
            .map(|t| self.cfg.grace_period().saturating_sub(t.elapsed()))
            .unwrap_or_default();
        ShowInfo {
            user: self.deps.user.clone(),
            emergency_info: self.cfg.emergency_info.clone(),
            hide_notification_content: self.cfg.hide_notification_content,
            show_media_controls: self.cfg.show_media_controls,
            actions: self.cfg.ui_actions(),
            grace_ms_remaining: grace.as_millis() as u64,
            failures: self.throttle.failures(),
            outputs_covered: self.outputs.0,
            outputs_total: self.outputs.1,
        }
    }

    fn send_show(&mut self) {
        let info = self.show_info();
        self.send_ui(UiEvent::Show(info));
        let secs = self.throttle.remaining_secs(Instant::now().into_std());
        if secs > 0 {
            self.send_ui(UiEvent::Throttle { seconds: secs });
        }
    }

    fn send_ui(&self, ev: UiEvent) {
        let id = self.auth.as_ref().map(|a| a.req_id).unwrap_or(0);
        self.send_ui_line(ev.to_wire(id));
    }

    fn send_ui_line(&self, line: String) {
        if let Some(u) = &self.ui {
            let _ = u.tx.send(UiOut::Line(line));
        }
    }

    async fn on_ui_request(&mut self, conn: u64, req: Request) {
        if self.ui.as_ref().map(|u| u.id) != Some(conn) {
            return; // stale connection
        }
        let id = req.id();
        if !self
            .ui_limiter
            .allow(&conn.to_string(), Instant::now().into_std())
        {
            self.send_ui_line(proto::error_response(
                id,
                codes::RATE_LIMITED,
                "too many requests",
            ));
            return;
        }
        match req {
            Request::Hello { id } => {
                let line = proto::ok_response(
                    id,
                    json!({
                        "proto": proto::PROTO_VERSION,
                        "version": crate::VERSION,
                        "locked": self.state == State::Locked,
                        "user": self.deps.user,
                    }),
                );
                self.send_ui_line(line);
            }
            Request::Begin { id } => self.ui_begin(id),
            Request::Answer { id, text } => match &self.auth {
                Some(a) => {
                    if a.txn.answer(text) {
                        self.send_ui_line(proto::ok_response(id, json!({})));
                    } else {
                        self.send_ui_line(proto::error_response(
                            id,
                            codes::NO_TRANSACTION,
                            "no authentication in progress",
                        ));
                    }
                }
                None => self.send_ui_line(proto::error_response(
                    id,
                    codes::NO_TRANSACTION,
                    "no authentication in progress",
                )),
            },
            Request::Cancel { id } => {
                self.cancel_auth();
                self.send_ui_line(proto::ok_response(id, json!({})));
            }
            Request::GraceUnlock { id } => {
                let in_grace = self.state == State::Locked
                    && self
                        .locked_at
                        .map(|t| t.elapsed() < self.cfg.grace_period())
                        .unwrap_or(false);
                if in_grace {
                    self.send_ui_line(proto::ok_response(id, json!({})));
                    self.do_unlock("grace").await;
                } else {
                    self.send_ui_line(proto::error_response(
                        id,
                        codes::NOT_ALLOWED,
                        "no grace window is open",
                    ));
                }
            }
            Request::Action { id, action } => self.ui_action(id, action),
        }
    }

    fn ui_begin(&mut self, id: u64) {
        if self.state != State::Locked {
            self.send_ui_line(proto::error_response(id, codes::NOT_LOCKED, "not locked"));
            return;
        }
        let secs = self.throttle.remaining_secs(Instant::now().into_std());
        if secs > 0 {
            // Enforced here, not in the UI: a hostile UI cannot skip it.
            self.send_ui_line(proto::error_response(id, codes::THROTTLED, "locked out"));
            self.send_ui(UiEvent::Throttle { seconds: secs });
            return;
        }
        self.cancel_auth();
        self.auth_gen += 1;
        let gen = self.auth_gen;
        let mut txn = Txn::start(
            self.deps.pam.clone(),
            self.cfg.pam.service.clone(),
            self.deps.user.clone(),
            self.cfg.pam_timeout(),
        );
        if let Some(mut rx) = txn.take_events() {
            let tx = self.ev_tx.clone();
            tokio::spawn(async move {
                while let Some(evt) = rx.recv().await {
                    let fin = matches!(evt, AuthEvent::Finished);
                    if tx.send(Event::Auth { gen, evt }).is_err() || fin {
                        break;
                    }
                }
            });
        }
        self.auth = Some(ActiveAuth {
            gen,
            req_id: id,
            txn,
        });
        self.send_ui_line(proto::ok_response(id, json!({})));
    }

    fn ui_action(&mut self, id: u64, action: UiAction) {
        let allowed = self.state == State::Locked
            && match action {
                UiAction::Shutdown => self.cfg.allow_shutdown,
                UiAction::SwitchUser => !self.cfg.greeter_session_id.is_empty(),
            };
        if !allowed {
            self.send_ui_line(proto::error_response(
                id,
                codes::NOT_ALLOWED,
                "action not available",
            ));
            return;
        }
        let logind = self.deps.logind.clone();
        let greeter = self.cfg.greeter_session_id.clone();
        tokio::spawn(async move {
            let r = match action {
                UiAction::Shutdown => logind.power_off().await,
                UiAction::SwitchUser => logind.activate_session(&greeter).await,
            };
            if let Err(e) = r {
                tracing::warn!(target: "locker", action = action.as_str(), "quick action failed: {e}");
            }
        });
        self.send_ui_line(proto::ok_response(id, json!({})));
    }

    // ── authentication ──────────────────────────────────────────────

    fn cancel_auth(&mut self) {
        if let Some(a) = self.auth.take() {
            a.txn.cancel();
        }
    }

    async fn on_auth(&mut self, gen: u64, evt: AuthEvent) {
        match &self.auth {
            Some(a) if a.gen == gen => {}
            _ => return, // stale transaction
        }
        match evt {
            AuthEvent::Prompt(spec) => {
                self.send_ui(UiEvent::Prompt {
                    kind: spec.kind,
                    text: spec.text,
                });
            }
            AuthEvent::Done(AuthOutcome::Success) => self.on_auth_success().await,
            AuthEvent::Done(AuthOutcome::Failed(reason)) => self.on_auth_failure(reason),
            AuthEvent::SetCredDone(_) => {}
            AuthEvent::Finished => {
                self.auth = None;
            }
        }
    }

    async fn on_auth_success(&mut self) {
        let req = self.auth.as_ref().map(|a| a.req_id).unwrap_or(0);
        self.auth = None;
        let ev = UiEvent::AuthResult {
            ok: true,
            reason: String::new(),
            failures: 0,
        };
        self.send_ui_line(ev.to_wire(req));
        if self.cfg.explicit_unlock {
            self.throttle.reset();
            self.grant_gen += 1;
            let g = self.grant_gen;
            self.grant = Some((g, Instant::now()));
            self.after(self.cfg.grant_ttl(), Event::GrantExpired { gen: g });
            tracing::info!(target: "locker", "PAM verified; waiting for Unlock()");
        } else {
            self.do_unlock("pam").await;
        }
    }

    fn on_auth_failure(&mut self, reason: AuthFailReason) {
        let req = self.auth.as_ref().map(|a| a.req_id).unwrap_or(0);
        self.auth = None;
        // Wrong credentials count; infrastructure problems do not.
        let penalised = matches!(
            reason,
            AuthFailReason::AuthErr
                | AuthFailReason::AcctExpired
                | AuthFailReason::Locked
                | AuthFailReason::NewAuthtokFailed
        );
        let mut delay = Duration::ZERO;
        if penalised {
            delay = self.throttle.record_failure(Instant::now().into_std());
            self.publish();
            let _ = self
                .sig_tx
                .send(Signal::AuthFailed(self.throttle.failures()));
        }
        tracing::warn!(target: "locker", reason = reason.ui_reason(), failures = self.throttle.failures(), "authentication failed");
        let ev = UiEvent::AuthResult {
            ok: false,
            reason: reason.ui_reason().to_string(),
            failures: self.throttle.failures(),
        };
        self.send_ui_line(ev.to_wire(req));
        if !delay.is_zero() {
            let secs = self.throttle.remaining_secs(Instant::now().into_std());
            self.send_ui_line(UiEvent::Throttle { seconds: secs }.to_wire(req));
        }
    }

    // ── logind ──────────────────────────────────────────────────────

    async fn on_logind(&mut self, ev: LogindEvent) {
        match ev {
            LogindEvent::Lock => {
                if self.cfg.honor_logind_lock {
                    self.do_lock(LockSource::Logind, None).await;
                }
            }
            LogindEvent::LidClosed(true) => {
                if self.cfg.lock_on_lid_close {
                    self.do_lock(LockSource::Lid, None).await;
                }
            }
            LogindEvent::LidClosed(false) => {}
            LogindEvent::PrepareForSleep(true) => {
                if !self.cfg.lock_on_suspend {
                    self.inhibitor = None;
                    return;
                }
                if self.state == State::Locked {
                    self.inhibitor = None;
                    return;
                }
                self.pending_sleep = true;
                self.sleep_gen += 1;
                let gen = self.sleep_gen;
                self.after(self.cfg.sleep_lock_timeout(), Event::SleepTimeout { gen });
                self.do_lock(LockSource::Sleep, None).await;
            }
            LogindEvent::PrepareForSleep(false) => {
                self.pending_sleep = false;
                if self.cfg.lock_on_suspend {
                    self.retake_inhibitor().await;
                }
            }
        }
    }

    fn release_sleep_hold(&mut self) {
        if self.pending_sleep {
            self.pending_sleep = false;
        }
        self.inhibitor = None;
    }

    async fn retake_inhibitor(&mut self) {
        if self.inhibitor.is_some() {
            return;
        }
        match tokio::time::timeout(BUS_CALL_TIMEOUT, self.deps.logind.take_sleep_inhibitor()).await
        {
            Ok(Ok(g)) => self.inhibitor = Some(g),
            Ok(Err(e)) => {
                tracing::warn!(target: "locker", "cannot take the sleep inhibitor: {e}; the lock will race the suspend")
            }
            Err(_) => tracing::warn!(target: "locker", "sleep inhibitor request timed out"),
        }
    }

    // ── reload ──────────────────────────────────────────────────────

    async fn on_reload(&mut self, cfg: Config) {
        if let Err(e) = cfg.validate() {
            tracing::error!(target: "locker", "reload rejected: {e}");
            return;
        }
        self.throttle.reconfigure(cfg.throttle.clone());
        self.ui_limiter = RateLimiter::new(
            Duration::from_millis(cfg.rate_limit.window_ms),
            cfg.rate_limit.max_calls,
        );
        let toggled_suspend = cfg.lock_on_suspend != self.cfg.lock_on_suspend;
        self.cfg = cfg;
        if toggled_suspend {
            if self.cfg.lock_on_suspend {
                self.retake_inhibitor().await;
            } else {
                self.inhibitor = None;
            }
        }
        tracing::info!(target: "locker", "configuration reloaded");
    }

    // ── helpers ─────────────────────────────────────────────────────

    fn publish(&self) {
        let snap = Snapshot {
            state: self.state.as_str(),
            locked: matches!(self.state, State::Locked | State::Unlocking),
            failures: self.throttle.failures(),
            outputs_covered: self.outputs.0,
            outputs_total: self.outputs.1,
        };
        self.snap_tx.send_if_modified(|cur| {
            if *cur == snap {
                false
            } else {
                *cur = snap;
                true
            }
        });
    }

    fn after(&self, d: Duration, ev: Event) -> JoinHandle<()> {
        let tx = self.ev_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(d).await;
            let _ = tx.send(ev);
        })
    }

    async fn notify_user(&self, summary: &str, body: &str) {
        let _ =
            tokio::time::timeout(BUS_CALL_TIMEOUT, self.deps.notifier.notify(summary, body)).await;
    }

    async fn bus_call_hint(&self, locked: bool) {
        match tokio::time::timeout(BUS_CALL_TIMEOUT, self.deps.logind.set_locked_hint(locked)).await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(target: "locker", "SetLockedHint failed: {e}"),
            Err(_) => tracing::warn!(target: "locker", "SetLockedHint timed out"),
        }
    }

    async fn bus_call_privacy(&self, locked: bool) {
        let hide = self.cfg.hide_notification_content;
        match tokio::time::timeout(
            BUS_CALL_TIMEOUT,
            self.deps.privacy.set_lock_state(locked, hide),
        )
        .await
        {
            Ok(Ok(())) => {}
            // Best effort: the UI gets the same flag in `Show`.
            Ok(Err(e)) => {
                tracing::debug!(target: "locker", "notification privacy not applied: {e}")
            }
            Err(_) => tracing::debug!(target: "locker", "notification privacy call timed out"),
        }
    }

    fn write_marker(&self) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.cfg.marker_path();
        let r = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            // SECURITY: O_NOFOLLOW — a same-uid attacker could otherwise
            // symlink the marker at an arbitrary file and we would truncate
            // it (mode 0600 applies at creation only).
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .and_then(|mut f| f.write_all(b"locked\n"));
        if let Err(e) = r {
            // Not fatal: refusing to lock because the marker cannot be
            // written would be the worse failure.
            tracing::error!(target: "locker", "cannot write lock marker {}: {e}", path.display());
        }
    }

    fn remove_marker(&self) {
        let path = self.cfg.marker_path();
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::error!(target: "locker", "cannot remove lock marker {}: {e}", path.display())
            }
        }
    }
}

/// Create the runtime dir with mode 0700 and verify it is private.
///
/// SECURITY (fail closed): if the directory already exists but is not
/// owned by this uid or is group/other-accessible, we refuse to use it —
/// a pre-created directory with loose permissions would let an attacker
/// unlink/replace `ui.sock` and capture the password typed into the lock
/// screen (socket-squatting).
pub fn ensure_state_dir(cfg: &Config) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = cfg.state_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| Error::Io(format!("create {}", dir.display()), e))?;
    validate_private_dir(&dir).map_err(|e| Error::Lock(format!("state dir {}: {e}", dir.display())))
}

/// The directory must be owned by the running uid and must not be
/// accessible by group/other (mode 0700/possibly stricter). Pure check —
/// unit-tested.
pub fn validate_private_dir(dir: &std::path::Path) -> std::result::Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(dir).map_err(|e| format!("cannot stat: {e}"))?;
    if !meta.is_dir() {
        return Err("not a directory".into());
    }
    let me = crate::sysffi::getuid();
    if meta.uid() != me {
        return Err(format!(
            "owned by uid {}, but the daemon runs as uid {me} (possible pre-created-dir attack)",
            meta.uid()
        ));
    }
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "mode {:o} is group/other accessible; require 0700",
            mode & 0o777
        ));
    }
    Ok(())
}

pub fn marker_exists(cfg: &Config) -> bool {
    cfg.marker_path().exists()
}

/// Real preflight: PAM service file present, UI binary executable.
pub struct FsPreflight;

impl Preflight for FsPreflight {
    fn check(&self, cfg: &Config) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let pam = std::path::Path::new(&cfg.pam_dir).join(&cfg.pam.service);
        if !pam.is_file() {
            return Err(Error::Lock(format!(
                "PAM service {:?} is not installed ({}); refusing to lock into an un-unlockable state",
                cfg.pam.service,
                pam.display()
            )));
        }
        if let Some(ui) = cfg.ui.exec.first() {
            let ok = std::fs::metadata(ui)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false);
            if !ok {
                return Err(Error::Lock(format!(
                    "lock UI {ui} is missing or not executable; refusing to lock into an un-unlockable state"
                )));
            }
        }
        Ok(())
    }
}
