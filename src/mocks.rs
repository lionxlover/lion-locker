#![forbid(unsafe_code)]
//! Scripted fakes for every port (tests, `--mock` demo mode, benches).

use crate::config::Config;
use crate::error::{Error, Result};
use crate::ports::*;
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Fake compositor backend.
///
/// Behaviour knobs (set before use): `confirm_after` — send `Locked` that
/// long after `lock()`; `None` = never confirm (tests emit manually via
/// [`MockBackend::emit`]); `deny` — answer `lock()` with `Finished`.
pub struct MockBackend {
    ev: mpsc::UnboundedSender<BackendEvent>,
    pub calls: Mutex<Vec<&'static str>>,
    pub confirm_after: Mutex<Option<Duration>>,
    pub deny: Mutex<bool>,
    pub lock_error: Mutex<bool>,
    pub unlock_error: Mutex<bool>,
}

impl MockBackend {
    pub fn new(ev: mpsc::UnboundedSender<BackendEvent>) -> Arc<MockBackend> {
        Arc::new(MockBackend {
            ev,
            calls: Mutex::new(vec![]),
            confirm_after: Mutex::new(Some(Duration::from_millis(1))),
            deny: Mutex::new(false),
            lock_error: Mutex::new(false),
            unlock_error: Mutex::new(false),
        })
    }

    pub fn emit(&self, e: BackendEvent) {
        let _ = self.ev.send(e);
    }

    pub fn count(&self, what: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| **c == what)
            .count()
    }
}

#[async_trait]
impl LockBackend for MockBackend {
    async fn lock(&self) -> Result<()> {
        self.calls.lock().unwrap().push("lock");
        if *self.lock_error.lock().unwrap() {
            return Err(Error::Wayland("scripted lock error".into()));
        }
        if *self.deny.lock().unwrap() {
            self.emit(BackendEvent::Finished);
            return Ok(());
        }
        let after = *self.confirm_after.lock().unwrap();
        if let Some(d) = after {
            let ev = self.ev.clone();
            tokio::spawn(async move {
                tokio::time::sleep(d).await;
                let _ = ev.send(BackendEvent::Locked);
            });
        }
        Ok(())
    }

    async fn unlock(&self) -> Result<()> {
        self.calls.lock().unwrap().push("unlock");
        if *self.unlock_error.lock().unwrap() {
            return Err(Error::Wayland("scripted unlock error".into()));
        }
        Ok(())
    }
}

/// Counts live inhibitors (guard drop = release).
#[derive(Default)]
pub struct MockLogind {
    pub hints: Mutex<Vec<bool>>,
    pub taken: AtomicUsize,
    pub live: Arc<AtomicUsize>,
    pub poweroffs: AtomicUsize,
    pub activated: Mutex<Vec<String>>,
    pub inhibit_error: Mutex<bool>,
}

struct LiveToken(Arc<AtomicUsize>);
impl Drop for LiveToken {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl Logind for MockLogind {
    async fn set_locked_hint(&self, locked: bool) -> Result<()> {
        self.hints.lock().unwrap().push(locked);
        Ok(())
    }
    async fn take_sleep_inhibitor(&self) -> Result<InhibitorGuard> {
        if *self.inhibit_error.lock().unwrap() {
            return Err(Error::Logind("scripted inhibit error".into()));
        }
        self.taken.fetch_add(1, Ordering::SeqCst);
        self.live.fetch_add(1, Ordering::SeqCst);
        Ok(InhibitorGuard::new(LiveToken(self.live.clone())))
    }
    async fn power_off(&self) -> Result<()> {
        self.poweroffs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn activate_session(&self, id: &str) -> Result<()> {
        self.activated.lock().unwrap().push(id.to_string());
        Ok(())
    }
}

#[derive(Default)]
pub struct MockNotifier {
    pub sent: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl Notifier for MockNotifier {
    async fn notify(&self, summary: &str, body: &str) -> Result<()> {
        self.sent
            .lock()
            .unwrap()
            .push((summary.to_string(), body.to_string()));
        Ok(())
    }
}

#[derive(Default)]
pub struct MockPrivacy {
    pub states: Mutex<Vec<(bool, bool)>>,
}

#[async_trait]
impl Privacy for MockPrivacy {
    async fn set_lock_state(&self, locked: bool, hide_content: bool) -> Result<()> {
        self.states.lock().unwrap().push((locked, hide_content));
        Ok(())
    }
}

/// Preflight with a scripted verdict.
#[derive(Default)]
pub struct MockPreflight {
    pub fail: Mutex<Option<String>>,
}

impl Preflight for MockPreflight {
    fn check(&self, _cfg: &Config) -> Result<()> {
        match &*self.fail.lock().unwrap() {
            Some(m) => Err(Error::Lock(m.clone())),
            None => Ok(()),
        }
    }
}

/// Fake UI processes: each spawn is a handle tests can exit or kill.
#[derive(Default)]
pub struct MockUiLauncher {
    pub spawns: AtomicUsize,
    pub fail_spawn: Mutex<bool>,
    children: Mutex<Vec<Arc<MockChildInner>>>,
}

pub struct MockChildInner {
    pid: u32,
    exit: watch::Sender<Option<bool>>,
}

impl MockChildInner {
    fn finish(&self, ok: bool) {
        let _ = self.exit.send_if_modified(|v| {
            if v.is_none() {
                *v = Some(ok);
                true
            } else {
                false
            }
        });
    }
}

struct MockChild(Arc<MockChildInner>);

#[async_trait]
impl ChildProcess for MockChild {
    fn pid(&self) -> u32 {
        self.0.pid
    }
    async fn wait(&self) -> bool {
        let mut rx = self.0.exit.subscribe();
        loop {
            if let Some(ok) = *rx.borrow() {
                return ok;
            }
            if rx.changed().await.is_err() {
                return false;
            }
        }
    }
    fn kill(&self) {
        self.0.finish(false);
    }
}

#[async_trait]
impl UiLauncher for MockUiLauncher {
    async fn spawn(&self, _argv: &[String]) -> Result<Box<dyn ChildProcess>> {
        if *self.fail_spawn.lock().unwrap() {
            return Err(Error::Lock("scripted spawn failure".into()));
        }
        let n = self.spawns.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, _rx) = watch::channel(None);
        let inner = Arc::new(MockChildInner {
            pid: 40_000 + n as u32,
            exit: tx,
        });
        self.children.lock().unwrap().push(inner.clone());
        Ok(Box::new(MockChild(inner)))
    }
}

impl MockUiLauncher {
    pub fn spawned(&self) -> usize {
        self.spawns.load(Ordering::SeqCst)
    }

    /// Crash the most recently spawned UI (abnormal exit).
    pub fn crash_latest(&self) {
        if let Some(c) = self.children.lock().unwrap().last() {
            c.finish(false);
        }
    }

    /// How many spawned children have not exited yet.
    pub fn alive(&self) -> usize {
        self.children
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.exit.borrow().is_none())
            .count()
    }
}
