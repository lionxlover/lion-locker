//! Shared harness: the real `LockerCore` wired to scripted fakes.
#![allow(dead_code)]

use lion_locker::config::Config;
use lion_locker::core::{Deps, Event, Handle, LockSource, LockerCore, Signal, UiOut};
use lion_locker::mocks::*;
use lion_locker::notify::Notify;
use lion_locker::pam::mock::{MockPamFactory, MockScript};
use lion_locker::ports::BackendEvent;
use lion_locker::proto;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub struct Harness {
    pub h: Handle,
    pub backend: Arc<MockBackend>,
    pub logind: Arc<MockLogind>,
    pub notifier: Arc<MockNotifier>,
    pub privacy: Arc<MockPrivacy>,
    pub preflight: Arc<MockPreflight>,
    pub launcher: Arc<MockUiLauncher>,
    pub sigs: mpsc::UnboundedReceiver<Signal>,
    pub join: JoinHandle<i32>,
    pub cfg: Config,
    pub _tmp: tempfile::TempDir,
    next_conn: u64,
}

pub fn test_config(tmp: &std::path::Path) -> Config {
    let json = format!(
        r#"{{"locker":{{
            "state_dir":"{}",
            "preflight":false,
            "owner_uid":1000,
            "ui":{{"exec":["/bin/true"],"respawn_backoff_ms":10,"respawn_backoff_max_ms":20}},
            "throttle":{{"free_attempts":2,"base_seconds":1,"cap_seconds":4}},
            "unlock_grant_ttl_ms":400,
            "sleep_lock_timeout_ms":300
        }}}}"#,
        tmp.display()
    );
    Config::parse(&json).unwrap()
}

/// A tempdir with production-realistic permissions.
///
/// The sandbox umask (002) makes `tempfile::tempdir()` create group-
/// accessible dirs (0775). In production the state dir is logind-managed
/// 0700 (`$XDG_RUNTIME_DIR` / `/run/user/<uid>`), and the daemon now
/// *fails closed* on anything looser — so tests that exercise the real
/// paths must start from a private dir.
pub fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir().unwrap();
    std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    t
}

impl Harness {
    pub async fn new() -> Harness {
        Harness::with(|_| {}, MockScript::success("hunter2")).await
    }

    pub async fn with(tweak: impl FnOnce(&mut Config), script: MockScript) -> Harness {
        let tmp = private_tempdir();
        let mut cfg = test_config(tmp.path());
        tweak(&mut cfg);
        cfg.validate().unwrap();
        Harness::build(cfg, tmp, script, true).await
    }

    pub async fn build(
        cfg: Config,
        tmp: tempfile::TempDir,
        script: MockScript,
        start: bool,
    ) -> Harness {
        // Direct `build` callers may hand us a default tempdir; make it
        // private the same way `with` does.
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700));
        }
        let (bev_tx, mut bev_rx) = mpsc::unbounded_channel();
        let backend = MockBackend::new(bev_tx);
        let logind = Arc::new(MockLogind::default());
        let notifier = Arc::new(MockNotifier::default());
        let privacy = Arc::new(MockPrivacy::default());
        let preflight = Arc::new(MockPreflight::default());
        let launcher = Arc::new(MockUiLauncher::default());
        let deps = Deps {
            backend: backend.clone(),
            logind: logind.clone(),
            notifier: notifier.clone(),
            privacy: privacy.clone(),
            preflight: preflight.clone(),
            ui_launcher: launcher.clone(),
            pam: Arc::new(MockPamFactory::new(script)),
            notify: Notify::disabled(),
            user: "lion".into(),
        };
        let (sig_tx, sigs) = mpsc::unbounded_channel();
        let (core, h) = LockerCore::new(cfg.clone(), deps, sig_tx);
        let fwd = h.ev_tx.clone();
        tokio::spawn(async move {
            while let Some(e) = bev_rx.recv().await {
                if fwd.send(Event::Backend(e)).is_err() {
                    break;
                }
            }
        });
        let join = if start {
            tokio::spawn(core.run())
        } else {
            tokio::spawn(async { 0 })
        };
        Harness {
            h,
            backend,
            logind,
            notifier,
            privacy,
            preflight,
            launcher,
            sigs,
            join,
            cfg,
            _tmp: tmp,
            next_conn: 0,
        }
    }

    /// Send a lock request and wait for the reply.
    pub async fn lock(&self, source: LockSource) -> lion_locker::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.h
            .ev_tx
            .send(Event::Lock {
                source,
                reply: Some(tx),
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .expect("lock reply timed out")
            .unwrap()
    }

    pub async fn bus_unlock(&self) -> lion_locker::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.h.ev_tx.send(Event::Unlock { reply: tx }).unwrap();
        tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .expect("unlock reply timed out")
            .unwrap()
    }

    pub fn send(&self, e: Event) {
        self.h.ev_tx.send(e).unwrap();
    }

    pub async fn wait_state(&self, want: &str) {
        let mut rx = self.h.snapshot.clone();
        let r = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if rx.borrow().state == want {
                    return;
                }
                rx.changed().await.unwrap();
            }
        })
        .await;
        assert!(
            r.is_ok(),
            "state never became {want}; is {}",
            self.h.snapshot.borrow().state
        );
    }

    pub fn state(&self) -> &'static str {
        self.h.snapshot.borrow().state
    }

    pub async fn connect_ui(&mut self) -> UiClient {
        self.next_conn += 1;
        let (tx, rx) = mpsc::unbounded_channel();
        let conn = self.next_conn;
        self.send(Event::UiConnected { conn, tx });
        UiClient {
            conn,
            rx,
            ev: self.h.ev_tx.clone(),
            next_id: 1,
        }
    }

    pub async fn finish(self) -> i32 {
        self.finish_keep().await.0
    }

    /// Stop the core but keep the temp dir alive (inspect files after exit).
    pub async fn finish_keep(self) -> (i32, tempfile::TempDir) {
        self.send(Event::SigTerm);
        let code = tokio::time::timeout(Duration::from_secs(3), self.join)
            .await
            .expect("core did not stop")
            .unwrap();
        (code, self._tmp)
    }
}

pub struct UiClient {
    pub conn: u64,
    pub rx: mpsc::UnboundedReceiver<UiOut>,
    ev: mpsc::UnboundedSender<Event>,
    next_id: u64,
}

impl UiClient {
    /// Send a request line as the real socket handler would (decoded).
    pub fn request(&mut self, mut body: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        body["proto"] = 1.into();
        body["id"] = id.into();
        let line = body.to_string();
        let req = proto::decode_request(&line).expect("test request must decode");
        self.ev
            .send(Event::UiRequest {
                conn: self.conn,
                req,
            })
            .unwrap();
        id
    }

    pub async fn next(&mut self) -> Option<Value> {
        match tokio::time::timeout(Duration::from_secs(3), self.rx.recv()).await {
            Ok(Some(UiOut::Line(l))) => Some(serde_json::from_str(&l).unwrap()),
            Ok(Some(UiOut::Close)) | Ok(None) => None,
            Err(_) => panic!("timed out waiting for a UI line"),
        }
    }

    /// Read lines until one satisfies `pred`; returns it.
    pub async fn until(&mut self, pred: impl Fn(&Value) -> bool) -> Value {
        for _ in 0..50 {
            let v = self.next().await.expect("UI channel closed");
            if pred(&v) {
                return v;
            }
        }
        panic!("expected line never arrived");
    }

    pub async fn event(&mut self, name: &'static str) -> Value {
        self.until(|v| v["event"] == name).await
    }

    pub async fn response(&mut self, id: u64) -> Value {
        self.until(|v| v["id"] == id && v.get("ok").is_some()).await
    }

    /// Run a whole PAM attempt with `password`; returns the AuthResult.
    pub async fn attempt(&mut self, password: &str) -> Value {
        let id = self.request(serde_json::json!({"op":"Begin"}));
        let r = self.response(id).await;
        assert_eq!(r["ok"], true, "Begin failed: {r}");
        self.event("Prompt").await;
        self.request(serde_json::json!({"op":"Answer","text":password}));
        self.event("AuthResult").await
    }

    pub fn closed(&mut self) -> bool {
        loop {
            match self.rx.try_recv() {
                Ok(UiOut::Close) => return true,
                Ok(_) => continue,
                Err(mpsc::error::TryRecvError::Disconnected) => return true,
                Err(_) => return false,
            }
        }
    }
}

pub fn backend_locked(h: &Harness) {
    h.backend.emit(BackendEvent::Locked);
}
