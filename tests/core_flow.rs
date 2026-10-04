//! Core behaviour against scripted fakes (spec 03 §3, §6, §10).
mod common;
use common::*;
use lion_locker::core::{Event, LockSource, Signal};
use lion_locker::ports::{BackendEvent, LogindEvent};
use lion_locker::Error;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[tokio::test]
async fn lock_engages_and_wires_everything() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    assert_eq!(h.state(), "locked");
    assert!(h.h.snapshot.borrow().locked);
    assert_eq!(h.sigs.recv().await, Some(Signal::Locked));
    // marker, hint, privacy, UI
    assert!(h.cfg.marker_path().exists());
    assert_eq!(*h.logind.hints.lock().unwrap(), vec![true]);
    assert_eq!(*h.privacy.states.lock().unwrap(), vec![(true, true)]);
    assert_eq!(h.launcher.spawned(), 1);
    // The Show event reaches a UI that connects afterwards.
    let mut ui = h.connect_ui().await;
    let show = ui.event("Show").await;
    assert_eq!(show["user"], "lion");
    assert_eq!(show["hide_notification_content"], true);
    assert_eq!(show["show_media_controls"], true);
    h.finish().await;
}

#[tokio::test]
async fn lock_is_idempotent_and_coalesces() {
    let h = Harness::new().await;
    let (a, b) = tokio::join!(h.lock(LockSource::Bus), h.lock(LockSource::Logind));
    a.unwrap();
    b.unwrap();
    h.lock(LockSource::Bus).await.unwrap();
    assert_eq!(h.backend.count("lock"), 1);
    assert_eq!(h.launcher.spawned(), 1);
    h.finish().await;
}

#[tokio::test]
async fn correct_password_unlocks_and_wrong_does_not() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;

    let bad = ui.attempt("wrong").await;
    assert_eq!(bad["ok"], false);
    assert_eq!(bad["failures"], 1);
    assert_eq!(h.state(), "locked");
    assert_eq!(h.backend.count("unlock"), 0);
    assert_eq!(h.sigs.recv().await, Some(Signal::Locked));
    assert_eq!(h.sigs.recv().await, Some(Signal::AuthFailed(1)));

    let good = ui.attempt("hunter2").await;
    assert_eq!(good["ok"], true);
    h.wait_state("unlocked").await;
    assert_eq!(h.backend.count("unlock"), 1);
    assert!(!h.cfg.marker_path().exists());
    assert_eq!(*h.logind.hints.lock().unwrap(), vec![true, false]);
    assert_eq!(h.sigs.recv().await, Some(Signal::Unlocked));
    ui.event("Hide").await;
    h.finish().await;
}

#[tokio::test]
async fn throttle_engages_and_is_enforced_by_the_daemon() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    // free_attempts = 2 → third failure starts a 1 s lockout
    for _ in 0..3 {
        assert_eq!(ui.attempt("nope").await["ok"], false);
    }
    let t = ui.event("Throttle").await;
    assert!(t["seconds"].as_u64().unwrap() >= 1);
    // A hostile UI that ignores the countdown is refused by the daemon.
    let id = ui.request(json!({"op":"Begin"}));
    let r = ui.response(id).await;
    assert_eq!(r["ok"], false);
    assert_eq!(r["error"]["code"], "throttled");
    // Even the right password cannot be tried during the lockout.
    assert_eq!(h.state(), "locked");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(ui.attempt("hunter2").await["ok"], true);
    h.wait_state("unlocked").await;
    h.finish().await;
}

#[tokio::test]
async fn throttle_state_is_sent_on_reconnect() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    {
        let mut ui = h.connect_ui().await;
        ui.event("Show").await;
        for _ in 0..3 {
            ui.attempt("nope").await;
        }
    }
    let mut ui2 = h.connect_ui().await;
    let show = ui2.event("Show").await;
    assert_eq!(show["failures"], 3);
    assert!(ui2.event("Throttle").await["seconds"].as_u64().unwrap() >= 1);
    h.finish().await;
}

#[tokio::test]
async fn pam_service_failure_is_not_a_penalty() {
    let mut h = Harness::with(|_| {}, lion_locker::pam::mock::MockScript::service_error()).await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    let id = ui.request(json!({"op":"Begin"}));
    assert_eq!(ui.response(id).await["ok"], true);
    // No prompt is ever shown; the verdict is a generic service error.
    let r = ui.event("AuthResult").await;
    assert_eq!(r["ok"], false);
    assert_eq!(r["reason"], "authentication service unavailable");
    assert_eq!(r["failures"], 0, "service errors must not count as guesses");
    assert_eq!(h.state(), "locked");
    h.finish().await;
}

#[tokio::test]
async fn bus_unlock_requires_a_pam_grant() {
    let h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    // Not authenticated → denied, still locked, backend untouched.
    assert!(matches!(h.bus_unlock().await, Err(Error::Denied(_))));
    assert_eq!(h.state(), "locked");
    assert_eq!(h.backend.count("unlock"), 0);
    // Not locked → error
    let h2 = Harness::new().await;
    assert!(h2.bus_unlock().await.is_err());
    h.finish().await;
    h2.finish().await;
}

#[tokio::test]
async fn explicit_unlock_mode_grant_then_unlock() {
    let mut h = Harness::with(
        |c| c.explicit_unlock = true,
        lion_locker::pam::mock::MockScript::success("hunter2"),
    )
    .await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    assert_eq!(ui.attempt("hunter2").await["ok"], true);
    // PAM verified, but the lock stays until the owner calls Unlock().
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.state(), "locked");
    h.bus_unlock().await.unwrap();
    h.wait_state("unlocked").await;
    // The grant is single-use.
    h.lock(LockSource::Bus).await.unwrap();
    assert!(h.bus_unlock().await.is_err());
    h.finish().await;
}

#[tokio::test]
async fn explicit_unlock_grant_expires() {
    let mut h = Harness::with(
        |c| c.explicit_unlock = true,
        lion_locker::pam::mock::MockScript::success("hunter2"),
    )
    .await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    ui.attempt("hunter2").await;
    tokio::time::sleep(Duration::from_millis(600)).await; // ttl is 400 ms
    assert!(matches!(h.bus_unlock().await, Err(Error::Denied(_))));
    assert_eq!(h.state(), "locked");
    h.finish().await;
}

#[tokio::test]
async fn ui_crash_never_unlocks_and_respawns() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    for i in 0..5 {
        let before = h.launcher.spawned();
        h.launcher.crash_latest();
        // respawn happens with backoff
        tokio::time::timeout(Duration::from_secs(3), async {
            while h.launcher.spawned() <= before {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no respawn after crash {i}"));
        assert_eq!(h.state(), "locked");
    }
    assert_eq!(h.backend.count("unlock"), 0);
    let _ = h.connect_ui().await;
    h.finish().await;
}

/// Spec 03 §10 chaos test: kill the lock UI 100 times; the session must
/// never become accessible.
#[tokio::test]
async fn chaos_kill_ui_100_times_never_unlocks() {
    let mut h = Harness::with(
        |c| {
            c.ui.respawn_backoff_ms = 10;
            c.ui.respawn_backoff_max_ms = 10;
        },
        lion_locker::pam::mock::MockScript::success("hunter2"),
    )
    .await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut seen = h.launcher.spawned();
    for i in 0..100 {
        h.launcher.crash_latest();
        // Interleave hostile traffic while the UI is dying.
        if i % 7 == 0 {
            let mut ui = h.connect_ui().await;
            ui.request(json!({"op":"Begin"}));
            drop(ui);
        }
        let _ = h.bus_unlock().await; // always denied
        tokio::time::timeout(Duration::from_secs(3), async {
            while h.launcher.spawned() <= seen {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no respawn after kill {i}"));
        seen = h.launcher.spawned();
        assert_eq!(h.state(), "locked", "iteration {i}");
        assert_eq!(h.backend.count("unlock"), 0, "iteration {i}");
    }
    assert!(h.h.snapshot.borrow().locked);
    assert!(h.cfg.marker_path().exists());
    assert_eq!(h.launcher.alive(), 1, "exactly one UI alive at the end");
    h.finish().await;
}

#[tokio::test]
async fn ui_disconnect_mid_auth_cancels_without_penalty() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    {
        let mut ui = h.connect_ui().await;
        ui.event("Show").await;
        let id = ui.request(json!({"op":"Begin"}));
        ui.response(id).await;
        ui.event("Prompt").await;
    } // UI dies here
    h.send(Event::UiDisconnected { conn: 1 });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.h.snapshot.borrow().failures, 0);
    // A fresh UI can authenticate normally.
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    assert_eq!(ui.attempt("hunter2").await["ok"], true);
    h.wait_state("unlocked").await;
    h.finish().await;
}

#[tokio::test]
async fn preflight_failure_refuses_to_lock() {
    let h = Harness::with(
        |c| c.preflight = true,
        lion_locker::pam::mock::MockScript::success("x"),
    )
    .await;
    *h.preflight.fail.lock().unwrap() = Some("PAM service missing".into());
    let r = h.lock(LockSource::Bus).await;
    assert!(matches!(r, Err(Error::Lock(_))));
    assert_eq!(h.state(), "unlocked");
    assert_eq!(h.backend.count("lock"), 0, "the screen must not be taken");
    assert!(!h.cfg.marker_path().exists());
    assert_eq!(h.notifier.sent.lock().unwrap().len(), 1);
    h.finish().await;
}

#[tokio::test]
async fn preflight_is_skipped_when_restoring_a_lock() {
    let h = Harness::with(
        |c| c.preflight = true,
        lion_locker::pam::mock::MockScript::success("x"),
    )
    .await;
    *h.preflight.fail.lock().unwrap() = Some("PAM service missing".into());
    // A restore must lock even if the unlock path looks broken: the
    // compositor may already be locked and nobody would own the lock.
    h.send(Event::Lock {
        source: LockSource::Startup,
        reply: None,
    });
    h.wait_state("locked").await;
    h.finish().await;
}

#[tokio::test]
async fn restart_with_marker_relocks_before_ready() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = test_config(tmp.path());
    std::fs::create_dir_all(cfg.state_dir()).unwrap();
    std::fs::write(cfg.marker_path(), b"locked\n").unwrap();
    let h = Harness::build(
        cfg,
        tmp,
        lion_locker::pam::mock::MockScript::success("hunter2"),
        true,
    )
    .await;
    h.wait_state("locked").await;
    assert_eq!(h.backend.count("lock"), 1);
    h.finish().await;
}

#[tokio::test]
async fn compositor_refusal_aborts_cleanly() {
    let h = Harness::new().await;
    *h.backend.deny.lock().unwrap() = true;
    let r = h.lock(LockSource::Bus).await;
    assert!(r.is_err());
    assert_eq!(h.state(), "unlocked");
    assert!(!h.cfg.marker_path().exists());
    assert_eq!(h.launcher.spawned(), 0);
    h.finish().await;
}

#[tokio::test]
async fn backend_lock_error_aborts_but_restore_retries() {
    let h = Harness::new().await;
    *h.backend.lock_error.lock().unwrap() = true;
    assert!(h.lock(LockSource::Bus).await.is_err());
    assert_eq!(h.state(), "unlocked");
    // Restore path: keeps retrying until the compositor accepts.
    let before = h.backend.count("lock");
    h.send(Event::Lock {
        source: LockSource::Startup,
        reply: None,
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(h.backend.count("lock") >= before + 2, "restore must retry");
    assert_eq!(h.state(), "locking");
    *h.backend.lock_error.lock().unwrap() = false;
    h.wait_state("locked").await;
    h.finish().await;
}

#[tokio::test]
async fn finished_while_locked_relocks_and_never_unlocks() {
    let h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    h.backend.emit(BackendEvent::Finished);
    tokio::time::timeout(Duration::from_secs(3), async {
        while h.backend.count("lock") < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(h.backend.count("unlock"), 0);
    h.wait_state("locked").await;
    h.finish().await;
}

#[tokio::test]
async fn fatal_backend_keeps_marker_and_exits_nonzero() {
    let h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    let marker = h.cfg.marker_path();
    h.backend
        .emit(BackendEvent::Fatal("wayland socket closed".into()));
    let code = tokio::time::timeout(Duration::from_secs(3), h.join)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(code, 1);
    assert!(marker.exists(), "restart must re-lock");
}

#[tokio::test]
async fn sigterm_while_locked_never_unlocks() {
    let h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    let marker = h.cfg.marker_path();
    let backend = h.backend.clone();
    let (code, _tmp) = h.finish_keep().await;
    assert_eq!(code, 0);
    assert_eq!(backend.count("unlock"), 0);
    assert!(
        marker.exists(),
        "the marker must survive so a restart re-locks"
    );
}

#[tokio::test]
async fn unlock_backend_failure_stays_locked() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    *h.backend.unlock_error.lock().unwrap() = true;
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    assert_eq!(ui.attempt("hunter2").await["ok"], true);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(h.state(), "locked");
    assert!(h.cfg.marker_path().exists());
    h.finish().await;
}

#[tokio::test]
async fn sleep_locks_before_suspend_and_releases_inhibitor() {
    let h = Harness::new().await;
    // startup takes the delay inhibitor
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.logind.live.load(Ordering::SeqCst), 1);
    h.send(Event::Logind(LogindEvent::PrepareForSleep(true)));
    h.wait_state("locked").await;
    // inhibitor released once the lock is engaged → suspend may proceed
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.logind.live.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("inhibitor must be released after the lock engages");
    // wake-up: a new inhibitor is taken for the next sleep
    h.send(Event::Logind(LogindEvent::PrepareForSleep(false)));
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.logind.live.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    h.finish().await;
}

#[tokio::test]
async fn sleep_deadline_releases_inhibitor_even_if_lock_never_confirms() {
    let h = Harness::new().await;
    *h.backend.confirm_after.lock().unwrap() = None; // compositor stalls
    tokio::time::sleep(Duration::from_millis(50)).await;
    h.send(Event::Logind(LogindEvent::PrepareForSleep(true)));
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.logind.live.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("suspend must not be blocked forever (300 ms deadline)");
    h.finish().await;
}

#[tokio::test]
async fn lock_on_suspend_false_takes_no_inhibitor() {
    let h = Harness::with(
        |c| c.lock_on_suspend = false,
        lion_locker::pam::mock::MockScript::success("x"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.logind.taken.load(Ordering::SeqCst), 0);
    h.send(Event::Logind(LogindEvent::PrepareForSleep(true)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.state(), "unlocked");
    h.finish().await;
}

#[tokio::test]
async fn lid_and_logind_lock_follow_config() {
    let h = Harness::new().await;
    h.send(Event::Logind(LogindEvent::LidClosed(false)));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.state(), "unlocked");
    h.send(Event::Logind(LogindEvent::LidClosed(true)));
    h.wait_state("locked").await;
    h.finish().await;

    let h = Harness::with(
        |c| {
            c.lock_on_lid_close = false;
            c.honor_logind_lock = false;
        },
        lion_locker::pam::mock::MockScript::success("x"),
    )
    .await;
    h.send(Event::Logind(LogindEvent::LidClosed(true)));
    h.send(Event::Logind(LogindEvent::Lock));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.state(), "unlocked");
    h.finish().await;
}

#[tokio::test]
async fn grace_period_allows_unlock_free_window_only() {
    let mut h = Harness::with(
        |c| c.grace_period_ms = 400,
        lion_locker::pam::mock::MockScript::success("x"),
    )
    .await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    let show = ui.event("Show").await;
    assert!(show["grace_ms_remaining"].as_u64().unwrap() > 0);
    let id = ui.request(json!({"op":"GraceUnlock"}));
    assert_eq!(ui.response(id).await["ok"], true);
    h.wait_state("unlocked").await;

    // After the window the request is refused.
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let id = ui.request(json!({"op":"GraceUnlock"}));
    let r = ui.response(id).await;
    assert_eq!(r["error"]["code"], "not_allowed");
    assert_eq!(h.state(), "locked");
    h.finish().await;
}

#[tokio::test]
async fn grace_disabled_by_default() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    let id = ui.request(json!({"op":"GraceUnlock"}));
    assert_eq!(ui.response(id).await["ok"], false);
    assert_eq!(h.state(), "locked");
    h.finish().await;
}

#[tokio::test]
async fn quick_actions_only_while_locked_and_when_enabled() {
    let mut h = Harness::with(
        |c| c.greeter_session_id = "c2".into(),
        lion_locker::pam::mock::MockScript::success("x"),
    )
    .await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    let show = ui.event("Show").await;
    assert_eq!(show["actions"], json!(["switch_user", "shutdown"]));
    let id = ui.request(json!({"op":"Action","action":"switch_user"}));
    assert_eq!(ui.response(id).await["ok"], true);
    let id = ui.request(json!({"op":"Action","action":"shutdown"}));
    assert_eq!(ui.response(id).await["ok"], true);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(*h.logind.activated.lock().unwrap(), vec!["c2".to_string()]);
    assert_eq!(h.logind.poweroffs.load(Ordering::SeqCst), 1);
    h.finish().await;

    let mut h = Harness::with(
        |c| c.allow_shutdown = false,
        lion_locker::pam::mock::MockScript::success("x"),
    )
    .await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    for a in ["shutdown", "switch_user"] {
        let id = ui.request(json!({"op":"Action","action":a}));
        assert_eq!(ui.response(id).await["error"]["code"], "not_allowed");
    }
    assert_eq!(h.logind.poweroffs.load(Ordering::SeqCst), 0);
    h.finish().await;
}

#[tokio::test]
async fn ui_requests_before_lock_are_refused() {
    let mut h = Harness::new().await;
    let mut ui = h.connect_ui().await;
    let id = ui.request(json!({"op":"Begin"}));
    assert_eq!(ui.response(id).await["error"]["code"], "not_locked");
    let id = ui.request(json!({"op":"GraceUnlock"}));
    assert_eq!(ui.response(id).await["ok"], false);
    h.finish().await;
}

#[tokio::test]
async fn ui_requests_are_rate_limited() {
    let mut h = Harness::with(
        |c| {
            c.rate_limit.max_calls = 5;
            c.rate_limit.window_ms = 60_000;
        },
        lion_locker::pam::mock::MockScript::success("x"),
    )
    .await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    let mut limited = false;
    for _ in 0..10 {
        let id = ui.request(json!({"op":"Hello"}));
        if ui.response(id).await["error"]["code"] == "rate_limited" {
            limited = true;
        }
    }
    assert!(limited);
    h.finish().await;
}

#[tokio::test]
async fn second_ui_connection_replaces_the_first() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut a = h.connect_ui().await;
    a.event("Show").await;
    let mut b = h.connect_ui().await;
    b.event("Show").await;
    assert!(a.closed());
    // The stale connection can no longer drive PAM.
    a.request(json!({"op":"Begin"}));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.state(), "locked");
    h.finish().await;
}

#[tokio::test]
async fn hello_reports_state() {
    let mut h = Harness::new().await;
    h.lock(LockSource::Bus).await.unwrap();
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    let id = ui.request(json!({"op":"Hello"}));
    let r = ui.response(id).await;
    assert_eq!(r["result"]["locked"], true);
    assert_eq!(r["result"]["user"], "lion");
    h.finish().await;
}

#[tokio::test]
async fn no_ui_spawn_when_exec_is_empty() {
    let mut h = Harness::with(
        |c| c.ui.exec = vec![],
        lion_locker::pam::mock::MockScript::success("hunter2"),
    )
    .await;
    h.lock(LockSource::Bus).await.unwrap();
    assert_eq!(h.launcher.spawned(), 0);
    // An externally started UI can still connect and unlock.
    let mut ui = h.connect_ui().await;
    ui.event("Show").await;
    assert_eq!(ui.attempt("hunter2").await["ok"], true);
    h.wait_state("unlocked").await;
    h.finish().await;
}

#[tokio::test]
async fn unlock_then_relock_works_repeatedly() {
    let mut h = Harness::new().await;
    for _ in 0..3 {
        h.lock(LockSource::Bus).await.unwrap();
        let mut ui = h.connect_ui().await;
        ui.event("Show").await;
        assert_eq!(ui.attempt("hunter2").await["ok"], true);
        h.wait_state("unlocked").await;
    }
    assert_eq!(h.backend.count("lock"), 3);
    assert_eq!(h.backend.count("unlock"), 3);
    assert_eq!(h.launcher.alive(), 0, "no UI left behind after unlock");
    h.finish().await;
}

#[tokio::test]
async fn reload_applies_new_limits_and_rejects_bad_config() {
    let mut h = Harness::new().await;
    let mut bad = h.cfg.clone();
    bad.grace_period_ms = 999_999;
    h.send(Event::Reload(Box::new(bad)));
    let mut good = h.cfg.clone();
    good.hide_notification_content = false;
    h.send(Event::Reload(Box::new(good)));
    h.lock(LockSource::Bus).await.unwrap();
    assert_eq!(*h.privacy.states.lock().unwrap(), vec![(true, false)]);
    let _ = &mut h;
    h.finish().await;
}

#[tokio::test]
async fn restore_survives_early_finished_events() {
    let h = Harness::new().await;
    // Compositor answers the first two restore attempts with `finished`.
    *h.backend.confirm_after.lock().unwrap() = None;
    h.send(Event::Lock {
        source: LockSource::Startup,
        reply: None,
    });
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_millis(30)).await;
        h.backend.emit(BackendEvent::Finished);
    }
    // Still "locking" (never "unlocked"): the state must not disagree with
    // a compositor that is in fact locked.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.state(), "locking");
    assert!(h.cfg.marker_path().exists());
    tokio::time::timeout(Duration::from_secs(3), async {
        while h.backend.count("lock") < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("must retry the lock request");
    h.backend.emit(BackendEvent::Locked);
    h.wait_state("locked").await;
    h.finish().await;
}

#[tokio::test]
async fn ui_pid_is_published_and_cleared() {
    let h = Harness::new().await;
    assert_eq!(h.h.ui_pid.load(Ordering::SeqCst), 0);
    h.lock(LockSource::Bus).await.unwrap();
    let pid = h.h.ui_pid.load(Ordering::SeqCst);
    assert!(pid > 0);
    h.launcher.crash_latest();
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.h.ui_pid.load(Ordering::SeqCst) == pid {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("pid must change after a crash/respawn");
    let ui_pid = h.h.ui_pid.clone();
    h.finish().await;
    assert_eq!(ui_pid.load(Ordering::SeqCst), 0);
}
