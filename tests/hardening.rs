//! Security regression tests for the hardening pass (spec 03 §8).
//!
//! Each test pins one fail-closed guarantee introduced by the review:
//!
//! 1. the state dir / socket dir is validated for ownership + privacy
//!    (socket-squatting on `ui.sock` would capture the lock-screen
//!    password),
//! 2. the lock marker is written with `O_NOFOLLOW` (a symlinked marker
//!    must not truncate an arbitrary same-uid file),
//! 3. the lock-waiter queue is bounded (a stalled compositor must not
//!    grow unbounded memory),
//! 4. the state-dir fallback never lands in `/tmp` (see `config.rs` unit
//!    tests for the pure resolution logic).
//!
//! The ownership (wrong-uid) branch of `validate_private_dir` cannot be
//! exercised without `CAP_CHOWN`; it is covered by inspection and by the
//! mode branches here.

mod common;
use common::*;

use lion_locker::core::{ensure_state_dir, validate_private_dir, Event, LockSource, MAX_WAITERS};
use lion_locker::ports::BackendEvent;
use lion_locker::uisock;
use lion_locker::Error;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tokio::sync::oneshot;

// ── 1. directory validation (socket-squatting) ──────────────────────

#[test]
fn validate_private_dir_accepts_owned_private_dir() {
    let tmp = private_tempdir();
    assert_eq!(validate_private_dir(tmp.path()), Ok(()));
}

#[test]
fn validate_private_dir_rejects_loose_modes() {
    // Any group/other bit fails closed, even harmless-looking 0750.
    for mode in [0o750, 0o701, 0o770, 0o777] {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        let err = validate_private_dir(tmp.path()).unwrap_err();
        assert!(
            err.contains("group/other accessible"),
            "mode {mode:o}: unexpected error {err:?}"
        );
    }
}

#[test]
fn validate_private_dir_rejects_missing_and_not_a_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("does-not-exist");
    assert!(validate_private_dir(&missing)
        .unwrap_err()
        .contains("cannot stat"));

    // A regular file (even mode 0600) is not a usable state dir.
    let file = tmp.path().join("not-a-dir");
    std::fs::write(&file, b"x").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(validate_private_dir(&file)
        .unwrap_err()
        .contains("not a directory"));
}

#[tokio::test]
async fn ensure_state_dir_fails_closed_on_precreated_loose_dir() {
    let tmp = tempfile::tempdir().unwrap();
    // "Attacker": pre-create the dir with group/other access. DirBuilder
    // create(recursive) silently succeeds on an existing dir — the
    // validation afterwards must catch it.
    let dir = tmp.path().join("state");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
    let mut cfg = test_config(tmp.path());
    cfg.state_dir = dir.display().to_string();
    let err = ensure_state_dir(&cfg).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("state dir") && msg.contains("group/other"),
        "{msg}"
    );
}

#[test]
fn uisock_bind_fails_closed_on_loose_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let loose = tmp.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = uisock::bind(&loose.join("ui.sock")).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("socket dir") && msg.contains("group/other"),
        "{msg}"
    );
    // No socket may be left behind after the refusal.
    assert!(!loose.join("ui.sock").exists());
}

// ── 2. lock marker symlink safety (O_NOFOLLOW) ──────────────────────

#[tokio::test]
async fn lock_marker_is_not_written_through_symlinks() {
    let h = Harness::new().await;
    let decoy = h.cfg.state_dir().join("decoy.txt");
    std::fs::write(&decoy, b"precious\n").unwrap();
    // "Attacker": replace the marker path with a symlink to a same-uid
    // file; without O_NOFOLLOW the daemon would truncate it.
    std::os::unix::fs::symlink(&decoy, h.cfg.marker_path()).unwrap();

    h.lock(LockSource::Bus).await.unwrap();
    assert_eq!(h.state(), "locked");

    // The lock still engaged (refusing to lock over a marker failure
    // would be the worse trade-off), but the target was NOT touched.
    assert_eq!(std::fs::read(&decoy).unwrap(), b"precious\n");
    h.finish().await;
}

// ── 3. bounded lock-waiter queue ─────────────────────────────────────

#[tokio::test]
async fn lock_waiter_queue_is_bounded() {
    let h = Harness::new().await;
    // A compositor that never confirms the lock keeps the core in
    // `Locking`; every D-Bus Lock() call queues a waiter.
    *h.backend.confirm_after.lock().unwrap() = None;

    let mut queued = Vec::new();
    for _ in 0..MAX_WAITERS {
        let (tx, rx) = oneshot::channel();
        h.h.ev_tx
            .send(Event::Lock {
                source: LockSource::Bus,
                reply: Some(tx),
            })
            .unwrap();
        queued.push(rx);
    }

    // The next caller is rejected immediately instead of growing the
    // queue without bound.
    let (tx, rx) = oneshot::channel();
    h.h.ev_tx
        .send(Event::Lock {
            source: LockSource::Bus,
            reply: Some(tx),
        })
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(3), rx)
        .await
        .expect("busy reply timed out")
        .expect("sender dropped")
    {
        Err(Error::Busy(m)) => assert!(m.contains("too many"), "unexpected message: {m}"),
        other => panic!("expected Error::Busy, got {other:?}"),
    }

    // A late compositor confirmation satisfies every queued waiter.
    h.backend.emit(BackendEvent::Locked);
    for rx in queued {
        let r = tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .expect("queued reply timed out")
            .expect("sender dropped");
        assert!(r.is_ok(), "queued waiter failed: {r:?}");
    }
    assert_eq!(h.state(), "locked");
    assert_eq!(std::fs::read(h.cfg.marker_path()).unwrap(), b"locked\n");
    h.finish().await;
}
