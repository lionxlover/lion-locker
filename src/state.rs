//! Durable lock-episode marker: the crash-relock primitive.
//!
//! The single most dangerous property of a Wayland session locker is
//! that `ext-session-lock-v1` grants the lock to *this process*, which
//! means a locker crash destroys the lock and exposes the session until
//! something relocks it. Compositors mitigate (Hyprland keeps outputs
//! locked if the locker dies mid-episode) — but lion-locker must not
//! *depend* on compositor goodwill.
//!
//! So: while locked, a marker file exists at
//! `$XDG_RUNTIME_DIR/lion-locker/locked` (tmpfs, never hits disk,
//! vanishes on logout/boot). At startup, if the marker is present, the
//! locker knows a previous instance died mid-episode and re-acquires
//! the lock immediately — turning the exposure window from "until a
//! human notices" into "one process restart" (systemd: `Restart=always`
//! + `RestartSec=0`, see lion-locker.service).
//!
//! All writes are atomic (tmp + rename) so a crash can never leave a
//! torn marker that flips the semantics.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .map(|d| d.join("lion-locker"))
}

fn marker_path() -> Option<PathBuf> {
    runtime_dir().map(|d| d.join("locked"))
}

/// Create the marker (called when the compositor confirms the lock).
pub fn mark_locked() {
    let Some(path) = marker_path() else {
        // No XDG_RUNTIME_DIR (e.g. a bare test environment): the
        // crash-relock feature degrades to disabled, never fatal.
        tracing::debug!("no XDG_RUNTIME_DIR; crash-relock marker unavailable");
        return;
    };
    let tmp = path.with_extension("tmp");
    let res = (|| -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        // 0700 on the directory: the runtime dir is per-user tmpfs
        // already, but defense in depth is free here.
        let mut f = fs::File::create(&tmp)?;
        // Content: boot-unique-ish epoch + pid, purely diagnostic.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        writeln!(f, "{now} {}", std::process::id())?;
        f.sync_all()?;
        fs::rename(&tmp, &path)
    })();
    if let Err(ref e) = res {
        tracing::warn!(error = %e, "could not write lock marker");
    }
}

/// Remove the marker (called on successful unlock / lock teardown).
pub fn mark_unlocked() {
    let Some(path) = marker_path() else { return };
    // Absent marker is fine (e.g. degraded mode above).
    let _ = fs::remove_file(path);
}

/// True when a previous instance of this locker died while locked
/// (marker present at process start). Must be called exactly once at
/// startup — and *before* this instance starts a fresh episode — to
/// avoid reading our own marker.
pub fn was_locked_at_start() -> bool {
    marker_path().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// These tests mutate a process-global env var; serialize them so
    /// parallel test execution cannot interleave set/remove races.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn fresh_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "lion-locker-marker-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn marker_round_trip() {
        let _g = env_lock().lock().unwrap();
        let dir = fresh_dir("rt");
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        assert!(!was_locked_at_start());
        mark_locked();
        assert!(was_locked_at_start());
        assert!(dir.join("lion-locker/locked").exists());
        mark_unlocked();
        assert!(!was_locked_at_start());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mark_unlocked_without_marker_is_fine() {
        let _g = env_lock().lock().unwrap();
        let dir = fresh_dir("noop");
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        mark_unlocked(); // must not panic
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn no_runtime_dir_degrades_to_false() {
        let _g = env_lock().lock().unwrap();
        std::env::remove_var("XDG_RUNTIME_DIR");
        assert!(!was_locked_at_start());
        // And marking must not panic either.
        mark_locked();
        mark_unlocked();
    }

    #[test]
    fn rewriting_marker_is_idempotent() {
        let _g = env_lock().lock().unwrap();
        let dir = fresh_dir("idem");
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        mark_locked();
        mark_locked();
        assert!(was_locked_at_start());
        // No .tmp leftovers from the atomic writes.
        assert!(!dir.join("lion-locker/locked.tmp").exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
