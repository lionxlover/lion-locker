//! Atomic counters exposed via `GetMetrics()` (same contract shape as
//! lion-greeter, extended with locker-specific events). Lock-free: every
//! counter is a relaxed atomic — these are telemetry, not control flow.

use std::sync::atomic::{AtomicU64, Ordering};

static EPISODES: AtomicU64 = AtomicU64::new(0);
static ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static SUCCESSES: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);
static THROTTLED_MILLIS: AtomicU64 = AtomicU64::new(0);
static CHATTER_EVENTS: AtomicU64 = AtomicU64::new(0);
static FRAMES_PRESENTED: AtomicU64 = AtomicU64::new(0);
static CRASH_RELOCKS: AtomicU64 = AtomicU64::new(0);
static STARTED: std::sync::LazyLock<std::time::Instant> =
    std::sync::LazyLock::new(std::time::Instant::now);
static STARTED_UNIX: AtomicU64 = AtomicU64::new(0);

pub fn init_started_unix() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    STARTED_UNIX.store(now, Ordering::Relaxed);
}

pub fn inc_episodes() {
    EPISODES.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_attempts() {
    ATTEMPTS.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_success() {
    SUCCESSES.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_failure() {
    FAILURES.fetch_add(1, Ordering::Relaxed);
}
pub fn add_throttled_ms(ms: u64) {
    THROTTLED_MILLIS.fetch_add(ms, Ordering::Relaxed);
}
pub fn inc_chatter() {
    CHATTER_EVENTS.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_frames() {
    FRAMES_PRESENTED.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_crash_relock() {
    CRASH_RELOCKS.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot as JSON (schema-stable; fields only get added).
pub fn to_json() -> String {
    serde_json::json!({
        "episodes": EPISODES.load(Ordering::Relaxed),
        "auth_attempts": ATTEMPTS.load(Ordering::Relaxed),
        "auth_successes": SUCCESSES.load(Ordering::Relaxed),
        "auth_failures": FAILURES.load(Ordering::Relaxed),
        "throttled_millis": THROTTLED_MILLIS.load(Ordering::Relaxed),
        "chatter_events": CHATTER_EVENTS.load(Ordering::Relaxed),
        "frames_presented": FRAMES_PRESENTED.load(Ordering::Relaxed),
        "crash_relocks": CRASH_RELOCKS.load(Ordering::Relaxed),
        "uptime_seconds": STARTED.elapsed().as_secs(),
        "started_unix": STARTED_UNIX.load(Ordering::Relaxed),
    })
    .to_string()
}

/// Zero the counters (not uptime) — `ResetMetrics()`.
pub fn reset() {
    for c in [
        &EPISODES,
        &ATTEMPTS,
        &SUCCESSES,
        &FAILURES,
        &THROTTLED_MILLIS,
        &CHATTER_EVENTS,
        &FRAMES_PRESENTED,
        &CRASH_RELOCKS,
    ] {
        c.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_schema_is_stable() {
        let j = to_json();
        for key in [
            "episodes",
            "auth_attempts",
            "auth_successes",
            "auth_failures",
            "throttled_millis",
            "chatter_events",
            "frames_presented",
            "crash_relocks",
            "uptime_seconds",
            "started_unix",
        ] {
            assert!(j.contains(&format!("\"{key}\"")), "missing key {key}");
        }
        // Valid JSON overall.
        assert!(serde_json::from_str::<serde_json::Value>(&j).is_ok());
    }

    #[test]
    fn counters_increment_and_reset() {
        reset();
        inc_episodes();
        inc_attempts();
        inc_attempts();
        inc_success();
        inc_frames();
        inc_crash_relock();
        add_throttled_ms(1500);
        let j = to_json();
        assert!(j.contains("\"episodes\":1"));
        assert!(j.contains("\"auth_attempts\":2"));
        assert!(j.contains("\"throttled_millis\":1500"));
        reset();
        assert!(to_json().contains("\"episodes\":0"));
    }
}
