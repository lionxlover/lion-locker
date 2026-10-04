#![forbid(unsafe_code)]
//! Wrong-password throttling and per-caller rate limiting.
//!
//! * [`AuthThrottle`] — exponential lockout after repeated failures
//!   (spec 03 §3 "throttling with a visible lockout countdown"). Soft
//!   layer: `pam_faillock` stays authoritative; this prevents the UI from
//!   becoming a fast guessing oracle even when PAM has no faillock.
//!   Time is injected (`Instant` parameters) so the table tests are
//!   deterministic; no timers (idle means idle).
//! * [`RateLimiter`] — sliding-window per-caller limiter for bus calls and
//!   UI requests (spec 03 §8 "rate-limit expensive calls"), bounded key
//!   map, lazy pruning.

use crate::config::ThrottleConfig;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AuthThrottle {
    cfg: ThrottleConfig,
    failures: u32,
    until: Option<Instant>,
}

impl AuthThrottle {
    pub fn new(cfg: ThrottleConfig) -> Self {
        AuthThrottle {
            cfg,
            failures: 0,
            until: None,
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Hot-reload new limits (SIGHUP) without forgetting current failures.
    pub fn reconfigure(&mut self, cfg: ThrottleConfig) {
        self.cfg = cfg;
    }

    /// Delay imposed after the `n`-th consecutive failure (pure).
    pub fn delay_for(cfg: &ThrottleConfig, n: u32) -> Duration {
        if !cfg.enabled || n <= cfg.free_attempts {
            return Duration::ZERO;
        }
        let exp = (n - cfg.free_attempts - 1).min(32);
        let secs = cfg
            .base_seconds
            .saturating_mul(1u64.checked_shl(exp).unwrap_or(u64::MAX))
            .min(cfg.cap_seconds);
        Duration::from_secs(secs)
    }

    /// Record a failure at `now`; returns the lockout it triggered.
    pub fn record_failure(&mut self, now: Instant) -> Duration {
        self.failures = self.failures.saturating_add(1);
        let d = Self::delay_for(&self.cfg, self.failures);
        self.until = if d.is_zero() {
            None
        } else {
            now.checked_add(d)
        };
        d
    }

    /// Remaining lockout at `now` (zero when free to try).
    pub fn remaining(&self, now: Instant) -> Duration {
        match self.until {
            Some(t) => t.saturating_duration_since(now),
            None => Duration::ZERO,
        }
    }

    /// Whole seconds remaining, rounded *up* so the UI never shows 0 while
    /// still locked out.
    pub fn remaining_secs(&self, now: Instant) -> u64 {
        let r = self.remaining(now);
        r.as_secs() + u64::from(r.subsec_nanos() > 0)
    }

    pub fn reset(&mut self) {
        self.failures = 0;
        self.until = None;
    }
}

/// Max tracked callers (overflow evicts the stalest).
const MAX_KEYS: usize = 256;

#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    max: u32,
    events: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new(window: Duration, max: u32) -> RateLimiter {
        RateLimiter {
            window,
            max: max.max(1),
            events: HashMap::new(),
        }
    }

    /// May `key` perform one more call at `now`? Records it when allowed.
    pub fn allow(&mut self, key: &str, now: Instant) -> bool {
        let window = self.window;
        let entry = self.events.entry(key.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) < window);
        if entry.len() >= self.max as usize {
            return false;
        }
        entry.push(now);
        if self.events.len() > MAX_KEYS {
            self.evict(now);
        }
        true
    }

    fn evict(&mut self, now: Instant) {
        let window = self.window;
        self.events.retain(|_, v| {
            v.retain(|t| now.duration_since(*t) < window);
            !v.is_empty()
        });
        while self.events.len() > MAX_KEYS {
            let oldest = self
                .events
                .iter()
                .min_by_key(|(_, v)| v.last().copied())
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.events.remove(&k);
                }
                None => break,
            }
        }
    }

    pub fn tracked_keys(&self) -> usize {
        self.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ThrottleConfig {
        ThrottleConfig {
            enabled: true,
            free_attempts: 3,
            base_seconds: 5,
            cap_seconds: 60,
        }
    }

    #[test]
    fn delay_table() {
        let c = cfg();
        let secs = |n| AuthThrottle::delay_for(&c, n).as_secs();
        // free attempts: 1..=3 → no delay
        assert_eq!([secs(0), secs(1), secs(2), secs(3)], [0, 0, 0, 0]);
        // then 5, 10, 20, 40, capped at 60
        assert_eq!(
            [secs(4), secs(5), secs(6), secs(7), secs(8)],
            [5, 10, 20, 40, 60]
        );
        assert_eq!(secs(9), 60);
        // absurd counts never overflow
        assert_eq!(secs(u32::MAX), 60);
    }

    #[test]
    fn disabled_never_delays() {
        let mut c = cfg();
        c.enabled = false;
        assert_eq!(AuthThrottle::delay_for(&c, 50), Duration::ZERO);
    }

    #[test]
    fn lockout_counts_down_and_resets() {
        let mut t = AuthThrottle::new(cfg());
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(t.record_failure(t0), Duration::ZERO);
        }
        assert_eq!(t.remaining_secs(t0), 0);
        assert_eq!(t.record_failure(t0), Duration::from_secs(5));
        assert_eq!(t.remaining_secs(t0), 5);
        assert_eq!(t.remaining_secs(t0 + Duration::from_millis(1500)), 4); // rounds up
        assert_eq!(t.remaining(t0 + Duration::from_secs(5)), Duration::ZERO);
        assert_eq!(t.failures(), 4);
        t.reset();
        assert_eq!(t.failures(), 0);
        assert_eq!(t.remaining(t0), Duration::ZERO);
    }

    #[test]
    fn limiter_window_and_bounds() {
        let mut r = RateLimiter::new(Duration::from_secs(1), 3);
        let t0 = Instant::now();
        assert!(r.allow("a", t0) && r.allow("a", t0) && r.allow("a", t0));
        assert!(!r.allow("a", t0));
        assert!(r.allow("b", t0)); // independent keys
        assert!(r.allow("a", t0 + Duration::from_millis(1100))); // window slid
        for i in 0..1000 {
            r.allow(&format!("k{i}"), t0);
        }
        assert!(r.tracked_keys() <= MAX_KEYS + 1);
    }
}
