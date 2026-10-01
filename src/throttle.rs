//! Escalating backoff for repeated failed unlock attempts. Simpler than
//! the greeter's (per-username) throttle: a lock episode only ever
//! concerns the one user who was already logged in, so there is exactly
//! one counter, reset whenever the lock ends.

use std::time::{Duration, Instant};

const FREE_ATTEMPTS: u32 = 2;
const MAX_LOCKOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Throttle {
    fails: u32,
    locked_until: Option<Instant>,
}

impl Throttle {
    pub fn remaining(&self) -> Option<Duration> {
        self.locked_until?
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
    }

    /// Record a failure; returns the lockout now in force (zero if none).
    pub fn record_failure(&mut self) -> Duration {
        self.fails = self.fails.saturating_add(1);
        if self.fails <= FREE_ATTEMPTS {
            return Duration::ZERO;
        }
        let secs = 2u64.saturating_pow((self.fails - FREE_ATTEMPTS).min(4));
        let d = Duration::from_secs(secs).min(MAX_LOCKOUT);
        self.locked_until = Some(Instant::now() + d);
        d
    }

    /// Called both on successful unlock and whenever a fresh lock episode
    /// begins, so attempts from a previous episode never carry over.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalates_then_resets() {
        let mut t = Throttle::default();
        assert_eq!(t.record_failure(), Duration::ZERO);
        assert_eq!(t.record_failure(), Duration::ZERO);
        assert_eq!(t.record_failure(), Duration::from_secs(2));
        assert!(t.remaining().is_some());
        t.reset();
        assert!(t.remaining().is_none());
    }
}
