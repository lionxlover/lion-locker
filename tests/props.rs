//! Property tests (spec 03 §10): the decoder and the throttle hold their
//! invariants for arbitrary input.
use lion_locker::config::{Config, ThrottleConfig};
use lion_locker::proto::{self, decode_request, Request};
use lion_locker::throttle::AuthThrottle;
use proptest::prelude::*;
use std::time::{Duration, Instant};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// No input panics; error text never exceeds its bound.
    #[test]
    fn decoder_never_panics(s in "\\PC{0,2000}") {
        match decode_request(&s) {
            Ok(_) => {}
            Err(e) => prop_assert!(e.to_wire().len() < 600),
        }
    }

    /// Structured-but-hostile requests: wrong types / extra keys / huge
    /// strings are rejected, valid ones accepted, and a secret never
    /// appears in any error string.
    #[test]
    fn answers_are_bounded_and_never_leaked(pw in "[ -~]{0,1300}", extra in proptest::bool::ANY) {
        let mut v = serde_json::json!({"proto":1,"id":7,"op":"Answer","text":pw});
        if extra { v["zzz"] = 1.into(); }
        let r = decode_request(&v.to_string());
        match r {
            Ok(Request::Answer { text, .. }) => {
                prop_assert!(!extra);
                prop_assert!(pw.len() <= 1024);
                prop_assert_eq!(text.as_str(), pw.as_str());
            }
            Ok(_) => prop_assert!(false, "wrong variant"),
            Err(e) => {
                prop_assert!(extra || pw.len() > 1024);
                if pw.len() >= 4 {
                    prop_assert!(!e.to_wire().contains(&pw));
                }
            }
        }
    }

    /// Sanitised text has no control characters and respects its cap.
    #[test]
    fn sanitize_is_safe(s in "\\PC{0,500}", cap in 0usize..64) {
        let out = proto::sanitize_text(&s, cap);
        prop_assert!(out.chars().count() <= cap);
        prop_assert!(out.chars().all(|c| (c as u32) >= 0x20 && (c as u32) != 0x7f));
    }

    /// Throttle delays are monotone non-decreasing in the failure count
    /// and never exceed the cap.
    #[test]
    fn throttle_is_monotone_and_capped(
        free in 0u32..10, base in 1u64..100, extra in 0u64..1000, n in 0u32..200,
    ) {
        let cfg = ThrottleConfig { enabled: true, free_attempts: free, base_seconds: base, cap_seconds: base + extra };
        let a = AuthThrottle::delay_for(&cfg, n);
        let b = AuthThrottle::delay_for(&cfg, n.saturating_add(1));
        prop_assert!(b >= a);
        prop_assert!(b <= Duration::from_secs(cfg.cap_seconds));
        if n <= free { prop_assert_eq!(a, Duration::ZERO); }
    }

    /// Remaining lockout never grows with time.
    #[test]
    fn lockout_only_shrinks(fails in 1u32..30, t1 in 0u64..500, dt in 0u64..500) {
        let mut t = AuthThrottle::new(ThrottleConfig { enabled: true, free_attempts: 0, base_seconds: 1, cap_seconds: 300 });
        let t0 = Instant::now();
        for _ in 0..fails { t.record_failure(t0); }
        let r1 = t.remaining(t0 + Duration::from_secs(t1));
        let r2 = t.remaining(t0 + Duration::from_secs(t1 + dt));
        prop_assert!(r2 <= r1);
    }

    /// Any config JSON either parses+validates or is rejected.
    #[test]
    fn config_parse_is_total(s in "\\PC{0,400}") {
        if let Ok(c) = Config::parse(&s) { prop_assert!(c.validate().is_ok()); }
    }
}
