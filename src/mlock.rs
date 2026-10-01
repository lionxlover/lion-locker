//! `mlockall(2)` hardening (same design as lion-greeter, sized for a
//! session process): keep the locker's address space out of swap so the
//! typed password (and its PAM copies on our side) never hit the disk.
//!
//! Why this matters *more* on a locker than a greeter: the greeter sees
//! one password per login; the locker holds a buffer that a user may
//! type into minutes after boot, on a machine whose swap is most likely
//! to be active (idle system, memory pressure, laptop suspend-to-disk).
//!
//! Degradation ladder (never fatal — a locker that refuses to run
//! because it cannot lock memory would leave the screen *unlocked*):
//!   1. `Locked` — full mlockall, `mlock` capability advertised.
//!   2. `SkippedSmallLimit` — RLIMIT_MEMLOCK too small (the 64 KiB
//!      default on many distros); run unlocked, log once.
//!   3. `Failed(errno)` — the syscall failed; run unlocked, log once.

use std::sync::atomic::{AtomicBool, Ordering};

/// The locker's heap is tiny (one password buffer + Wayland state);
/// 8 MiB of future-growth headroom is generous headroom, still small
/// enough not to reject sane per-user limits.
const HEADROOM_BYTES: libc::rlim_t = 8 * 1024 * 1024;

const MCL_CURRENT: libc::c_int = 1;
const MCL_FUTURE: libc::c_int = 2;

/// Compile-time sanity band for the headroom constant.
const _: () = assert!(
    HEADROOM_BYTES >= 1024 * 1024,
    "mlock headroom too small for PAM buffers"
);
const _: () = assert!(
    HEADROOM_BYTES <= 64 * 1024 * 1024,
    "mlock headroom rejects sane per-user limits"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlockOutcome {
    Locked,
    SkippedSmallLimit { hard_limit: u64 },
    Failed { errno: i32 },
}

static LOCKED: AtomicBool = AtomicBool::new(false);

/// Apply `mlockall(MCL_CURRENT | MCL_FUTURE)` with an RLIMIT guard.
/// Idempotent; never fatal.
pub fn apply() -> MlockOutcome {
    if LOCKED.load(Ordering::Acquire) {
        return MlockOutcome::Locked;
    }

    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `rl` is a valid, stack-allocated rlimit struct.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) };
    if rc == 0 {
        let unlimited = rl.rlim_max == libc::RLIM_INFINITY;
        if !unlimited && rl.rlim_max < HEADROOM_BYTES {
            tracing::warn!(
                hard_limit = rl.rlim_max,
                "RLIMIT_MEMLOCK too small; running without memory lock"
            );
            return MlockOutcome::SkippedSmallLimit {
                hard_limit: rl.rlim_max,
            };
        }
    }

    // SAFETY: plain libc call; no pointers.
    let rc = unsafe { libc::mlockall(MCL_CURRENT | MCL_FUTURE) };
    if rc != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        tracing::warn!(errno, "mlockall failed; running without memory lock");
        return MlockOutcome::Failed { errno };
    }

    LOCKED.store(true, Ordering::Release);
    tracing::info!("mlockall applied: typed password cannot be swapped out");
    MlockOutcome::Locked
}

/// Whether memory is actually locked (feeds `Capabilities`).
pub fn is_locked() -> bool {
    LOCKED.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_ladder_never_panics() {
        // Whatever the sandbox limit is, apply() must return one of the
        // three outcomes and stay idempotent.
        let first = apply();
        assert!(matches!(
            first,
            MlockOutcome::Locked
                | MlockOutcome::SkippedSmallLimit { .. }
                | MlockOutcome::Failed { .. }
        ));
        if first == MlockOutcome::Locked {
            assert_eq!(apply(), MlockOutcome::Locked);
            assert!(is_locked());
        }
    }

    #[test]
    fn mcl_flags_cover_present_and_future() {
        // Locking only current pages would leave the *next* keystroke's
        // buffer pageable.
        assert_eq!(MCL_CURRENT | MCL_FUTURE, 3);
    }

    #[test]
    fn outcomes_are_copy_eq_debug() {
        fn assert_traits<T: Copy + PartialEq + Eq + std::fmt::Debug>(_: &T) {}
        assert_traits(&MlockOutcome::Locked);
        assert_traits(&MlockOutcome::Failed { errno: 1 });
    }
}
