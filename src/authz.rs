#![forbid(unsafe_code)]
//! Caller authorization policy (spec 03 §8).
//!
//! Callers are identified by the D-Bus daemon (bus-verified uid, never a
//! caller-supplied string) and pinned with a pidfd where possible.
//!
//! Deliberate deviation from "authorize through `lion-auth`" (see
//! DESIGN.md §6): `lion-auth` (spec 22) does not exist yet, and the one
//! privileged decision this daemon makes — *unlock* — is already gated by
//! something stronger than any policy daemon: a fresh PAM re-authentication
//! performed by this process. `Lock` is not privileged (anyone who can
//! lock-screen themselves loses nothing) and must keep working when every
//! other service is down, so it is owner-only + rate-limited instead of
//! routed through a service that could be unavailable.
//!
//! - `Lock`: bus-verified uid == session owner (root is *not* special).
//! - `Unlock`: uid == owner **and** a live PAM-verified grant (core check).
//!   Root alone is denied: fail closed.
//! - read-only properties: unrestricted.

/// Stable action ids (shared vocabulary with other LionOS daemons).
pub mod actions {
    pub const LOCK: &str = "session.lock";
    pub const UNLOCK: &str = "session.unlock";
    pub const READ: &str = "session.read";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    owner_uid: u32,
}

impl Policy {
    pub fn new(owner_uid: u32) -> Policy {
        Policy { owner_uid }
    }

    pub fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// Is `uid` allowed to *request* `action`? (Unlock additionally
    /// requires a PAM-verified grant, enforced by the core.)
    pub fn allows(&self, action: &str, uid: u32) -> bool {
        match action {
            actions::READ => true,
            actions::LOCK | actions::UNLOCK => uid == self.owner_uid,
            // Unknown action ids are denied (fail closed).
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_may_lock_and_request_unlock() {
        let p = Policy::new(1000);
        assert!(p.allows(actions::LOCK, 1000));
        assert!(p.allows(actions::UNLOCK, 1000));
    }

    #[test]
    fn strangers_and_root_are_denied() {
        let p = Policy::new(1000);
        for uid in [0, 1, 999, 1001, u32::MAX] {
            assert!(!p.allows(actions::LOCK, uid), "uid {uid} lock");
            assert!(!p.allows(actions::UNLOCK, uid), "uid {uid} unlock");
        }
    }

    #[test]
    fn reads_are_open_and_unknown_actions_denied() {
        let p = Policy::new(1000);
        assert!(p.allows(actions::READ, 4242));
        assert!(!p.allows("session.format-disk", 1000));
        assert!(!p.allows("", 1000));
    }
}
