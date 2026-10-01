//! logind integration: honor `loginctl lock-session` (the standard
//! Linux desktop locking convention) by subscribing to our session's
//! `Lock` signal on `org.freedesktop.login1`.
//!
//! This is what makes the LionOS lock screen interoperate with the rest
//! of the desktop ecosystem: `loginctl lock-session`, systemd user
//! session shutdown hooks, and any third-party idle manager that speaks
//! the standard protocol instead of ours.
//!
//! Rules:
//! * `Lock` (logind)      -> start a lock episode (same as our `Lock()`).
//! * `Unlock` (logind)    -> *ignored, logged loudly*. A remote
//!   administrative unlock request must never bypass PAM on a lock
//!   screen; only the typed (or biometric) credential unlocks.
//! * Absent logind / no session id -> feature degrades to off, never
//!   fatal (WLRoots-less test environments, bare Wayland sessions).

use zbus::{MatchRule, MessageStream};

/// `$XDG_SESSION_ID` -> the logind object path for this session, with
/// the same character-escaping logind itself uses (only alphanumerics
/// and `_` survive; everything else becomes `_XX` hex).
pub fn session_path(session_id: &str) -> Option<String> {
    if session_id.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(session_id.len() + 32);
    out.push_str("/org/freedesktop/login1/session/");
    for b in session_id.bytes() {
        if b.is_ascii_alphanumeric() || b == b'_' {
            out.push(b as char);
        } else {
            out.push_str(&format!("_{:02X}", b));
        }
    }
    Some(out)
}

/// Spawn the logind signal watcher on `conn`. Lock requests are
/// forwarded through `lock_tx`; errors degrade to a warn log.
pub async fn watch(conn: zbus::Connection, lock_tx: tokio::sync::mpsc::UnboundedSender<()>) {
    let Some(session_id) = std::env::var("XDG_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        tracing::debug!("no XDG_SESSION_ID; logind lock-signal integration disabled");
        return;
    };
    let Some(path) = session_path(&session_id) else {
        return;
    };

    let lock_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.login1.Session")
        .expect("static interface name")
        .member("Lock")
        .expect("static member name")
        .path(path.as_str())
        .expect("escaped session path")
        .build();

    let unlock_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.login1.Session")
        .expect("static interface name")
        .member("Unlock")
        .expect("static member name")
        .path(path.as_str())
        .expect("escaped session path")
        .build();

    let mut lock_stream = match MessageStream::for_match_rule(lock_rule, &conn, None).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not subscribe to logind Lock signal");
            return;
        }
    };
    let mut unlock_stream = match MessageStream::for_match_rule(unlock_rule, &conn, None).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not subscribe to logind Unlock signal");
            return;
        }
    };

    tracing::info!(session = %session_id, "logind lock-signal integration active");

    loop {
        tokio::select! {
            msg = lock_stream.next() => {
                match msg {
                    Some(Ok(_m)) => {
                        tracing::info!("logind Lock signal -> starting lock episode");
                        let _ = lock_tx.send(());
                    }
                    Some(Err(e)) => tracing::warn!(error = %e, "logind Lock stream error"),
                    None => return,
                }
            }
            msg = unlock_stream.next() => {
                match msg {
                    Some(Ok(_m)) => {
                        // Deliberately NOT honored: a remote unlock must
                        // never bypass PAM. Logged loudly so operators
                        // notice tooling that expects it to work.
                        tracing::warn!(
                            "logind Unlock signal ignored (unlock requires credentials)"
                        );
                    }
                    Some(Err(e)) => tracing::warn!(error = %e, "logind Unlock stream error"),
                    None => return,
                }
            }
        }
    }
}

// `MessageStream` yields `Result<Message, zbus::Error>`; pull the type
// in so the import above is exercised even if a future refactor stops
// naming it directly.
#[allow(unused_imports)]
use zbus::export::futures_util::StreamExt as _;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_path_escaping() {
        // Plain digits pass through.
        assert_eq!(
            session_path("42"),
            Some("/org/freedesktop/login1/session/42".into())
        );
        // Dashes (cgroup-style ids like "2-user.slice" on some distros)
        // become _XX escapes.
        assert_eq!(
            session_path("a-b"),
            Some("/org/freedesktop/login1/session/a_2Db".into())
        );
        // Empty is None, not a path to the session collection root.
        assert_eq!(session_path(""), None);
    }

    #[test]
    fn path_is_always_under_login1_sessions() {
        for id in ["7", "c1", "user/1000"] {
            let p = session_path(id).unwrap();
            assert!(p.starts_with("/org/freedesktop/login1/session/"));
        }
    }
}
