#![forbid(unsafe_code)]
//! Real PAM backend: safe wrapper over the audited `pam::sys` FFI.
//!
//! All `unsafe` lives in `sys.rs` (see its audit box). This module only
//! sequences `pam_authenticate → pam_acct_mgmt → (pam_chauthtok) →
//! pam_setcred → pam_end` and maps return codes to generic outcomes.
//! Detailed codes are logged with `tracing` (never secrets, never
//! responses).

use super::sys::{self, LibPam};
use super::{AuthFailReason, AuthOutcome, ConvShim, PamService, PamServiceFactory};
use crate::error::Result;
use std::ffi::CString;
use std::os::raw::c_int;

/// Factory backed by dlopen'd libpam. Construction fails closed if the
/// library cannot be loaded (spec 03 §8).
pub struct RealPamFactory {
    lib: &'static LibPam,
}

impl RealPamFactory {
    pub fn new() -> Result<Self> {
        let lib = LibPam::load().map_err(crate::error::Error::Pam)?;
        Ok(RealPamFactory { lib })
    }
}

impl PamServiceFactory for RealPamFactory {
    fn open(
        &self,
        service: &str,
        user: &str,
        conv: ConvShim,
    ) -> std::result::Result<Box<dyn PamService>, AuthFailReason> {
        let svc = RealPamService::open(self.lib, service, user, conv).map_err(|(code, what)| {
            tracing::warn!(
                target: "pam",
                pam_code = code,
                "pam_start failed for service {service:?} ({what})"
            );
            AuthFailReason::ServiceError
        })?;
        Ok(Box::new(svc))
    }

    fn describe(&self) -> &'static str {
        "libpam (dlopen, Linux-PAM)"
    }
}

struct RealPamService {
    lib: &'static LibPam,
    handle: *mut sys::PamHandleT,
    service: CString,
    user: CString,
    /// Shim (conversation bridge) — must outlive the pam handle.
    _conv: Box<ConvShim>,
    last_rc: c_int,
}

// The handle is only ever touched from the single worker thread that
// created it (crate::auth owns the thread); the raw pointer keeps this
// type !Send, which structurally enforces that contract.

fn cstring(s: &str, what: &str) -> std::result::Result<CString, (i32, String)> {
    if s.is_empty() || s.len() > 64 {
        return Err((sys::PAM_SYSTEM_ERR, format!("{what} length out of range")));
    }
    CString::new(s).map_err(|_| (sys::PAM_SYSTEM_ERR, format!("{what} contains NUL")))
}

fn map_fail_rc(rc: i32) -> AuthFailReason {
    match rc {
        sys::PAM_ACCT_EXPIRED => AuthFailReason::AcctExpired,
        sys::PAM_PERM_DENIED | sys::PAM_AUTHTOK_LOCK_BUSY => AuthFailReason::Locked,
        _ => AuthFailReason::AuthErr, // includes AUTH_ERR, USER_UNKNOWN, MAXTRIES, …
    }
}

impl RealPamService {
    fn open(
        lib: &'static LibPam,
        service: &str,
        user: &str,
        conv: ConvShim,
    ) -> std::result::Result<RealPamService, (i32, String)> {
        let service_c = cstring(service, "service")?;
        let user_c = cstring(user, "user")?;
        // Thread-safety: contract from sys.rs — all later calls stay on this
        // thread; the shim box is stored and outlives the handle.
        let (handle, conv) = lib
            .start(&service_c, &user_c, Box::new(conv))
            .map_err(|code| (code, "pam_start failed".to_string()))?;
        Ok(RealPamService {
            lib,
            handle,
            service: service_c,
            user: user_c,
            _conv: conv,
            last_rc: sys::PAM_SUCCESS,
        })
    }

    fn log_rc(&self, stage: &str, rc: i32) {
        let text = self.lib.strerror(self.handle, rc);
        tracing::debug!(
            target: "pam",
            stage,
            pam_code = rc,
            pam_text = %text,
            service = %self.service.to_string_lossy(),
            "PAM stage result"
        );
    }
}

impl PamService for RealPamService {
    fn authenticate(&mut self) -> AuthOutcome {
        tracing::debug!(
            target: "pam",
            user = %self.user.to_string_lossy(),
            service = %self.service.to_string_lossy(),
            "starting PAM transaction"
        );
        let rc = self.lib.authenticate(self.handle);
        self.last_rc = rc;
        self.log_rc("authenticate", rc);
        if rc != sys::PAM_SUCCESS {
            return AuthOutcome::Failed(map_fail_rc(rc));
        }
        let rc = self.lib.acct_mgmt(self.handle);
        self.log_rc("acct_mgmt", rc);
        match rc {
            sys::PAM_SUCCESS => AuthOutcome::Success,
            sys::PAM_NEW_AUTHTOK_REQD => {
                // Expired-password change flow, driven through the same
                // conversation bridge.
                let rc2 = self.lib.chauthtok_expired(self.handle);
                self.last_rc = rc2;
                self.log_rc("chauthtok", rc2);
                if rc2 != sys::PAM_SUCCESS {
                    return AuthOutcome::Failed(if rc2 == sys::PAM_PERM_DENIED {
                        AuthFailReason::Locked
                    } else {
                        AuthFailReason::NewAuthtokFailed
                    });
                }
                let rc3 = self.lib.acct_mgmt(self.handle);
                self.log_rc("acct_mgmt(recheck)", rc3);
                if rc3 == sys::PAM_SUCCESS {
                    AuthOutcome::Success
                } else {
                    AuthOutcome::Failed(map_fail_rc(rc3))
                }
            }
            _ => AuthOutcome::Failed(map_fail_rc(rc)),
        }
    }

    fn setcred(&mut self) -> std::result::Result<(), AuthFailReason> {
        let rc = self.lib.setcred_establish(self.handle);
        self.last_rc = rc;
        self.log_rc("setcred", rc);
        if rc == sys::PAM_SUCCESS {
            Ok(())
        } else {
            Err(AuthFailReason::ServiceError)
        }
    }

    fn end(self: Box<Self>) {
        // Drop impl performs pam_end.
    }
}

impl Drop for RealPamService {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let rc = self.lib.end(self.handle, self.last_rc);
            if rc != sys::PAM_SUCCESS {
                tracing::debug!(target: "pam", pam_code = rc, "pam_end returned non-success");
            }
            self.handle = std::ptr::null_mut();
        }
        // `self._conv` (the shim) drops after the handle is gone. Correct
        // ordering: PAM must not invoke the callback after pam_end.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ConvBridge;
    use crate::pam::{Conversation, PromptSpec};
    use crate::secret::Secret;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    /// FFI smoke test against the real libpam (sandbox-safe: uses the
    /// `other` stack, expects a non-success verdict; skips if libpam is
    /// absent). Full-stack behaviour is covered by the systemd-nspawn
    /// integration test in CI (spec 03 §10).
    #[test]
    fn real_pam_linkage_smoke() {
        let Ok(lib) = LibPam::load() else {
            eprintln!("skipping: libpam not available in this environment");
            return;
        };
        let (evt_tx, _evt_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_cmd_tx, cmd_rx) = mpsc::channel();
        let bridge = ConvBridge::new(evt_tx, Arc::new(Mutex::new(cmd_rx)), Duration::from_secs(5));
        match RealPamService::open(lib, "other", "nobody", ConvShim::new(Box::new(bridge))) {
            Err(_) => {
                // /etc/pam.d/other missing → pam_start fails; the FFI path
                // itself is exercised and fails closed. Acceptable.
            }
            Ok(mut svc) => {
                let out = svc.authenticate();
                assert!(
                    !out.ok(),
                    "the `other` stack must not authenticate nobody; got {out:?}"
                );
                assert_ne!(
                    out,
                    AuthOutcome::Failed(AuthFailReason::Timeout),
                    "conversation must not hang"
                );
                Box::new(svc).end();
            }
        }
    }

    #[test]
    fn service_string_validation() {
        assert!(cstring("", "service").is_err());
        assert!(cstring(&"s".repeat(65), "service").is_err());
        assert!(cstring("with\u{0}nul", "service").is_err());
        assert!(cstring("lion-locker", "service").is_ok());
    }

    /// The bridge must translate PAM prompt styles and enforce the step
    /// timeout (mirrors mock tests, through the shared Conversation impl).
    #[test]
    fn bridge_timeout_via_conversation() {
        let (evt_tx, mut evt_rx) = tokio::sync::mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let mut bridge = ConvBridge::new(
            evt_tx,
            Arc::new(Mutex::new(cmd_rx)),
            Duration::from_millis(40),
        );
        let prompts = vec![PromptSpec::secret("Password: ")];
        let err = bridge.converse(&prompts).unwrap_err();
        assert_eq!(err, crate::pam::ConvError::Timeout);
        // the prompt event was delivered
        assert!(matches!(
            evt_rx.try_recv(),
            Ok(crate::auth::AuthEvent::Prompt(_))
        ));
        let _ = cmd_tx; // keep alive so the error is Timeout, not ChannelClosed
    }

    #[test]
    fn bridge_answer_flow() {
        let (evt_tx, _evt_rx) = tokio::sync::mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let mut bridge =
            ConvBridge::new(evt_tx, Arc::new(Mutex::new(cmd_rx)), Duration::from_secs(2));
        let prompt_handle = std::thread::spawn(move || {
            let prompts = vec![
                PromptSpec::secret("Password: "),
                PromptSpec::visible("OTP: "),
            ];
            bridge.converse(&prompts)
        });
        // wait for both prompts to be announced, then answer
        cmd_tx
            .send(crate::auth::WorkerCmd::Answer(Secret::new("pw".into())))
            .unwrap();
        cmd_tx
            .send(crate::auth::WorkerCmd::Answer(Secret::new("123456".into())))
            .unwrap();
        let answers = prompt_handle.join().unwrap().unwrap();
        assert_eq!(answers[0].as_str(), "pw");
        assert_eq!(answers[1].as_str(), "123456");
    }
}
