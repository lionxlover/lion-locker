//! PAM re-authentication for the lock screen, with module-chatter
//! forwarding (the fingerprint / 2FA UX channel).
//!
//! Unlike `lion-greeter`, there is no session to start here -- the user's
//! session is already running underneath the lock. This only verifies the
//! password and reports pass/fail; the caller (`service.rs`) is the one
//! that releases the Wayland lock on success.
//!
//! 0.2.0: the PAM conversation is no longer a mock. A
//! [`PasswordSource`](crate::pam_ffi::PasswordSource) answers password
//! prompts and forwards `PAM_TEXT_INFO` / `PAM_ERROR_MSG` text back to
//! the lock screen, so stacks that include `pam_fprintd` (or any other
//! chatter-driving module) get their "place your finger on the reader"
//! UX for free, without the password ever leaving this process.

use crate::pam_ffi::{self, Chatter, PamContext, PasswordSource};
use thiserror::Error;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use zeroize::Zeroizing;

/// Corresponds to /etc/pam.d/lion-locker.
const PAM_SERVICE: &str = "lion-locker";

#[derive(Debug, Error, Clone)]
pub enum AuthError {
    #[error("Incorrect password")]
    InvalidCredentials,
    #[error("This account can no longer be used")]
    AccountInvalid,
    #[error("Sign-in is temporarily unavailable")]
    Service,
}

/// PAM service name, for `--check-pam` diagnostics.
pub fn pam_service() -> &'static str {
    PAM_SERVICE
}

/// Re-authenticate `username` (the session's own user -- never a
/// different account) against the given password. Runs PAM on a
/// dedicated OS thread since it's a blocking C library, forwards module
/// chatter to `chatter_tx` as it happens, and returns the result over a
/// oneshot so the async side never blocks on it.
pub fn spawn_check(
    username: String,
    password: Zeroizing<String>,
    chatter_tx: UnboundedSender<Chatter>,
) -> oneshot::Receiver<Result<(), AuthError>> {
    let (tx, rx) = oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("lion-locker-auth".into())
        .spawn(move || {
            let result = check(&username, password, &chatter_tx);
            let _ = tx.send(result);
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "could not spawn auth thread");
    }
    rx
}

fn check(
    username: &str,
    password: Zeroizing<String>,
    chatter_tx: &UnboundedSender<Chatter>,
) -> Result<(), AuthError> {
    let tx = chatter_tx.clone();
    let source = Box::new(PasswordSource::new(
        password,
        Box::new(move |c| {
            // The channel may be gone if the episode ended; that's fine.
            let _ = tx.send(c);
        }),
    ));
    let mut ctx = PamContext::start_with_source(PAM_SERVICE, username, source).map_err(|e| {
        tracing::error!(pam_code = e, "PAM init failed");
        AuthError::Service
    })?;

    ctx.authenticate(true).map_err(|e| {
        tracing::warn!(user = username, pam_code = e, "unlock attempt failed");
        map_pam(e)
    })?;
    ctx.acct_mgmt(true).map_err(map_pam)?;

    tracing::info!(user = username, "unlock succeeded");
    Ok(())
}

fn map_pam(code: i32) -> AuthError {
    use pam_ffi::*;
    match code {
        PAM_AUTH_ERR | PAM_USER_UNKNOWN | PAM_CRED_INSUFFICIENT | PAM_MAXTRIES => {
            AuthError::InvalidCredentials
        }
        PAM_ACCT_EXPIRED | PAM_NEW_AUTHTOK_REQD | PAM_PERM_DENIED => AuthError::AccountInvalid,
        _ => AuthError::Service,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pam_error_mapping() {
        assert!(matches!(map_pam(7), AuthError::InvalidCredentials));
        assert!(matches!(map_pam(16), AuthError::InvalidCredentials));
        assert!(matches!(map_pam(17), AuthError::InvalidCredentials));
        assert!(matches!(map_pam(13), AuthError::AccountInvalid));
        assert!(matches!(map_pam(12), AuthError::AccountInvalid));
        assert!(matches!(map_pam(6), AuthError::AccountInvalid));
        assert!(matches!(map_pam(19), AuthError::Service));
        assert!(matches!(map_pam(0), AuthError::Service)); // unknown codes -> Service
    }

    #[test]
    fn service_name_is_stable() {
        assert_eq!(pam_service(), "lion-locker");
    }
}
