//! PAM abstraction (spec 03 §3 Authentication, §10 testing).
//!
//! The seam: [`PamServiceFactory`] / [`PamService`] with two
//! implementations —
//! - [`crate::pam::real`] backed by `pam/sys.rs` (dlopen'd libpam FFI), and
//! - [`crate::pam::mock`] (scripted conversations for unit tests).
//!
//! NOTE ON `unsafe`: this parent module cannot carry
//! `#![forbid(unsafe_code)]` because the audited FFI child module
//! `pam::sys` legitimately contains `unsafe` (spec 03 §8: "No unsafe
//! outside small, audited, commented FFI modules"). Everything defined
//! *here* is plain safe code; the only unsafe in the whole crate lives in
//! `pam::sys` and `crate::sysffi`.

pub mod mock;
#[cfg(feature = "real-pam")]
pub mod real;
#[cfg(feature = "real-pam")]
pub mod sys;

use crate::proto::PromptKind;
use crate::secret::Secret;
use std::time::Duration;

/// One PAM conversation prompt (pre-translation of `struct pam_message`).
#[derive(Debug, Clone)]
pub struct PromptSpec {
    pub kind: PromptKind,
    pub text: String,
}

impl PromptSpec {
    pub fn secret(text: impl Into<String>) -> Self {
        PromptSpec {
            kind: PromptKind::Secret,
            text: text.into(),
        }
    }

    pub fn visible(text: impl Into<String>) -> Self {
        PromptSpec {
            kind: PromptKind::Visible,
            text: text.into(),
        }
    }

    pub fn info(text: impl Into<String>) -> Self {
        PromptSpec {
            kind: PromptKind::Info,
            text: text.into(),
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        PromptSpec {
            kind: PromptKind::Error,
            text: text.into(),
        }
    }
}

/// Errors the conversation can fail with (all non-revealing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvError {
    Cancelled,
    Timeout,
    ChannelClosed,
}

/// The conversation bridge implemented by the auth engine (channels to the
/// UI socket); PAM callbacks and the mock both drive it.
pub trait Conversation {
    /// Present `prompts`, return one answer per prompt.
    fn converse(&mut self, prompts: &[PromptSpec]) -> Result<Vec<Secret>, ConvError>;
}

/// Concrete holder so a raw `*mut c_void` appdata pointer stays thin
/// (a `*mut dyn Conversation` would be fat and lose its vtable).
pub struct ConvShim {
    pub inner: Box<dyn Conversation>,
}

impl ConvShim {
    pub fn new(inner: Box<dyn Conversation>) -> Self {
        ConvShim { inner }
    }
}

/// Generic, non-revealing failure reasons surfaced to the UI
/// (detailed PAM codes are logged server-side only, spec 03 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailReason {
    /// Wrong password / generic denial (also USER_UNKNOWN — never confirm
    /// account existence to untrusted callers).
    AuthErr,
    /// `PAM_ACCT_EXPIRED`.
    AcctExpired,
    /// `PAM_PERM_DENIED` / faillock lock-out.
    Locked,
    /// Expired-password change flow failed.
    NewAuthtokFailed,
    /// UI or daemon cancelled the conversation.
    Cancelled,
    /// Conversation step exceeded the hard timeout.
    Timeout,
    /// PAM service itself failed (pam_start etc.) — fail closed.
    ServiceError,
}

impl AuthFailReason {
    /// Stable, user-facing reason text (spec 03 §4 `AuthResult{reason}`).
    pub fn ui_reason(&self) -> &'static str {
        match self {
            AuthFailReason::AuthErr => "authentication failed",
            AuthFailReason::AcctExpired => "account expired",
            AuthFailReason::Locked => "account locked",
            AuthFailReason::NewAuthtokFailed => "password change failed",
            AuthFailReason::Cancelled => "cancelled",
            AuthFailReason::Timeout => "timed out",
            AuthFailReason::ServiceError => "authentication service unavailable",
        }
    }
}

/// Result of a full PAM login transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    Success,
    Failed(AuthFailReason),
}

impl AuthOutcome {
    pub fn ok(&self) -> bool {
        matches!(self, AuthOutcome::Success)
    }
}

/// One live PAM transaction. Created, driven and dropped on the dedicated
/// worker thread owned by [`crate::auth`] — never shared across threads,
/// which is what keeps the raw pam_handle in the real backend sound.
pub trait PamService {
    /// Full login flow: `pam_authenticate` → `pam_acct_mgmt`, with the
    /// expired-password change (`pam_chauthtok`) flow when required.
    fn authenticate(&mut self) -> AuthOutcome;

    /// `pam_setcred(PAM_ESTABLISH_CRED)` — called after `AuthOutcome::Success`,
    /// before launching the session.
    fn setcred(&mut self) -> Result<(), AuthFailReason>;

    /// `pam_end` — consumes the transaction.
    fn end(self: Box<Self>);
}

/// Factory opening transactions; shared (Send+Sync), called on the worker
/// thread. `conv` is the bridge to the UI.
pub trait PamServiceFactory: Send + Sync {
    fn open(
        &self,
        service: &str,
        user: &str,
        conv: ConvShim,
    ) -> Result<Box<dyn PamService>, AuthFailReason>;

    /// Human-readable backend name (logs, `--check-config`).
    fn describe(&self) -> &'static str;
}

/// Suggested hard timeout for a PAM conversation step (spec 03 §6: 30 s).
pub const DEFAULT_CONV_TIMEOUT: Duration = Duration::from_secs(30);
