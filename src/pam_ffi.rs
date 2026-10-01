//! Minimal, dependency-free PAM FFI for lion-locker (vendored, shared
//! design with lion-greeter 0.5's battle-tested binding).
//!
//! Why vendored instead of `pam-client`: the locker is security-critical
//! *and* must build on minimal LionOS images — `pam-client`'s mock
//! conversation could not forward module chatter (the fingerprint /
//! 2FA "place your finger" text) anyway, and dropping the crate removes
//! its transitive link/build requirements entirely.
//!
//! The locker needs only: `pam_start`, `pam_authenticate`,
//! `pam_acct_mgmt`, `pam_end` — no session functions (the user's
//! session already exists under the lock), no env list.
//!
//! Conversation model: a pluggable [`ConvSource`] answers password
//! prompts and gets a `notify` hook for display-only module messages
//! (`PAM_TEXT_INFO` / `PAM_ERROR_MSG`) — which is exactly what
//! pam_fprintd-style biometric stacks use to drive their UX. The
//! callback is panic-contained (`catch_unwind` -> `PAM_CONV_ERR`) and
//! refuses unknown message styles (including binary prompts).

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

use libc::{calloc, free, size_t, strdup};
use zeroize::Zeroizing;

/// Make a NUL-terminated, zeroizable byte buffer from a `&str`.
fn zeroizing_cstr(s: &str) -> Result<Zeroizing<Vec<u8>>, ()> {
    if s.as_bytes().contains(&0) {
        return Err(()); // embedded NUL — not a valid PAM secret
    }
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0u8);
    Ok(Zeroizing::new(v))
}

/// Duplicate an answer into a malloc'd C string for libpam, wiping our
/// intermediate copy on the way out (libpam/module owns the copy).
fn dup_answer(answer: &str) -> *mut c_char {
    match zeroizing_cstr(answer) {
        Ok(buf) => unsafe { strdup(buf.as_ptr() as *const c_char) },
        Err(()) => ptr::null_mut(),
    }
}

// ── libpam return codes (subset of <security/pam_appl.h>) ─────────────
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_PERM_DENIED: c_int = 6;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_CRED_INSUFFICIENT: c_int = 8;
pub const PAM_NEW_AUTHTOK_REQD: c_int = 12;
pub const PAM_ACCT_EXPIRED: c_int = 13;
pub const PAM_USER_UNKNOWN: c_int = 16;
pub const PAM_MAXTRIES: c_int = 17;
/// Conversation failed (module could not get its answer).
pub const PAM_CONV_ERR: c_int = 19;

// ── pam_message msg_style values ──────────────────────────────────────
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;

// ── flag bits ─────────────────────────────────────────────────────────
const PAM_SILENT: c_int = 0x8000;

// ── libpam C ABI ──────────────────────────────────────────────────────

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: unsafe extern "C" fn(
        c_int,
        *const *const PamMessage,
        *mut *mut PamResponse,
        *mut c_void,
    ) -> c_int,
    appdata_ptr: *mut c_void,
}

extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        ph: *mut *mut c_void,
    ) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_acct_mgmt(handle: *mut c_void, flags: c_int) -> c_int;
}

// ── conversation source model ─────────────────────────────────────────

/// Style of one PAM conversation message, normalized for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptStyle {
    /// Secret input (password / PIN).
    Secret,
    /// Visible input (rare on a lock screen).
    Visible,
    /// `PAM_ERROR_MSG` — display as an error line.
    Error,
    /// `PAM_TEXT_INFO` — display as an info line (e.g. "Place your
    /// finger on the reader" from pam_fprintd).
    Info,
}

impl PromptStyle {
    /// Stable numeric form for the D-Bus wire (1=secret, 2=visible,
    /// 3=error, 4=info — matches PAM's msg_style numbering).
    pub fn as_u32(self) -> u32 {
        match self {
            PromptStyle::Secret => 1,
            PromptStyle::Visible => 2,
            PromptStyle::Error => 3,
            PromptStyle::Info => 4,
        }
    }

    /// True for styles that require an answer (vs display-only).
    pub fn needs_answer(self) -> bool {
        matches!(self, PromptStyle::Secret | PromptStyle::Visible)
    }
}

/// A module message forwarded for display (style + text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chatter {
    pub style: PromptStyle,
    pub text: String,
}

/// Source of answers for PAM prompts. Implementations run on the
/// (blocking) auth thread and must never panic — a panic surfaces as
/// `PAM_CONV_ERR` and fails only the current unlock attempt.
pub trait ConvSource: Send + Sync {
    /// Answer for an input prompt. `None` fails the conversation.
    fn answer(&self, style: PromptStyle, prompt: &str) -> Option<Zeroizing<String>>;
    /// Display-only message hook (info / error text).
    fn notify(&self, _style: PromptStyle, _text: &str) {}
}

/// Password-only source (the classic unlock flow): answers `Secret`
/// prompts with the submitted password, forwards chatter.
pub struct PasswordSource {
    password: Zeroizing<Vec<u8>>,
    /// Where display-only messages go (may be a no-op channel).
    chatter: Box<dyn Fn(Chatter) + Send + Sync>,
}

impl PasswordSource {
    pub fn new(password: Zeroizing<String>, chatter: Box<dyn Fn(Chatter) + Send + Sync>) -> Self {
        let pw = zeroizing_cstr(password.as_str()).unwrap_or_else(|_| Zeroizing::new(vec![0u8]));
        Self {
            password: pw,
            chatter,
        }
    }
}

impl ConvSource for PasswordSource {
    fn answer(&self, style: PromptStyle, _prompt: &str) -> Option<Zeroizing<String>> {
        match style {
            PromptStyle::Secret => {
                // SAFETY: NUL-terminated buffer without interior NULs.
                let cstr = unsafe { CStr::from_ptr(self.password.as_ptr() as *const c_char) };
                let s = cstr.to_str().ok()?;
                Some(Zeroizing::new(s.to_owned()))
            }
            // A lock screen must never answer identity prompts: the
            // session's own user is fixed, and a module that asks for a
            // *different* user here is a configuration error at worst,
            // a probing attempt at best. Fail the conversation.
            PromptStyle::Visible => None,
            PromptStyle::Error | PromptStyle::Info => None,
        }
    }

    fn notify(&self, style: PromptStyle, text: &str) {
        if matches!(style, PromptStyle::Error | PromptStyle::Info) && !text.is_empty() {
            (self.chatter)(Chatter {
                style,
                text: text.to_owned(),
            });
        }
    }
}

/// Owns the source the conversation callback consults; boxed so the
/// `appdata_ptr` handed to libpam stays stable for the handle's life.
struct ConvData {
    source: Box<dyn ConvSource>,
}

// ── the conversation callback ─────────────────────────────────────────

unsafe fn conv_impl(
    num_msg: c_int,
    msgs: *const *const PamMessage,
    out_resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msgs.is_null() || out_resp.is_null() || appdata.is_null() {
        return libc::EINVAL;
    }
    let data = &*(appdata as *const ConvData);

    let n = num_msg as size_t;
    let elem = std::mem::size_of::<PamResponse>();
    let buf = calloc(n, elem) as *mut PamResponse;
    if buf.is_null() {
        return libc::ENOMEM;
    }

    let mut written: size_t = 0;
    for i in 0..n {
        let mptr = *msgs.add(i);
        if mptr.is_null() {
            conv_free_responses(buf, written);
            free(buf as *mut c_void);
            return libc::EINVAL;
        }
        let m = &*mptr;
        let slot = buf.add(i);
        (*slot).resp = ptr::null_mut();
        (*slot).resp_retcode = 0;

        // SAFETY: libpam guarantees `msg` is a valid C string for the
        // duration of the call.
        let text = if m.msg.is_null() {
            ""
        } else {
            CStr::from_ptr(m.msg).to_str().unwrap_or("")
        };

        let style = match m.msg_style {
            PAM_PROMPT_ECHO_OFF => PromptStyle::Secret,
            PAM_PROMPT_ECHO_ON => PromptStyle::Visible,
            PAM_ERROR_MSG => PromptStyle::Error,
            PAM_TEXT_INFO => PromptStyle::Info,
            _ => {
                // Refuse unknown styles (e.g. PAM_BINARY_PROMPT).
                conv_free_responses(buf, written);
                free(buf as *mut c_void);
                return libc::EINVAL;
            }
        };

        if !style.needs_answer() {
            data.source.notify(style, text);
            continue;
        }

        let Some(answer) = data.source.answer(style, text) else {
            // No answer (identity prompt, embedded NUL, ...) -> the
            // conversation fails, NOT the password check.
            conv_free_responses(buf, written);
            free(buf as *mut c_void);
            return PAM_CONV_ERR;
        };
        let dup = dup_answer(answer.as_str());
        if dup.is_null() {
            conv_free_responses(buf, written);
            free(buf as *mut c_void);
            return libc::ENOMEM;
        }
        (*slot).resp = dup;
        written += 1;
    }

    *out_resp = buf;
    PAM_SUCCESS
}

unsafe fn conv_free_responses(buf: *mut PamResponse, count: size_t) {
    for i in 0..count {
        let p = (*buf.add(i)).resp;
        if !p.is_null() {
            free(p as *mut c_void);
        }
    }
}

unsafe extern "C" fn pam_conv_callback(
    num_msg: c_int,
    msgs: *const *const PamMessage,
    out_resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    // Panicking across the FFI boundary is UB; convert to conv failure.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        conv_impl(num_msg, msgs, out_resp, appdata)
    }));
    res.unwrap_or(PAM_CONV_ERR)
}

// ── safe wrapper ───────────────────────────────────────────────────────

/// RAII PAM handle. `pam_end` runs on drop with the last status so
/// module cleanup hooks fire.
pub struct PamContext {
    handle: *mut c_void,
    #[allow(dead_code)]
    conv_data: Box<ConvData>,
    last_status: c_int,
}

// SAFETY: the handle is owned by the auth thread for its whole life
// (never used from two threads at once), but may be sent to it.
unsafe impl Send for PamContext {}

impl PamContext {
    /// `pam_start(service, user, conv)` with a custom conversation
    /// source. The source is boxed here so its address stays stable
    /// for the handle's life.
    pub fn start_with_source(
        service: &str,
        username: &str,
        source: Box<dyn ConvSource>,
    ) -> Result<Self, c_int> {
        let svc = CString::new(service).map_err(|_| libc::EINVAL)?;
        let user = CString::new(username).map_err(|_| libc::EINVAL)?;
        let conv_data = Box::new(ConvData { source });

        let conv = PamConv {
            conv: pam_conv_callback,
            appdata_ptr: &*conv_data as *const ConvData as *mut c_void,
        };

        let mut handle: *mut c_void = ptr::null_mut();
        // SAFETY: conv and appdata are valid for the lifetime of
        // conv_data, which outlives this PamContext.
        let rc = unsafe { pam_start(svc.as_ptr(), user.as_ptr(), &conv, &mut handle) };
        if rc != PAM_SUCCESS || handle.is_null() {
            return Err(rc);
        }

        Ok(PamContext {
            handle,
            conv_data,
            last_status: PAM_SUCCESS,
        })
    }

    /// `pam_authenticate(3)` — verify the password. `silent = true`
    /// suppresses module chatter to the *journal*; our conversation
    /// still receives it for display.
    pub fn authenticate(&mut self, silent: bool) -> Result<(), c_int> {
        let flags = if silent { PAM_SILENT } else { 0 };
        let rc = unsafe { pam_authenticate(self.handle, flags) };
        self.last_status = rc;
        if rc == PAM_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }

    /// `pam_acct_mgmt(3)` — account validity (expiry, lockout).
    pub fn acct_mgmt(&mut self, silent: bool) -> Result<(), c_int> {
        let flags = if silent { PAM_SILENT } else { 0 };
        let rc = unsafe { pam_acct_mgmt(self.handle, flags) };
        self.last_status = rc;
        if rc == PAM_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }
}

impl Drop for PamContext {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }
        // SAFETY: handle is valid for the lifetime of self, dropped once.
        unsafe { pam_end(self.handle, self.last_status) };
        self.handle = ptr::null_mut();
        // conv_data (and the Zeroizing password inside) drops here.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_style_semantics() {
        assert!(PromptStyle::Secret.needs_answer());
        assert!(PromptStyle::Visible.needs_answer());
        assert!(!PromptStyle::Error.needs_answer());
        assert!(!PromptStyle::Info.needs_answer());
        assert_eq!(PromptStyle::Secret.as_u32(), 1);
        assert_eq!(PromptStyle::Info.as_u32(), 4);
    }

    #[test]
    fn password_source_answers_secret_only() {
        let chatter: Vec<Chatter> = Vec::new();
        let _ = chatter;
        let src = PasswordSource::new(Zeroizing::new("hunter2".into()), Box::new(|_| {}));
        assert_eq!(
            src.answer(PromptStyle::Secret, "Password: ")
                .unwrap()
                .as_str(),
            "hunter2"
        );
        // Identity prompts are refused on a lock screen.
        assert!(src.answer(PromptStyle::Visible, "Username: ").is_none());
    }

    #[test]
    fn password_source_forwards_chatter() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Chatter>::new()));
        let s2 = seen.clone();
        let src = PasswordSource::new(
            Zeroizing::new(String::new()),
            Box::new(move |c| s2.lock().unwrap().push(c)),
        );
        src.notify(PromptStyle::Info, "Place your finger on the reader");
        src.notify(PromptStyle::Error, "Sensor busy");
        // Secret/Visible notify calls are not forwarded.
        src.notify(PromptStyle::Secret, "Password: ");
        let g = seen.lock().unwrap();
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].text, "Place your finger on the reader");
        assert_eq!(g[1].style, PromptStyle::Error);
    }

    #[test]
    fn interior_nul_rejected() {
        let src = PasswordSource::new(Zeroizing::new("bad\u{0}pw".into()), Box::new(|_| {}));
        // The source was built with an empty fallback password instead
        // of panicking; the answer must be empty, never the broken one.
        assert_eq!(src.answer(PromptStyle::Secret, "x").unwrap().as_str(), "");
    }

    #[test]
    fn conv_err_code_matches_linux_pam() {
        assert_eq!(PAM_CONV_ERR, 19);
    }

    #[test]
    fn dup_answer_round_trip() {
        assert!(dup_answer("with\u{0}nul").is_null());
        let p = dup_answer("abc123");
        assert!(!p.is_null());
        // SAFETY: allocated by strdup; freed exactly once here.
        unsafe { free(p as *mut c_void) };
    }
}
