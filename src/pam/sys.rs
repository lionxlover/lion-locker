//! libpam FFI, loaded at runtime with `dlopen(3)`.
//!
//! ════════════════════════════════════════════════════════════════════════
//! AUDIT BOX — the ONLY `unsafe` in this crate beside `crate::sysffi`.
//! Reviewed against Linux-PAM 1.5.x `include/security/_pam_types.h`,
//! `_pam_types_compat.h` and `pam_start.c`. Invariants:
//!
//! 1. Symbols are resolved once (process-wide `OnceLock`) from
//!    `libpam.so.0` / `libpam.so` with `RTLD_NOW | RTLD_LOCAL` and are
//!    never `dlclose`d — no unloading while a handle lives.
//! 2. `pam_start` receives a `pam_conv` whose `appdata_ptr` is a thin
//!    `*mut ConvShim` owned (Box) by `RealPamService` for the whole
//!    transaction; the service is created, driven and dropped on a single
//!    dedicated worker thread, so the pointer is valid for every callback
//!    invocation. It is never dereferenced from another thread.
//! 3. The conversation callback bounds `num_msg ≤ 32` and treats every
//!    message pointer as a borrowed NUL-terminated C string (read via
//!    `CStr`, never written).
//! 4. Response buffers are allocated with `malloc` (PAM's allocator) and
//!    ownership passes to PAM on `PAM_SUCCESS`; on error the callback
//!    frees them itself. Linux-PAM overwrites authtok copies it makes.
//!    Answers containing interior NUL bytes are rejected (fail closed).
//! 5. `pam_end` runs exactly once per handle (in `Drop`, idempotent via
//!    nulling).
//! 6. No PAM input or output is ever logged.
//!
//! ════════════════════════════════════════════════════════════════════════
//!
//! The handle-taking methods below take a raw pointer that only this
//! module's audit contract can validate (single-thread ownership by the
//! non-`Send` `RealPamService`); marking them `unsafe` would push
//! uncheckable invariants into callers, so the derefs are audited here
//! and the lint is suppressed for exactly this module.
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(unsafe_code)] // audited module — see box above; see DESIGN.md

use crate::pam::{ConvShim, PromptSpec};
use crate::proto::PromptKind;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

// ── PAM constants (Linux-PAM _pam_types.h) ─────────────────────────────
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_PERM_DENIED: c_int = 6;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_USER_UNKNOWN: c_int = 10;
pub const PAM_MAXTRIES: c_int = 11;
pub const PAM_NEW_AUTHTOK_REQD: c_int = 12;
pub const PAM_ACCT_EXPIRED: c_int = 13;
pub const PAM_AUTHTOK_LOCK_BUSY: c_int = 22;
pub const PAM_CONV_ERR: c_int = 19;
pub const PAM_SYSTEM_ERR: c_int = 4;

pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
pub const PAM_PROMPT_ECHO_ON: c_int = 2;
pub const PAM_ERROR_MSG: c_int = 3;
pub const PAM_TEXT_INFO: c_int = 4;

pub const PAM_ESTABLISH_CRED: c_int = 0x0002;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: c_int = 0x0020;

/// Upper bound on messages per conversation call (PAM_MAX_NUM_MSG).
const PAM_MAX_NUM_MSG: usize = 32;
/// Upper bound on one response (PAM_MAX_RESP_SIZE + slack).
const PAM_MAX_RESP_SIZE: usize = 512;

// ── Opaque/repr types ──────────────────────────────────────────────────
#[repr(C)]
pub struct PamHandleT {
    _private: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_code: c_int,
}

type ConvFn = unsafe extern "C" fn(
    c_int,
    *const *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConvStruct {
    conv: Option<ConvFn>,
    appdata_ptr: *mut c_void,
}

// ── Function pointer types ─────────────────────────────────────────────
type PamStartFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const PamConvStruct,
    *mut *mut PamHandleT,
) -> c_int;
type PamEndFn = unsafe extern "C" fn(*mut PamHandleT, c_int) -> c_int;
type PamAuthFn = unsafe extern "C" fn(*mut PamHandleT, c_int) -> c_int;
type PamStrerrorFn = unsafe extern "C" fn(*mut PamHandleT, c_int) -> *const c_char;

/// Loaded libpam API table.
pub struct LibPam {
    pam_start: PamStartFn,
    pam_end: PamEndFn,
    pam_authenticate: PamAuthFn,
    pam_acct_mgmt: PamAuthFn,
    pam_chauthtok: PamAuthFn,
    pam_setcred: PamAuthFn,
    pam_strerror: PamStrerrorFn,
    _lib: *mut c_void, // never closed (see audit box §1)
}

unsafe impl Send for LibPam {}
unsafe impl Sync for LibPam {}

impl LibPam {
    /// Resolve libpam once per process. Fails closed with a descriptive
    /// error when the library or any symbol is unavailable.
    pub fn load() -> Result<&'static LibPam, String> {
        static LIB: OnceLock<Result<LibPam, String>> = OnceLock::new();
        let res = LIB.get_or_init(|| unsafe { Self::dlopen_pam() });
        res.as_ref().map_err(|e: &String| e.clone())
    }

    unsafe fn dlopen_pam() -> Result<LibPam, String> {
        let mut last_err = "no library candidate".to_string();
        for name in ["libpam.so.0", "libpam.so.2", "libpam.so"] {
            let handle = libc::dlopen(
                std::ffi::CString::new(name)
                    .map_err(|e| e.to_string())?
                    .as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            );
            if handle.is_null() {
                // SAFETY: dlopen returns a static error string on failure.
                last_err = CStr::from_ptr(libc::dlerror())
                    .to_string_lossy()
                    .into_owned();
                continue;
            }
            let lib = Self::resolve(handle).inspect_err(|_| {
                libc::dlclose(handle);
            })?;
            return Ok(lib);
        }
        Err(format!("cannot dlopen libpam: {last_err}"))
    }

    unsafe fn resolve(lib: *mut c_void) -> Result<LibPam, String> {
        fn sym(lib: *mut c_void, name: &str) -> Result<*mut c_void, String> {
            let cname = CString::new(name).map_err(|e| e.to_string())?;
            let p = unsafe { libc::dlsym(lib, cname.as_ptr()) };
            if p.is_null() {
                Err(format!("libpam is missing symbol {name}"))
            } else {
                Ok(p)
            }
        }
        // SAFETY: transmutes are sound because the pointee signatures were
        // checked against Linux-PAM headers (audit box); dlsym returns the
        // default (latest) symbol version.
        Ok(LibPam {
            // clang-format off
            pam_start: std::mem::transmute::<*mut c_void, PamStartFn>(sym(lib, "pam_start")?),
            pam_end: std::mem::transmute::<*mut c_void, PamEndFn>(sym(lib, "pam_end")?),
            pam_authenticate: std::mem::transmute::<*mut c_void, PamAuthFn>(sym(
                lib,
                "pam_authenticate",
            )?),
            pam_acct_mgmt: std::mem::transmute::<*mut c_void, PamAuthFn>(sym(
                lib,
                "pam_acct_mgmt",
            )?),
            pam_chauthtok: std::mem::transmute::<*mut c_void, PamAuthFn>(sym(
                lib,
                "pam_chauthtok",
            )?),
            pam_setcred: std::mem::transmute::<*mut c_void, PamAuthFn>(sym(lib, "pam_setcred")?),
            pam_strerror: std::mem::transmute::<*mut c_void, PamStrerrorFn>(sym(
                lib,
                "pam_strerror",
            )?),
            // clang-format on
            _lib: lib,
        })
    }

    /// `pam_start(service, user, conv)` with the shim as appdata.
    ///
    /// Thread-safety: the returned handle must only be driven from the
    /// creating thread (enforced structurally: callers store it in a
    /// non-`Send` service created on the worker thread).
    pub fn start(
        &'static self,
        service: &CStr,
        user: &CStr,
        mut shim: Box<ConvShim>,
    ) -> Result<(*mut PamHandleT, Box<ConvShim>), c_int> {
        let mut handle: *mut PamHandleT = std::ptr::null_mut();
        // SAFETY: appdata points at the shim's heap allocation — the
        // address stays valid no matter where the Box itself is moved; the
        // conv struct is copied by pam_start.
        let conv = PamConvStruct {
            conv: Some(pam_conv_callback),
            appdata_ptr: &mut *shim as *mut ConvShim as *mut c_void,
        };
        let rc = unsafe { (self.pam_start)(service.as_ptr(), user.as_ptr(), &conv, &mut handle) };
        if rc != PAM_SUCCESS || handle.is_null() {
            return Err(if rc == PAM_SUCCESS {
                PAM_SYSTEM_ERR
            } else {
                rc
            });
        }
        Ok((handle, shim))
    }

    pub fn authenticate(&self, h: *mut PamHandleT) -> c_int {
        // SAFETY: handle valid, single-thread contract (see start()).
        unsafe { (self.pam_authenticate)(h, 0) }
    }

    pub fn acct_mgmt(&self, h: *mut PamHandleT) -> c_int {
        // SAFETY: handle valid, single-thread contract.
        unsafe { (self.pam_acct_mgmt)(h, 0) }
    }

    pub fn chauthtok_expired(&self, h: *mut PamHandleT) -> c_int {
        // SAFETY: handle valid, single-thread contract.
        unsafe { (self.pam_chauthtok)(h, PAM_CHANGE_EXPIRED_AUTHTOK) }
    }

    pub fn setcred_establish(&self, h: *mut PamHandleT) -> c_int {
        // SAFETY: handle valid, single-thread contract.
        unsafe { (self.pam_setcred)(h, PAM_ESTABLISH_CRED) }
    }

    pub fn end(&self, h: *mut PamHandleT, rc: c_int) -> c_int {
        // SAFETY: handle valid; called exactly once (caller nulls it).
        unsafe { (self.pam_end)(h, rc) }
    }

    /// `pam_strerror` — static description text, safe for logging.
    pub fn strerror(&self, h: *mut PamHandleT, rc: c_int) -> String {
        // SAFETY: strerror only reads the handle; returns static text.
        let p = unsafe { (self.pam_strerror)(h, rc) };
        if p.is_null() {
            format!("PAM error {rc}")
        } else {
            // SAFETY: PAM guarantees a NUL-terminated static string.
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    }
}

// ── Conversation callback ──────────────────────────────────────────────
/// SAFETY: contract per audit box §2–§4: `appdata_ptr` is a valid
/// `*mut ConvShim` for the transaction; message arrays are borrowed and
/// bounded; response memory is malloc'd and handed to PAM only on
/// `PAM_SUCCESS`.
unsafe extern "C" fn pam_conv_callback(
    num_msg: c_int,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    if num_msg <= 0 || num_msg as usize > PAM_MAX_NUM_MSG || msg.is_null() || resp.is_null() {
        return PAM_CONV_ERR;
    }
    // SAFETY: audit box §2 — pointer is a live ConvShim on this thread.
    let shim = &mut *(appdata_ptr as *mut ConvShim);

    let mut prompts = Vec::with_capacity(num_msg as usize);
    for i in 0..num_msg as usize {
        // SAFETY: pam guarantees msg[i] valid for the duration of the call.
        let m = *msg.add(i);
        if m.is_null() {
            return PAM_CONV_ERR;
        }
        let style = (*m).msg_style;
        // SAFETY: `msg` is a NUL-terminated borrowed C string.
        let text = CStr::from_ptr((*m).msg).to_string_lossy();
        let text = crate::proto::sanitize_text(&text, 1024);
        let kind = match style {
            PAM_PROMPT_ECHO_OFF => PromptKind::Secret,
            PAM_PROMPT_ECHO_ON => PromptKind::Visible,
            PAM_ERROR_MSG => PromptKind::Error,
            PAM_TEXT_INFO => PromptKind::Info,
            _ => return PAM_CONV_ERR,
        };
        prompts.push(PromptSpec { kind, text });
    }

    let count = num_msg as usize;
    match shim.inner.converse(&prompts) {
        Ok(answers) => {
            if answers.len() != count {
                return PAM_CONV_ERR;
            }
            for a in &answers {
                if a.as_str().len() > PAM_MAX_RESP_SIZE || a.as_str().contains('\0') {
                    return PAM_CONV_ERR;
                }
            }
            // SAFETY: allocation size is exact; zeroed so resp_code and
            // unused slots are 0.
            let arr = libc::calloc(count, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
            if arr.is_null() {
                return PAM_CONV_ERR;
            }
            for (i, a) in answers.iter().enumerate() {
                let bytes = a.as_str().as_bytes();
                // SAFETY: malloc(len+1) then memcpy; PAM takes ownership.
                let buf = libc::malloc(bytes.len() + 1) as *mut c_char;
                if buf.is_null() {
                    free_responses(arr, i);
                    return PAM_CONV_ERR;
                }
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr() as *const c_void,
                    buf as *mut c_void,
                    bytes.len(),
                );
                // SAFETY: NUL terminator within the malloc'd len+1.
                *buf.add(bytes.len()) = 0;
                // SAFETY: arr has `count` slots.
                (*arr.add(i)).resp = buf;
                (*arr.add(i)).resp_code = 0;
            }
            *resp = arr;
            PAM_SUCCESS
        }
        Err(_) => PAM_CONV_ERR,
    }
}

/// SAFETY: frees the first `filled` slots plus the array itself; used only
/// on the error path where PAM does not take ownership.
unsafe fn free_responses(arr: *mut PamResponse, filled: usize) {
    for i in 0..filled {
        // SAFETY: slots 0..filled were assigned malloc'd buffers.
        let p = (*arr.add(i)).resp;
        if !p.is_null() {
            libc::free(p as *mut c_void);
        }
    }
    libc::free(arr as *mut c_void);
}
