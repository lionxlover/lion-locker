#![forbid(unsafe_code)]
//! Local lock-UI socket protocol, version 1 (spec 03 §4: "Local socket to
//! `lion-lockscreen`: Show, Hide, Prompt, AuthResult, Throttle").
//!
//! Wire format: one JSON object per line (JSON-lines), UTF-8, LF-delimited.
//! Every message carries `proto` (must be `1`) and a request id.
//!
//! UI → daemon (requests):
//! `{"proto":1,"id":1,"op":"Hello"}`
//! `{"proto":1,"id":2,"op":"Begin"}`              start a PAM transaction
//! `{"proto":1,"id":3,"op":"Answer","text":"…"}`  answer to the current prompt
//! `{"proto":1,"id":4,"op":"Cancel"}`
//! `{"proto":1,"id":5,"op":"GraceUnlock"}`        only inside the grace window
//! `{"proto":1,"id":6,"op":"Action","action":"shutdown"}`
//!
//! Daemon → UI:
//! response `{"proto":1,"id":1,"ok":true,"result":{…}}`
//! error    `{"proto":1,"id":1,"ok":false,"error":{"code":"…","message":"…"}}`
//! events   `Show{…}`, `Hide`, `Prompt{kind,text}`, `AuthResult{ok,reason,failures}`,
//!          `Throttle{seconds}`
//!
//! Decoding is hand-validated (not derive-based): every field is bounded,
//! unknown fields are rejected, and the answer text is moved into a
//! zeroizing [`Secret`] immediately. This is the parser the fuzz target
//! exercises (spec 03 §10).

use crate::secret::Secret;
use serde_json::{json, Map, Value};

pub const PROTO_VERSION: u64 = 1;

/// Hard cap on one wire line. Secrets are bounded to 1 KiB by [`Secret`];
/// 8 KiB leaves room for JSON overhead only.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Cap for identifier-ish strings (actions).
pub const MAX_IDENT_BYTES: usize = 32;

pub mod codes {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const BAD_PROTO: &str = "proto_version";
    pub const UNKNOWN_OP: &str = "unknown_op";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const BUSY: &str = "busy";
    pub const NOT_LOCKED: &str = "not_locked";
    pub const NOT_AUTHENTICATED: &str = "not_authenticated";
    pub const THROTTLED: &str = "throttled";
    pub const NOT_ALLOWED: &str = "not_allowed";
    pub const NO_TRANSACTION: &str = "no_transaction";
    pub const INTERNAL: &str = "internal";
}

/// Quick actions available on the lock screen (spec 03 §3 "Emergency info
/// text and quick actions … that never expose session content").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiAction {
    SwitchUser,
    Shutdown,
}

impl UiAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            UiAction::SwitchUser => "switch_user",
            UiAction::Shutdown => "shutdown",
        }
    }
    pub fn parse(s: &str) -> Option<UiAction> {
        match s {
            "switch_user" => Some(UiAction::SwitchUser),
            "shutdown" => Some(UiAction::Shutdown),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum Request {
    Hello { id: u64 },
    Begin { id: u64 },
    Answer { id: u64, text: Secret },
    Cancel { id: u64 },
    GraceUnlock { id: u64 },
    Action { id: u64, action: UiAction },
}

impl Request {
    pub fn id(&self) -> u64 {
        match self {
            Request::Hello { id }
            | Request::Begin { id }
            | Request::Answer { id, .. }
            | Request::Cancel { id }
            | Request::GraceUnlock { id }
            | Request::Action { id, .. } => *id,
        }
    }
}

/// Decode failure; `id` is echoed whenever it could be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub id: u64,
    pub code: &'static str,
    pub message: String,
}

impl DecodeError {
    fn new(id: u64, code: &'static str, message: impl Into<String>) -> Self {
        DecodeError {
            id,
            code,
            message: message.into(),
        }
    }
    pub fn to_wire(&self) -> String {
        error_response(self.id, self.code, &self.message)
    }
}

fn check_fields(obj: &Map<String, Value>, id: u64, allowed: &[&str]) -> Result<(), DecodeError> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            // Key names are caller-controlled: never echo them back.
            return Err(DecodeError::new(
                id,
                codes::BAD_REQUEST,
                "unknown field in request",
            ));
        }
    }
    Ok(())
}

/// Decode one request line.
pub fn decode_request(line: &str) -> Result<Request, DecodeError> {
    let v: Value = serde_json::from_str(line)
        .map_err(|_| DecodeError::new(0, codes::BAD_REQUEST, "malformed JSON"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| DecodeError::new(0, codes::BAD_REQUEST, "request must be an object"))?;

    // id first so every later error can echo it.
    let id = match obj.get("id") {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| DecodeError::new(0, codes::BAD_REQUEST, "id must be an unsigned int"))?,
        Some(_) => {
            return Err(DecodeError::new(
                0,
                codes::BAD_REQUEST,
                "id must be a number",
            ))
        }
        None => return Err(DecodeError::new(0, codes::BAD_REQUEST, "missing id")),
    };
    match obj.get("proto") {
        Some(Value::Number(n)) if n.as_u64() == Some(PROTO_VERSION) => {}
        Some(_) => {
            return Err(DecodeError::new(
                id,
                codes::BAD_PROTO,
                format!("unsupported proto; supported: {PROTO_VERSION}"),
            ))
        }
        None => return Err(DecodeError::new(id, codes::BAD_PROTO, "missing proto")),
    }
    let op = match obj.get("op") {
        Some(Value::String(s)) if s.len() <= MAX_IDENT_BYTES => s.as_str(),
        Some(_) => return Err(DecodeError::new(id, codes::BAD_REQUEST, "bad op")),
        None => return Err(DecodeError::new(id, codes::BAD_REQUEST, "missing op")),
    };

    match op {
        "Hello" => {
            check_fields(obj, id, &["proto", "id", "op"])?;
            Ok(Request::Hello { id })
        }
        "Begin" => {
            check_fields(obj, id, &["proto", "id", "op"])?;
            Ok(Request::Begin { id })
        }
        "Cancel" => {
            check_fields(obj, id, &["proto", "id", "op"])?;
            Ok(Request::Cancel { id })
        }
        "GraceUnlock" => {
            check_fields(obj, id, &["proto", "id", "op"])?;
            Ok(Request::GraceUnlock { id })
        }
        "Answer" => {
            check_fields(obj, id, &["proto", "id", "op", "text"])?;
            let text = obj
                .get("text")
                .ok_or_else(|| DecodeError::new(id, codes::BAD_REQUEST, "missing text"))?;
            let s = text
                .as_str()
                .ok_or_else(|| DecodeError::new(id, codes::BAD_REQUEST, "text must be a string"))?;
            if s.len() > 1024 {
                return Err(DecodeError::new(
                    id,
                    codes::BAD_REQUEST,
                    "answer too long (max 1024 bytes)",
                ));
            }
            // NUL cannot cross the PAM C boundary; reject rather than truncate.
            if s.contains('\0') {
                return Err(DecodeError::new(
                    id,
                    codes::BAD_REQUEST,
                    "answer contains NUL",
                ));
            }
            Ok(Request::Answer {
                id,
                text: Secret::new(s.to_owned()),
            })
        }
        "Action" => {
            check_fields(obj, id, &["proto", "id", "op", "action"])?;
            let a = obj
                .get("action")
                .and_then(Value::as_str)
                .ok_or_else(|| DecodeError::new(id, codes::BAD_REQUEST, "missing action"))?;
            let action = UiAction::parse(a)
                .ok_or_else(|| DecodeError::new(id, codes::BAD_REQUEST, "unknown action"))?;
            Ok(Request::Action { id, action })
        }
        _ => Err(DecodeError::new(id, codes::UNKNOWN_OP, "unknown op")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    Secret,
    Visible,
    Info,
    Error,
}

impl PromptKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PromptKind::Secret => "secret",
            PromptKind::Visible => "visible",
            PromptKind::Info => "info",
            PromptKind::Error => "error",
        }
    }
}

/// Payload of the `Show` event: what `lion-lockscreen` should draw.
/// Never contains session content (spec 03 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowInfo {
    pub user: String,
    pub emergency_info: String,
    pub hide_notification_content: bool,
    pub show_media_controls: bool,
    /// Quick actions the UI may offer (`Action` op names).
    pub actions: Vec<&'static str>,
    /// Milliseconds of the unlock-free grace window still open (0 = none).
    pub grace_ms_remaining: u64,
    /// Wrong-password feedback state for the first frame.
    pub failures: u32,
    /// Outputs currently covered / total (diagnostics for the UI).
    pub outputs_covered: u32,
    pub outputs_total: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Show(ShowInfo),
    Hide,
    Prompt {
        kind: PromptKind,
        text: String,
    },
    AuthResult {
        ok: bool,
        reason: String,
        failures: u32,
    },
    Throttle {
        seconds: u64,
    },
}

impl Event {
    pub fn to_wire(&self, id: u64) -> String {
        let ev = match self {
            Event::Show(s) => json!({
                "event": "Show",
                "user": sanitize_text(&s.user, 64),
                "emergency_info": sanitize_text(&s.emergency_info, 512),
                "hide_notification_content": s.hide_notification_content,
                "show_media_controls": s.show_media_controls,
                "actions": s.actions,
                "grace_ms_remaining": s.grace_ms_remaining,
                "failures": s.failures,
                "outputs_covered": s.outputs_covered,
                "outputs_total": s.outputs_total,
            }),
            Event::Hide => json!({"event": "Hide"}),
            Event::Prompt { kind, text } => json!({
                "event": "Prompt",
                "kind": kind.as_str(),
                "text": sanitize_text(text, 1024),
            }),
            Event::AuthResult {
                ok,
                reason,
                failures,
            } => json!({
                "event": "AuthResult",
                "ok": ok,
                "reason": sanitize_text(reason, 128),
                "failures": failures,
            }),
            Event::Throttle { seconds } => json!({"event": "Throttle", "seconds": seconds}),
        };
        with_envelope(ev, id)
    }
}

fn with_envelope(mut v: Value, id: u64) -> String {
    if let Some(o) = v.as_object_mut() {
        o.insert("proto".into(), json!(PROTO_VERSION));
        o.insert("id".into(), json!(id));
    }
    v.to_string()
}

pub fn ok_response(id: u64, result: Value) -> String {
    json!({"proto": PROTO_VERSION, "id": id, "ok": true, "result": result}).to_string()
}

pub fn error_response(id: u64, code: &str, message: &str) -> String {
    json!({
        "proto": PROTO_VERSION,
        "id": id,
        "ok": false,
        "error": {"code": code, "message": sanitize_text(message, 256)},
    })
    .to_string()
}

/// Strip control characters (newline/tab → space) and length-bound, so
/// terminal escapes or journald control bytes never reach the UI.
pub fn sanitize_text(s: &str, cap: usize) -> String {
    let mut out = String::with_capacity(s.len().min(cap));
    for c in s.chars().take(cap) {
        match c {
            '\n' | '\t' => out.push(' '),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(s: &str) -> Result<Request, DecodeError> {
        decode_request(s)
    }

    #[test]
    fn all_ops_decode() {
        assert!(matches!(
            dec(r#"{"proto":1,"id":1,"op":"Hello"}"#),
            Ok(Request::Hello { id: 1 })
        ));
        assert!(matches!(
            dec(r#"{"proto":1,"id":2,"op":"Begin"}"#),
            Ok(Request::Begin { id: 2 })
        ));
        assert!(matches!(
            dec(r#"{"proto":1,"id":3,"op":"Cancel"}"#),
            Ok(Request::Cancel { id: 3 })
        ));
        assert!(matches!(
            dec(r#"{"proto":1,"id":4,"op":"GraceUnlock"}"#),
            Ok(Request::GraceUnlock { id: 4 })
        ));
        match dec(r#"{"proto":1,"id":5,"op":"Answer","text":"pw"}"#).unwrap() {
            Request::Answer { id: 5, text } => assert_eq!(text.as_str(), "pw"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            dec(r#"{"proto":1,"id":6,"op":"Action","action":"shutdown"}"#),
            Ok(Request::Action {
                id: 6,
                action: UiAction::Shutdown
            })
        ));
    }

    #[test]
    fn rejects_malformed_and_echoes_id_when_known() {
        assert_eq!(dec("nope").unwrap_err().code, codes::BAD_REQUEST);
        assert_eq!(dec("[1]").unwrap_err().code, codes::BAD_REQUEST);
        let e = dec(r#"{"proto":2,"id":9,"op":"Hello"}"#).unwrap_err();
        assert_eq!((e.id, e.code), (9, codes::BAD_PROTO));
        let e = dec(r#"{"proto":1,"id":7,"op":"Nope"}"#).unwrap_err();
        assert_eq!((e.id, e.code), (7, codes::UNKNOWN_OP));
        let e = dec(r#"{"proto":1,"id":8,"op":"Hello","extra":1}"#).unwrap_err();
        assert_eq!((e.id, e.code), (8, codes::BAD_REQUEST));
        // The offending key is never reflected.
        assert!(!e.message.contains("extra"));
    }

    #[test]
    fn answer_bounds_and_nul() {
        let big = "x".repeat(1025);
        let line = format!(r#"{{"proto":1,"id":1,"op":"Answer","text":"{big}"}}"#);
        assert_eq!(dec(&line).unwrap_err().code, codes::BAD_REQUEST);
        let e = dec(r#"{"proto":1,"id":1,"op":"Answer","text":"a\u0000b"}"#).unwrap_err();
        assert_eq!(e.code, codes::BAD_REQUEST);
        assert!(dec(r#"{"proto":1,"id":1,"op":"Answer"}"#).is_err());
        assert!(dec(r#"{"proto":1,"id":1,"op":"Answer","text":5}"#).is_err());
    }

    #[test]
    fn answer_secret_never_in_error_or_debug() {
        let r = dec(r#"{"proto":1,"id":1,"op":"Answer","text":"hunter2"}"#).unwrap();
        assert!(!format!("{r:?}").contains("hunter2"));
        // Failure path with a secret-looking payload must not echo it.
        let e = dec(r#"{"proto":1,"id":1,"op":"Answer","text":"hunter2","zzz":1}"#).unwrap_err();
        assert!(!e.to_wire().contains("hunter2"));
    }

    #[test]
    fn id_types() {
        assert!(dec(r#"{"proto":1,"id":-1,"op":"Hello"}"#).is_err());
        assert!(dec(r#"{"proto":1,"id":"1","op":"Hello"}"#).is_err());
        assert!(dec(r#"{"proto":1,"op":"Hello"}"#).is_err());
        assert!(dec(r#"{"id":1,"op":"Hello"}"#).is_err());
    }

    #[test]
    fn unknown_action_rejected() {
        assert!(dec(r#"{"proto":1,"id":1,"op":"Action","action":"rm -rf"}"#).is_err());
        assert!(dec(r#"{"proto":1,"id":1,"op":"Action"}"#).is_err());
    }

    #[test]
    fn events_have_envelope_and_are_sanitized() {
        let w = Event::Prompt {
            kind: PromptKind::Secret,
            text: "Pass\x1b[31mword:\n".into(),
        }
        .to_wire(9);
        assert!(w.contains(r#""proto":1"#) && w.contains(r#""id":9"#));
        assert!(!w.contains('\x1b'));
        let v: Value = serde_json::from_str(&w).unwrap();
        assert_eq!(v["event"], "Prompt");
        assert_eq!(v["kind"], "secret");
        let t = Event::Throttle { seconds: 30 }.to_wire(0);
        assert!(t.contains(r#""seconds":30"#));
        let h = Event::Hide.to_wire(0);
        assert!(h.contains(r#""event":"Hide""#));
    }

    #[test]
    fn show_event_carries_privacy_flags() {
        let w = Event::Show(ShowInfo {
            user: "lion".into(),
            emergency_info: "Call 555".into(),
            hide_notification_content: true,
            show_media_controls: false,
            actions: vec!["shutdown"],
            grace_ms_remaining: 0,
            failures: 2,
            outputs_covered: 1,
            outputs_total: 2,
        })
        .to_wire(0);
        let v: Value = serde_json::from_str(&w).unwrap();
        assert_eq!(v["hide_notification_content"], true);
        assert_eq!(v["show_media_controls"], false);
        assert_eq!(v["actions"][0], "shutdown");
        assert_eq!(v["failures"], 2);
    }

    #[test]
    fn sanitize_strips_controls_and_caps() {
        assert_eq!(sanitize_text("a\u{7}b\nc", 10), "ab c");
        assert_eq!(sanitize_text("abcdef", 3), "abc");
    }
}
