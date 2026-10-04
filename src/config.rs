#![forbid(unsafe_code)]
//! Configuration loading and validation (the `lion-config` client).
//!
//! Standalone builds read the `locker.*` key tree from a JSON keyfile
//! (`{"locker": {...}}`, default `/etc/lion/locker.json`), the same
//! convention as lion-session/lion-greeter. The JSON Schema in
//! `packaging/lion-config/locker.schema.json` is canonical
//! (`--print-schema`); the loader mirrors it with strict unknown-field
//! rejection and range validation (fail closed on anything unexpected).
//!
//! Spec 03 §5 keys: `locker.lock_on_suspend`, `locker.grace_period_ms`,
//! `locker.hide_notification_content`, `locker.show_media_controls`.
//! Everything else is a documented, namespaced extension.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const SCHEMA_JSON: &str = include_str!("../packaging/lion-config/locker.schema.json");
pub const DEFAULT_CONFIG_PATH: &str = "/etc/lion/locker.json";

/// `locker.pam`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PamConfig {
    /// PAM service used for re-authentication (`/etc/pam.d/<service>`).
    #[serde(default = "d_pam_service")]
    pub service: String,
    /// Hard timeout for one conversation step (spec 03 §6).
    #[serde(default = "d_pam_timeout")]
    pub timeout_seconds: u64,
}

impl Default for PamConfig {
    fn default() -> Self {
        PamConfig {
            service: d_pam_service(),
            timeout_seconds: d_pam_timeout(),
        }
    }
}

fn d_pam_service() -> String {
    "lion-locker".into()
}
fn d_pam_timeout() -> u64 {
    30
}

/// `locker.throttle` — soft layer; `pam_faillock` stays authoritative.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThrottleConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// Failures allowed before any delay is imposed.
    #[serde(default = "d_free")]
    pub free_attempts: u32,
    /// First delay (seconds); doubles with every further failure.
    #[serde(default = "d_base")]
    pub base_seconds: u64,
    #[serde(default = "d_cap")]
    pub cap_seconds: u64,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        ThrottleConfig {
            enabled: true,
            free_attempts: d_free(),
            base_seconds: d_base(),
            cap_seconds: d_cap(),
        }
    }
}

fn d_true() -> bool {
    true
}
fn d_free() -> u32 {
    3
}
fn d_base() -> u64 {
    5
}
fn d_cap() -> u64 {
    300
}

/// `locker.ui` — the lock-screen UI process the locker supervises.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiConfig {
    /// argv of `lion-lockscreen`; empty = no UI is spawned (tests/demo:
    /// an external process may still connect to the socket).
    #[serde(default = "d_ui_exec")]
    pub exec: Vec<String>,
    /// Unix socket path; empty → `<state_dir>/ui.sock`.
    #[serde(default)]
    pub socket_path: String,
    /// When non-empty, a connecting peer's cgroup must end with this
    /// (identify callers by cgroup, spec 03 §8). Empty disables the check
    /// (tests); the shipped config pins `lion-lockscreen.service`.
    #[serde(default)]
    pub expected_cgroup_suffix: String,
    #[serde(default = "d_respawn")]
    pub respawn_backoff_ms: u64,
    #[serde(default = "d_respawn_max")]
    pub respawn_backoff_max_ms: u64,
}

impl Default for UiConfig {
    fn default() -> Self {
        UiConfig {
            exec: d_ui_exec(),
            socket_path: String::new(),
            expected_cgroup_suffix: String::new(),
            respawn_backoff_ms: d_respawn(),
            respawn_backoff_max_ms: d_respawn_max(),
        }
    }
}

fn d_ui_exec() -> Vec<String> {
    vec!["/usr/libexec/lion-lockscreen".into()]
}
fn d_respawn() -> u64 {
    250
}
fn d_respawn_max() -> u64 {
    5000
}

/// `locker.rate_limit` — per-caller limit on bus calls and UI requests.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default = "d_rl_window")]
    pub window_ms: u64,
    #[serde(default = "d_rl_max")]
    pub max_calls: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            window_ms: d_rl_window(),
            max_calls: d_rl_max(),
        }
    }
}

fn d_rl_window() -> u64 {
    10_000
}
fn d_rl_max() -> u32 {
    30
}

/// `locker.bus`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BusConfig {
    /// Well-known name owned on the session bus.
    #[serde(default = "d_bus_name")]
    pub name: String,
    /// Bus carrying `org.freedesktop.login1`: `system` (production) or
    /// `session` (private-bus acceptance tests).
    #[serde(default = "d_logind_bus")]
    pub logind: String,
}

impl Default for BusConfig {
    fn default() -> Self {
        BusConfig {
            name: d_bus_name(),
            logind: d_logind_bus(),
        }
    }
}

fn d_bus_name() -> String {
    "os.lionos.Locker1".into()
}
fn d_logind_bus() -> String {
    "system".into()
}

/// `locker.*`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    // ── spec 03 §5 ──────────────────────────────────────────────────
    #[serde(default = "d_true")]
    pub lock_on_suspend: bool,
    /// Optional unlock-free window after lock (0 = disabled).
    #[serde(default)]
    pub grace_period_ms: u64,
    #[serde(default = "d_true")]
    pub hide_notification_content: bool,
    #[serde(default = "d_true")]
    pub show_media_controls: bool,
    // ── namespaced extensions ───────────────────────────────────────
    /// Lock when logind reports the lid closed (spec 03 §3).
    #[serde(default = "d_true")]
    pub lock_on_lid_close: bool,
    /// Honour logind's per-session `Lock` signal (`loginctl lock-session`).
    /// The `Unlock` signal is never honoured (fail closed).
    #[serde(default = "d_true")]
    pub honor_logind_lock: bool,
    /// Free-form text on the lock screen (never session content).
    #[serde(default)]
    pub emergency_info: String,
    /// Offer the shutdown quick action.
    #[serde(default = "d_true")]
    pub allow_shutdown: bool,
    /// Session id of the greeter; non-empty enables the switch-user action.
    #[serde(default)]
    pub greeter_session_id: String,
    /// `true`: a successful PAM auth only creates a short-lived unlock
    /// *grant*; the lock stays until the owner calls `Unlock()` (lets the
    /// lock-screen UI finish its animation first).
    #[serde(default)]
    pub explicit_unlock: bool,
    #[serde(default = "d_grant_ttl")]
    pub unlock_grant_ttl_ms: u64,
    /// How long a suspend is held (delay inhibitor) waiting for the lock
    /// to engage.
    #[serde(default = "d_sleep_wait")]
    pub sleep_lock_timeout_ms: u64,
    /// Lock cover colour (`#RRGGBB`), Leonux "Obsidian Dark" by default.
    #[serde(default = "d_cover")]
    pub cover_color: String,
    /// Verify at lock time that an unlock path exists (PAM service file,
    /// UI binary) — refuse to lock into an un-unlockable state (§6).
    #[serde(default = "d_true")]
    pub preflight: bool,
    #[serde(default = "d_pam_dir")]
    pub pam_dir: String,
    /// Runtime state dir (lock marker, socket); empty → `$XDG_RUNTIME_DIR/lion-locker`.
    #[serde(default)]
    pub state_dir: String,
    #[serde(default)]
    pub pam: PamConfig,
    #[serde(default)]
    pub throttle: ThrottleConfig,
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub bus: BusConfig,
    /// Owner uid override (tests/nspawn fixtures); default: process uid.
    #[serde(default)]
    pub owner_uid: Option<u32>,
}

fn d_grant_ttl() -> u64 {
    5_000
}
fn d_sleep_wait() -> u64 {
    2_000
}
fn d_cover() -> String {
    "#14161C".into()
}
fn d_pam_dir() -> String {
    "/etc/pam.d".into()
}

impl Default for Config {
    fn default() -> Self {
        serde_json::from_str("{}").expect("static defaults parse")
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        Config::parse(&raw).map_err(|e| match e {
            Error::Config(m) => Error::Config(format!("{}: {m}", path.display())),
            other => other,
        })
    }

    /// Accepts the `lion-config` file form `{"locker": {...}}` and requires
    /// the wrapper (fail closed on malformed structure).
    pub fn parse(raw: &str) -> Result<Config> {
        let v: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| Error::Config(format!("{e}")))?;
        let inner = v
            .get("locker")
            .cloned()
            .ok_or_else(|| Error::Config("missing top-level \"locker\" object".into()))?;
        let cfg: Config =
            serde_json::from_value(inner).map_err(|e| Error::Config(format!("{e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        range("locker.grace_period_ms", self.grace_period_ms, 0, 60_000)?;
        range(
            "locker.unlock_grant_ttl_ms",
            self.unlock_grant_ttl_ms,
            100,
            60_000,
        )?;
        range(
            "locker.sleep_lock_timeout_ms",
            self.sleep_lock_timeout_ms,
            100,
            4_500,
        )?;
        range(
            "locker.pam.timeout_seconds",
            self.pam.timeout_seconds,
            1,
            300,
        )?;
        range(
            "locker.throttle.base_seconds",
            self.throttle.base_seconds,
            1,
            3_600,
        )?;
        range(
            "locker.throttle.cap_seconds",
            self.throttle.cap_seconds,
            1,
            86_400,
        )?;
        range(
            "locker.throttle.free_attempts",
            self.throttle.free_attempts as u64,
            0,
            20,
        )?;
        if self.throttle.cap_seconds < self.throttle.base_seconds {
            return Err(Error::Config(
                "locker.throttle.cap_seconds must be >= base_seconds".into(),
            ));
        }
        range(
            "locker.ui.respawn_backoff_ms",
            self.ui.respawn_backoff_ms,
            10,
            60_000,
        )?;
        range(
            "locker.ui.respawn_backoff_max_ms",
            self.ui.respawn_backoff_max_ms,
            10,
            600_000,
        )?;
        if self.ui.respawn_backoff_max_ms < self.ui.respawn_backoff_ms {
            return Err(Error::Config(
                "locker.ui.respawn_backoff_max_ms must be >= respawn_backoff_ms".into(),
            ));
        }
        range(
            "locker.rate_limit.window_ms",
            self.rate_limit.window_ms,
            100,
            600_000,
        )?;
        range(
            "locker.rate_limit.max_calls",
            self.rate_limit.max_calls as u64,
            1,
            10_000,
        )?;
        if !matches!(self.bus.logind.as_str(), "system" | "session") {
            return Err(Error::Config(
                "locker.bus.logind must be \"system\" or \"session\"".into(),
            ));
        }
        if self.bus.name.is_empty()
            || self.bus.name.len() > 255
            || self.bus.name.contains(char::is_whitespace)
        {
            return Err(Error::Config(
                "locker.bus.name is not a valid bus name".into(),
            ));
        }
        if self.emergency_info.len() > 512 {
            return Err(Error::Config(
                "locker.emergency_info exceeds 512 bytes".into(),
            ));
        }
        if self
            .emergency_info
            .chars()
            .any(|c| c.is_control() && c != '\n')
        {
            return Err(Error::Config(
                "locker.emergency_info contains control characters".into(),
            ));
        }
        parse_color(&self.cover_color)?;
        if !valid_pam_service(&self.pam.service) {
            return Err(Error::Config(
                "locker.pam.service must match [A-Za-z0-9_.-]{1,64}".into(),
            ));
        }
        if !self.greeter_session_id.is_empty() && !valid_ident(&self.greeter_session_id) {
            return Err(Error::Config(
                "locker.greeter_session_id must match [A-Za-z0-9_.-]{1,64}".into(),
            ));
        }
        if self.ui.exec.iter().any(|a| a.contains('\0')) {
            return Err(Error::Config("locker.ui.exec contains NUL".into()));
        }
        if !self.ui.exec.is_empty() && !Path::new(&self.ui.exec[0]).is_absolute() {
            return Err(Error::Config(
                "locker.ui.exec[0] must be an absolute path".into(),
            ));
        }
        Ok(())
    }

    pub fn grace_period(&self) -> Duration {
        Duration::from_millis(self.grace_period_ms)
    }
    pub fn grant_ttl(&self) -> Duration {
        Duration::from_millis(self.unlock_grant_ttl_ms)
    }
    pub fn sleep_lock_timeout(&self) -> Duration {
        Duration::from_millis(self.sleep_lock_timeout_ms)
    }
    pub fn pam_timeout(&self) -> Duration {
        Duration::from_secs(self.pam.timeout_seconds)
    }

    /// `$XDG_RUNTIME_DIR/lion-locker` unless overridden.
    ///
    /// SECURITY: when `XDG_RUNTIME_DIR` is unset we fall back to
    /// `/run/user/<uid>/lion-locker` (created by logind, mode 0700) —
    /// never `/tmp`, which is world-writable: an attacker could pre-create
    /// the directory and swap the UI socket for their own, harvesting the
    /// password typed into the lock screen. `ensure_state_dir` and
    /// `uisock::bind` additionally verify ownership and privacy of the
    /// directory before it is used.
    pub fn state_dir(&self) -> PathBuf {
        state_dir_from(
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
            crate::sysffi::getuid(),
            &self.state_dir,
        )
    }

    pub fn socket_path(&self) -> PathBuf {
        if self.ui.socket_path.is_empty() {
            self.state_dir().join("ui.sock")
        } else {
            PathBuf::from(&self.ui.socket_path)
        }
    }

    pub fn marker_path(&self) -> PathBuf {
        self.state_dir().join("locked")
    }

    pub fn owner(&self) -> u32 {
        self.owner_uid.unwrap_or_else(crate::sysffi::getuid)
    }

    /// Cover colour as 0xAARRGGBB (opaque).
    pub fn cover_argb(&self) -> u32 {
        parse_color(&self.cover_color).unwrap_or(0xFF14_161C)
    }

    /// Quick actions the lock screen may offer.
    pub fn ui_actions(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !self.greeter_session_id.is_empty() {
            v.push("switch_user");
        }
        if self.allow_shutdown {
            v.push("shutdown");
        }
        v
    }
}

fn range(name: &str, v: u64, lo: u64, hi: u64) -> Result<()> {
    if (lo..=hi).contains(&v) {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "{name} out of range [{lo}, {hi}]: {v}"
        )))
    }
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// Pure state-dir resolution, split out of [`Config::state_dir`] so the
/// fallback is deterministic under test (no env mutation, no parallel-test
/// races). Order: explicit config override, then `$XDG_RUNTIME_DIR`, then
/// the logind-managed `/run/user/<uid>`.
///
/// SECURITY: the final fallback must never be `/tmp` (world-writable:
/// socket-squatting on `ui.sock` would capture the lock-screen password).
fn state_dir_from(xdg: Option<&std::ffi::OsStr>, uid: u32, custom: &str) -> PathBuf {
    if !custom.is_empty() {
        return PathBuf::from(custom);
    }
    match xdg {
        Some(d) if !d.is_empty() => PathBuf::from(d).join("lion-locker"),
        _ => PathBuf::from(format!("/run/user/{uid}/lion-locker")),
    }
}

fn valid_pam_service(s: &str) -> bool {
    valid_ident(s)
}

/// `#RRGGBB` → opaque `0xFFRRGGBB`.
pub fn parse_color(s: &str) -> Result<u32> {
    let h = s
        .strip_prefix('#')
        .filter(|h| h.len() == 6 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Config("locker.cover_color must be #RRGGBB".into()))?;
    let rgb = u32::from_str_radix(h, 16).map_err(|e| Error::Config(e.to_string()))?;
    Ok(0xFF00_0000 | rgb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let c = Config::default();
        assert!(c.lock_on_suspend);
        assert_eq!(c.grace_period_ms, 0);
        assert!(c.hide_notification_content);
        assert!(c.show_media_controls);
        assert_eq!(c.cover_argb(), 0xFF14_161C);
        c.validate().unwrap();
    }

    #[test]
    fn parse_requires_wrapper_and_rejects_unknown() {
        assert!(Config::parse("{}").is_err());
        assert!(Config::parse(r#"{"locker":{"bogus":1}}"#).is_err());
        assert!(Config::parse(r#"{"locker":{"pam":{"nope":1}}}"#).is_err());
        let c = Config::parse(r#"{"locker":{"lock_on_suspend":false,"grace_period_ms":1500}}"#)
            .unwrap();
        assert!(!c.lock_on_suspend);
        assert_eq!(c.grace_period(), Duration::from_millis(1500));
    }

    #[test]
    fn range_checks() {
        for bad in [
            r#"{"locker":{"grace_period_ms":999999}}"#,
            r#"{"locker":{"pam":{"timeout_seconds":0}}}"#,
            r#"{"locker":{"throttle":{"base_seconds":10,"cap_seconds":5}}}"#,
            r#"{"locker":{"cover_color":"red"}}"#,
            r##"{"locker":{"cover_color":"#12345"}}"##,
            r#"{"locker":{"sleep_lock_timeout_ms":60000}}"#,
            r#"{"locker":{"pam":{"service":"../etc/passwd"}}}"#,
            r#"{"locker":{"greeter_session_id":"a b"}}"#,
            r#"{"locker":{"ui":{"exec":["relative/path"]}}}"#,
            r#"{"locker":{"emergency_info":"a\u0007b"}}"#,
            r#"{"locker":{"bus":{"logind":"carrier-pigeon"}}}"#,
            r#"{"locker":{"bus":{"name":""}}}"#,
        ] {
            assert!(Config::parse(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn actions_follow_config() {
        let mut c = Config::default();
        assert_eq!(c.ui_actions(), vec!["shutdown"]);
        c.greeter_session_id = "c2".into();
        assert_eq!(c.ui_actions(), vec!["switch_user", "shutdown"]);
        c.allow_shutdown = false;
        assert_eq!(c.ui_actions(), vec!["switch_user"]);
    }

    #[test]
    fn color_parse() {
        assert_eq!(parse_color("#E63950").unwrap(), 0xFFE6_3950);
        assert!(parse_color("E63950").is_err());
    }

    #[test]
    fn state_dir_resolution_order() {
        use std::ffi::OsStr;
        // 1. Explicit config override wins.
        assert_eq!(
            state_dir_from(Some(OsStr::new("/run/user/1000")), 1000, "/var/lib/ll"),
            PathBuf::from("/var/lib/ll")
        );
        // 2. XDG_RUNTIME_DIR when set and non-empty.
        assert_eq!(
            state_dir_from(Some(OsStr::new("/run/user/1000")), 1000, ""),
            PathBuf::from("/run/user/1000/lion-locker")
        );
        // Empty XDG_RUNTIME_DIR is treated as unset.
        assert_eq!(
            state_dir_from(Some(OsStr::new("")), 1000, ""),
            PathBuf::from("/run/user/1000/lion-locker")
        );
        // 3. Unset → logind-managed /run/user/<uid>, NEVER /tmp.
        assert_eq!(
            state_dir_from(None, 1000, ""),
            PathBuf::from("/run/user/1000/lion-locker")
        );
    }

    #[test]
    fn state_dir_fallback_is_never_tmp() {
        // SECURITY regression guard: the fallback must resolve under
        // /run/user (logind, 0700). /tmp is world-writable and would let
        // an attacker squat the UI socket.
        for xdg in [None, Some(std::ffi::OsStr::new(""))] {
            let d = state_dir_from(xdg, 4242, "");
            assert!(
                d.starts_with("/run/user/4242"),
                "fallback {d:?} not under /run/user"
            );
            assert!(!d.starts_with("/tmp"), "fallback must not be /tmp: {d:?}");
            assert!(d.ends_with("lion-locker"));
        }
    }

    #[test]
    fn schema_is_valid_json_and_names_component() {
        let v: serde_json::Value = serde_json::from_str(SCHEMA_JSON).unwrap();
        assert!(v["title"].as_str().unwrap().contains("Lion Locker"));
    }

    #[test]
    fn schema_lists_every_config_key() {
        let v: serde_json::Value = serde_json::from_str(SCHEMA_JSON).unwrap();
        let props = &v["properties"]["locker"]["properties"];
        for k in [
            "lock_on_suspend",
            "grace_period_ms",
            "hide_notification_content",
            "show_media_controls",
            "lock_on_lid_close",
            "honor_logind_lock",
            "emergency_info",
            "allow_shutdown",
            "greeter_session_id",
            "explicit_unlock",
            "unlock_grant_ttl_ms",
            "sleep_lock_timeout_ms",
            "cover_color",
            "preflight",
            "pam_dir",
            "state_dir",
            "pam",
            "throttle",
            "ui",
            "rate_limit",
            "bus",
            "owner_uid",
        ] {
            assert!(props.get(k).is_some(), "schema missing {k}");
        }
    }
}
