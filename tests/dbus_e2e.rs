//! End-to-end D-Bus acceptance tests (spec 03 §10): a private
//! `dbus-daemon` and the REAL `lion-locker` binary in `--mock` mode
//! (scripted compositor + PAM behind the real bus interface and the real
//! UI socket), driven through a real zbus client.
//!
//! Positive and negative path for every public member:
//! Lock / Unlock / IsLocked / State / Failures / Locked / Unlocked /
//! AuthFailed, plus caller-authorization (non-owner denied) and the
//! "Unlock needs a PAM grant" rule.
//!
//! Tests serialize on one mutex (shared process-global env).
#![cfg(feature = "real-bus")]

use futures_util::StreamExt;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

static SERIAL: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lion-locker")
}

#[zbus::proxy(
    interface = "os.lionos.Locker1",
    default_service = "os.lionos.Locker1",
    default_path = "/os/lionos/Locker1"
)]
trait Locker1 {
    fn lock(&self) -> zbus::Result<()>;
    fn unlock(&self) -> zbus::Result<()>;
    #[zbus(property)]
    fn is_locked(&self) -> zbus::Result<bool>;
    #[zbus(property)]
    fn state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn failures(&self) -> zbus::Result<u32>;
    #[zbus(signal)]
    fn locked(&self) -> zbus::Result<()>;
    #[zbus(signal)]
    fn unlocked(&self) -> zbus::Result<()>;
    #[zbus(signal)]
    fn auth_failed(&self, count: u32) -> zbus::Result<()>;
}

struct Env {
    bus: String,
    dir: tempfile::TempDir,
    conn: zbus::Connection,
    daemon: tokio::process::Child,
}

fn my_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

impl Env {
    async fn start(extra: &str, owner_uid: Option<u32>) -> Env {
        let out = tokio::process::Command::new("dbus-daemon")
            .args(["--session", "--fork", "--print-address=1", "--print-pid=1"])
            .output()
            .await
            .expect("dbus-daemon present (spec CI image)");
        let text = String::from_utf8_lossy(&out.stdout);
        let bus = text.lines().next().expect("bus address").trim().to_string();
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &bus);

        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("run");
        let owner = owner_uid.unwrap_or_else(my_uid);
        let cfg = format!(
            r#"{{"locker":{{
                "state_dir":"{}",
                "owner_uid":{owner},
                "unlock_grant_ttl_ms":3000,
                "throttle":{{"free_attempts":1,"base_seconds":1,"cap_seconds":2}}
                {extra}
            }}}}"#,
            state.display()
        );
        let cfg_path = dir.path().join("locker.json");
        std::fs::write(&cfg_path, cfg).unwrap();

        let daemon = tokio::process::Command::new(bin())
            .arg("--mock")
            .arg("--config")
            .arg(&cfg_path)
            .env("DBUS_SESSION_BUS_ADDRESS", &bus)
            .env("RUST_LOG", "info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("daemon spawns");

        let conn = zbus::connection::Builder::session()
            .unwrap()
            .build()
            .await
            .unwrap();
        let env = Env {
            bus,
            dir,
            conn,
            daemon,
        };
        env.wait_name().await;
        env
    }

    async fn wait_name(&self) {
        let dbus = zbus::fdo::DBusProxy::new(&self.conn).await.unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let name = zbus::names::BusName::try_from("os.lionos.Locker1".to_string()).unwrap();
            if dbus.name_has_owner(name).await.unwrap_or(false) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "daemon never owned its name"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_failures(&self, want: u32) {
        let p = self.proxy().await;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let n = p.failures().await.unwrap_or(u32::MAX);
            if n == want {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "failures never {want} (now {n})"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }

    fn sock(&self) -> std::path::PathBuf {
        self.dir.path().join("run").join("ui.sock")
    }

    async fn proxy(&self) -> Locker1Proxy<'_> {
        Locker1Proxy::new(&self.conn).await.unwrap()
    }

    async fn wait_state(&self, want: &str) {
        let p = self.proxy().await;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let s = p.state().await.unwrap_or_default();
            if s == want {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "state never {want} (now {s})"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.daemon.start_kill();
        // Best effort: stop the private bus daemon too.
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "pkill -f -- '{}' 2>/dev/null",
                self.bus.replace('\'', "")
            ))
            .status();
    }
}

/// Minimal UI-protocol client over the real socket.
struct UiClient {
    r: BufReader<tokio::net::unix::OwnedReadHalf>,
    w: tokio::net::unix::OwnedWriteHalf,
    next: u64,
}

impl UiClient {
    async fn connect(path: &std::path::Path) -> UiClient {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let s = loop {
            match UnixStream::connect(path).await {
                Ok(s) => break s,
                Err(_) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                Err(e) => panic!("cannot connect to UI socket: {e}"),
            }
        };
        let (r, w) = s.into_split();
        UiClient {
            r: BufReader::new(r),
            w,
            next: 1,
        }
    }

    async fn send(&mut self, mut v: serde_json::Value) {
        v["proto"] = 1.into();
        v["id"] = self.next.into();
        self.next += 1;
        self.w.write_all(format!("{v}\n").as_bytes()).await.unwrap();
    }

    async fn until(&mut self, pred: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let r = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                if self.r.read_line(&mut line).await.unwrap() == 0 {
                    panic!("socket closed");
                }
                let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                if pred(&v) {
                    return v;
                }
            }
        })
        .await;
        r.expect("timed out waiting for UI line")
    }

    async fn attempt(&mut self, pw: &str) -> serde_json::Value {
        self.send(serde_json::json!({"op":"Begin"})).await;
        self.until(|v| v["event"] == "Prompt").await;
        self.send(serde_json::json!({"op":"Answer","text":pw}))
            .await;
        self.until(|v| v["event"] == "AuthResult").await
    }
}

#[tokio::test]
async fn lock_unlock_roundtrip_with_properties_and_signals() {
    let _g = SERIAL.lock().await;
    let env = Env::start("", None).await;
    let p = env.proxy().await;

    // Initial state.
    assert!(!p.is_locked().await.unwrap());
    assert_eq!(p.state().await.unwrap(), "unlocked");
    assert_eq!(p.failures().await.unwrap(), 0);

    let mut locked = p.receive_locked().await.unwrap();
    let mut unlocked = p.receive_unlocked().await.unwrap();
    let mut auth_failed = p.receive_auth_failed().await.unwrap();

    // Lock (positive): returns after the (scripted) compositor confirms.
    p.lock().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), locked.next())
        .await
        .expect("Locked signal")
        .unwrap();
    assert!(p.is_locked().await.unwrap());
    assert_eq!(p.state().await.unwrap(), "locked");
    // Idempotent.
    p.lock().await.unwrap();

    // Unlock without a PAM grant (negative): denied, still locked.
    let err = p.unlock().await.unwrap_err();
    assert!(
        err.to_string().contains("not authenticated") || err.to_string().contains("AccessDenied"),
        "{err}"
    );
    assert!(p.is_locked().await.unwrap());

    // Wrong password → AuthFailed signal + Failures property.
    let mut ui = UiClient::connect(&env.sock()).await;
    ui.until(|v| v["event"] == "Show").await;
    let bad = ui.attempt("wrong").await;
    assert_eq!(bad["ok"], false);
    let sig = tokio::time::timeout(Duration::from_secs(3), auth_failed.next())
        .await
        .expect("AuthFailed signal")
        .unwrap();
    assert_eq!(sig.args().unwrap().count, 1);
    env.wait_failures(1).await; // PropertiesChanged trails the signal
    assert!(p.is_locked().await.unwrap());

    // Right password (after the 1 s lockout) → Unlocked signal.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let good = ui.attempt("lion").await;
    assert_eq!(good["ok"], true);
    tokio::time::timeout(Duration::from_secs(3), unlocked.next())
        .await
        .expect("Unlocked signal")
        .unwrap();
    env.wait_state("unlocked").await;
    env.wait_failures(0).await;
    assert!(!env.proxy().await.is_locked().await.unwrap());
}

#[tokio::test]
async fn non_owner_cannot_lock_or_unlock() {
    let _g = SERIAL.lock().await;
    // The daemon believes the owner is some other uid; this test process
    // (a different uid from the daemon's point of view) must be refused.
    let env = Env::start("", Some(my_uid() + 4242)).await;
    let p = env.proxy().await;
    for r in [p.lock().await, p.unlock().await] {
        let e = r.expect_err("non-owner must be denied");
        assert!(
            e.to_string().contains("AccessDenied")
                || e.to_string().contains("not the session owner"),
            "{e}"
        );
    }
    assert!(!p.is_locked().await.unwrap());
    assert_eq!(p.state().await.unwrap(), "unlocked");
}

#[tokio::test]
async fn explicit_unlock_mode_needs_pam_then_unlock_call() {
    let _g = SERIAL.lock().await;
    let env = Env::start(r#","explicit_unlock":true"#, None).await;
    let p = env.proxy().await;
    p.lock().await.unwrap();
    let mut ui = UiClient::connect(&env.sock()).await;
    ui.until(|v| v["event"] == "Show").await;
    // PAM verified → grant only; the lock stays.
    let good = ui.attempt("lion").await;
    assert_eq!(good["ok"], true);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(p.is_locked().await.unwrap());
    // Owner calls Unlock() with the grant → unlocked.
    p.unlock().await.unwrap();
    env.wait_state("unlocked").await;
    // Single use: lock again, Unlock() must be denied.
    p.lock().await.unwrap();
    assert!(p.unlock().await.is_err());
    assert!(p.is_locked().await.unwrap());
}

#[tokio::test]
async fn bus_calls_are_rate_limited() {
    let _g = SERIAL.lock().await;
    let env = Env::start(r#","rate_limit":{"window_ms":60000,"max_calls":6}"#, None).await;
    let p = env.proxy().await;
    let mut limited = false;
    for _ in 0..15 {
        if let Err(e) = p.lock().await {
            if e.to_string().contains("LimitsExceeded") || e.to_string().contains("too many") {
                limited = true;
                break;
            }
        }
    }
    assert!(limited, "expected a rate-limit error");
}

#[tokio::test]
async fn restart_with_marker_relocks_before_serving() {
    let _g = SERIAL.lock().await;
    let mut env = Env::start("", None).await;
    {
        let p = env.proxy().await;
        p.lock().await.unwrap();
    }
    // Kill the daemon abruptly (crash); the marker stays behind.
    env.daemon.kill().await.unwrap();
    let marker = env.dir.path().join("run").join("locked");
    assert!(marker.exists(), "lock marker must survive a crash");
    // A new daemon on the same state dir re-locks on its own.
    let cfg_path = env.dir.path().join("locker.json");
    env.daemon = tokio::process::Command::new(bin())
        .arg("--mock")
        .arg("--config")
        .arg(&cfg_path)
        .env("DBUS_SESSION_BUS_ADDRESS", &env.bus)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    env.wait_name().await;
    env.wait_state("locked").await;
    assert!(env.proxy().await.is_locked().await.unwrap());
}
