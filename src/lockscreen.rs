//! The D-Bus contract between `lion-locker` and `lion-lockscreen`, on the
//! session bus. Two interfaces at the same well-known names/paths, one
//! per direction of the conversation:
//!
//! `lion-locker` calls **into** `lion-lockscreen`
//!   Bus / path  : os.lionos.Lockscreen / /os/lionos/Lockscreen
//!   Interface   : os.lionos.Lockscreen1
//!   Show(outputs: as) -> ()        start rendering; these outputs are
//!                                  locked and awaiting frames
//!   Hide() -> ()                   stop rendering, the lock has ended
//!   PointerMotion(output: s, x: d, y: d) -> ()
//!   PointerButton(output: s, button: u, pressed: b) -> ()
//!   KeyActivity() -> ()            "a key was pressed" -- never *which*
//!                                  key, so lion-lockscreen can animate a
//!                                  keystroke without ever seeing the
//!                                  password
//!   AuthState(state: s, message: s) -> ()
//!                                  state is "verifying" | "retry" | "unlocking"
//!   DisplayMessage(text: s, style: u) -> ()
//!                                  PAM module chatter forwarded live
//!                                  (style: 3=error, 4=info) — this is
//!                                  how "place your finger on the
//!                                  reader" (pam_fprintd) and 2FA
//!                                  instructions reach the screen
//!   CapsLock(on: b) -> ()          Caps Lock toggled; show the indicator
//!
//! `lion-lockscreen` calls **into** `lion-locker`
//!   Bus / path  : os.lionos.Locker / /os/lionos/Locker  (same object as
//!                 the public service.rs interface, different interface name)
//!   Interface   : os.lionos.Locker.Render1
//!   Ready(outputs: as) -> ()       lion-lockscreen has offscreen buffers
//!                                  ready for these outputs, in response
//!                                  to Show()
//!   PresentFrame(output: s, fd: h, width: i32, height: i32,
//!                stride: i32, format: s) -> ()
//!                                  a new rendered frame for `output`,
//!                                  as a POSIX shared-memory fd (wl_shm
//!                                  layout); lion-locker wraps it in a
//!                                  wl_buffer and commits it to that
//!                                  output's lock surface. Stale frames
//!                                  for the same output are coalesced
//!                                  (see service.rs) so a render loop
//!                                  cannot queue unbounded memory.

use tokio::sync::mpsc::UnboundedSender;
use zbus::{interface, proxy, zvariant::OwnedFd, Connection};

#[allow(dead_code)] // referenced by the #[proxy] attribute below as a literal
const LOCKSCREEN_BUS: &str = "os.lionos.Lockscreen";
const LOCKSCREEN_PATH: &str = "/os/lionos/Lockscreen";
const LOCKER_BUS: &str = "os.lionos.Locker";
const LOCKER_PATH: &str = "/os/lionos/Locker";

#[proxy(
    interface = "os.lionos.Lockscreen1",
    default_service = "os.lionos.Lockscreen",
    default_path = "/os/lionos/Lockscreen"
)]
trait Lockscreen1 {
    async fn show(&self, outputs: Vec<String>) -> zbus::Result<()>;
    async fn hide(&self) -> zbus::Result<()>;
    async fn pointer_motion(&self, output: &str, x: f64, y: f64) -> zbus::Result<()>;
    async fn pointer_button(&self, output: &str, button: u32, pressed: bool) -> zbus::Result<()>;
    async fn key_activity(&self) -> zbus::Result<()>;
    async fn auth_state(&self, state: &str, message: &str) -> zbus::Result<()>;
    async fn display_message(&self, text: &str, style: u32) -> zbus::Result<()>;
    async fn caps_lock(&self, on: bool) -> zbus::Result<()>;
}

/// Thin, reconnect-tolerant handle for calling into lion-lockscreen.
/// Every call is logged-and-ignored on failure: a lockscreen that hasn't
/// started yet, or has crashed, must never be able to stop the lock or
/// the PAM check from working -- worst case the screen just stays as the
/// Wayland lock surface's blank Obsidian Dark backdrop (see wayland.rs).
pub struct LockscreenClient {
    conn: Connection,
}

impl LockscreenClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn proxy(&self) -> zbus::Result<Lockscreen1Proxy<'static>> {
        Lockscreen1Proxy::builder(&self.conn).build().await
    }

    pub async fn show(&self, outputs: Vec<String>) {
        self.call(|p| async move { p.show(outputs).await }).await;
    }

    pub async fn hide(&self) {
        self.call(|p| async move { p.hide().await }).await;
    }

    pub async fn key_activity(&self) {
        self.call(|p| async move { p.key_activity().await }).await;
    }

    pub async fn auth_state(&self, state: &str, message: &str) {
        let (state, message) = (state.to_owned(), message.to_owned());
        self.call(|p| async move { p.auth_state(&state, &message).await })
            .await;
    }

    pub async fn pointer_motion(&self, output: &str, x: f64, y: f64) {
        let output = output.to_owned();
        self.call(|p| async move { p.pointer_motion(&output, x, y).await })
            .await;
    }

    pub async fn pointer_button(&self, output: &str, button: u32, pressed: bool) {
        let output = output.to_owned();
        self.call(|p| async move { p.pointer_button(&output, button, pressed).await })
            .await;
    }

    /// Forward live PAM module chatter (fingerprint prompts, 2FA
    /// instructions, lockout notices) to the lock screen.
    pub async fn display_message(&self, text: &str, style: u32) {
        let text = text.to_owned();
        self.call(|p| async move { p.display_message(&text, style).await })
            .await;
    }

    /// Report a Caps Lock transition so the UI can show its indicator.
    pub async fn caps_lock(&self, on: bool) {
        self.call(|p| async move { p.caps_lock(on).await }).await;
    }

    async fn call<F, Fut>(&self, f: F)
    where
        F: FnOnce(Lockscreen1Proxy<'static>) -> Fut,
        Fut: std::future::Future<Output = zbus::Result<()>>,
    {
        match self.proxy().await {
            Ok(p) => {
                if let Err(e) = f(p).await {
                    tracing::debug!(error = %e, "lion-lockscreen call failed (ignored)");
                }
            }
            Err(e) => tracing::debug!(error = %e, "lion-lockscreen not reachable (ignored)"),
        }
    }
}

/// A frame handed from lion-lockscreen, forwarded to wayland.rs for
/// attaching to that output's lock surface. The fd is a plain owned
/// fd (converted from the D-Bus `zvariant::OwnedFd` on receipt).
#[derive(Debug)]
pub struct Frame {
    pub output: String,
    pub fd: std::os::fd::OwnedFd,
    pub width: i32,
    pub height: i32,
    pub stride: i32,
    pub format: String,
}

/// Server side of `os.lionos.Locker.Render1`, the half of the contract
/// lion-lockscreen calls into. Registered on the same object path as the
/// public `Locker1` interface in service.rs -- zbus allows multiple
/// interfaces per path.
pub struct RenderService {
    frames: UnboundedSender<Frame>,
    ready: UnboundedSender<Vec<String>>,
}

impl RenderService {
    pub fn new(frames: UnboundedSender<Frame>, ready: UnboundedSender<Vec<String>>) -> Self {
        Self { frames, ready }
    }
}

#[interface(name = "os.lionos.Locker.Render1")]
impl RenderService {
    async fn ready(&self, outputs: Vec<String>) {
        let _ = self.ready.send(outputs);
    }

    async fn present_frame(
        &self,
        output: String,
        fd: OwnedFd,
        width: i32,
        height: i32,
        stride: i32,
        format: String,
    ) {
        let _ = self.frames.send(Frame {
            output,
            fd: fd.into(),
            width,
            height,
            stride,
            format,
        });
    }
}

// service.rs owns the single session-bus connection that claims
// `os.lionos.Locker` and registers both this interface and the public
// `Locker1` one (service.rs) at the same object path -- zbus supports
// multiple interfaces per path, and a single owner keeps "who claims the
// bus name" unambiguous.

// Referenced only in doc comments above, but named here so `cargo doc` /
// readers can find the constants next to what they describe.
#[allow(dead_code)]
const _DOC_LOCKSCREEN_PATH: &str = LOCKSCREEN_PATH;
#[allow(dead_code)]
const _DOC_LOCKER_PATH: &str = LOCKER_PATH;
#[allow(dead_code)]
const _DOC_LOCKER_BUS: &str = LOCKER_BUS;
