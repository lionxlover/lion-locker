//! The `ext-session-lock-v1` client: the part of lion-locker that actually
//! grabs input.
//!
//! Once `wl_session_lock.lock()` is acknowledged by the compositor
//! (`Locked` event), the protocol guarantees no other client's surfaces
//! are visible or receive input -- only this client's lock surfaces are.
//! That is the entirety of "grab input while locked": lion-locker doesn't
//! implement any input-grabbing logic of its own, it just holds the one
//! object the compositor requires for the guarantee to apply.
//!
//! Each output's lock surface is filled with a solid Obsidian Dark
//! (`#14161C`) backdrop the instant it's created -- so there is never a
//! frame where the screen shows anything else, even before
//! lion-lockscreen has produced its first real frame -- and is then kept
//! up to date with whatever `lion-lockscreen` sends via `PresentFrame`
//! (see lockscreen.rs).
//!
//! wayland-client's dispatch loop is synchronous and wants to own its
//! thread; it runs on a dedicated one here; see `spawn`.

use crate::lockscreen::Frame;
use anyhow::{bail, Context, Result};
use std::{collections::HashMap, os::fd::AsFd};
use tokio::sync::{mpsc, oneshot};
use wayland_client::{
    globals::GlobalListContents,
    protocol::{
        wl_keyboard, wl_output, wl_pointer, wl_registry, wl_seat, wl_shm, wl_shm_pool, wl_surface,
    },
    Connection as WlConnection, Dispatch, EventQueue, QueueHandle, WEnum,
};
use wayland_protocols::ext::session_lock::v1::client::{
    ext_session_lock_manager_v1::{self, ExtSessionLockManagerV1},
    ext_session_lock_surface_v1::{self, ExtSessionLockSurfaceV1},
    ext_session_lock_v1::{self, ExtSessionLockV1},
};

/// Obsidian Dark's base background, as opaque premultiplied BGRX8888 --
/// the backdrop painted into every lock surface before real content
/// arrives.
const BACKDROP_RGB: (u8, u8, u8) = (0x14, 0x16, 0x1C);

/// Events the Wayland thread reports up to the async side.
#[derive(Debug)]
pub enum WlEvent {
    /// The compositor has confirmed the lock; no other surface can be
    /// seen or receive input from here on.
    Locked,
    /// The compositor refused (or already-locked-elsewhere revoked) the
    /// lock; nothing was grabbed.
    Finished,
    /// A new output gained a lock surface and is ready for frames.
    OutputReady(String),
    KeyChar(char),
    KeyBackspace,
    KeySubmit,
    KeyCancel,
    PointerMotion {
        output: String,
        x: f64,
        y: f64,
    },
    PointerButton {
        output: String,
        button: u32,
        pressed: bool,
    },
    /// Caps Lock toggled while locked (drives the UI's indicator so a
    /// mistyped-then-caps password is not a mystery).
    CapsLock(bool),
}

/// Commands the async side sends down to the Wayland thread.
pub enum WlCommand {
    /// Begin a lock episode: create the session lock object.
    Lock(oneshot::Sender<Result<()>>),
    /// Attach and commit a rendered frame to one output's lock surface.
    Present(Frame),
    /// End the lock episode: `unlock_and_destroy` + drop all surfaces.
    Unlock,
    /// Tear the Wayland thread down cleanly (reserved for graceful
    /// session shutdown wiring; not triggered by any current caller).
    #[allow(dead_code)] // deliberate API surface for lion-session
    Shutdown,
}

/// A cheap, cloneable handle for sending commands to the Wayland thread.
/// The event stream (`WlEvent`) is returned separately from `spawn`,
/// since only one consumer can own an `mpsc::UnboundedReceiver` at a time
/// and it's the service-level event loop that owns it (see service.rs).
#[derive(Clone)]
pub struct WlHandle {
    cmd_tx: std::sync::mpsc::Sender<WlCommand>,
}

impl WlHandle {
    /// Begin a lock episode and *wait for the compositor's
    /// confirmation* (the `locked` event) before returning, so callers
    /// know exactly when the grab is enforced. Bounded by a timeout:
    /// if the compositor never answers we unlock what we started and
    /// report failure — callers surface that instead of silently
    /// pretending the screen is locked when it is not.
    pub async fn lock(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(WlCommand::Lock(tx)).ok();
        match tokio::time::timeout(std::time::Duration::from_secs(3), rx).await {
            Ok(res) => res.context("Wayland thread gone")?,
            Err(_) => {
                self.unlock();
                anyhow::bail!("compositor did not confirm the session lock within 3s")
            }
        }
    }

    pub fn present(&self, frame: Frame) {
        let _ = self.cmd_tx.send(WlCommand::Present(frame));
    }

    pub fn unlock(&self) {
        let _ = self.cmd_tx.send(WlCommand::Unlock);
    }
}

/// Connects to the compositor and starts the Wayland thread. Returns a
/// handle for issuing commands plus the stream of events it produces.
pub fn spawn() -> Result<(WlHandle, mpsc::UnboundedReceiver<WlEvent>)> {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel();

    let (ready_tx, ready_rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("lion-locker-wayland".into())
        .spawn(move || match State::connect(evt_tx) {
            Ok(state) => {
                let _ = ready_tx.send(Ok(()));
                state.run(cmd_rx);
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
            }
        })
        .context("spawning Wayland thread")?;

    // Block briefly for the initial connection/roundtrip so `spawn()`
    // fails loudly at startup rather than silently later on first Lock().
    ready_rx
        .blocking_recv()
        .context("Wayland thread died before connecting")??;

    Ok((WlHandle { cmd_tx }, evt_rx))
}

struct OutputState {
    wl_output: wl_output::WlOutput,
    name: String,
    lock_surface: Option<ExtSessionLockSurfaceV1>,
    surface: Option<wl_surface::WlSurface>,
    width: i32,
    height: i32,
}

struct State {
    evt_tx: mpsc::UnboundedSender<WlEvent>,
    queue_handle: QueueHandle<State>,
    compositor: Option<wayland_client::protocol::wl_compositor::WlCompositor>,
    shm: Option<wl_shm::WlShm>,
    lock_manager: Option<ExtSessionLockManagerV1>,
    /// Kept alive on purpose: dropping the WlSeat binding would destroy
    /// the keyboard/pointer objects we derive from it. Never *read*.
    #[allow(dead_code)]
    seat: Option<wl_seat::WlSeat>,
    outputs: HashMap<u32, OutputState>,
    lock: Option<ExtSessionLockV1>,
    xkb: crate::keyboard::XkbState,
    /// Reply channel for the in-flight `WlCommand::Lock`, fired by the
    /// `locked` confirmation event (or failed by `finished`).
    lock_confirm: Option<oneshot::Sender<Result<()>>>,
    /// Output whose lock surface the pointer last entered, for
    /// multi-monitor pointer routing.
    pointer_output: Option<String>,
}

impl State {
    fn connect(evt_tx: mpsc::UnboundedSender<WlEvent>) -> Result<RunningState> {
        let conn = WlConnection::connect_to_env().context(
            "connecting to the Wayland compositor (is WAYLAND_DISPLAY set? lion-session should have set it)",
        )?;
        let (globals, mut queue) = wayland_client::globals::registry_queue_init::<State>(&conn)
            .context("initial registry roundtrip")?;
        let qh = queue.handle();

        let compositor = globals
            .bind::<wayland_client::protocol::wl_compositor::WlCompositor, _, _>(&qh, 4..=6, ())
            .ok();
        let shm = globals.bind::<wl_shm::WlShm, _, _>(&qh, 1..=1, ()).ok();
        let seat = globals.bind::<wl_seat::WlSeat, _, _>(&qh, 5..=9, ()).ok();
        let lock_manager = globals
            .bind::<ExtSessionLockManagerV1, _, _>(&qh, 1..=1, ())
            .context("compositor does not support ext-session-lock-v1")?;

        let mut state = State {
            evt_tx,
            queue_handle: qh.clone(),
            compositor,
            shm,
            lock_manager: Some(lock_manager),
            seat,
            outputs: HashMap::new(),
            lock: None,
            xkb: crate::keyboard::XkbState::new(),
            lock_confirm: None,
            pointer_output: None,
        };

        // Bind every currently-known wl_output too, so we already have
        // per-output state by the time Lock() is called.
        for global in globals.contents().clone_list() {
            if global.interface == "wl_output" {
                let output = globals.registry().bind::<wl_output::WlOutput, _, _>(
                    global.name,
                    global.version.min(4),
                    &qh,
                    (),
                );
                state.outputs.insert(
                    global.name,
                    OutputState {
                        wl_output: output,
                        name: format!("output-{}", global.name),
                        lock_surface: None,
                        surface: None,
                        width: 0,
                        height: 0,
                    },
                );
            }
        }

        queue
            .roundtrip(&mut state)
            .context("second roundtrip (output info)")?;

        Ok(RunningState { conn, queue, state })
    }
}

struct RunningState {
    conn: WlConnection,
    queue: EventQueue<State>,
    state: State,
}

impl RunningState {
    /// Blocking event loop for the lifetime of the daemon. Dispatches
    /// Wayland events and drains queued commands between dispatch calls;
    /// wayland-client has no async story of its own, so this is the
    /// simplest correct design rather than trying to bridge it into tokio.
    fn run(mut self, cmd_rx: std::sync::mpsc::Receiver<WlCommand>) {
        loop {
            // Non-blocking drain of anything the async side queued up.
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    WlCommand::Lock(reply) => {
                        match self.do_lock() {
                            Ok(()) => {
                                // Reply is deferred until the compositor's
                                // `locked` event (fired by the
                                // ExtSessionLockV1 dispatcher below).
                                self.state.lock_confirm = Some(reply);
                            }
                            Err(e) => {
                                let _ = reply.send(Err(e));
                            }
                        }
                    }
                    WlCommand::Present(frame) => self.do_present(frame),
                    WlCommand::Unlock => self.do_unlock(),
                    WlCommand::Shutdown => return,
                }
            }
            if let Err(e) = self.queue.blocking_dispatch(&mut self.state) {
                tracing::error!(error = %e, "Wayland connection lost");
                let _ = self.state.evt_tx.send(WlEvent::Finished);
                return;
            }
        }
    }

    fn do_lock(&mut self) -> Result<()> {
        let Some(manager) = &self.state.lock_manager else {
            bail!("no ext_session_lock_manager_v1");
        };
        let lock = manager.lock(&self.state.queue_handle, ());

        let output_names: Vec<u32> = self.state.outputs.keys().copied().collect();
        self.state.lock = Some(lock);
        for name in output_names {
            attach_lock_surface(&mut self.state, name)?;
        }
        self.conn.flush().ok();
        Ok(())
    }

    fn do_present(&mut self, frame: Frame) {
        let Some(shm) = &self.state.shm else {
            tracing::warn!("no wl_shm; cannot present frame");
            return;
        };
        let Some(out) = self
            .state
            .outputs
            .values_mut()
            .find(|o| o.name == frame.output)
        else {
            tracing::warn!(output = %frame.output, "PresentFrame for unknown output");
            return;
        };
        let Some(surface) = &out.surface else { return };

        // SAFETY: `frame.fd` is an fd we received over D-Bus specifically
        // to be mmap'd as a wl_shm pool; the size we pass matches what
        // lion-lockscreen told us via `height * stride`.
        let pool = shm.create_pool(
            frame.fd.as_fd(),
            frame.height * frame.stride,
            &self.state.queue_handle,
            (),
        );
        let format = shm_format(&frame.format);
        let buffer = pool.create_buffer(
            0,
            frame.width,
            frame.height,
            frame.stride,
            format,
            &self.state.queue_handle,
            (),
        );
        surface.attach(Some(&buffer), 0, 0);
        surface.damage_buffer(0, 0, frame.width, frame.height);
        surface.commit();
        pool.destroy();
    }

    fn do_unlock(&mut self) {
        if let Some(lock) = self.state.lock.take() {
            lock.unlock_and_destroy();
        }
        for out in self.state.outputs.values_mut() {
            if let Some(ls) = out.lock_surface.take() {
                ls.destroy();
            }
            if let Some(s) = out.surface.take() {
                s.destroy();
            }
        }
        self.conn.flush().ok();
    }
}

fn shm_format(name: &str) -> wl_shm::Format {
    match name {
        "xrgb8888" => wl_shm::Format::Xrgb8888,
        "argb8888" => wl_shm::Format::Argb8888,
        other => {
            tracing::warn!(format = other, "unknown pixel format, assuming Argb8888");
            wl_shm::Format::Argb8888
        }
    }
}

// -- Dispatch impls -----------------------------------------------------
//
// Each of these just turns a Wayland event into either internal
// bookkeeping or a `WlEvent` sent up to the async side.

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _contents: &GlobalListContents,
        _: &WlConnection,
        qh: &QueueHandle<Self>,
    ) {
        // Hotplug: an output that appears mid-session (dock, projector)
        // gets bound immediately. If we are locked right now, it also
        // gets a lock surface at once — a monitor plugged in while the
        // screen is locked must never show session content, not even
        // until the next frame arrives.
        if let wl_registry::Event::Global {
            name,
            interface,
            version,
        } = event
        {
            if interface == "wl_output" {
                let output =
                    registry.bind::<wl_output::WlOutput, _, _>(name, version.min(4), qh, ());
                state.outputs.insert(
                    name,
                    OutputState {
                        wl_output: output,
                        name: format!("output-{name}"),
                        lock_surface: None,
                        surface: None,
                        width: 0,
                        height: 0,
                    },
                );
                if state.lock.is_some() {
                    if let Err(e) = attach_lock_surface(state, name) {
                        tracing::warn!(output = name, error = %e, "could not lock hotplug output");
                    }
                }
            }
        }
    }
}

/// Create (surface + lock surface) for one already-bound output while a
/// lock object exists. Shared by `do_lock` and the hotplug path.
fn attach_lock_surface(state: &mut State, output_name: u32) -> Result<()> {
    let Some(compositor) = state.compositor.clone() else {
        bail!("no wl_compositor");
    };
    let Some(lock) = state.lock.clone() else {
        bail!("no session lock object");
    };
    let Some(out) = state.outputs.get(&output_name) else {
        bail!("unknown output {output_name}");
    };
    let wl_output = out.wl_output.clone();
    let surface = compositor.create_surface(&state.queue_handle, ());
    let lock_surface =
        lock.get_lock_surface(&surface, &wl_output, &state.queue_handle, output_name);
    let out = state.outputs.get_mut(&output_name).unwrap();
    out.surface = Some(surface);
    out.lock_surface = Some(lock_surface);
    Ok(())
}

impl Dispatch<wayland_client::protocol::wl_compositor::WlCompositor, ()> for State {
    fn event(
        _: &mut Self,
        _: &wayland_client::protocol::wl_compositor::WlCompositor,
        _: wayland_client::protocol::wl_compositor::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_shm::WlShm, ()> for State {
    fn event(
        _: &mut Self,
        _: &wl_shm::WlShm,
        _: wl_shm::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_shm_pool::WlShmPool, ()> for State {
    fn event(
        _: &mut Self,
        _: &wl_shm_pool::WlShmPool,
        _: wl_shm_pool::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wayland_client::protocol::wl_buffer::WlBuffer, ()> for State {
    fn event(
        _: &mut Self,
        buffer: &wayland_client::protocol::wl_buffer::WlBuffer,
        event: wayland_client::protocol::wl_buffer::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
        if matches!(event, wayland_client::protocol::wl_buffer::Event::Release) {
            buffer.destroy();
        }
    }
}

impl Dispatch<wl_surface::WlSurface, ()> for State {
    fn event(
        _: &mut Self,
        _: &wl_surface::WlSurface,
        _: wl_surface::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_output::WlOutput, ()> for State {
    fn event(
        state: &mut Self,
        output: &wl_output::WlOutput,
        event: wl_output::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_output::Event::Name { name } = event {
            if let Some(o) = state.outputs.values_mut().find(|o| o.wl_output == *output) {
                o.name = name;
            }
        }
    }
}

impl Dispatch<ExtSessionLockManagerV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ExtSessionLockManagerV1,
        _: ext_session_lock_manager_v1::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ExtSessionLockV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ExtSessionLockV1,
        event: ext_session_lock_v1::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_session_lock_v1::Event::Locked => {
                // Fire the deferred Lock() reply: the grab is now real,
                // not merely requested.
                if let Some(reply) = state.lock_confirm.take() {
                    let _ = reply.send(Ok(()));
                }
                let _ = state.evt_tx.send(WlEvent::Locked);
            }
            ext_session_lock_v1::Event::Finished => {
                // If a Lock() was still awaiting confirmation, fail it.
                if let Some(reply) = state.lock_confirm.take() {
                    let _ = reply.send(Err(anyhow::anyhow!(
                        "session lock ended before confirmation"
                    )));
                }
                state.lock = None;
                let _ = state.evt_tx.send(WlEvent::Finished);
            }
            _ => {}
        }
    }
}

impl Dispatch<ExtSessionLockSurfaceV1, u32> for State {
    fn event(
        state: &mut Self,
        surface: &ExtSessionLockSurfaceV1,
        event: ext_session_lock_surface_v1::Event,
        output_name: &u32,
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
        if let ext_session_lock_surface_v1::Event::Configure {
            serial,
            width,
            height,
        } = event
        {
            surface.ack_configure(serial);
            if let Some(out) = state.outputs.get_mut(output_name) {
                out.width = width as i32;
                out.height = height as i32;
                // Paint the Obsidian Dark backdrop immediately so there is
                // never a frame with undefined content, even before
                // lion-lockscreen's first PresentFrame arrives.
                paint_backdrop(state, *output_name);
                if let Some(o) = state.outputs.get(output_name) {
                    let _ = state.evt_tx.send(WlEvent::OutputReady(o.name.clone()));
                }
            }
        }
    }
}

/// Fill one output's surface with a solid `BACKDROP_RGB`, via a one-shot
/// anonymous shm buffer. This is the *only* pixel content lion-locker
/// ever produces itself -- everything else comes from lion-lockscreen.
fn paint_backdrop(state: &mut State, output_name: u32) {
    let Some(shm) = &state.shm else { return };
    let Some(out) = state.outputs.get(&output_name) else {
        return;
    };
    let (Some(surface), w, h) = (out.surface.as_ref(), out.width.max(1), out.height.max(1)) else {
        return;
    };

    let stride = w * 4;
    let size = (stride * h) as usize;
    let Ok(fd) = create_memfd(size) else { return };

    let (r, g, b) = BACKDROP_RGB;
    let pixel = u32::from_le_bytes([b, g, r, 0xFF]); // Xrgb8888, little-endian
                                                     // SAFETY: `fd` was just created by us at exactly `size` bytes and is
                                                     // not shared with anything else yet.
    if let Ok(map) = unsafe { memmap_fill(&fd, size, pixel) } {
        drop(map); // flushed by munmap
    }

    let pool = shm.create_pool(fd.as_fd(), size as i32, &state.queue_handle, ());
    let buffer = pool.create_buffer(
        0,
        w,
        h,
        stride,
        wl_shm::Format::Xrgb8888,
        &state.queue_handle,
        (),
    );
    surface.attach(Some(&buffer), 0, 0);
    surface.damage_buffer(0, 0, w, h);
    surface.commit();
    pool.destroy();
}

fn create_memfd(size: usize) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let name = std::ffi::CString::new("lion-locker-backdrop").unwrap();
    // SAFETY: standard memfd_create usage; the raw fd is immediately
    // wrapped in an OwnedFd so it's closed if anything below fails.
    let raw = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if raw < 0 {
        bail!("memfd_create failed: {}", std::io::Error::last_os_error());
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::ftruncate(raw, size as i64) } != 0 {
        bail!("ftruncate failed: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// # Safety
/// `fd` must be a memfd/shm fd at least `size` bytes, not concurrently
/// mapped or written elsewhere.
unsafe fn memmap_fill(
    fd: &std::os::fd::OwnedFd,
    size: usize,
    pixel: u32,
) -> Result<memmap_guard::Map> {
    memmap_guard::Map::new(fd, size, pixel)
}

/// Tiny inline mmap wrapper so this module doesn't need the `memmap2`
/// crate just for "map, fill with a repeating u32, unmap".
mod memmap_guard {
    use super::*;
    use std::os::fd::AsRawFd;

    pub struct Map {
        ptr: *mut libc::c_void,
        len: usize,
    }

    impl Map {
        pub unsafe fn new(fd: &std::os::fd::OwnedFd, len: usize, pixel: u32) -> Result<Self> {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            );
            if ptr == libc::MAP_FAILED {
                bail!("mmap failed: {}", std::io::Error::last_os_error());
            }
            let words = ptr as *mut u32;
            for i in 0..(len / 4) {
                std::ptr::write(words.add(i), pixel);
            }
            Ok(Self { ptr, len })
        }
    }

    impl Drop for Map {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.ptr, self.len);
            }
        }
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for State {
    fn event(
        _: &mut Self,
        seat: &wl_seat::WlSeat,
        event: wl_seat::Event,
        _: &(),
        _: &WlConnection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_seat::Event::Capabilities {
            capabilities: WEnum::Value(caps),
        } = event
        {
            if caps.contains(wl_seat::Capability::Keyboard) {
                seat.get_keyboard(qh, ());
            }
            if caps.contains(wl_seat::Capability::Pointer) {
                seat.get_pointer(qh, ());
            }
        }
    }
}

impl Dispatch<wl_keyboard::WlKeyboard, ()> for State {
    fn event(
        state: &mut Self,
        _: &wl_keyboard::WlKeyboard,
        event: wl_keyboard::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_keyboard::Event::Keymap {
                format: WEnum::Value(wl_keyboard::KeymapFormat::XkbV1),
                fd,
                size,
            } => {
                state.xkb.load_keymap(fd, size as usize);
            }
            wl_keyboard::Event::Keymap { .. } => {}
            wl_keyboard::Event::Key {
                key,
                state: WEnum::Value(wl_keyboard::KeyState::Pressed),
                ..
            } => {
                handle_key_press(state, key);
            }
            wl_keyboard::Event::Key { .. } => {}
            wl_keyboard::Event::Modifiers {
                mods_depressed,
                mods_latched,
                mods_locked,
                group,
                ..
            } => {
                // Only a *change* in Caps Lock is reported upward (the
                // UI's indicator, so users stop losing passwords to it).
                if let Some(caps) =
                    state
                        .xkb
                        .update_modifiers(mods_depressed, mods_latched, mods_locked, group)
                {
                    let _ = state.evt_tx.send(WlEvent::CapsLock(caps));
                }
            }
            _ => {}
        }
    }
}

fn handle_key_press(state: &mut State, keycode: u32) {
    use crate::keyboard::KeyOutcome;
    match state.xkb.process(keycode) {
        KeyOutcome::Char(c) => {
            let _ = state.evt_tx.send(WlEvent::KeyChar(c));
        }
        KeyOutcome::Backspace => {
            let _ = state.evt_tx.send(WlEvent::KeyBackspace);
        }
        KeyOutcome::Enter => {
            let _ = state.evt_tx.send(WlEvent::KeySubmit);
        }
        KeyOutcome::Escape => {
            let _ = state.evt_tx.send(WlEvent::KeyCancel);
        }
        KeyOutcome::Ignored => {}
    }
}

impl Dispatch<wl_pointer::WlPointer, ()> for State {
    fn event(
        state: &mut Self,
        _: &wl_pointer::WlPointer,
        event: wl_pointer::Event,
        _: &(),
        _: &WlConnection,
        _: &QueueHandle<Self>,
    ) {
        // Multi-monitor pointer routing: Enter/Leave carry the surface,
        // and we know which output each lock surface belongs to since
        // we created them ourselves. Motion/Button resolve to the
        // entered output (falling back to the single-output case).
        if let wl_pointer::Event::Enter { surface, .. } = &event {
            state.pointer_output = state
                .outputs
                .values()
                .find(|o| o.surface.as_ref() == Some(surface))
                .map(|o| o.name.clone());
        }
        if matches!(event, wl_pointer::Event::Leave { .. }) {
            state.pointer_output = None;
        }
        let output = state
            .pointer_output
            .clone()
            .or_else(|| single_output_name(state));
        let Some(output) = output else { return };
        match event {
            wl_pointer::Event::Motion {
                surface_x,
                surface_y,
                ..
            } => {
                let _ = state.evt_tx.send(WlEvent::PointerMotion {
                    output,
                    x: surface_x,
                    y: surface_y,
                });
            }
            wl_pointer::Event::Button {
                button,
                state: bstate,
                ..
            } => {
                let pressed = matches!(bstate, WEnum::Value(wl_pointer::ButtonState::Pressed));
                let _ = state.evt_tx.send(WlEvent::PointerButton {
                    output,
                    button,
                    pressed,
                });
            }
            _ => {}
        }
    }
}

fn single_output_name(state: &State) -> Option<String> {
    if state.outputs.len() == 1 {
        state.outputs.values().next().map(|o| o.name.clone())
    } else {
        None // multi-output pointer routing needs Enter/Leave tracking (TODO)
    }
}
