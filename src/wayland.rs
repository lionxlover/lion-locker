#![forbid(unsafe_code)]
//! ext-session-lock-v1 client (spec 03 §3 "Locking").
//!
//! The compositor itself guarantees that, once it has sent `locked`,
//! nothing but lock surfaces is visible or focusable — and that the screen
//! *stays* locked if this process dies. This module only has to ask for
//! the lock, put a lock surface with a committed buffer on **every**
//! output (including outputs that appear later: hot-plugged monitors come
//! up locked immediately), and report what the compositor says.
//!
//! Threading: a dedicated thread owns the Wayland connection and runs a
//! blocking `poll(2)` over the connection fd and a wake-up eventfd. It has
//! no timers, so an idle locker causes zero wakeups (spec 03 §7). Commands
//! (`lock`/`unlock`) arrive over a std channel + eventfd kick; results go
//! back as [`BackendEvent`]s.
//!
//! The cover is a single opaque solid colour (Leonux "Obsidian Dark" by
//! default) in an `xrgb8888` shm buffer written through a memfd — no mmap,
//! therefore no `unsafe`. Buffers are cached per (width, height).
//!
//! **Deferred (v1, see DESIGN.md §2):** handing the lock surfaces to
//! `lion-lockscreen` (shm frame hand-off + input forwarding over the UI
//! socket). Until then the cover is the lock screen and the UI socket
//! carries state only.

use crate::error::{Error, Result};
use crate::ports::{BackendEvent, LockBackend};
use async_trait::async_trait;
use rustix::event::{eventfd, poll, EventfdFlags, PollFd, PollFlags};
use rustix::fs::{ftruncate, memfd_create, MemfdFlags};
use std::collections::HashMap;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::{
    wl_buffer::{self, WlBuffer},
    wl_compositor::WlCompositor,
    wl_output::{self, WlOutput},
    wl_registry::{self, WlRegistry},
    wl_shm::{self, WlShm},
    wl_shm_pool::WlShmPool,
    wl_surface::{self, WlSurface},
};
use wayland_client::{delegate_noop, Connection, Dispatch, EventQueue, Proxy, QueueHandle, WEnum};
use wayland_protocols::ext::session_lock::v1::client::{
    ext_session_lock_manager_v1::ExtSessionLockManagerV1,
    ext_session_lock_surface_v1::{self, ExtSessionLockSurfaceV1},
    ext_session_lock_v1::{self, ExtSessionLockV1},
};

enum Cmd {
    Lock,
    Unlock(oneshot::Sender<Result<()>>),
}

/// Handle used by the core (`LockBackend`).
pub struct WaylandBackend {
    cmd_tx: std_mpsc::Sender<Cmd>,
    kick: Arc<OwnedFd>,
}

impl WaylandBackend {
    /// Connect to `$WAYLAND_DISPLAY` and spawn the protocol thread.
    /// Fails (closed) when the compositor lacks `ext_session_lock_manager_v1`
    /// — a locker that cannot lock must not pretend to.
    pub fn connect(
        cover_argb: u32,
        events: mpsc::UnboundedSender<BackendEvent>,
    ) -> Result<WaylandBackend> {
        let conn = Connection::connect_to_env()
            .map_err(|e| Error::Wayland(format!("cannot connect to the compositor: {e}")))?;
        Self::with_connection(conn, cover_argb, events)
    }

    pub fn with_connection(
        conn: Connection,
        cover_argb: u32,
        events: mpsc::UnboundedSender<BackendEvent>,
    ) -> Result<WaylandBackend> {
        let (globals, mut queue) = registry_queue_init::<State>(&conn)
            .map_err(|e| Error::Wayland(format!("registry: {e}")))?;
        let qh = queue.handle();
        let bind_err = |what: &str, e: &dyn std::fmt::Display| {
            Error::Wayland(format!("compositor lacks {what}: {e}"))
        };
        let compositor: WlCompositor = globals
            .bind(&qh, 4..=6, ())
            .or_else(|_| globals.bind(&qh, 1..=3, ()))
            .map_err(|e| bind_err("wl_compositor", &e))?;
        let shm: WlShm = globals
            .bind(&qh, 1..=1, ())
            .map_err(|e| bind_err("wl_shm", &e))?;
        let lock_mgr: ExtSessionLockManagerV1 = globals
            .bind(&qh, 1..=1, ())
            .map_err(|e| bind_err("ext_session_lock_manager_v1", &e))?;

        let mut state = State {
            compositor,
            shm,
            lock_mgr,
            cover_argb,
            events,
            outputs: HashMap::new(),
            lock: None,
            locked: false,
            buffers: HashMap::new(),
            fatal: None,
        };
        // Bind outputs that exist already.
        let existing: Vec<(u32, u32)> = globals
            .contents()
            .clone_list()
            .into_iter()
            .filter(|g| g.interface == "wl_output")
            .map(|g| (g.name, g.version))
            .collect();
        for (name, version) in existing {
            state.add_output(&globals_registry(&globals), name, version, &qh);
        }
        queue
            .roundtrip(&mut state)
            .map_err(|e| Error::Wayland(format!("initial roundtrip: {e}")))?;

        let (cmd_tx, cmd_rx) = std_mpsc::channel();
        let kick = Arc::new(
            eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
                .map_err(|e| Error::Wayland(format!("eventfd: {e}")))?,
        );
        let thread_kick = kick.clone();
        std::thread::Builder::new()
            .name("lion-locker-wl".into())
            .spawn(move || {
                run_loop(conn, queue, state, cmd_rx, thread_kick);
            })
            .map_err(|e| Error::Wayland(format!("spawn: {e}")))?;
        Ok(WaylandBackend { cmd_tx, kick })
    }

    fn send(&self, cmd: Cmd) -> Result<()> {
        self.cmd_tx
            .send(cmd)
            .map_err(|_| Error::Wayland("wayland thread is gone".into()))?;
        // Kick the poll loop.
        let _ = rustix::io::write(self.kick.as_fd(), &1u64.to_ne_bytes());
        Ok(())
    }
}

fn globals_registry(g: &wayland_client::globals::GlobalList) -> WlRegistry {
    g.registry().clone()
}

#[async_trait]
impl LockBackend for WaylandBackend {
    async fn lock(&self) -> Result<()> {
        self.send(Cmd::Lock)
    }

    async fn unlock(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::Unlock(tx))?;
        rx.await
            .map_err(|_| Error::Wayland("wayland thread dropped the unlock".into()))?
    }
}

struct OutputSlot {
    wl_output: WlOutput,
    surface: Option<WlSurface>,
    lock_surface: Option<ExtSessionLockSurfaceV1>,
    committed: bool,
}

pub(crate) struct State {
    compositor: WlCompositor,
    shm: WlShm,
    lock_mgr: ExtSessionLockManagerV1,
    cover_argb: u32,
    events: mpsc::UnboundedSender<BackendEvent>,
    /// Keyed by the registry global name.
    outputs: HashMap<u32, OutputSlot>,
    lock: Option<ExtSessionLockV1>,
    locked: bool,
    buffers: HashMap<(i32, i32), (WlBuffer, WlShmPool)>,
    fatal: Option<String>,
}

impl State {
    fn add_output(
        &mut self,
        registry: &WlRegistry,
        name: u32,
        version: u32,
        qh: &QueueHandle<State>,
    ) {
        if self.outputs.contains_key(&name) {
            return;
        }
        let wl_output = registry.bind::<WlOutput, _, _>(name, version.min(4), qh, name);
        self.outputs.insert(
            name,
            OutputSlot {
                wl_output,
                surface: None,
                lock_surface: None,
                committed: false,
            },
        );
        // Hot-plug while locked/locking: cover it right away.
        if self.lock.is_some() {
            self.cover(name, qh);
        }
    }

    fn cover(&mut self, name: u32, qh: &QueueHandle<State>) {
        let Some(lock) = self.lock.clone() else {
            return;
        };
        let compositor = self.compositor.clone();
        let Some(slot) = self.outputs.get_mut(&name) else {
            return;
        };
        if slot.lock_surface.is_some() {
            return;
        }
        let surface = compositor.create_surface(qh, ());
        let ls = lock.get_lock_surface(&surface, &slot.wl_output, qh, name);
        slot.surface = Some(surface);
        slot.lock_surface = Some(ls);
        slot.committed = false;
        self.report_outputs();
    }

    fn uncover(&mut self, name: u32) {
        if let Some(slot) = self.outputs.get_mut(&name) {
            if let Some(ls) = slot.lock_surface.take() {
                ls.destroy();
            }
            if let Some(s) = slot.surface.take() {
                s.destroy();
            }
            slot.committed = false;
        }
    }

    fn report_outputs(&self) {
        let total = self.outputs.len() as u32;
        let covered = self.outputs.values().filter(|o| o.committed).count() as u32;
        let _ = self.events.send(BackendEvent::Outputs { covered, total });
    }

    fn buffer_for(&mut self, w: i32, h: i32, qh: &QueueHandle<State>) -> Result<WlBuffer> {
        if let Some((b, _)) = self.buffers.get(&(w, h)) {
            return Ok(b.clone());
        }
        let stride = w
            .checked_mul(4)
            .ok_or_else(|| Error::Wayland("width overflow".into()))?;
        let size = stride
            .checked_mul(h)
            .filter(|s| *s > 0 && *s <= 256 * 1024 * 1024)
            .ok_or_else(|| Error::Wayland("implausible output size".into()))?;
        let fd = memfd_create("lion-locker-cover", MemfdFlags::CLOEXEC)
            .map_err(|e| Error::Wayland(format!("memfd_create: {e}")))?;
        ftruncate(&fd, size as u64).map_err(|e| Error::Wayland(format!("ftruncate: {e}")))?;
        // Fill with the cover colour (xrgb8888, little endian).
        let px = self.cover_argb.to_le_bytes();
        let mut row = Vec::with_capacity(stride as usize);
        for _ in 0..w {
            row.extend_from_slice(&px);
        }
        let mut f = std::fs::File::from(
            fd.try_clone()
                .map_err(|e| Error::Wayland(format!("dup memfd: {e}")))?,
        );
        for _ in 0..h {
            f.write_all(&row)
                .map_err(|e| Error::Wayland(format!("fill cover: {e}")))?;
        }
        let pool = self.shm.create_pool(fd.as_fd(), size, qh, ());
        let buf = pool.create_buffer(0, w, h, stride, wl_shm::Format::Xrgb8888, qh, ());
        self.buffers.insert((w, h), (buf.clone(), pool));
        Ok(buf)
    }

    fn drop_buffers(&mut self) {
        for (_, (b, p)) in self.buffers.drain() {
            b.destroy();
            p.destroy();
        }
    }
}

fn run_loop(
    conn: Connection,
    mut queue: EventQueue<State>,
    mut state: State,
    cmd_rx: std_mpsc::Receiver<Cmd>,
    kick: Arc<OwnedFd>,
) {
    let qh = queue.handle();
    loop {
        // 1. Commands.
        loop {
            match cmd_rx.try_recv() {
                Ok(Cmd::Lock) => {
                    if state.lock.is_none() {
                        let lock = state.lock_mgr.lock(&qh, ());
                        state.lock = Some(lock);
                        state.locked = false;
                        let names: Vec<u32> = state.outputs.keys().copied().collect();
                        for n in names {
                            state.cover(n, &qh);
                        }
                    }
                }
                Ok(Cmd::Unlock(reply)) => {
                    let r = do_unlock(&conn, &mut queue, &mut state);
                    let _ = reply.send(r);
                }
                Err(std_mpsc::TryRecvError::Empty) => break,
                Err(std_mpsc::TryRecvError::Disconnected) => return,
            }
        }

        // 2. Dispatch whatever is already queued, then flush requests.
        if let Err(e) = queue.dispatch_pending(&mut state) {
            fatal(&state, format!("dispatch: {e}"));
            return;
        }
        if let Some(msg) = state.fatal.take() {
            fatal(&state, msg);
            return;
        }
        if let Err(e) = conn.flush() {
            fatal(&state, format!("flush: {e}"));
            return;
        }

        // 3. Sleep until the compositor or the core has something to say.
        let Some(guard) = conn.prepare_read() else {
            continue;
        };
        let conn_fd = guard.connection_fd();
        let mut fds = [
            PollFd::new(&conn_fd, PollFlags::IN),
            PollFd::new(&*kick, PollFlags::IN),
        ];
        match poll(&mut fds, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => {
                fatal(&state, format!("poll: {e}"));
                return;
            }
        }
        let conn_ready = fds[0]
            .revents()
            .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR);
        let kicked = fds[1].revents().contains(PollFlags::IN);
        if conn_ready {
            if let Err(e) = guard.read() {
                if !matches!(&e, wayland_client::backend::WaylandError::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock)
                {
                    fatal(&state, format!("read: {e}"));
                    return;
                }
            }
        } else {
            drop(guard);
        }
        if kicked {
            let mut buf = [0u8; 8];
            let _ = rustix::io::read(&*kick, &mut buf);
        }
    }
}

fn fatal(state: &State, msg: String) {
    let _ = state.events.send(BackendEvent::Fatal(msg));
}

fn do_unlock(conn: &Connection, queue: &mut EventQueue<State>, state: &mut State) -> Result<()> {
    let Some(lock) = state.lock.take() else {
        return Ok(()); // nothing held
    };
    if state.locked {
        lock.unlock_and_destroy();
    } else {
        lock.destroy();
    }
    state.locked = false;
    let names: Vec<u32> = state.outputs.keys().copied().collect();
    for n in names {
        state.uncover(n);
    }
    state.drop_buffers();
    // The compositor must have processed unlock before we report success.
    queue
        .roundtrip(state)
        .map_err(|e| Error::Wayland(format!("unlock roundtrip: {e}")))?;
    conn.flush()
        .map_err(|e| Error::Wayland(format!("flush: {e}")))?;
    Ok(())
}

// ── Dispatch plumbing ───────────────────────────────────────────────

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        state: &mut Self,
        registry: &WlRegistry,
        event: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        match event {
            wl_registry::Event::Global {
                name,
                interface,
                version,
            } => {
                if interface == "wl_output" {
                    state.add_output(registry, name, version, qh);
                }
            }
            wl_registry::Event::GlobalRemove { name } if state.outputs.contains_key(&name) => {
                state.uncover(name);
                if let Some(o) = state.outputs.remove(&name) {
                    if o.wl_output.version() >= 3 {
                        o.wl_output.release();
                    }
                }
                state.report_outputs();
            }
            _ => {}
        }
    }
}

impl Dispatch<ExtSessionLockV1, ()> for State {
    fn event(
        state: &mut Self,
        lock: &ExtSessionLockV1,
        event: ext_session_lock_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            ext_session_lock_v1::Event::Locked => {
                state.locked = true;
                let _ = state.events.send(BackendEvent::Locked);
            }
            ext_session_lock_v1::Event::Finished => {
                // Protocol: destroy the object; if we were locked the
                // compositor keeps the session locked on its own.
                lock.destroy();
                let names: Vec<u32> = state.outputs.keys().copied().collect();
                for n in names {
                    state.uncover(n);
                }
                state.drop_buffers();
                state.lock = None;
                state.locked = false;
                let _ = state.events.send(BackendEvent::Finished);
            }
            _ => {}
        }
    }
}

impl Dispatch<ExtSessionLockSurfaceV1, u32> for State {
    fn event(
        state: &mut Self,
        ls: &ExtSessionLockSurfaceV1,
        event: ext_session_lock_surface_v1::Event,
        name: &u32,
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        let ext_session_lock_surface_v1::Event::Configure {
            serial,
            width,
            height,
        } = event
        else {
            return;
        };
        ls.ack_configure(serial);
        let (w, h) = (width as i32, height as i32);
        if w <= 0 || h <= 0 {
            state.fatal = Some(format!("compositor configured a {w}x{h} lock surface"));
            return;
        }
        match state.buffer_for(w, h, qh) {
            Ok(buf) => {
                if let Some(slot) = state.outputs.get_mut(name) {
                    if let Some(s) = &slot.surface {
                        s.attach(Some(&buf), 0, 0);
                        s.damage_buffer(0, 0, w, h);
                        s.commit();
                        slot.committed = true;
                    }
                }
                state.report_outputs();
            }
            Err(e) => state.fatal = Some(format!("cannot draw the cover: {e}")),
        }
    }
}

impl Dispatch<WlOutput, u32> for State {
    fn event(
        _: &mut Self,
        _: &WlOutput,
        _: wl_output::Event,
        _: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlSurface, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlSurface,
        _: wl_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlBuffer, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlBuffer,
        _: wl_buffer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        // Release events are irrelevant: the buffer is static and shared.
    }
}

impl Dispatch<WlShm, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlShm,
        _: wl_shm::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(State: WlCompositor);
delegate_noop!(State: WlShmPool);
delegate_noop!(State: ExtSessionLockManagerV1);

#[allow(dead_code)]
fn _unused(_: WEnum<wl_shm::Format>) {}
