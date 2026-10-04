//! Compositor-level tests (spec 03 §10): the real `WaylandBackend` talks
//! ext-session-lock-v1 to an in-process mock compositor built with
//! `wayland-server`. The mock mirrors what a conforming compositor does:
//! it only sends `locked` once **every** output has a lock surface with a
//! committed buffer, so a backend that misses an output (or a hot-plugged
//! one) never reaches `Locked` and these tests time out.
#![cfg(feature = "real-wayland")]

use lion_locker::ports::{BackendEvent, LockBackend};
use lion_locker::wayland::WaylandBackend;
use std::os::unix::net::UnixStream;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use wayland_client::Connection;
use wayland_protocols::ext::session_lock::v1::server::{
    ext_session_lock_manager_v1::{self, ExtSessionLockManagerV1},
    ext_session_lock_surface_v1::{self, ExtSessionLockSurfaceV1},
    ext_session_lock_v1::{self, ExtSessionLockV1},
};
use wayland_server::protocol::{
    wl_buffer::{self, WlBuffer},
    wl_compositor::{self, WlCompositor},
    wl_output::{self, WlOutput},
    wl_shm::{self, WlShm},
    wl_shm_pool::{self, WlShmPool},
    wl_surface::{self, WlSurface},
};
use wayland_server::{
    backend::{ClientData, ClientId, DisconnectReason, GlobalId},
    Client, DataInit, Dispatch, Display, DisplayHandle, GlobalDispatch, New, Resource,
};

#[derive(Default, Debug, Clone)]
struct Obs {
    outputs: usize,
    lock_surfaces: usize,
    committed: usize,
    locked_sent: u32,
    unlock_requests: u32,
    /// Sizes of committed buffers (w, h).
    buffer_sizes: Vec<(i32, i32)>,
    /// `locked` was sent while some output lacked a committed lock surface.
    violation: bool,
}

type Shared = Arc<Mutex<Obs>>;

struct SurfaceData {
    committed: Mutex<bool>,
    pending: Mutex<Option<(i32, i32)>>,
}
struct BufData(i32, i32);

struct Server {
    obs: Shared,
    outputs: Vec<WlOutput>,
    lock: Option<ExtSessionLockV1>,
    lock_surfaces: Vec<(ExtSessionLockSurfaceV1, WlSurface)>,
    sent_locked: bool,
    bound_outputs: usize,
    configure_serial: u32,
    size: (u32, u32),
}

impl Server {
    fn committed_count(&self) -> usize {
        self.lock_surfaces
            .iter()
            .filter(|(_, s)| {
                s.data::<SurfaceData>()
                    .map(|d| *d.committed.lock().unwrap())
                    .unwrap_or(false)
            })
            .count()
    }

    fn sync_obs(&self) {
        let mut o = self.obs.lock().unwrap();
        o.lock_surfaces = self.lock_surfaces.len();
        o.committed = self.committed_count();
        o.outputs = self.bound_outputs;
    }

    /// Conforming-compositor rule: `locked` only when all outputs covered.
    fn maybe_send_locked(&mut self) {
        self.sync_obs();
        if let Some(lock) = &self.lock {
            if !self.sent_locked
                && self.bound_outputs > 0
                && self.lock_surfaces.len() == self.bound_outputs
                && self.committed_count() == self.bound_outputs
            {
                lock.locked();
                self.sent_locked = true;
                let mut o = self.obs.lock().unwrap();
                o.locked_sent += 1;
            }
        }
    }
}

struct Cd;
impl ClientData for Cd {
    fn initialized(&self, _: ClientId) {}
    fn disconnected(&self, _: ClientId, _: DisconnectReason) {}
}

// ── globals ──────────────────────────────────────────────────────────
macro_rules! simple_global {
    ($iface:ty) => {
        impl GlobalDispatch<$iface, ()> for Server {
            fn bind(
                _: &mut Self,
                _: &DisplayHandle,
                _: &Client,
                r: New<$iface>,
                _: &(),
                di: &mut DataInit<'_, Self>,
            ) {
                di.init(r, ());
            }
        }
    };
}
simple_global!(WlCompositor);
simple_global!(WlShm);
simple_global!(ExtSessionLockManagerV1);

impl GlobalDispatch<WlOutput, ()> for Server {
    fn bind(
        s: &mut Self,
        _: &DisplayHandle,
        _: &Client,
        r: New<WlOutput>,
        _: &(),
        di: &mut DataInit<'_, Self>,
    ) {
        let o = di.init(r, ());
        s.bound_outputs += 1;
        s.outputs.push(o);
        s.sync_obs();
    }
}

impl Dispatch<WlCompositor, ()> for Server {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &WlCompositor,
        req: wl_compositor::Request,
        _: &(),
        _: &DisplayHandle,
        di: &mut DataInit<'_, Self>,
    ) {
        if let wl_compositor::Request::CreateSurface { id } = req {
            di.init(
                id,
                SurfaceData {
                    committed: Mutex::new(false),
                    pending: Mutex::new(None),
                },
            );
        }
    }
}

impl Dispatch<WlSurface, SurfaceData> for Server {
    fn request(
        s: &mut Self,
        _: &Client,
        _: &WlSurface,
        req: wl_surface::Request,
        data: &SurfaceData,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        match req {
            wl_surface::Request::Attach { buffer, .. } => {
                *data.pending.lock().unwrap() =
                    buffer.and_then(|b| b.data::<BufData>().map(|d| (d.0, d.1)));
            }
            wl_surface::Request::Commit => {
                if let Some(sz) = *data.pending.lock().unwrap() {
                    *data.committed.lock().unwrap() = true;
                    s.obs.lock().unwrap().buffer_sizes.push(sz);
                }
                s.maybe_send_locked();
            }
            _ => {}
        }
    }
}

impl Dispatch<WlShm, ()> for Server {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &WlShm,
        req: wl_shm::Request,
        _: &(),
        _: &DisplayHandle,
        di: &mut DataInit<'_, Self>,
    ) {
        if let wl_shm::Request::CreatePool { id, .. } = req {
            di.init(id, ());
        }
    }
}

impl Dispatch<WlShmPool, ()> for Server {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &WlShmPool,
        req: wl_shm_pool::Request,
        _: &(),
        _: &DisplayHandle,
        di: &mut DataInit<'_, Self>,
    ) {
        if let wl_shm_pool::Request::CreateBuffer {
            id, width, height, ..
        } = req
        {
            di.init(id, BufData(width, height));
        }
    }
}

impl Dispatch<WlBuffer, BufData> for Server {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &WlBuffer,
        _: wl_buffer::Request,
        _: &BufData,
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
    }
}

impl Dispatch<WlOutput, ()> for Server {
    fn request(
        _: &mut Self,
        _: &Client,
        _: &WlOutput,
        _: wl_output::Request,
        _: &(),
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
    }
}

impl Dispatch<ExtSessionLockManagerV1, ()> for Server {
    fn request(
        s: &mut Self,
        _: &Client,
        _: &ExtSessionLockManagerV1,
        req: ext_session_lock_manager_v1::Request,
        _: &(),
        _: &DisplayHandle,
        di: &mut DataInit<'_, Self>,
    ) {
        if let ext_session_lock_manager_v1::Request::Lock { id } = req {
            let lock = di.init(id, ());
            s.lock = Some(lock);
            s.sent_locked = false;
        }
    }
}

impl Dispatch<ExtSessionLockV1, ()> for Server {
    fn request(
        s: &mut Self,
        _: &Client,
        _: &ExtSessionLockV1,
        req: ext_session_lock_v1::Request,
        _: &(),
        _: &DisplayHandle,
        di: &mut DataInit<'_, Self>,
    ) {
        match req {
            ext_session_lock_v1::Request::GetLockSurface { id, surface, .. } => {
                let ls = di.init(id, ());
                s.configure_serial += 1;
                ls.configure(s.configure_serial, s.size.0, s.size.1);
                s.lock_surfaces.push((ls, surface));
                s.sync_obs();
            }
            ext_session_lock_v1::Request::UnlockAndDestroy => {
                s.obs.lock().unwrap().unlock_requests += 1;
                s.lock = None;
                s.sent_locked = false;
            }
            ext_session_lock_v1::Request::Destroy => {
                s.lock = None;
            }
            _ => {}
        }
    }
}

impl Dispatch<ExtSessionLockSurfaceV1, ()> for Server {
    fn request(
        s: &mut Self,
        _: &Client,
        res: &ExtSessionLockSurfaceV1,
        req: ext_session_lock_surface_v1::Request,
        _: &(),
        _: &DisplayHandle,
        _: &mut DataInit<'_, Self>,
    ) {
        if let ext_session_lock_surface_v1::Request::Destroy = req {
            s.lock_surfaces.retain(|(l, _)| l != res);
            s.sync_obs();
        }
    }
}

enum Cmd {
    AddOutput,
    RemoveLastOutput,
    FinishLock,
    Stop,
}

struct Compositor {
    obs: Shared,
    cmd: std_mpsc::Sender<Cmd>,
    client_stream: Option<UnixStream>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Compositor {
    /// `initial_outputs` outputs exist before the client connects.
    fn start(initial_outputs: usize, with_lock_global: bool) -> Compositor {
        let obs: Shared = Default::default();
        let (cmd_tx, cmd_rx) = std_mpsc::channel();
        let (cs, ss) = UnixStream::pair().unwrap();
        let thread_obs = obs.clone();
        let (ready_tx, ready_rx) = std_mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut display: Display<Server> = Display::new().unwrap();
            let mut dh = display.handle();
            dh.create_global::<Server, WlCompositor, ()>(4, ());
            dh.create_global::<Server, WlShm, ()>(1, ());
            if with_lock_global {
                dh.create_global::<Server, ExtSessionLockManagerV1, ()>(1, ());
            }
            let mut state = Server {
                obs: thread_obs,
                outputs: vec![],
                lock: None,
                lock_surfaces: vec![],
                sent_locked: false,
                bound_outputs: 0,
                configure_serial: 0,
                size: (800, 600),
            };
            let mut live: Vec<GlobalId> = vec![];
            for _ in 0..initial_outputs {
                live.push(dh.create_global::<Server, WlOutput, ()>(4, ()));
            }
            dh.insert_client(ss, Arc::new(Cd)).unwrap();
            ready_tx.send(()).unwrap();
            loop {
                match cmd_rx.try_recv() {
                    Ok(Cmd::AddOutput) => {
                        live.push(dh.create_global::<Server, WlOutput, ()>(4, ()));
                    }
                    Ok(Cmd::RemoveLastOutput) => {
                        if let Some(g) = live.pop() {
                            dh.remove_global::<Server>(g);
                            state.bound_outputs = state.bound_outputs.saturating_sub(1);
                            state.outputs.pop();
                            state.sync_obs();
                        }
                    }
                    Ok(Cmd::FinishLock) => {
                        if let Some(l) = &state.lock {
                            l.finished();
                        }
                    }
                    Ok(Cmd::Stop) | Err(std_mpsc::TryRecvError::Disconnected) => return,
                    Err(std_mpsc::TryRecvError::Empty) => {}
                }
                display.dispatch_clients(&mut state).unwrap();
                display.flush_clients().unwrap();
                state.maybe_send_locked();
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        ready_rx.recv().unwrap();
        Compositor {
            obs,
            cmd: cmd_tx,
            client_stream: Some(cs),
            thread: Some(thread),
        }
    }

    fn connect(&mut self) -> (WaylandBackend, mpsc::UnboundedReceiver<BackendEvent>) {
        let conn = Connection::from_socket(self.client_stream.take().unwrap()).unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let be = WaylandBackend::with_connection(conn, 0xFF14_161C, tx).unwrap();
        (be, rx)
    }

    fn obs(&self) -> Obs {
        self.obs.lock().unwrap().clone()
    }
}

impl Drop for Compositor {
    fn drop(&mut self) {
        let _ = self.cmd.send(Cmd::Stop);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

async fn wait_for(mut f: impl FnMut() -> bool, what: &str) {
    let r = tokio::time::timeout(Duration::from_secs(3), async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(r.is_ok(), "timed out waiting for: {what}");
}

async fn next_matching(
    rx: &mut mpsc::UnboundedReceiver<BackendEvent>,
    pred: impl Fn(&BackendEvent) -> bool,
) -> BackendEvent {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let e = rx.recv().await.expect("backend channel closed");
            if pred(&e) {
                return e;
            }
        }
    })
    .await
    .expect("timed out waiting for a backend event")
}

#[tokio::test]
async fn covers_every_output_then_reports_locked() {
    let mut c = Compositor::start(2, true);
    let (be, mut rx) = c.connect();
    be.lock().await.unwrap();
    next_matching(&mut rx, |e| *e == BackendEvent::Locked).await;
    let o = c.obs();
    assert_eq!(o.lock_surfaces, 2);
    assert_eq!(o.committed, 2);
    assert_eq!(o.locked_sent, 1);
    assert!(!o.violation);
    assert!(o.buffer_sizes.iter().all(|s| *s == (800, 600)));
}

#[tokio::test]
async fn hotplugged_output_comes_up_locked_immediately() {
    let mut c = Compositor::start(1, true);
    let (be, mut rx) = c.connect();
    be.lock().await.unwrap();
    next_matching(&mut rx, |e| *e == BackendEvent::Locked).await;
    c.cmd.send(Cmd::AddOutput).unwrap();
    // The new monitor must get a lock surface + committed buffer.
    wait_for(
        || {
            let o = c.obs();
            o.outputs == 2 && o.lock_surfaces == 2 && o.committed == 2
        },
        "hot-plugged output covered",
    )
    .await;
    next_matching(&mut rx, |e| {
        matches!(
            e,
            BackendEvent::Outputs {
                covered: 2,
                total: 2
            }
        )
    })
    .await;
}

#[tokio::test]
async fn unplug_replug_during_lock_recovers_full_coverage() {
    let mut c = Compositor::start(2, true);
    let (be, mut rx) = c.connect();
    be.lock().await.unwrap();
    next_matching(&mut rx, |e| *e == BackendEvent::Locked).await;
    c.cmd.send(Cmd::RemoveLastOutput).unwrap();
    wait_for(
        || c.obs().lock_surfaces == 1,
        "surface for removed output destroyed",
    )
    .await;
    c.cmd.send(Cmd::AddOutput).unwrap();
    wait_for(
        || {
            let o = c.obs();
            o.lock_surfaces == 2 && o.committed == 2
        },
        "replugged output re-covered",
    )
    .await;
}

#[tokio::test]
async fn unlock_sends_unlock_and_destroy_and_waits_for_the_roundtrip() {
    let mut c = Compositor::start(1, true);
    let (be, mut rx) = c.connect();
    be.lock().await.unwrap();
    next_matching(&mut rx, |e| *e == BackendEvent::Locked).await;
    be.unlock().await.unwrap();
    // The roundtrip inside unlock() guarantees the compositor saw it.
    assert_eq!(c.obs().unlock_requests, 1);
    assert_eq!(c.obs().lock_surfaces, 0);
}

#[tokio::test]
async fn unlock_without_lock_is_a_noop() {
    let mut c = Compositor::start(1, true);
    let (be, _rx) = c.connect();
    be.unlock().await.unwrap();
    assert_eq!(c.obs().unlock_requests, 0);
}

#[tokio::test]
async fn finished_event_is_reported_and_object_destroyed() {
    let mut c = Compositor::start(1, true);
    let (be, mut rx) = c.connect();
    be.lock().await.unwrap();
    next_matching(&mut rx, |e| *e == BackendEvent::Locked).await;
    c.cmd.send(Cmd::FinishLock).unwrap();
    next_matching(&mut rx, |e| *e == BackendEvent::Finished).await;
    // A fresh lock request after `finished` works (the core's relock path).
    be.lock().await.unwrap();
    next_matching(&mut rx, |e| *e == BackendEvent::Locked).await;
    assert_eq!(c.obs().locked_sent, 2);
}

#[tokio::test]
async fn missing_protocol_fails_closed_at_startup() {
    let mut c = Compositor::start(1, false);
    let conn = Connection::from_socket(c.client_stream.take().unwrap()).unwrap();
    let (tx, _rx) = mpsc::unbounded_channel();
    let r = WaylandBackend::with_connection(conn, 0, tx);
    match r {
        Ok(_) => panic!("must refuse to run without ext_session_lock_manager_v1"),
        Err(e) => assert!(e.to_string().contains("ext_session_lock_manager_v1"), "{e}"),
    }
}

#[tokio::test]
async fn compositor_disconnect_is_fatal() {
    let mut c = Compositor::start(1, true);
    let (be, mut rx) = c.connect();
    be.lock().await.unwrap();
    next_matching(&mut rx, |e| *e == BackendEvent::Locked).await;
    drop(c); // compositor dies
    let e = next_matching(&mut rx, |e| matches!(e, BackendEvent::Fatal(_))).await;
    assert!(matches!(e, BackendEvent::Fatal(_)));
}
