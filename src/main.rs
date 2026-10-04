#![forbid(unsafe_code)]
//! `lion-locker` entry point (spec 03 §9): flags, backend selection, the
//! tokio runtime, signal handling and the final exit code.
//!
//! Modes:
//! - `--mock` — all-fakes demo: scripted compositor, no D-Bus, PAM accepts
//!   the password `lion`, real UI socket. Drive it with
//!   `cargo run --example locker_client`.
//! - real (default) — ext-session-lock-v1 via `$WAYLAND_DISPLAY`, libpam,
//!   logind (system bus), `os.lionos.Locker1` on the session bus.
//!
//! Startup is fail-closed: no compositor lock protocol, no libpam, or an
//! unresolvable session owner means the daemon exits non-zero rather than
//! run in a state where it could lock but not unlock.

use lion_locker::cli::{self, Args};
use lion_locker::config::{Config, DEFAULT_CONFIG_PATH};
use lion_locker::core::{Deps, Event, FsPreflight, Handle, LockerCore};
use lion_locker::notify::Notify;
use lion_locker::pam::PamServiceFactory;
use lion_locker::ports::*;
use lion_locker::{backends, sysffi, uisock, SCHEMA_JSON, SPEC, VERSION};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .init();
}

fn main() {
    let args = match cli::from_env() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("lion-locker: {e}");
            std::process::exit(2);
        }
    };
    if args.version {
        println!("lion-locker {VERSION} (LionOS spec {SPEC})");
        return;
    }
    if args.print_schema {
        println!("{SCHEMA_JSON}");
        return;
    }

    let config_path = args
        .config
        .clone()
        .or_else(|| std::env::var_os("LION_LOCKER_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

    if args.check_config {
        match Config::load(&config_path) {
            Ok(cfg) => {
                println!(
                    "ok: {} (lock_on_suspend={}, grace_period_ms={}, hide_notification_content={}, pam_service={})",
                    config_path.display(),
                    cfg.lock_on_suspend,
                    cfg.grace_period_ms,
                    cfg.hide_notification_content,
                    cfg.pam.service
                );
            }
            Err(e) => {
                eprintln!("config error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // A missing config file is fine for --mock; real mode wants the
    // shipped defaults file but still starts without one (all keys have
    // defaults) — an *invalid* file is fatal.
    let cfg = if config_path.exists() {
        match Config::load(&config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("lion-locker: {e}");
                std::process::exit(1);
            }
        }
    } else {
        Config::default()
    };

    init_logging();
    std::env::set_var("LION_LOCKER_CONFIG", &config_path);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(run(cfg, args));
    std::process::exit(code);
}

async fn run(mut cfg: Config, args: Args) -> i32 {
    if args.mock {
        // A mock run has no real UI binary: an external client connects.
        cfg.ui.exec = vec![];
        cfg.preflight = false;
    }
    let user = match sysffi::username_of_uid(cfg.owner()) {
        Some(u) => u,
        None if args.mock => "lion".to_string(),
        None => {
            tracing::error!(target: "locker", "cannot resolve uid {} to a user name", cfg.owner());
            return 1;
        }
    };

    if let Err(e) = lion_locker::core::ensure_state_dir(&cfg) {
        tracing::error!(target: "locker", "{e}");
        return 1;
    }
    let listener = match uisock::bind(&cfg.socket_path()) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "locker", "cannot bind the UI socket: {e}");
            return 1;
        }
    };

    let (bev_tx, mut bev_rx) = mpsc::unbounded_channel::<BackendEvent>();
    let (lev_tx, mut lev_rx) = mpsc::unbounded_channel::<LogindEvent>();
    let (sig_tx, sig_rx) = mpsc::unbounded_channel();

    let deps = if args.mock {
        mock_deps(&cfg, bev_tx.clone(), user)
    } else {
        match real_deps(&cfg, bev_tx.clone(), lev_tx, user).await {
            Ok(d) => d,
            Err(code) => return code,
        }
    };

    let (core, handle) = LockerCore::new(cfg.clone(), deps, sig_tx);
    spawn_bridges(&handle, &mut bev_rx, &mut lev_rx);
    spawn_signal_bridge(handle.ev_tx.clone());
    tokio::spawn(uisock::serve(
        listener,
        cfg.clone(),
        handle.ev_tx.clone(),
        handle.ui_pid.clone(),
    ));

    // The bus service runs in mock mode too (scripted compositor/PAM behind
    // the real interface): the D-Bus acceptance tests drive exactly this.
    #[cfg(feature = "real-bus")]
    let _bus_conn = match lion_locker::bus::serve(&cfg, &cfg.bus.name, &handle, sig_rx).await {
        Ok(c) => Some(c),
        Err(e) => {
            if args.mock {
                tracing::warn!(target: "bus", "mock mode without a session bus: {e}");
                None
            } else {
                tracing::error!(target: "bus", "cannot serve {}: {e}", cfg.bus.name);
                return 1;
            }
        }
    };
    #[cfg(not(feature = "real-bus"))]
    drop(sig_rx);

    if args.mock && std::env::var_os("LION_LOCKER_MOCK_AUTOLOCK").is_some() {
        // Demo: lock shortly after start so a client has something to unlock.
        let tx = handle.ev_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let _ = tx.send(Event::Lock {
                source: lion_locker::core::LockSource::Bus,
                reply: None,
            });
        });
    }

    core.run().await
}

fn spawn_bridges(
    handle: &Handle,
    bev_rx: &mut mpsc::UnboundedReceiver<BackendEvent>,
    lev_rx: &mut mpsc::UnboundedReceiver<LogindEvent>,
) {
    let tx = handle.ev_tx.clone();
    let mut b = std::mem::replace(bev_rx, mpsc::unbounded_channel().1);
    tokio::spawn(async move {
        while let Some(e) = b.recv().await {
            if tx.send(Event::Backend(e)).is_err() {
                break;
            }
        }
    });
    let tx = handle.ev_tx.clone();
    let mut l = std::mem::replace(lev_rx, mpsc::unbounded_channel().1);
    tokio::spawn(async move {
        while let Some(e) = l.recv().await {
            if tx.send(Event::Logind(e)).is_err() {
                break;
            }
        }
    });
}

/// SIGTERM → graceful stop (the compositor keeps the screen locked);
/// SIGHUP → reload the config without dropping the UI (spec 03 §9).
fn spawn_signal_bridge(ev_tx: mpsc::UnboundedSender<Event>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut hup = signal(SignalKind::hangup()).expect("SIGHUP handler");
        loop {
            tokio::select! {
                _ = term.recv() => {
                    let _ = ev_tx.send(Event::SigTerm);
                    return;
                }
                _ = hup.recv() => {
                    let path = std::env::var_os("LION_LOCKER_CONFIG")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
                    match Config::load(&path) {
                        Ok(c) => { let _ = ev_tx.send(Event::Reload(Box::new(c))); }
                        Err(e) => tracing::error!(target: "locker", "SIGHUP: reload rejected: {e}"),
                    }
                }
            }
        }
    });
}

fn mock_deps(cfg: &Config, bev_tx: mpsc::UnboundedSender<BackendEvent>, user: String) -> Deps {
    use lion_locker::mocks::*;
    use lion_locker::pam::mock::{MockPamFactory, MockScript};
    tracing::info!(target: "locker", "mock mode: scripted compositor, no bus; PAM password is \"lion\"");
    let _ = cfg;
    Deps {
        backend: MockBackend::new(bev_tx),
        logind: Arc::new(MockLogind::default()),
        notifier: Arc::new(MockNotifier::default()),
        privacy: Arc::new(MockPrivacy::default()),
        preflight: Arc::new(MockPreflight::default()),
        ui_launcher: Arc::new(MockUiLauncher::default()),
        pam: Arc::new(MockPamFactory::new(MockScript::success("lion"))),
        notify: Notify::from_env(),
        user,
    }
}

#[cfg_attr(
    not(all(feature = "real-pam", feature = "real-wayland", feature = "real-bus")),
    allow(unused_variables, unreachable_code)
)]
async fn real_deps(
    cfg: &Config,
    bev_tx: mpsc::UnboundedSender<BackendEvent>,
    lev_tx: mpsc::UnboundedSender<LogindEvent>,
    user: String,
) -> std::result::Result<Deps, i32> {
    // PAM first: a locker that cannot unlock must not run (fail closed).
    #[cfg(feature = "real-pam")]
    let pam: Arc<dyn PamServiceFactory> = match lion_locker::pam::real::RealPamFactory::new() {
        Ok(f) => Arc::new(f),
        Err(e) => {
            tracing::error!(target: "locker", "libpam unavailable ({e}); refusing to run");
            return Err(1);
        }
    };
    #[cfg(not(feature = "real-pam"))]
    let pam: Arc<dyn PamServiceFactory> = {
        tracing::error!(target: "locker", "built without real-pam; use --mock");
        return Err(1);
    };

    #[cfg(feature = "real-wayland")]
    let backend: Arc<dyn LockBackend> =
        match lion_locker::wayland::WaylandBackend::connect(cfg.cover_argb(), bev_tx) {
            Ok(b) => Arc::new(b),
            Err(e) => {
                tracing::error!(target: "locker", "{e}");
                return Err(1);
            }
        };
    #[cfg(not(feature = "real-wayland"))]
    let backend: Arc<dyn LockBackend> = {
        let _ = bev_tx;
        tracing::error!(target: "locker", "built without real-wayland; use --mock");
        return Err(1);
    };

    #[cfg(feature = "real-bus")]
    let (logind, notifier, privacy): (Arc<dyn Logind>, Arc<dyn Notifier>, Arc<dyn Privacy>) = {
        use backends::zbus_backends::*;
        let which = if cfg.bus.logind == "session" {
            LogindBus::Session
        } else {
            LogindBus::System
        };
        let logind: Arc<dyn Logind> = match ZbusLogind::connect(which).await {
            Ok(l) => {
                l.watch(lev_tx);
                Arc::new(l)
            }
            Err(e) => {
                tracing::warn!(target: "locker", "logind unreachable ({e}): no lock-before-sleep, no lid/lock signals, no quick actions");
                Arc::new(backends::NullLogind)
            }
        };
        let notifier: Arc<dyn Notifier> = match NotificationsNotifier::connect().await {
            Ok(n) => Arc::new(n),
            Err(_) => Arc::new(backends::LogNotifier),
        };
        let privacy: Arc<dyn Privacy> = match NotificationPrivacy::connect().await {
            Ok(p) => Arc::new(p),
            Err(_) => Arc::new(backends::NoopPrivacy),
        };
        (logind, notifier, privacy)
    };
    #[cfg(not(feature = "real-bus"))]
    let (logind, notifier, privacy): (Arc<dyn Logind>, Arc<dyn Notifier>, Arc<dyn Privacy>) = {
        let _ = lev_tx;
        (
            Arc::new(backends::NullLogind),
            Arc::new(backends::LogNotifier),
            Arc::new(backends::NoopPrivacy),
        )
    };

    Ok(Deps {
        backend,
        logind,
        notifier,
        privacy,
        preflight: Arc::new(FsPreflight),
        ui_launcher: Arc::new(backends::DirectLauncher {
            socket_path: cfg.socket_path(),
        }),
        pam,
        notify: Notify::from_env(),
        user,
    })
}
