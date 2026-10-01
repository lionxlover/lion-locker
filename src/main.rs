//! lion-locker: owns lock-screen *authentication*, for LionOS.
//!
//! On `Lock()` it:
//!   1. grabs input via the `ext-session-lock-v1` Wayland protocol, so no
//!      surface but its own can be seen or receive input while locked --
//!      and waits for the compositor's `locked` *confirmation* before
//!      reporting success (a lock request that failed is surfaced, not
//!      silently assumed)
//!   2. tells `lion-lockscreen` to render (over D-Bus) -- the visuals are
//!      entirely that component's job; this daemon never draws a pixel
//!      beyond the pre-render safety backdrop
//!   3. reads the keyboard itself (it holds the only surfaces the
//!      compositor delivers input to) and re-authenticates the typed
//!      password via PAM, forwarding module chatter ("place your finger
//!      on the reader") to the lock screen live
//!   4. on success, releases the Wayland lock and tells `lion-lockscreen`
//!      to hide; the session underneath was never touched
//!
//! If the process dies while locked, the durable episode marker
//! (state.rs) plus `Restart=always`/`RestartSec=0` in the unit re-acquire
//! the lock at next start ("crash-relock"), collapsing the classic
//! Wayland "locker crash = exposed session" window to one restart.
//!
//! The password never leaves this process: lion-lockscreen is told about
//! UI-relevant *events* (pointer motion, "a key was pressed", verifying /
//! retry / unlocking, module chatter) but is never given the characters
//! typed. Memory is `mlockall`ed so the buffer cannot be swapped out.
//!
//! Out of scope, on purpose: deciding *when* to lock (`lion-idle`'s job --
//! this only executes `Lock()`, including logind's standard `Lock` signal
//! for `loginctl lock-session`) and rendering anything
//! (`lion-lockscreen`'s job).
//!
//! # CLI
//!
//! `--version`, `--check-pam`, and `--print-runtime` are sysadmin
//! inspection modes that run and exit (no compositor needed). The
//! default (no args / `--daemon`) runs the long-lived service.

mod auth;
mod keyboard;
mod lockscreen;
mod logind;
mod metrics;
mod mlock;
mod pam_ffi;
mod password;
mod service;
mod state;
mod throttle;
mod wayland;

use anyhow::{Context, Result};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("--daemon");

    // CLI inspection modes run without tracing setup noise.
    match mode {
        "--version" => {
            println!(
                "lion-locker {} (LionOS lock-screen auth daemon)\n\
                 Edition 2021, MSRV rustc {}\n\
                 PAM service: lion-locker\n\
                 Wayland protocol: ext-session-lock-v1",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_RUST_VERSION"),
            );
            return ExitCode::SUCCESS;
        }
        "--check-pam" => return run_check_pam(),
        other if other != "--daemon" && other != "--serve" && !other.is_empty() => {
            eprintln!("lion-locker: unknown mode `{other}`");
            eprintln!(
                "Usage:\n  \
                 lion-locker [--daemon]     Run the long-lived lock-screen service (default)\n  \
                 lion-locker --version      Print version info and exit\n  \
                 lion-locker --check-pam    Probe the PAM stack and exit"
            );
            return ExitCode::from(1);
        }
        _ => {}
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lion_locker=info".into()),
        )
        .init();

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "lion-locker starting");
    metrics::init_started_unix();

    // Swap-out protection for the password buffer before any episode can
    // start. Never fatal (degradation ladder in mlock.rs); the outcome
    // feeds the Capabilities property.
    match mlock::apply() {
        mlock::MlockOutcome::Locked => {}
        mlock::MlockOutcome::SkippedSmallLimit { hard_limit } => {
            tracing::warn!(hard_limit, "memory lock skipped (RLIMIT_MEMLOCK too small)");
        }
        mlock::MlockOutcome::Failed { errno } => {
            tracing::warn!(errno, "memory lock failed; running without it");
        }
    }

    // Wayland's event loop is blocking/synchronous by design and owns its
    // own OS thread (see wayland.rs); everything else -- D-Bus, PAM,
    // throttling -- runs on the async runtime and talks to it over channels.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("lion-locker: could not build runtime: {e}");
            return ExitCode::from(1);
        }
    };

    match rt.block_on(async_main()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lion-locker: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn async_main() -> Result<()> {
    let (wl, wl_events) = wayland::spawn().context("starting Wayland session-lock client")?;
    service::serve(wl, wl_events).await
}

/// Probe the PAM stack (`lion-locker` service) so a sysadmin can verify
/// post-install that the re-auth path is loadable. `pam_start` +
/// immediate `pam_end` with a sentinel user; no authentication attempt.
fn run_check_pam() -> ExitCode {
    let probe = "lion-locker-probe";
    let empty = zeroize::Zeroizing::new(String::new());
    let source = Box::new(pam_ffi::PasswordSource::new(empty, Box::new(|_| {})));
    match pam_ffi::PamContext::start_with_source(auth::pam_service(), probe, source) {
        Ok(_ctx) => {
            println!("PAM service `{}` loads cleanly", auth::pam_service());
            ExitCode::SUCCESS
        }
        Err(code) => {
            eprintln!(
                "PAM service `{}` failed to start (code {code}).\n\
                 Check /etc/pam.d/lion-locker and the modules it includes.",
                auth::pam_service()
            );
            ExitCode::from(1)
        }
    }
}
