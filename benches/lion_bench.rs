//! lion-bench hooks (spec 03 §7): lock latency against the scripted
//! compositor, UI-protocol decode throughput, throttle bookkeeping, and
//! idle RSS. Emits JSON (one object per line) so `lion-bench` can consume
//! it and CI can fail on >10% regression.
//!
//! Run: `cargo bench` (harness = false; plain timings, no criterion).
//! The spec target ("lock engaged < 100 ms from request") applies to the
//! real compositor round trip; here the scripted compositor confirms in
//! ~1 ms, so `lock_core_overhead_us` measures *our* share of that budget.

use lion_locker::config::{Config, ThrottleConfig};
use lion_locker::core::{Deps, Event, LockSource, LockerCore};
use lion_locker::mocks::*;
use lion_locker::notify::Notify;
use lion_locker::pam::mock::{MockPamFactory, MockScript};
use lion_locker::proto;
use lion_locker::throttle::{AuthThrottle, RateLimiter};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

fn emit(name: &str, value: f64, unit: &str) {
    println!(
        "{{\"component\":\"lion-locker\",\"metric\":\"{name}\",\"value\":{value:.3},\"unit\":\"{unit}\"}}"
    );
}

fn rss_kib() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0)
}

fn percentile(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

async fn lock_latency() {
    let tmp = tempfile::tempdir().unwrap();
    // Production-realistic private state dir (sandbox umask 002 otherwise
    // leaves the tempdir 0775 and the core logs a validation error).
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let cfg = Config::parse(&format!(
        r#"{{"locker":{{"state_dir":"{}","preflight":false,"owner_uid":1000,"lock_on_suspend":false,"ui":{{"exec":[]}}}}}}"#,
        tmp.path().display()
    ))
    .unwrap();
    let (bev_tx, mut bev_rx) = mpsc::unbounded_channel();
    let backend = MockBackend::new(bev_tx);
    *backend.confirm_after.lock().unwrap() = Some(Duration::ZERO);
    let deps = Deps {
        backend: backend.clone(),
        logind: Arc::new(MockLogind::default()),
        notifier: Arc::new(MockNotifier::default()),
        privacy: Arc::new(MockPrivacy::default()),
        preflight: Arc::new(MockPreflight::default()),
        ui_launcher: Arc::new(MockUiLauncher::default()),
        pam: Arc::new(MockPamFactory::new(MockScript::success("x"))),
        notify: Notify::disabled(),
        user: "bench".into(),
    };
    let (sig_tx, _sig_rx) = mpsc::unbounded_channel();
    let (core, h) = LockerCore::new(cfg, deps, sig_tx);
    let fwd = h.ev_tx.clone();
    tokio::spawn(async move {
        while let Some(e) = bev_rx.recv().await {
            let _ = fwd.send(Event::Backend(e));
        }
    });
    tokio::spawn(core.run());

    // Wait for the compositor-confirm → "locked" transition without
    // going through the bus: request and measure to the Lock reply.
    let mut samples = Vec::new();
    for _ in 0..200 {
        let (tx, rx) = oneshot::channel();
        let t0 = Instant::now();
        h.ev_tx
            .send(Event::Lock {
                source: LockSource::Bus,
                reply: Some(tx),
            })
            .unwrap();
        rx.await.unwrap().unwrap();
        samples.push(t0.elapsed().as_secs_f64() * 1e6);
        // Unlock directly through the backend path is not exposed; reuse
        // the explicit core cycle: restart state via a fresh run is too
        // heavy, so only the first sample is a true cold lock — the rest
        // measure the already-locked idempotent fast path. Keep both.
        if samples.len() == 1 {
            emit("lock_cold_us", samples[0], "us");
        }
    }
    emit(
        "lock_warm_p50_us",
        percentile(&mut samples[1..].to_vec(), 0.5),
        "us",
    );
    emit(
        "lock_warm_p99_us",
        percentile(&mut samples[1..].to_vec(), 0.99),
        "us",
    );
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    // 1. decode throughput
    let lines = [
        r#"{"proto":1,"id":1,"op":"Hello"}"#,
        r#"{"proto":1,"id":2,"op":"Begin"}"#,
        r#"{"proto":1,"id":3,"op":"Answer","text":"correct horse battery staple"}"#,
        r#"{"proto":1,"id":4,"op":"Action","action":"shutdown"}"#,
    ];
    let n = 200_000;
    let t0 = Instant::now();
    let mut ok = 0u64;
    for i in 0..n {
        if proto::decode_request(lines[i % lines.len()]).is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, n as u64);
    emit(
        "decode_per_sec",
        n as f64 / t0.elapsed().as_secs_f64(),
        "ops/s",
    );

    // 2. event serialisation
    let t0 = Instant::now();
    let mut bytes = 0usize;
    for i in 0..100_000u64 {
        bytes += proto::Event::AuthResult {
            ok: false,
            reason: "incorrect password".into(),
            failures: (i % 9) as u32,
        }
        .to_wire(i)
        .len();
    }
    assert!(bytes > 0);
    emit(
        "encode_per_sec",
        100_000.0 / t0.elapsed().as_secs_f64(),
        "ops/s",
    );

    // 3. throttle + rate limiter bookkeeping
    let cfg = ThrottleConfig::default();
    let t0 = Instant::now();
    let mut acc = Duration::ZERO;
    for n in 0..1_000_000u32 {
        acc += AuthThrottle::delay_for(&cfg, n % 64);
    }
    assert!(acc > Duration::ZERO);
    emit(
        "throttle_delay_per_sec",
        1e6 / t0.elapsed().as_secs_f64(),
        "ops/s",
    );

    let mut rl = RateLimiter::new(Duration::from_secs(10), 1_000_000);
    let now = Instant::now();
    let t0 = Instant::now();
    for i in 0..200_000 {
        rl.allow(&format!("c{}", i % 100), now);
    }
    emit(
        "ratelimit_per_sec",
        200_000.0 / t0.elapsed().as_secs_f64(),
        "ops/s",
    );

    // 4. lock latency through the real core
    rt.block_on(lock_latency());

    // 5. idle RSS (spec 03 §7: < 10 MB idle, no wakeups)
    std::thread::sleep(Duration::from_millis(200));
    emit("rss_kib", rss_kib(), "KiB");
}
