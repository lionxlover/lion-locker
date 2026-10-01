# lion-locker TEST REPORT — 0.2.0

## Static gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | ✅ clean |
| `cargo test` | ✅ 28/28 (0.1.0 shipped with zero tests and did not compile) |
| `cargo clippy --all-targets -- -D warnings` | ✅ clean |
| `cargo build --release` | ✅ (LTO, 1 CGU, strip, panic=abort) |
| CLI smoke: `--version`, `--check-pam` | ✅ (PAM service loads cleanly, exit 0) |

## Unit coverage by module

| Module | Tests | What they pin down |
|---|---|---|
| `pam_ffi` | 6 | prompt-style semantics; password source answers Secret only; chatter forwarded with style; interior-NUL rejection; `PAM_CONV_ERR=19`; `dup_answer` round trip |
| `auth` | 2 | PAM error-code mapping (7 classes); stable service name |
| `password` | 4 | push/backspace/take round trip; 1024-byte cap; multi-byte chars never split; take leaves empty buffer |
| `throttle` | 1 | escalation curve + reset |
| `state` | 4 | marker round trip; unlock-without-marker no-op; no-RUNTIME_DIR degradation; idempotent rewrite leaves no .tmp |
| `metrics` | 2 | stable JSON schema (10 keys); increment + reset |
| `mlock` | 3 | outcome ladder never panics + idempotence; MCL flags cover future pages; outcome traits |
| `service` | 4 | frame coalescing (newest-per-output, last-occurrence order, interleaved case); stable state strings |
| `logind` | 2 | session path escaping (plain + dash-escaped); path always under login1/session |

## Live verification notes (environment-honest)

- The sandbox has **no Wayland compositor**, so the
  `ext-session-lock-v1` episode path is validated structurally
  (compiles, types check, confirmation plumbing unit-reasoned) rather
  than against a live compositor. `--check-pam` *is* live-verified
  against real libpam (loads the `other`-fallback stack cleanly).
- The system's `libxkbcommon` has no dev package; the build links
  against the runtime `libxkbcommon.so.0` via a local pkg-config shim
  — on a real LionOS image with `xkbcommon-dev` the build needs no
  shim. `libpam` needs nothing special (`build.rs` falls back to
  `-l:libpam.so.0`).
- PAM conversation behavior (chatter forwarding) is unit-verified at
  the `ConvSource` level; end-to-end unlock requires a session and a
  real password, i.e. a LionOS image.

## Regression hazards closed by this release

1. 0.1.0 did not compile (five distinct errors) — now builds clean
   through `-D warnings`.
2. 0.1.0's `Lock()` could silently fail — now returns confirmation.
3. Locker crash previously = exposed session — now crash-relock.
4. Multi-monitor: 0.1.0 dropped all pointer events — now routed.
5. Hotplug-while-locked: 0.1.0 showed session content on the new
   output — now locked instantly.
6. Frame channel: unbounded fd queue — now coalesced.
7. Env-var tests raced in parallel — now serialized via a test mutex.
