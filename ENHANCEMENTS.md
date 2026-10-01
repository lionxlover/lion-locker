# lion-locker ENHANCEMENTS — 0.1.0 → 0.2.0

## Baseline findings (why 0.2.0 exists)

The 0.1.0 source arrived with **five latent compile errors** — it had
never built as shipped: two wrong `Dispatch` signatures
(`wl_compositor`, `ExtSessionLockManagerV1` took `()` instead of their
`Event` enums), a `WlRegistry` dispatch implementation that did not
satisfy the trait bound `registry_queue_init` requires
(`GlobalListContents` user-data), a broken
`xkb_state_keymap` fd type (RawFd vs OwnedFd double-wrap), and an
unsatisfiable lifetime in the `LockscreenClient::call` closure. Fixing
those was the entry fee; everything below is the value on top.

## 1. PAM conversation with module-chatter forwarding (the headline)

`pam-client`'s mock conversation is gone, replaced by the vendored
`pam_ffi.rs` (same battle-tested design as lion-greeter 0.5.0): a
pluggable `ConvSource` answers password prompts while forwarding
`PAM_TEXT_INFO` / `PAM_ERROR_MSG` text to the lock screen *as it
happens* (`DisplayMessage` on the Lockscreen1 contract). Stacks that
include `pam_fprintd` now get their "place your finger on the reader"
UX with zero locker-side per-module code; identity prompts
(`PAM_PROMPT_ECHO_ON`) are refused outright — a lock screen must never
answer "which user". The conversation callback stays panic-contained
(`catch_unwind` → `PAM_CONV_ERR`) and rejects unknown message styles.

## 2. Crash-relock (the Wayland locker's missing safety net)

`ext-session-lock-v1` grants the lock to *this process*, so a locker
crash historically exposes the session until a human notices. 0.2.0
adds the durable episode marker (`state.rs`): while locked, a file
exists in `$XDG_RUNTIME_DIR/lion-locker/locked` (tmpfs; atomic
tmp+rename writes). At startup, a present marker means the previous
instance died mid-episode → re-acquire the lock immediately
(`crash_relocks` metric counts it). The unit file pairs this with
`Restart=always` + `RestartSec=0`. No XDG_RUNTIME_DIR → feature
degrades off, never fatal.

## 3. Lock() now means *locked*

0.1.0's `Lock()` fired the request and returned `()` — callers could
not tell "locked" from "lock silently failed". 0.2.0 waits for the
compositor's `locked` confirmation (deferred reply through the Wayland
thread; 3 s timeout, on which the half-started lock is torn down) and
returns `bool`. `GetState()` / `Locked` property / `LockStateChanged`
signal give the desktop live state.

## 4. logind compatibility

`loginctl lock-session` now works: we subscribe to our session's
logind `Lock` signal and start an episode. logind's `Unlock` signal is
deliberately **refused and logged** — an administrative unlock must
never bypass PAM on a lock screen. Absent logind / no
`XDG_SESSION_ID` → integration off, never fatal. (Session path
escaping matches logind's own, unit-tested.)

## 5. mlockall for the password buffer

Same degradation-ladder design as the greeter (8 MiB headroom guard,
`Locked` / `SkippedSmallLimit` / `Failed`, never fatal). The locker
arguably needs it *more* than a greeter: the buffer is typed into a
machine that is most likely to be under memory pressure (idle, swap
active). The `mlock` capability string reports the real outcome.

## 6. Wayland correctness

- **Output hotplug while locked**: a monitor plugged in mid-episode
  gets a lock surface *immediately* — it never shows session content,
  not even for one frame.
- **Multi-monitor pointer routing**: Enter/Leave surface→output
  tracking replaces the single-output-only fallback (0.1.0 dropped all
  pointer events on multi-monitor setups).
- **Caps Lock detection** via the keymap's LED state, forwarded as
  transitions only (users stop losing passwords to it).

## 7. Memory-safety hardening

- Password buffer is length-capped (1024 bytes): a stuck key repeat or
  hostile auto-replayer cannot grow it without bound in mlocked RAM.
- Frame coalescing: `PresentFrame` spam keeps only the newest frame
  per output — each queued Frame owns an fd, so an unbounded channel
  was an unbounded shared-memory liability. Pure function, unit-tested
  for ordering semantics.
- `LazyLock` for the metrics clock (0.1.0-era `Instant::now()` in a
  static would not compile).

## 8. Observability

`GetMetrics()` JSON: episodes, auth_attempts, auth_successes,
auth_failures, throttled_millis, chatter_events, frames_presented,
crash_relocks, uptime_seconds, started_unix — the same schema family
as lion-greeter, extended with locker-specific events. Plus
`Capabilities` (`session-lock-v1`, `pam`, `chatter`, `crash-relock`,
`logind`, `metrics`, `capslock-indicator`, conditionally `mlock`).

## 9. Deployment

- `systemd/lion-locker.service`: `Restart=always` + `RestartSec=0`
  (the crash-relock contract) plus a session-grade sandbox
  (NoNewPrivileges, MemoryDenyWriteExecute, syscall architecture
  pinning, AF_UNIX/AF_NETLINK only, LimitMEMLOCK=infinity).
- CLI: `--version`, `--check-pam` (runs without a compositor, for
  install scripts and CI smoke).

## What did NOT change

The 0.1.0 security spine: password never leaves the process
(lockscreen sees *that* a key was pressed, never *which*), the
render/auth process split (a lockscreen crash can never compromise the
lock), zeroizing password buffer, per-episode throttle escalation,
Obsidian-Dark pre-render backdrop so there is no undefined frame, and
the deliberate absence of any `Unlock()` method.
