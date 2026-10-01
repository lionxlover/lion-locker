# lion-locker

LionOS lock-screen *authentication* daemon. Runs as one of `lion-session`'s
autostart apps, in the user's own session.

## What it does
- Grabs input via `ext-session-lock-v1` the moment `Lock()` is called --
  the Wayland protocol itself guarantees no other surface is visible or
  receives input once the lock is confirmed, and `Lock()` only returns
  `true` after the compositor's `locked` **confirmation** (a failed lock
  request is surfaced, never silently assumed)
- Reads the keyboard directly (it's the only client input goes to while
  locked) and re-authenticates the typed password via PAM, forwarding
  live module chatter to the lock screen ("place your finger on the
  reader" from pam_fprintd, 2FA instructions, lockout notices)
- Tells `lion-lockscreen` when to show/hide and relays pointer motion,
  "a key was pressed", Caps Lock transitions, module messages, and
  verifying/retry/unlocking state -- but never the password itself,
  which never leaves this process (and never leaves RAM: the address
  space is `mlockall`ed)
- Accepts rendered frames back from `lion-lockscreen` (as shared-memory
  fds passed over D-Bus) and attaches them to the right output's lock
  surface, coalescing stale frames so a hot render loop cannot queue
  unbounded shared memory
- **Re-locks itself after a crash**: while locked, a durable episode
  marker exists in `$XDG_RUNTIME_DIR`; if the locker dies mid-episode,
  the next start (systemd `Restart=always`, `RestartSec=0`) sees the
  marker and re-acquires the lock immediately -- the Wayland locker's
  classic "crash = session exposed" window collapses to one restart
- Honors `loginctl lock-session` (the logind `Lock` signal) for
  ecosystem compatibility; logind's `Unlock` signal is deliberately
  *refused* -- nothing but a PAM-verified credential ends a lock episode
- Locks outputs that are hotplugged while already locked (a monitor
  plugged in during a lock never shows session content), and routes
  pointer events to the correct output on multi-monitor setups

## What it deliberately does not do
- Decide *when* to lock -- that's `lion-idle`; this only executes
  `Lock()` (its own, or logind's)
- Render anything -- every pixel on screen comes from
  `lion-lockscreen`, except the solid Obsidian Dark backdrop painted
  the instant a lock surface exists, before any real frame has arrived
- Expose any `Unlock()` method -- the asymmetry is the point

## Interfaces
- `os.lionos.Locker1` (public, session bus): `Lock() -> b` (true =
  compositor confirmed), `GetState() -> s` ("idle"|"locking"|"locked"),
  `GetMetrics() -> s`, `ResetMetrics()`, properties `Version`,
  `Capabilities`, `Locked`, signal `LockStateChanged(s)`
- `os.lionos.Locker.Render1` (private, called by `lion-lockscreen`):
  `Ready(outputs)`, `PresentFrame(output, fd, width, height, stride,
  format)`
- Calls out to `os.lionos.Lockscreen1` on `lion-lockscreen`: `Show`,
  `Hide`, `PointerMotion`, `PointerButton`, `KeyActivity`,
  `AuthState`, `DisplayMessage`, `CapsLock`

See `src/lockscreen.rs` for the full documented contract.

## Build & test

```
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The build is self-contained: PAM FFI is vendored (no `pam-client`, no
bindgen, no libclang; `build.rs` links `libpam.so` or falls back to
`libpam.so.0`), the same design as lion-greeter.

## CLI

```
lion-locker [--daemon]     Run the long-lived lock-screen service (default)
lion-locker --version      Print version info and exit
lion-locker --check-pam    Probe the PAM stack and exit
```

## Files
- `src/wayland.rs` -- the `ext-session-lock-v1` client, lock
  confirmation, output hotplug, multi-monitor pointer routing
- `src/keyboard.rs` -- xkbcommon keymap handling + Caps Lock detection
- `src/auth.rs` -- PAM re-auth (own OS thread, chatter forwarding)
- `src/pam_ffi.rs` -- vendored PAM FFI with pluggable conversation source
- `src/service.rs` -- the state machine, public D-Bus surface, metrics,
  frame coalescing, crash-relock
- `src/lockscreen.rs` -- the D-Bus contract with `lion-lockscreen`
- `src/state.rs` -- durable lock-episode marker (crash-relock primitive)
- `src/logind.rs` -- `loginctl lock-session` compatibility
- `src/mlock.rs` -- swap-out protection with graceful degradation
- `src/metrics.rs` -- atomic counters exposed via `GetMetrics()`
- `src/throttle.rs` -- escalating lockout after repeated failures
- `src/password.rs` -- zeroizing, length-capped password buffer
- `ENHANCEMENTS.md` -- change log for 0.1.0 -> 0.2.0
- `TEST_REPORT.md` -- verification matrix
