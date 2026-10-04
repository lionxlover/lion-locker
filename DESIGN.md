# lion-locker — design (spec 03)

## 1. What it is

A per-user daemon that locks the screen with `ext-session-lock-v1`,
re-authenticates the session owner with PAM, supervises the
`lion-lockscreen` UI over a private socket, locks before suspend through a
logind delay inhibitor, and serves `os.lionos.Locker1`.

```
 D-Bus (Lock/Unlock)  logind (Lock, sleep, lid)   lion-lockscreen (socket)
          │                    │                          │
          └──────────┬─────────┴──────────────────────────┘
                     ▼
              ┌────────────┐   ports (traits)   ┌────────────────────┐
              │ LockerCore │ ─────────────────▶ │ wayland / logind / │
              │ one task,  │                    │ notify / launcher  │
              │ one channel│ ◀───────────────── │ (real or mock)     │
              └─────┬──────┘   BackendEvent     └────────────────────┘
                    │ Txn (thread per PAM transaction)
                    ▼
                 libpam (dlopen)
```

Same architecture as lion-session: one core task owns all state; every
input (bus, compositor, logind, UI socket, PAM worker, timers) is an
`Event` on one channel. Deterministic ordering, no locks, and true
idleness: no timers or wakeups unless there is work.

## 2. Known gaps — read before relying on this in a real session

**G1. The lock screen cannot be *used* yet.** With `ext-session-lock-v1`
only the lock client's own surfaces are visible, and only they receive
input. A separate `lion-lockscreen` process therefore cannot show anything
or receive keystrokes on its own. This crate implements the protocol side
completely (cover on every output incl. hot-plug, lock/unlock/finished
handling, PAM, throttling, supervision), but the cover is a solid colour
and **no `wl_seat`/keyboard is bound**. Closing this needs one of:
(a) a frame hand-off (shm/dmabuf from the UI attached to the lock
surfaces) plus input forwarding (keymap + key events) over the socket, or
(b) making `lion-lockscreen` the lock client itself and keeping this
daemon as the policy/PAM/D-Bus half. This is a cross-component decision
for the lock-screen spec; the UI protocol (docs/PROTOCOL.md) is designed
so (a) only *adds* messages.

Consequence today: on a real compositor the screen locks and stays locked,
and the PAM/throttle/unlock machinery is exercised end to end in tests, but
a person cannot type a password. `locker.preflight` verifies the PAM
service and UI binary exist; it cannot verify an input path. Do not enable
this on a machine you cannot reach by SSH/TTY until G1 is closed.

**G2. No nspawn end-to-end job** (needs `lion-lockscreen` + compositor).
**G3. Real PAM is only smoke-tested** (`real_pam_linkage_smoke`); the
conversation logic is tested against `MockPamFactory` and a fake
`pam_conv` bridge, not against a PAM stack with real modules.
**G4. No real-compositor test.** The Wayland backend is tested against an
in-process `wayland-server` mock that enforces the "locked only after
every output has a committed lock surface" rule, not against Smithay.

## 3. Safety invariants (spec 03 §6)

1. **Never fall back to unlocked.** `Unlocked` is reachable only through
   `do_unlock`, called from exactly three places: a successful PAM
   verdict, a consumed PAM-verified grant (`explicit_unlock`), and the
   opt-in grace window. UI crash/garbage, compositor `finished`, SIGTERM,
   logind `Unlock`, a failed backend unlock: all stay locked.
2. **Refuse to lock into an un-unlockable state** (preflight: PAM service
   file present, UI binary executable) — except when restoring a lock
   (`Startup`/`Relock`), where the compositor may already be locked.
3. **Crash safety.** A marker in the 0700 runtime dir is written *before*
   the lock request and removed only after the compositor processed
   `unlock_and_destroy`. A restarted daemon re-locks before `READY=1`.
   `Restart=always`, `StartLimitIntervalSec=0`.
4. **PAM for the owner only.** The user name comes from the owner uid
   (`getpwuid_r`); no caller supplies one. No `setcred`, no session.
5. **Hung PAM:** every conversation step has a hard timeout; a module that
   never returns parks one thread (documented trade-off).
6. **Suspend:** a delay inhibitor is held while idle; on
   `PrepareForSleep(true)` the lock is requested and the inhibitor is
   released as soon as the compositor confirms — or after
   `sleep_lock_timeout_ms` (<4.5 s) so a stalled compositor cannot block
   suspend forever.

## 4. State machine

`Unlocked → Locking → Locked → Unlocking → Unlocked`.
`Locking` aborts to `Unlocked` on compositor refusal (`finished` before
`locked`) or a failed request — except restore paths, which retry with
backoff because "unlocked" would disagree with a possibly-locked
compositor. `finished` while `Locked` triggers a re-lock, never an unlock.
A failed `unlock_and_destroy` returns to `Locked`.

## 5. Authentication and throttling

Wrong credentials count (`AuthErr`, expired, locked, authtok); service
failures, timeouts and cancellations do not. Delay after the n-th failure:
`0` while `n ≤ free_attempts`, then `base · 2^(n-free-1)` capped. Enforced
in the daemon (`Begin` → `throttled`), so a hostile UI cannot skip it;
`pam_faillock` stays authoritative. A UI that dies mid-conversation aborts
the transaction without penalty. Answers are `Zeroizing` end to end
(codec → `Secret` → PAM) and never reach logs, errors or `Debug`.

## 6. Authorization (deviation from spec §8)

Spec: "authorize via lion-auth". `lion-auth` does not exist yet. The only
privileged decision is *unlock*, already gated by something stronger than a
policy daemon (a fresh PAM verification by this process, single-use, short
TTL). `Lock` is harmless to the owner and must work when everything else is
down, so it is owner-only + rate-limited rather than routed through a
service that could be unavailable. Root is not special. When `lion-auth`
lands, `Policy::allows` is the single seam to replace.

## 7. UI process and socket

Spawned with a cleared environment (allow-list only), `kill_on_drop`,
exponential respawn backoff reset after a >10 s run. The socket admits only
the supervised child's pid (SO_PEERCRED) and the owner uid; an external UI
can instead be pinned by cgroup suffix. Peer pid is pinned with a pidfd for
the connection's lifetime. Frames ≤ 8 KiB; a new connection replaces the
old one (and aborts any open PAM transaction).

## 8. Performance (spec 03 §7)

Lock engage budget (<100 ms) is dominated by the compositor round trip;
our share measured against the scripted compositor: cold lock ≈ 1.2 ms
(incl. thread/channel startup), idempotent path ≈ 2 µs. Idle RSS ≈ 7 MB of
bench process (limit 10 MB). The Wayland thread blocks in `poll(2)` on the
connection and an eventfd: zero wakeups when idle. The cover buffer is one
shm buffer per output size, written through a memfd (no `mmap`, no
`unsafe`).

## 9. Testing

- unit tests in every module (proto, codec, config, throttle, authz,
  uisock admission, PAM mock/bridge);
- `tests/core_flow.rs` — 37 scenarios against fakes incl. the **100-kill
  chaos test** (UI killed 100 times while hostile traffic hits Begin /
  Unlock: never unlocks, exactly one UI alive at the end);
- `tests/wayland_mock.rs` — real backend vs in-process compositor
  (multi-output, hot-plug, unplug/replug, finished, missing protocol,
  compositor death);
- `tests/dbus_e2e.rs` — real binary (`--mock`) on a private `dbus-daemon`:
  every method/property/signal, non-owner denied, grant rules, rate limit,
  crash → restart → re-lock;
- `tests/props.rs` (proptest) and `tests/fuzz_smoke.rs`; cargo-fuzz targets
  `decode_request`, `parse_config`;
- `tests/hardening.rs` — security regression suite for the §11 hardening
  pass (dir ownership/privacy, marker `O_NOFOLLOW`, bounded waiter queue).

## 10. Unsafe

`#![forbid(unsafe_code)]` everywhere except two audited modules:
`sysffi` (getuid, pidfd_open, kill, getpwuid_r) and `pam::sys` (dlopen'd
libpam). Same convention as lion-greeter/lion-session.

## 11. Security hardening pass (post-review)

A focused audit of same-uid attack surface hardened four fail-closed
guarantees; regression tests live in `tests/hardening.rs`:

1. **State-dir fallback is `/run/user/<uid>/lion-locker`, never `/tmp`.**
   A world-writable parent would let an attacker pre-create the directory,
   swap `ui.sock` for their own socket and harvest the password typed
   into the lock screen (socket-squatting). With `XDG_RUNTIME_DIR` unset
   we now resolve to the logind-managed per-user dir (0700). The
   resolution is a pure function (`config::state_dir_from`) so the
   branch is unit-tested deterministically.
2. **The socket directory is validated before `uisock::bind` returns.**
   `DirBuilder::create(recursive)` succeeds silently on an *existing*
   directory without tightening its mode, so both `ensure_state_dir`
   and `uisock::bind` now refuse (fail closed) any directory that is
   not owned by the daemon's uid or is group/other-accessible. The
   daemon exits non-zero rather than binding into a squatted dir.
3. **The lock marker is written with `O_NOFOLLOW`.** A same-uid attacker
   could symlink `locked` at an arbitrary file; `open(O_TRUNC)` would
   clobber it (mode 0600 applies at creation only). The symlink is now
   rejected (`ELOOP`); the lock still engages — refusing to lock over a
   marker failure would be the worse trade-off (DESIGN.md §3.3).
4. **The lock-waiter queue is bounded (`MAX_WAITERS = 128`).** The bus
   rate limiter bounds the *rate* of `Lock()` calls, not the *total*
   number of coalesced waiters; a compositor that never confirms would
   otherwise accumulate oneshots without limit. Excess callers get
   `Error::Busy`, surfaced on the bus as `LimitsExceeded` (distinct
   from `AccessDenied`, so clients can retry) — see docs/DBUS.md.

Toolchain drift note: the clippy fixes in this pass (collapsible match in
`wayland.rs`, `field_reassign_with_default` in `uisock.rs` tests) are
pre-existing patterns surfaced by the current clippy (1.99), not logic
changes. Benchmark parity was verified by running `lion_bench` against the
pre-hardening tree in the *same* 2-core container: warm/cold lock and RSS
are within noise, so the hardening costs nothing measurable (absolute
latencies in this container are ~7x the checked-in baseline recorded on
the reference machine; CI compares on consistent runners).
