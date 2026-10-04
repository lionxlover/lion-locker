# lion-locker — integration notes and deviations

## Toolchain

The sandbox Rust is 1.82; crates released since require newer Cargo
(edition2024) or rustc. `Cargo.lock` is committed **pinned for 1.82**
(zbus 5.5 stack, proptest 1.9, zeroize 1.8, indexmap 2.11, …) and the build
uses `--locked`. Everything compiles and all tests pass on 1.82; on a
current toolchain `cargo update` is expected to work, but that was not
re-verified. `rust-version = "1.80"` is declared, not tested below 1.82.

**Re-verified on a newer sandbox (rustc 1.99, 2026-10):** `cargo test`
(default features *and* `--no-default-features`), `cargo clippy
--all-targets -- -D warnings`, `cargo fmt --check` and `cargo deny
--all-features check` (advisories / bans / licenses / sources) all pass
with the pinned lock. Three pre-existing clippy warnings surfaced by the
newer clippy were fixed (no logic changes). `deny.toml` dropped its
redundant compound `"MIT OR Apache-2.0"` entry: cargo-deny ≥ 0.18 rejects
it while `MIT` and `Apache-2.0` were already allowed individually. The
RustSec advisory check was run locally with cargo-deny 0.20.2 (0.18.x
cannot parse CVSS:4.0 advisories in today's DB).

## Contracts other components must honour

- **lion-lockscreen** — protocol in docs/PROTOCOL.md. It is spawned and
  admitted by pid; see DESIGN.md §2 G1 for the open rendering/input
  hand-off question.
- **lion-session** — its `Lock()` should call `os.lionos.Locker1.Lock()`
  (or logind `LockSession`, which this daemon honours via the session
  `Lock` signal). Its `Suspend` should rely on this daemon's sleep
  inhibitor rather than locking itself.
- **lion-notifications** — optional `os.lionos.Notifications1.SetLockState
  (locked: b, hide_content: b)`; best effort, absence is fine. The UI gets
  the same flag in `Show`.
- **lion-compositor** — must implement `ext_session_lock_manager_v1`; the
  daemon exits non-zero at startup without it.
- **PAM** — ship `/etc/pam.d/lion-locker` (packaging/pam/). The unit must
  not set `NoNewPrivileges` (pam_unix uses the setuid `unix_chkpwd`).

## Deviations from the spec

1. No `lion-auth` (see DESIGN.md §6).
2. Config is read from a JSON keyfile like the sibling components; the
   `lion-config` live-reload path is SIGHUP.
3. Extensions beyond spec keys/members are namespaced and documented:
   properties `State`, `Failures`; config keys listed in the schema.

## Behaviour changes in the hardening pass (2026-10)

- **State-dir fallback:** with `XDG_RUNTIME_DIR` unset the runtime dir is
  now `/run/user/<uid>/lion-locker` (logind-managed, 0700) instead of
  `/tmp/lion-locker-<uid>`. Deployments that ran without logind and
  without an explicit `locker.state_dir` must set `state_dir` explicitly
  — the daemon now *fails closed* (exits non-zero at bind time) rather
  than exposing the UI socket in a world-writable parent. See
  DESIGN.md §11.
- **`LimitsExceeded`** is now also returned when 128 `Lock()` calls are
  already waiting on a compositor that has not confirmed the lock
  (previously they queued unbounded; the reply was still just delayed).
  Retry-with-backoff is the correct client response, as with rate
  limiting.

## Noticed in lion-session (not changed here)

`packaging/dbus/os.lion.Session1.service` declares `Name=os.lionos.Session1`;
D-Bus activation files must be named after the bus name
(`os.lionos.Session1.service`), so activation will not find it as shipped.
