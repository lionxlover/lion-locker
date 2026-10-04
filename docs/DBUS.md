# `os.lionos.Locker1` (spec 03 §4)

Session bus. Object path `/os/lionos/Locker1`. Machine-readable definition:
`packaging/data/os.lionos.Locker1.xml`.

## Methods

| Method | Who | Effect |
|---|---|---|
| `Lock()` | session owner | Lock the screen. Returns when the compositor confirmed the lock (`locked` event) or the attempt failed. Idempotent; concurrent calls coalesce into one compositor request. |
| `Unlock()` | session owner **and** a live PAM grant | Only meaningful with `locker.explicit_unlock = true`: after a successful *local* PAM authentication the daemon holds a single-use grant for `unlock_grant_ttl_ms`. Without a grant: `AccessDenied` ("not authenticated"), whoever calls. |

Errors: `AccessDenied` (not the owner / no grant), `LimitsExceeded`
(rate limit, default 30 calls / 10 s per bus unique name; **or** the
lock-waiter queue is full — 128 `Lock()` calls already awaiting a
compositor confirmation, which only happens while the compositor is
stalled: retry later, do not treat as a policy denial), `Timeout` (core
did not answer within 5 s), `Failed` (lock refused, preflight failed, ...).

## Properties

`IsLocked` (b) — true from "compositor confirmed" until unlock completes.
`State` (s, extension) — `unlocked | locking | locked | unlocking`.
`Failures` (u, extension) — consecutive failed attempts.

`PropertiesChanged` is emitted whenever the snapshot changes, and always
**before** the matching signal, so a client that wakes on `Locked` can read
`IsLocked == true` immediately.

## Signals

`Locked()`, `Unlocked()`, `AuthFailed(count: u)`.

## Caller identity

Taken from the bus daemon (`GetConnectionUnixUser`/`ProcessID`), never from
message fields. The pid is pinned with a pidfd; cgroup and pid are logged
for audit. Authorization is owner-only: root is *not* special.

## Deviation from spec

Spec 03 §8 says "authorize via lion-auth". `lion-auth` (spec 22) does not
exist yet. See `DESIGN.md` §6 for why the local owner-only policy is the
safe interim choice.
