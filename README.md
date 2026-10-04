# lion-locker

LionOS secure screen lock (spec 03): `ext-session-lock-v1` + PAM +
`os.lionos.Locker1`. **Read DESIGN.md §2 first** — the lock-screen
rendering/input hand-off to `lion-lockscreen` is not done yet.

```sh
cargo test --locked                       # unit + core + wayland-mock + dbus e2e
cargo bench --bench lion_bench            # JSON metrics; gate: packaging/ci/check_bench.py
lion-locker --check-config -c conf/lion-locker.json
lion-locker --mock &                      # demo: scripted compositor, password "lion"
LION_LOCKER_MOCK_AUTOLOCK=1 lion-locker --mock &   # locks itself 200 ms after start
cargo run --example locker_client -- "$XDG_RUNTIME_DIR/lion-locker/ui.sock" lion
```

| Doc | |
|---|---|
| DESIGN.md | architecture, invariants, known gaps |
| MIGRATION.md | toolchain pin, cross-component contracts, deviations |
| docs/DBUS.md | `os.lionos.Locker1` |
| docs/PROTOCOL.md | lock-UI socket protocol v1 |

Features: `real-bus`, `real-pam`, `real-wayland` (all default).
License: MIT OR Apache-2.0.
