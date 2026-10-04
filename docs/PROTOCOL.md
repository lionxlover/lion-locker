# Lock-UI socket protocol, version 1

Socket: `$XDG_RUNTIME_DIR/lion-locker/ui.sock` (dir 0700, socket 0600), also
exported to the supervised UI as `LION_LOCKER_SOCKET`. JSON-lines, UTF-8,
one object per line, max 8 KiB per line (longer → connection dropped).

Admission (kernel-mediated, `SO_PEERCRED`):
- peer uid must equal the session owner;
- when the locker spawns the UI itself, the peer pid must equal the
  supervised child's pid (nobody is admitted while no UI runs);
- when `locker.ui.exec` is empty (externally managed UI) and
  `expected_cgroup_suffix` is set, the peer cgroup must end with it.

A new admitted connection replaces the old one.

## Requests (UI → daemon)

Every request: `{"proto":1,"id":<u64>,"op":"…"}`; unknown fields rejected.

| op | fields | notes |
|---|---|---|
| `Hello` | – | → `{version, locked, user}` |
| `Begin` | – | start a PAM transaction for the session owner. `throttled` while locked out. |
| `Answer` | `text` (≤1024 B, no NUL) | answer to the current `Prompt`. Zeroized after the PAM call. |
| `Cancel` | – | abort the transaction |
| `GraceUnlock` | – | only inside `grace_period_ms` after the lock |
| `Action` | `action`: `shutdown` \| `switch_user` | only if enabled in config |

Responses: `{"proto":1,"id":N,"ok":true,"result":{…}}` or
`{"ok":false,"error":{"code","message"}}`. Codes: `bad_request`,
`proto_version`, `unknown_op`, `rate_limited`, `not_locked`, `throttled`,
`not_allowed`, `no_transaction`.

## Events (daemon → UI)

`Show{user, emergency_info, hide_notification_content, show_media_controls,
actions[], grace_ms_remaining, failures, outputs_covered, outputs_total}` ·
`Hide` · `Prompt{kind: secret|visible|info|error, text}` ·
`AuthResult{ok, reason, failures}` · `Throttle{seconds}`.

`AuthResult.reason` is deliberately generic ("incorrect password",
"authentication service unavailable", …): PAM detail codes stay in the
daemon log.

## Rules for UI authors

1. Retry connecting; the daemon refuses you while it has no UI to admit.
2. Ignore unknown event fields.
3. Never log or persist the password; the daemon enforces throttling, so a
   UI that ignores `Throttle` only wastes its own time.
4. The countdown shown to the user comes from `Throttle.seconds`.
