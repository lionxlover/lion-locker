#![forbid(unsafe_code)]
//! The lock-UI Unix socket server (spec 03 §4 "Local socket to
//! lion-lockscreen").
//!
//! Security (spec 03 §8 "identify callers by pidfd/cgroup, never by
//! caller-supplied strings"):
//! * the socket lives in a 0700 directory and is itself 0600;
//! * every connection's identity comes from `SO_PEERCRED` (kernel-mediated):
//!   uid must be the session owner;
//! * when the locker spawns the UI itself, the peer pid must equal the
//!   supervised child's pid — a stray same-uid process can neither talk to
//!   PAM through the locker nor kick the real UI off the socket;
//! * otherwise (externally managed UI) the peer's cgroup must end with
//!   `locker.ui.expected_cgroup_suffix` when configured;
//! * the peer pid is pinned with a pidfd for the lifetime of the
//!   connection so the identity cannot be recycled underneath us.
//!
//! One reader task and one writer task per connection; the core owns all
//! state. Frames are bounded (8 KiB) and secrets are wiped by the codec.

use crate::codec::{FrameReader, FrameWriter};
use crate::config::Config;
use crate::core::{Event, UiOut};
use crate::error::{Error, Result};
use crate::proto::{self, codes};
use crate::sysffi;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

/// Why a peer was refused (logged; never sent to the peer).
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    WrongUid,
    NotTheSupervisedUi,
    WrongCgroup,
    NoPeerCredentials,
}

/// Pure admission decision (unit-tested).
pub fn admit(
    cfg: &Config,
    peer_uid: u32,
    peer_pid: Option<u32>,
    supervised_pid: u32,
    cgroup_of: impl Fn(u32) -> Option<String>,
) -> std::result::Result<(), Refusal> {
    if peer_uid != cfg.owner() {
        return Err(Refusal::WrongUid);
    }
    if !cfg.ui.exec.is_empty() {
        // Locker-spawned UI: only that exact process may connect. While no
        // UI is running (pid 0) nobody is admitted — fail closed; the UI
        // retries.
        return match peer_pid {
            Some(p) if supervised_pid != 0 && p == supervised_pid => Ok(()),
            Some(_) | None => Err(Refusal::NotTheSupervisedUi),
        };
    }
    if !cfg.ui.expected_cgroup_suffix.is_empty() {
        let pid = peer_pid.ok_or(Refusal::NoPeerCredentials)?;
        return match cgroup_of(pid) {
            Some(cg) if cg.ends_with(&cfg.ui.expected_cgroup_suffix) => Ok(()),
            _ => Err(Refusal::WrongCgroup),
        };
    }
    Ok(())
}

/// Bind the socket (0600, in a 0700 dir). A stale socket file from a
/// previous run is replaced.
///
/// SECURITY (fail closed): the parent directory is validated for
/// ownership and privacy before the socket is bound. A pre-created
/// directory with loose permissions would let an attacker unlink/replace
/// `ui.sock` with their own socket and capture the password typed into
/// the lock screen (socket-squatting).
pub fn bind(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::DirBuilderExt;
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::Io(format!("create {}", dir.display()), e))?;
        crate::core::validate_private_dir(dir).map_err(|e| {
            Error::Lock(format!(
                "socket dir {}: {e} (possible pre-created-dir attack)",
                dir.display()
            ))
        })?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::Io(format!("remove stale {}", path.display()), e)),
    }
    let l =
        UnixListener::bind(path).map_err(|e| Error::Io(format!("bind {}", path.display()), e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::Io(format!("chmod {}", path.display()), e))?;
    Ok(l)
}

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// Accept loop. Runs until the listener fails or the core goes away.
pub async fn serve(
    listener: UnixListener,
    cfg: Config,
    ev: mpsc::UnboundedSender<Event>,
    ui_pid: Arc<AtomicU32>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::error!(target: "uisock", "accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        if ev.is_closed() {
            return;
        }
        let cred = match stream.peer_cred() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target: "uisock", "no peer credentials: {e}");
                continue;
            }
        };
        let pid = cred.pid().map(|p| p as u32);
        if let Err(why) = admit(
            &cfg,
            cred.uid(),
            pid,
            ui_pid.load(Ordering::SeqCst),
            sysffi::cgroup_of_pid,
        ) {
            tracing::warn!(target: "uisock", ?why, uid = cred.uid(), pid = pid.unwrap_or(0), "UI connection refused");
            continue; // drop the stream
        }
        // Pin the peer identity for the connection's lifetime.
        let pidfd = pid.and_then(sysffi::pidfd_open);
        let conn = NEXT_CONN.fetch_add(1, Ordering::SeqCst);
        tracing::info!(target: "uisock", conn, pid = pid.unwrap_or(0), pinned = pidfd.is_some(), "UI connected");
        tokio::spawn(handle_conn(conn, stream, ev.clone(), pidfd));
    }
}

async fn handle_conn(
    conn: u64,
    stream: UnixStream,
    ev: mpsc::UnboundedSender<Event>,
    _pidfd: Option<std::os::fd::OwnedFd>,
) {
    let (rd, wr) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<UiOut>();
    let writer = tokio::spawn(async move {
        let mut w = FrameWriter::new(wr);
        while let Some(out) = rx.recv().await {
            match out {
                UiOut::Line(l) => {
                    if w.write_frame(&l).await.is_err() {
                        break;
                    }
                }
                UiOut::Close => break,
            }
        }
        let _ = w.shutdown().await;
    });

    if ev
        .send(Event::UiConnected {
            conn,
            tx: tx.clone(),
        })
        .is_err()
    {
        return;
    }

    let mut reader = FrameReader::new(rd);
    loop {
        match reader.next_frame().await {
            Ok(Some(frame)) => match proto::decode_request(&frame) {
                Ok(req) => {
                    if ev.send(Event::UiRequest { conn, req }).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(UiOut::Line(e.to_wire()));
                }
            },
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(target: "uisock", conn, "dropping connection: {e}");
                let _ = tx.send(UiOut::Line(proto::error_response(
                    0,
                    codes::BAD_REQUEST,
                    "protocol violation; connection closed",
                )));
                break;
            }
        }
    }
    let _ = tx.send(UiOut::Close);
    let _ = ev.send(Event::UiDisconnected { conn });
    let _ = writer.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(exec: bool, suffix: &str) -> Config {
        let mut c = Config {
            owner_uid: Some(1000),
            ..Default::default()
        };
        if !exec {
            c.ui.exec = vec![];
        }
        c.ui.expected_cgroup_suffix = suffix.into();
        c
    }

    #[test]
    fn wrong_uid_is_always_refused() {
        for exec in [true, false] {
            assert_eq!(
                admit(&cfg(exec, ""), 1001, Some(5), 5, |_| None),
                Err(Refusal::WrongUid)
            );
            // root is not special either
            assert_eq!(
                admit(&cfg(exec, ""), 0, Some(5), 5, |_| None),
                Err(Refusal::WrongUid)
            );
        }
    }

    #[test]
    fn supervised_ui_pid_must_match() {
        let c = cfg(true, "");
        assert_eq!(admit(&c, 1000, Some(77), 77, |_| None), Ok(()));
        assert_eq!(
            admit(&c, 1000, Some(78), 77, |_| None),
            Err(Refusal::NotTheSupervisedUi)
        );
        // no UI running: nobody admitted
        assert_eq!(
            admit(&c, 1000, Some(77), 0, |_| None),
            Err(Refusal::NotTheSupervisedUi)
        );
        assert_eq!(
            admit(&c, 1000, None, 77, |_| None),
            Err(Refusal::NotTheSupervisedUi)
        );
    }

    #[test]
    fn external_ui_uses_cgroup_pin() {
        let c = cfg(false, "lion-lockscreen.service");
        let good = |_| Some("/user.slice/app.slice/lion-lockscreen.service".to_string());
        let bad = |_| Some("/user.slice/app.slice/evil.service".to_string());
        assert_eq!(admit(&c, 1000, Some(9), 0, good), Ok(()));
        assert_eq!(admit(&c, 1000, Some(9), 0, bad), Err(Refusal::WrongCgroup));
        assert_eq!(
            admit(&c, 1000, Some(9), 0, |_| None),
            Err(Refusal::WrongCgroup)
        );
        assert_eq!(
            admit(&c, 1000, None, 0, good),
            Err(Refusal::NoPeerCredentials)
        );
        // no pinning configured → uid check alone
        assert_eq!(admit(&cfg(false, ""), 1000, Some(9), 0, |_| None), Ok(()));
    }

    #[tokio::test]
    async fn bind_sets_private_modes_and_replaces_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("ui.sock");
        let _l1 = bind(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dmode = std::fs::metadata(p.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dmode, 0o700);
        drop(_l1);
        // stale file left behind: rebinding must work
        let _l2 = bind(&p).unwrap();
    }

    #[tokio::test]
    async fn frames_flow_and_garbage_is_survivable() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        // The socket dir must be private (production: logind 0700); the
        // sandbox umask creates tempdirs 0775, which bind() now refuses.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let p = dir.path().join("ui.sock");
        let l = bind(&p).unwrap();
        let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
        let mut c = Config {
            owner_uid: Some(sysffi::getuid()),
            ..Default::default()
        };
        c.ui.exec = vec![];
        tokio::spawn(serve(l, c, ev_tx, Arc::new(AtomicU32::new(0))));

        let mut s = UnixStream::connect(&p).await.unwrap();
        // connected event
        assert!(matches!(
            ev_rx.recv().await,
            Some(Event::UiConnected { .. })
        ));
        // garbage line → error response, connection survives
        s.write_all(b"not json\n").await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = s.read(&mut buf).await.unwrap();
        let line = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(line.contains("bad_request"), "{line}");
        // valid request reaches the core
        s.write_all(b"{\"proto\":1,\"id\":3,\"op\":\"Hello\"}\n")
            .await
            .unwrap();
        match ev_rx.recv().await {
            Some(Event::UiRequest { req, .. }) => assert_eq!(req.id(), 3),
            other => panic!("{other:?}"),
        }
        // oversized frame → connection dropped + disconnect event
        let big = vec![b'x'; proto::MAX_LINE_BYTES + 10];
        let _ = s.write_all(&big).await;
        loop {
            match ev_rx.recv().await {
                Some(Event::UiDisconnected { .. }) => break,
                Some(_) => continue,
                None => panic!("no disconnect"),
            }
        }
    }
}
