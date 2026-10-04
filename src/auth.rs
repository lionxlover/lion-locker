#![forbid(unsafe_code)]
//! Re-authentication engine (spec 03 §3 "Unlocking", §6, §8).
//!
//! One PAM transaction per [`Txn::start`] runs on a dedicated worker
//! thread (PAM handles are thread-affine). The conversation callback and
//! the worker loop share the thread, so the command receiver sits behind a
//! `Mutex` that is never contended (the callback holds it only while PAM
//! is prompting).
//!
//! ```text
//! core ──Begin──▶ Txn::start ──spawn──▶ worker: pam_start + authenticate
//!   ◀──Prompt──── ConvBridge ◀──────────  (PAM conversation callback)
//!   ──Answer────▶ ConvBridge ───────────▶
//!   ◀──Done(outcome)──────────────────── verdict; the thread ends
//! ```
//!
//! Differences from lion-greeter's engine: no `setcred`/launch phase (the
//! screen lock does not open a session), and the transaction ends right
//! after the verdict. Failure handling:
//! - UI crash/disconnect → the core cancels the transaction; the next
//!   conversation step fails and the transaction is wiped.
//! - PAM hang → every conversation step has a hard timeout
//!   (`locker.pam.timeout_seconds`); a module that never returns parks one
//!   thread until PAM returns (documented trade-off, DESIGN.md §3).
//! - All answers travel as [`Secret`] (zeroizing).

use crate::pam::{
    AuthFailReason, AuthOutcome, ConvError, Conversation, PamServiceFactory, PromptSpec,
};
use crate::secret::Secret;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedReceiver;

/// Commands the core sends into a worker.
#[derive(Debug)]
pub enum WorkerCmd {
    /// Answer to the current prompt (zeroizing).
    Answer(Secret),
    /// Abort the conversation.
    Cancel,
    /// Kept for protocol parity with lion-greeter's engine; ignored.
    SetCred,
    /// `pam_end` + thread exit.
    End,
}

/// Events the worker reports back.
#[derive(Debug)]
pub enum AuthEvent {
    Prompt(PromptSpec),
    /// Verdict of `authenticate` (PAM round trip complete).
    Done(AuthOutcome),
    /// Kept for parity; the locker never calls setcred.
    SetCredDone(Result<(), AuthFailReason>),
    /// Worker thread has finished and the transaction is closed.
    Finished,
}

pub type SharedCmdRx = Arc<Mutex<Receiver<WorkerCmd>>>;

/// Bridge between the (possibly C) conversation callback and the async
/// core. One per transaction.
pub struct ConvBridge {
    evt: tokio::sync::mpsc::UnboundedSender<AuthEvent>,
    cmd: SharedCmdRx,
    step_timeout: Duration,
}

impl ConvBridge {
    pub fn new(
        evt: tokio::sync::mpsc::UnboundedSender<AuthEvent>,
        cmd: SharedCmdRx,
        step_timeout: Duration,
    ) -> Self {
        ConvBridge {
            evt,
            cmd,
            step_timeout,
        }
    }

    fn next_answer(&mut self) -> Result<Secret, ConvError> {
        let deadline = Instant::now()
            .checked_add(self.step_timeout)
            .ok_or(ConvError::Timeout)?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ConvError::Timeout);
            }
            let rx = self.cmd.lock().map_err(|_| ConvError::ChannelClosed)?;
            match rx.recv_timeout(remaining) {
                Ok(WorkerCmd::Answer(s)) => return Ok(s),
                Ok(WorkerCmd::Cancel) => return Err(ConvError::Cancelled),
                Ok(_) => continue,
                Err(mpsc::RecvTimeoutError::Timeout) => return Err(ConvError::Timeout),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ConvError::ChannelClosed),
            }
        }
    }
}

impl Conversation for ConvBridge {
    fn converse(&mut self, prompts: &[PromptSpec]) -> Result<Vec<Secret>, ConvError> {
        for p in prompts {
            self.evt
                .send(AuthEvent::Prompt(p.clone()))
                .map_err(|_| ConvError::ChannelClosed)?;
        }
        let mut answers = Vec::with_capacity(prompts.len());
        for _ in prompts {
            answers.push(self.next_answer()?);
        }
        Ok(answers)
    }
}

/// Handle to one live PAM transaction.
pub struct Txn {
    cmd_tx: mpsc::Sender<WorkerCmd>,
    evt_rx: Option<UnboundedReceiver<AuthEvent>>,
}

impl Txn {
    /// Spawn the worker thread for one transaction.
    pub fn start(
        factory: Arc<dyn PamServiceFactory>,
        service: String,
        user: String,
        step_timeout: Duration,
    ) -> Txn {
        let (evt_tx, evt_rx) = tokio::sync::mpsc::unbounded_channel::<AuthEvent>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<WorkerCmd>();
        let cmd_rx = Arc::new(Mutex::new(cmd_rx));
        let bridge_cmd = cmd_rx.clone();
        let done_tx = evt_tx.clone();
        let spawned = std::thread::Builder::new()
            .name("lion-locker-auth".into())
            .spawn(move || {
                let bridge = ConvBridge::new(done_tx.clone(), bridge_cmd, step_timeout);
                let shim = crate::pam::ConvShim::new(Box::new(bridge));
                let mut svc = match factory.open(&service, &user, shim) {
                    Ok(s) => s,
                    Err(reason) => {
                        let _ = done_tx.send(AuthEvent::Done(AuthOutcome::Failed(reason)));
                        let _ = done_tx.send(AuthEvent::Finished);
                        return;
                    }
                };
                let outcome = svc.authenticate();
                let _ = done_tx.send(AuthEvent::Done(outcome));
                svc.end();
                let _ = done_tx.send(AuthEvent::Finished);
            });
        if spawned.is_err() {
            // Thread spawn failed: fail closed with a service error so the
            // core's state machine stays consistent.
            let _ = evt_tx.send(AuthEvent::Done(AuthOutcome::Failed(
                AuthFailReason::ServiceError,
            )));
            let _ = evt_tx.send(AuthEvent::Finished);
        }
        Txn {
            cmd_tx,
            evt_rx: Some(evt_rx),
        }
    }

    /// Take the event receiver (the core moves it into a pump task).
    pub fn take_events(&mut self) -> Option<UnboundedReceiver<AuthEvent>> {
        self.evt_rx.take()
    }

    /// Route an answer into the live conversation.
    pub fn answer(&self, secret: Secret) -> bool {
        self.cmd_tx.send(WorkerCmd::Answer(secret)).is_ok()
    }

    /// Abort: cancel the conversation and end the transaction.
    pub fn cancel(&self) {
        let _ = self.cmd_tx.send(WorkerCmd::Cancel);
        let _ = self.cmd_tx.send(WorkerCmd::End);
    }
}

impl Drop for Txn {
    fn drop(&mut self) {
        // Dropping the sender disconnects the worker's command channel,
        // which fails any pending conversation step (ChannelClosed).
        let _ = self.cmd_tx.send(WorkerCmd::End);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pam::mock::{MockPamFactory, MockScript};

    async fn run_to_verdict(
        factory: MockPamFactory,
        answers: &[&str],
        timeout: Duration,
    ) -> AuthOutcome {
        let mut t = Txn::start(
            Arc::new(factory),
            "lion-locker".into(),
            "lion".into(),
            timeout,
        );
        let mut rx = t.take_events().unwrap();
        let mut remaining: Vec<String> = answers.iter().map(|s| s.to_string()).collect();
        remaining.reverse();
        loop {
            match rx.recv().await.expect("worker ended without verdict") {
                AuthEvent::Prompt(_) => {
                    if let Some(a) = remaining.pop() {
                        assert!(t.answer(Secret::new(a)));
                    }
                }
                AuthEvent::Done(o) => return o,
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn success_and_failure() {
        let f = MockPamFactory::new(MockScript::success("pw"));
        assert_eq!(
            run_to_verdict(f, &["pw"], Duration::from_secs(5)).await,
            AuthOutcome::Success
        );
        let f = MockPamFactory::new(MockScript::failure("pw"));
        assert_eq!(
            run_to_verdict(f, &["bad"], Duration::from_secs(5)).await,
            AuthOutcome::Failed(AuthFailReason::AuthErr)
        );
    }

    #[tokio::test]
    async fn multi_prompt_flow() {
        let f = MockPamFactory::new(MockScript::multi_prompt("pw", "123456"));
        assert_eq!(
            run_to_verdict(f, &["pw", "123456"], Duration::from_secs(5)).await,
            AuthOutcome::Success
        );
    }

    #[tokio::test]
    async fn step_timeout_fails_closed() {
        let f = MockPamFactory::new(MockScript::success("pw"));
        // never answer → conversation step times out
        assert_eq!(
            run_to_verdict(f, &[], Duration::from_millis(60)).await,
            AuthOutcome::Failed(AuthFailReason::Timeout)
        );
    }

    #[tokio::test]
    async fn broken_service_is_a_service_error() {
        let mut f = MockPamFactory::new(MockScript::success("pw"));
        f.broken = true;
        assert_eq!(
            run_to_verdict(f, &[], Duration::from_secs(1)).await,
            AuthOutcome::Failed(AuthFailReason::ServiceError)
        );
    }

    #[tokio::test]
    async fn cancel_aborts_the_conversation() {
        let f = MockPamFactory::new(MockScript::success("pw"));
        let mut t = Txn::start(
            Arc::new(f),
            "s".into(),
            "lion".into(),
            Duration::from_secs(5),
        );
        let mut rx = t.take_events().unwrap();
        assert!(matches!(rx.recv().await, Some(AuthEvent::Prompt(_))));
        t.cancel();
        loop {
            match rx.recv().await {
                Some(AuthEvent::Done(o)) => {
                    assert_eq!(o, AuthOutcome::Failed(AuthFailReason::Cancelled));
                    break;
                }
                Some(_) => {}
                None => panic!("no verdict"),
            }
        }
    }

    #[tokio::test]
    async fn dropping_the_handle_aborts_too() {
        let f = MockPamFactory::new(MockScript::success("pw"));
        let mut t = Txn::start(
            Arc::new(f),
            "s".into(),
            "lion".into(),
            Duration::from_secs(5),
        );
        let mut rx = t.take_events().unwrap();
        assert!(matches!(rx.recv().await, Some(AuthEvent::Prompt(_))));
        drop(t);
        loop {
            match rx.recv().await {
                Some(AuthEvent::Done(o)) => {
                    assert!(!o.ok());
                    break;
                }
                Some(_) => {}
                None => panic!("no verdict"),
            }
        }
    }
}
