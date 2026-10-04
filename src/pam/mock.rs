#![forbid(unsafe_code)]
//! Scripted mock PAM backend (spec 03 §10: "mock PAM conversation —
//! success, fail, expired, multi-prompt, timeout").
//!
//! The mock owns no FFI; it plays a [`MockScript`] against the *real*
//! [`Conversation`] bridge, so the conversation plumbing, timeouts and
//! cancellation semantics are exercised exactly as with libpam.

use super::{
    AuthFailReason, AuthOutcome, ConvError, Conversation, PamService, PamServiceFactory, PromptSpec,
};
use std::collections::HashMap;
use std::time::Duration;

/// One conversation round inside a script.
#[derive(Debug, Clone)]
pub struct MockRound {
    pub prompts: Vec<PromptSpec>,
    /// Expected answers, one per prompt; `None` accepts anything.
    pub expected: Vec<Option<String>>,
}

/// A scripted PAM transaction.
#[derive(Debug, Clone)]
pub struct MockScript {
    /// Prompts issued before the authenticate verdict.
    pub auth_rounds: Vec<MockRound>,
    /// Verdict of `pam_authenticate`.
    pub auth: AuthOutcome,
    /// Verdict of `pam_acct_mgmt` (run only when auth succeeded).
    pub acct: AuthOutcome,
    /// Expired-password flow: if `acct` is `PAM_NEW_AUTHTOK_REQD`-equivalent
    /// this script runs as `pam_chauthtok`.
    pub chauthtok: Option<(Vec<MockRound>, AuthOutcome)>,
    /// Result of `pam_setcred`.
    pub setcred: Result<(), AuthFailReason>,
    /// Simulate a hung PAM module before any prompt: the worker sleeps.
    pub hang: Option<Duration>,
}

impl MockScript {
    /// Straightforward password success.
    pub fn success(password: &str) -> Self {
        MockScript {
            auth_rounds: vec![MockRound {
                prompts: vec![PromptSpec::secret("Password: ")],
                expected: vec![Some(password.to_string())],
            }],
            auth: AuthOutcome::Success,
            acct: AuthOutcome::Success,
            chauthtok: None,
            setcred: Ok(()),
            hang: None,
        }
    }

    /// Multi-step: password + visible OTP prompt, then success.
    pub fn multi_prompt(password: &str, otp: &str) -> Self {
        MockScript {
            auth_rounds: vec![MockRound {
                prompts: vec![
                    PromptSpec::secret("Password: "),
                    PromptSpec::visible("OTP code: "),
                ],
                expected: vec![Some(password.to_string()), Some(otp.to_string())],
            }],
            auth: AuthOutcome::Success,
            acct: AuthOutcome::Success,
            chauthtok: None,
            setcred: Ok(()),
            hang: None,
        }
    }

    /// Wrong password → generic auth failure.
    pub fn failure(expected_password: &str) -> Self {
        MockScript {
            auth_rounds: vec![MockRound {
                prompts: vec![PromptSpec::secret("Password: ")],
                expected: vec![Some(expected_password.to_string())],
            }],
            auth: AuthOutcome::Failed(AuthFailReason::AuthErr),
            acct: AuthOutcome::Success,
            chauthtok: None,
            setcred: Ok(()),
            hang: None,
        }
    }

    /// Expired password: current, new, confirm prompts, then success.
    pub fn expired(cur: &str, new: &str) -> Self {
        MockScript {
            auth_rounds: vec![MockRound {
                prompts: vec![PromptSpec::secret("Current password: ")],
                expected: vec![Some(cur.to_string())],
            }],
            auth: AuthOutcome::Success,
            // NEW_AUTHTOK_REQD is represented by a failed-with-marker outcome:
            acct: AuthOutcome::Failed(AuthFailReason::NewAuthtokFailed),
            chauthtok: Some((
                vec![MockRound {
                    prompts: vec![
                        PromptSpec::secret("New password: "),
                        PromptSpec::secret("Retype new password: "),
                    ],
                    expected: vec![Some(new.to_string()), Some(new.to_string())],
                }],
                AuthOutcome::Success,
            )),
            setcred: Ok(()),
            hang: None,
        }
    }

    /// Module hangs before prompting (drives the transaction deadline).
    pub fn hang(d: Duration) -> Self {
        MockScript {
            auth_rounds: vec![],
            auth: AuthOutcome::Success,
            acct: AuthOutcome::Success,
            chauthtok: None,
            setcred: Ok(()),
            hang: Some(d),
        }
    }

    /// pam_start fails — fail closed service error.
    pub fn service_error() -> Self {
        MockScript {
            auth_rounds: vec![],
            auth: AuthOutcome::Failed(AuthFailReason::ServiceError),
            acct: AuthOutcome::Failed(AuthFailReason::ServiceError),
            chauthtok: None,
            setcred: Err(AuthFailReason::ServiceError),
            hang: None,
        }
    }
}

/// Mock factory: scripts keyed by user name.
#[derive(Clone)]
pub struct MockPamFactory {
    scripts: HashMap<String, MockScript>,
    fallback: MockScript,
    /// When true, `open()` fails for every service/user (backend missing).
    pub broken: bool,
}

impl MockPamFactory {
    pub fn new(fallback: MockScript) -> Self {
        MockPamFactory {
            scripts: HashMap::new(),
            fallback,
            broken: false,
        }
    }

    pub fn with_script(mut self, user: &str, script: MockScript) -> Self {
        self.scripts.insert(user.to_string(), script);
        self
    }
}

struct MockService {
    script: MockScript,
    conv: super::ConvShim,
}

fn run_rounds(rounds: &[MockRound], conv: &mut dyn Conversation) -> Option<AuthFailReason> {
    for round in rounds {
        let answers = match conv.converse(&round.prompts) {
            Ok(a) => a,
            Err(ConvError::Cancelled) => return Some(AuthFailReason::Cancelled),
            Err(ConvError::Timeout) => return Some(AuthFailReason::Timeout),
            Err(ConvError::ChannelClosed) => return Some(AuthFailReason::Cancelled),
        };
        for (ans, exp) in answers.iter().zip(round.expected.iter()) {
            if let Some(want) = exp {
                if ans.as_str() != want {
                    return Some(AuthFailReason::AuthErr);
                }
            }
        }
    }
    None
}

impl PamService for MockService {
    fn authenticate(&mut self) -> AuthOutcome {
        if let Some(hang) = self.script.hang {
            std::thread::sleep(hang);
        }
        if let Some(reason) = run_rounds(&self.script.auth_rounds, self.conv.inner.as_mut()) {
            return AuthOutcome::Failed(reason);
        }
        if !self.script.auth.ok() {
            return self.script.auth;
        }
        // Account management + expired-password change flow.
        if self.script.acct == AuthOutcome::Failed(AuthFailReason::NewAuthtokFailed) {
            if let Some((rounds, outcome)) = &self.script.chauthtok.clone() {
                if let Some(reason) = run_rounds(rounds, self.conv.inner.as_mut()) {
                    return AuthOutcome::Failed(reason);
                }
                if !outcome.ok() {
                    return *outcome;
                }
            } else {
                return AuthOutcome::Failed(AuthFailReason::NewAuthtokFailed);
            }
        } else if !self.script.acct.ok() {
            return self.script.acct;
        }
        AuthOutcome::Success
    }

    fn setcred(&mut self) -> Result<(), AuthFailReason> {
        self.script.setcred
    }

    fn end(self: Box<Self>) {
        // no-op: mock holds no resources
    }
}

impl PamServiceFactory for MockPamFactory {
    fn open(
        &self,
        _service: &str,
        user: &str,
        conv: super::ConvShim,
    ) -> Result<Box<dyn PamService>, AuthFailReason> {
        if self.broken {
            return Err(AuthFailReason::ServiceError);
        }
        let script = self
            .scripts
            .get(user)
            .cloned()
            .unwrap_or_else(|| self.fallback.clone());
        Ok(Box::new(MockService { script, conv }))
    }

    fn describe(&self) -> &'static str {
        "mock-pam (scripted)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ConvBridge;
    use crate::secret::Secret;
    use std::sync::{mpsc, Arc, Mutex};

    fn drive(script: MockScript, script_name: &str, answers: &[&str]) -> AuthOutcome {
        let (evt_tx, _evt_rx) = tokio_channel();
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let bridge = ConvBridge::new(evt_tx, Arc::new(Mutex::new(cmd_rx)), Duration::from_secs(5));
        // feed answers eagerly
        for a in answers {
            cmd_tx
                .send(crate::auth::WorkerCmd::Answer(Secret::new(
                    (*a).to_string(),
                )))
                .unwrap();
        }
        let mut svc = MockPamFactory::new(MockScript::failure("nope"))
            .with_script(script_name, script)
            .open(
                "lion-locker",
                script_name,
                super::super::ConvShim::new(Box::new(bridge)),
            )
            .unwrap();
        svc.authenticate()
    }

    fn tokio_channel() -> (
        tokio::sync::mpsc::UnboundedSender<crate::auth::AuthEvent>,
        tokio::sync::mpsc::UnboundedReceiver<crate::auth::AuthEvent>,
    ) {
        tokio::sync::mpsc::unbounded_channel()
    }

    #[test]
    fn success_scenario() {
        let out = drive(MockScript::success("pw"), "alice", &["pw"]);
        assert_eq!(out, AuthOutcome::Success);
    }

    #[test]
    fn fail_scenario() {
        let out = drive(MockScript::failure("right"), "alice", &["wrong"]);
        assert_eq!(out, AuthOutcome::Failed(AuthFailReason::AuthErr));
    }

    #[test]
    fn expired_scenario() {
        let out = drive(
            MockScript::expired("old", "new"),
            "alice",
            &["old", "new", "new"],
        );
        assert_eq!(out, AuthOutcome::Success);
    }

    #[test]
    fn multi_prompt_scenario() {
        let out = drive(
            MockScript::multi_prompt("pw", "123456"),
            "alice",
            &["pw", "123456"],
        );
        assert_eq!(out, AuthOutcome::Success);
        // wrong OTP → generic failure
        let out = drive(
            MockScript::multi_prompt("pw", "123456"),
            "alice",
            &["pw", "999999"],
        );
        assert_eq!(out, AuthOutcome::Failed(AuthFailReason::AuthErr));
    }

    #[test]
    fn service_error_fail_closed() {
        let out = drive(MockScript::service_error(), "alice", &[]);
        assert_eq!(out, AuthOutcome::Failed(AuthFailReason::ServiceError));
    }

    #[test]
    fn no_answer_times_out() {
        let (evt_tx, _rx) = tokio_channel();
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let bridge = ConvBridge::new(
            evt_tx,
            Arc::new(Mutex::new(cmd_rx)),
            Duration::from_millis(50),
        );
        let mut svc = MockPamFactory::new(MockScript::failure("x"))
            .with_script("bob", MockScript::success("pw"))
            .open(
                "lion-locker",
                "bob",
                super::super::ConvShim::new(Box::new(bridge)),
            )
            .unwrap();
        let _keep_alive = cmd_tx; // channel stays connected; nobody answers
        let out = svc.authenticate();
        assert_eq!(out, AuthOutcome::Failed(AuthFailReason::Timeout));
    }
}
