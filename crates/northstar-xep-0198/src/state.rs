#![forbid(unsafe_code)]

//! Deterministic state machine for XEP-0198 Stream Management lifecycle.
//!
//! State transitions accept injected time values only, ensuring strict determinism
//! without internal wall-clock or timer access.

use crate::counter::SmCounter;
use crate::error::{FailedReason, SmError, StateError};
use crate::negotiation::{negotiate_enable, EnableConfig};
use crate::queue::{UnackedEntry, UnackedQueue};
use crate::wire::{AckAnswerElement, EnableElement, EnabledElement, ResumeElement, ResumedElement};

/// Lifecycle state of an XEP-0198 stream management session.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SmState {
    /// Stream management is not enabled on this stream.
    Disabled,
    /// Stream management is active on a live, connected transport.
    Active(ActiveSession),
    /// Transport was disconnected; the session is suspended awaiting resumption.
    Suspended(SuspendedSession),
    /// Resumption deadline expired while in suspension.
    Expired { expires_at: u64 },
    /// Resumption or negotiation failed terminally.
    Failed(FailedReason),
    /// Stream was explicitly closed or terminated.
    Terminated,
}

/// State for a live, active stream management session.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActiveSession {
    /// Number of handled stanzas received from the remote entity.
    pub inbound_h: SmCounter,
    /// Number of stanzas sent to the remote entity.
    pub outbound_h: SmCounter,
    /// Last handled count acknowledged by the remote entity.
    pub acked_h: SmCounter,
    /// Unacknowledged outbound stanza queue.
    pub unacked_queue: UnackedQueue<String>,
    /// Whether stream resumption is allowed for this session.
    pub resume_allowed: bool,
    /// Resumption bearer token / ID issued to the client (if resumable).
    pub resume_id: Option<String>,
    /// Resumption timeout in seconds.
    pub resume_timeout_seconds: u32,
}

/// State for a suspended stream management session waiting for reconnection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SuspendedSession {
    /// Inbound handled count at suspension.
    pub inbound_h: SmCounter,
    /// Outbound handled count at suspension.
    pub outbound_h: SmCounter,
    /// Acknowledged count at suspension.
    pub acked_h: SmCounter,
    /// Preserved unacknowledged queue for replay.
    pub unacked_queue: UnackedQueue<String>,
    /// Resumption bearer token string.
    pub resume_id: String,
    /// Resumption timeout in seconds.
    pub resume_timeout_seconds: u32,
    /// Injected timestamp (e.g. seconds or monotonic epoch) when suspension began.
    pub suspended_at: u64,
    /// Injected timestamp when the suspension lease expires (`suspended_at + resume_timeout_seconds`).
    pub expires_at: u64,
}

/// Outcome returned when stream resumption succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeSuccessOutcome {
    /// The `<resumed/>` wire element to send to the client.
    pub resumed_element: ResumedElement,
    /// Stanzas removed from the queue because the client's `h` acknowledged them.
    pub acknowledged_on_resume: Vec<UnackedEntry<String>>,
    /// Remaining unacknowledged stanzas to be replayed over the reconnected transport.
    pub replay_stanzas: Vec<String>,
}

/// Deterministic Stream Management state machine engine.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SmStateMachine {
    state: SmState,
    max_stanzas: usize,
    max_bytes: usize,
}

impl SmStateMachine {
    /// Creates a new state machine in the `Disabled` initial state.
    pub fn new(max_stanzas: usize, max_bytes: usize) -> Self {
        Self {
            state: SmState::Disabled,
            max_stanzas,
            max_bytes,
        }
    }

    /// Current session lifecycle state.
    pub fn state(&self) -> &SmState {
        &self.state
    }

    /// Whether stream management is active on this stream.
    pub fn is_active(&self) -> bool {
        matches!(self.state, SmState::Active(_))
    }

    /// Whether the stream session is currently suspended.
    pub fn is_suspended(&self) -> bool {
        matches!(self.state, SmState::Suspended(_))
    }

    /// Enables stream management on this stream.
    ///
    /// Accepts client `<enable/>` request, server config, optional resume ID token,
    /// and device identification status.
    pub fn enable(
        &mut self,
        request: &EnableElement,
        config: &EnableConfig,
        resume_id: Option<String>,
        has_device_id: bool,
    ) -> Result<EnabledElement, SmError> {
        if !matches!(self.state, SmState::Disabled) {
            return Err(StateError::InvalidStateTransition {
                from: "non-disabled",
                event: "enable",
            }
            .into());
        }

        let negotiated = negotiate_enable(request, config, has_device_id);
        let id_for_client = if negotiated.resume {
            resume_id.clone()
        } else {
            None
        };

        self.state = SmState::Active(ActiveSession {
            inbound_h: SmCounter::ZERO,
            outbound_h: SmCounter::ZERO,
            acked_h: SmCounter::ZERO,
            unacked_queue: UnackedQueue::new(self.max_stanzas, self.max_bytes),
            resume_allowed: negotiated.resume,
            resume_id,
            resume_timeout_seconds: negotiated.timeout_seconds,
        });

        Ok(EnabledElement {
            id: id_for_client,
            resume: negotiated.resume,
            max: Some(negotiated.timeout_seconds),
            location: negotiated.location,
        })
    }

    /// Records receipt and handling of an inbound stanza (message, presence, iq).
    ///
    /// Advances `inbound_h` by 1. Returns the new inbound count.
    pub fn record_inbound_stanza(&mut self) -> Result<SmCounter, SmError> {
        match &mut self.state {
            SmState::Active(session) => {
                session.inbound_h.advance();
                Ok(session.inbound_h)
            }
            _ => Err(StateError::NotActive.into()),
        }
    }

    /// Records transmission of an outbound stanza, enqueuing it in the unacked queue.
    ///
    /// Advances `outbound_h` by 1. Returns the assigned sequence counter.
    pub fn record_outbound_stanza(
        &mut self,
        stanza: String,
        byte_size: usize,
    ) -> Result<SmCounter, SmError> {
        match &mut self.state {
            SmState::Active(session) => {
                session.outbound_h.advance();
                let seq = session.outbound_h;
                session.unacked_queue.push_back(stanza, byte_size, seq)?;
                Ok(seq)
            }
            _ => Err(StateError::NotActive.into()),
        }
    }

    /// Generates an `<a h='inbound_h'/>` acknowledgement answer to respond to an `<r/>` request.
    pub fn handle_ack_request(&self) -> Result<AckAnswerElement, SmError> {
        match &self.state {
            SmState::Active(session) => Ok(AckAnswerElement {
                h: session.inbound_h,
            }),
            _ => Err(StateError::NotActive.into()),
        }
    }

    /// Processes an incoming `<a h='...'/>` answer from the remote entity.
    ///
    /// Validates `h` against `acked_h`, `outbound_h`, and the queue.
    /// Pops newly acknowledged stanzas from the queue in FIFO order and updates `acked_h`.
    pub fn handle_ack_answer(
        &mut self,
        h: SmCounter,
    ) -> Result<Vec<UnackedEntry<String>>, SmError> {
        match &mut self.state {
            SmState::Active(session) => {
                let delta = SmCounter::validate_ack(
                    session.acked_h,
                    h,
                    session.unacked_queue.len(),
                    session.outbound_h,
                )?;
                let acknowledged = session.unacked_queue.acknowledge(delta);
                session.acked_h = h;
                Ok(acknowledged)
            }
            _ => Err(StateError::NotActive.into()),
        }
    }

    /// Suspends an active, resumable session upon transport disconnection.
    ///
    /// `now` is an injected timestamp (e.g. Unix seconds). Expiry is set to `now + timeout`.
    pub fn suspend(&mut self, now: u64) -> Result<(), SmError> {
        let current_state = std::mem::replace(&mut self.state, SmState::Disabled);
        match current_state {
            SmState::Active(session) if session.resume_allowed => {
                let resume_id = session
                    .resume_id
                    .ok_or(StateError::InvalidStateTransition {
                        from: "active-without-token",
                        event: "suspend",
                    })?;
                let expires_at = now.saturating_add(u64::from(session.resume_timeout_seconds));
                self.state = SmState::Suspended(SuspendedSession {
                    inbound_h: session.inbound_h,
                    outbound_h: session.outbound_h,
                    acked_h: session.acked_h,
                    unacked_queue: session.unacked_queue,
                    resume_id,
                    resume_timeout_seconds: session.resume_timeout_seconds,
                    suspended_at: now,
                    expires_at,
                });
                Ok(())
            }
            SmState::Active(_) => {
                // Non-resumable active session transitions to Terminated upon disconnect
                self.state = SmState::Terminated;
                Ok(())
            }
            other => {
                self.state = other;
                Err(StateError::InvalidStateTransition {
                    from: "non-active",
                    event: "suspend",
                }
                .into())
            }
        }
    }

    /// Checks if a suspended session has expired based on injected timestamp `now`.
    ///
    /// If `now > expires_at`, transitions to `Expired` and returns `true`.
    pub fn check_expiry(&mut self, now: u64) -> bool {
        if let SmState::Suspended(session) = &self.state {
            if now > session.expires_at {
                self.state = SmState::Expired {
                    expires_at: session.expires_at,
                };
                return true;
            }
        }
        false
    }

    /// Resumes a suspended stream management session.
    ///
    /// Validates that:
    /// 1. The session is in `Suspended` state.
    /// 2. `now <= expires_at` (not expired).
    /// 3. `request.previd == session.resume_id`.
    /// 4. `request.h` is a valid handled counter acknowledgement.
    ///
    /// Upon success, transitions to `Active`, pops stanzas acknowledged by `request.h`,
    /// and returns `ResumeSuccessOutcome` containing the `<resumed/>` element and replay FIFO.
    pub fn resume(
        &mut self,
        request: &ResumeElement,
        now: u64,
    ) -> Result<ResumeSuccessOutcome, SmError> {
        let current_state = std::mem::replace(&mut self.state, SmState::Disabled);
        match current_state {
            SmState::Suspended(mut session) => {
                if now > session.expires_at {
                    self.state = SmState::Expired {
                        expires_at: session.expires_at,
                    };
                    return Err(StateError::SessionExpired {
                        expires_at: session.expires_at,
                        now,
                    }
                    .into());
                }

                if session.resume_id != request.previd {
                    self.state = SmState::Suspended(session);
                    return Err(StateError::ResumeFailed(FailedReason::ItemNotFound).into());
                }

                // Validate client's h acknowledgement against the unacked queue
                let delta = match SmCounter::validate_ack(
                    session.acked_h,
                    request.h,
                    session.unacked_queue.len(),
                    session.outbound_h,
                ) {
                    Ok(delta) => delta,
                    Err(err) => {
                        // Handled count too high on resume is terminal failure
                        self.state = SmState::Failed(FailedReason::UndefinedCondition);
                        return Err(err.into());
                    }
                };

                let acknowledged = session.unacked_queue.acknowledge(delta);
                let replay_stanzas = session
                    .unacked_queue
                    .replay_payloads()
                    .cloned()
                    .collect::<Vec<_>>();

                let resumed_element = ResumedElement {
                    previd: request.previd.clone(),
                    h: session.inbound_h,
                    location: None,
                };

                self.state = SmState::Active(ActiveSession {
                    inbound_h: session.inbound_h,
                    outbound_h: session.outbound_h,
                    acked_h: request.h,
                    unacked_queue: session.unacked_queue,
                    resume_allowed: true,
                    resume_id: Some(session.resume_id),
                    resume_timeout_seconds: session.resume_timeout_seconds,
                });

                Ok(ResumeSuccessOutcome {
                    resumed_element,
                    acknowledged_on_resume: acknowledged,
                    replay_stanzas,
                })
            }
            SmState::Expired { expires_at } => {
                self.state = SmState::Expired { expires_at };
                Err(StateError::SessionExpired { expires_at, now }.into())
            }
            other => {
                self.state = other;
                Err(StateError::InvalidStateTransition {
                    from: "non-suspended",
                    event: "resume",
                }
                .into())
            }
        }
    }

    /// Explicitly closes or terminates the session.
    pub fn close(&mut self) {
        self.state = SmState::Terminated;
    }

    /// Marks the session as failed with the given reason.
    pub fn fail(&mut self, reason: FailedReason) {
        self.state = SmState::Failed(reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_sm_lifecycle_and_resumption() {
        let mut sm = SmStateMachine::new(10, 1000);
        assert_eq!(sm.state(), &SmState::Disabled);

        // 1. Enable
        let enable_req = EnableElement {
            resume: true,
            max: Some(60),
            location: None,
        };
        let config = EnableConfig::default();
        let enabled = sm
            .enable(&enable_req, &config, Some("token123".into()), false)
            .unwrap();
        assert!(enabled.resume);
        assert_eq!(enabled.id.as_deref(), Some("token123"));
        assert!(sm.is_active());

        // 2. Inbound and Outbound stanza exchange
        sm.record_inbound_stanza().unwrap();
        sm.record_inbound_stanza().unwrap();

        sm.record_outbound_stanza("<msg-1/>".into(), 8).unwrap();
        sm.record_outbound_stanza("<msg-2/>".into(), 8).unwrap();
        sm.record_outbound_stanza("<msg-3/>".into(), 8).unwrap();

        // 3. Client acks first message
        let acked = sm.handle_ack_answer(SmCounter::new(1)).unwrap();
        assert_eq!(acked.len(), 1);
        assert_eq!(acked[0].payload, "<msg-1/>");

        // 4. Server responds to <r/>
        let ack_answer = sm.handle_ack_request().unwrap();
        assert_eq!(ack_answer.h.get(), 2);

        // 5. Connection drops at now = 1000 -> Suspend
        sm.suspend(1000).unwrap();
        assert!(sm.is_suspended());

        // 6. Resume at now = 1020 (before expires_at = 1060)
        let resume_req = ResumeElement {
            previd: "token123".into(),
            h: SmCounter::new(2), // client also saw msg-2
        };
        let outcome = sm.resume(&resume_req, 1020).unwrap();
        assert_eq!(outcome.resumed_element.h.get(), 2); // server inbound_h is 2
        assert_eq!(outcome.acknowledged_on_resume.len(), 1);
        assert_eq!(outcome.acknowledged_on_resume[0].payload, "<msg-2/>");
        assert_eq!(outcome.replay_stanzas, vec!["<msg-3/>"]);

        assert!(sm.is_active());
    }

    #[test]
    fn resumption_fails_after_expiry() {
        let mut sm = SmStateMachine::new(10, 1000);
        let enable_req = EnableElement {
            resume: true,
            max: Some(60),
            location: None,
        };
        sm.enable(
            &enable_req,
            &EnableConfig::default(),
            Some("token123".into()),
            false,
        )
        .unwrap();
        sm.suspend(1000).unwrap();

        // Check expiry at 1061 (> 1000 + 60)
        assert!(sm.check_expiry(1061));
        assert_eq!(sm.state(), &SmState::Expired { expires_at: 1060 });

        // Resume fails
        let resume_req = ResumeElement {
            previd: "token123".into(),
            h: SmCounter::new(0),
        };
        assert!(matches!(
            sm.resume(&resume_req, 1061),
            Err(SmError::State(StateError::SessionExpired { .. }))
        ));
    }

    #[test]
    fn resumption_rejects_invalid_token() {
        let mut sm = SmStateMachine::new(10, 1000);
        let enable_req = EnableElement {
            resume: true,
            max: Some(60),
            location: None,
        };
        sm.enable(
            &enable_req,
            &EnableConfig::default(),
            Some("correct_token".into()),
            false,
        )
        .unwrap();
        sm.suspend(1000).unwrap();

        let resume_req = ResumeElement {
            previd: "wrong_token".into(),
            h: SmCounter::new(0),
        };
        assert!(matches!(
            sm.resume(&resume_req, 1010),
            Err(SmError::State(StateError::ResumeFailed(
                FailedReason::ItemNotFound
            )))
        ));
        assert!(sm.is_suspended()); // Session remains suspended on wrong token
    }
}
