//! The runtime holders for one Delivery claim and each accepted worker
//! attempt. Dropping a holder destroys its child before retiring its owner.

#[cfg(test)]
use super::ClaimedMixDelivery;
use anyhow::Result;
use futures::future::BoxFuture;
pub(crate) use northstar_delivery_core::mix_outbox as core;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

#[cfg(test)]
pub(crate) fn rows(deliveries: Vec<ClaimedMixDelivery>) -> core::Rows {
    deliveries
        .into_iter()
        .map(|delivery| {
            Arc::new(core::Row {
                source: northstar_delivery_core::MixDelivery {
                    delivery_id: delivery.delivery_id,
                    lease_token: delivery.lease_token,
                },
                event_id: delivery.event_id,
                channel_id: delivery.channel_id,
                channel_jid: delivery.channel_jid,
                participant_id: delivery.recipient.participant_id,
                recipient_jid: delivery.recipient.jid,
                recipient_nick: delivery.recipient.nick,
                stanza: delivery.stanza,
                authoritative_stanza_id: delivery.authoritative_stanza_id,
                archive: delivery.archive,
                encrypted: delivery.encrypted,
                attempt_count: delivery.attempt_count,
                route_wake_generation: delivery.route_wake_generation,
            })
        })
        .collect::<Vec<_>>()
        .into()
}

pub(crate) fn commit_error<E: Into<anyhow::Error>>(error: core::CommitError<E>) -> anyhow::Error {
    match error {
        core::CommitError::Observation(error) => error.into(),
        core::CommitError::Commit(error) => error.into(),
    }
}

#[derive(Clone)]
pub(crate) struct ClaimHandle {
    pub(crate) observation: core::ClaimObservation,
    terminal: Arc<Mutex<Option<core::TerminalReason>>>,
}
impl ClaimHandle {
    pub(crate) fn finish_as(&self, reason: core::TerminalReason) {
        self.terminal
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_or_insert(reason);
    }
    fn retire(&self, default: core::TerminalReason) {
        let reason = if default == core::TerminalReason::Panicked {
            default
        } else {
            self.terminal
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .unwrap_or(default)
        };
        let snapshot = self.observation.retire(reason);
        let knowledge = match snapshot.knowledge {
            core::ClaimKnowledge::NoStatementEntered => "not_entered",
            core::ClaimKnowledge::ReadEmpty => "read_empty",
            core::ClaimKnowledge::AutocommitStatementEntered => "statement_entered",
            core::ClaimKnowledge::StatementReceipt(_) => "statement_receipt",
        };
        tracing::debug!(target: "rust_xmpp_server::xmpp::mix_outbox_owner", knowledge, terminal=?snapshot.terminal, "MIX claim ownership retired");
    }
}

pub(crate) struct ClaimTurn {
    request: core::ClaimRequest,
    handle: ClaimHandle,
}
impl ClaimTurn {
    #[cfg(test)]
    pub(crate) fn observation(&self) -> core::ClaimObservation {
        self.handle.observation.clone()
    }
    pub(crate) fn new(limit: i64, max_bytes: i64) -> Result<Self> {
        let observation = core::ClaimObservation::new(core::ClaimCommand { limit, max_bytes });
        let request = observation.request()?;
        Ok(Self {
            request,
            handle: ClaimHandle {
                observation,
                terminal: Arc::new(Mutex::new(None)),
            },
        })
    }
    pub(crate) fn run<F>(
        self,
        child: impl FnOnce(core::ClaimRequest, ClaimHandle) -> F + Send + 'static,
    ) -> ClaimRun
    where
        F: Future<Output = Result<Vec<OwnedAttempt>>> + Send + 'static,
    {
        let owner = self.handle;
        let handle = owner.clone();
        let future = async move { child(self.request, handle).await };
        ClaimRun {
            child: Some(Box::pin(future)),
            retirement: ClaimRetirement {
                owner,
                polling: false,
                retired: false,
            },
        }
    }
}

pub(crate) struct ClaimRun {
    child: Option<BoxFuture<'static, Result<Vec<OwnedAttempt>>>>,
    retirement: ClaimRetirement,
}
struct ClaimRetirement {
    owner: ClaimHandle,
    polling: bool,
    retired: bool,
}
impl ClaimRetirement {
    fn finish(&mut self, reason: core::TerminalReason) {
        self.owner.retire(reason);
        self.retired = true;
    }
}
impl Drop for ClaimRetirement {
    fn drop(&mut self) {
        if !self.retired {
            self.finish(if self.polling || std::thread::panicking() {
                core::TerminalReason::Panicked
            } else {
                core::TerminalReason::Cancelled
            });
        }
    }
}
impl Future for ClaimRun {
    type Output = Result<Vec<OwnedAttempt>>;
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.retirement.polling = true;
        let result = match this
            .child
            .as_mut()
            .expect("MIX claim polled after completion")
            .as_mut()
            .poll(context)
        {
            Poll::Pending => {
                this.retirement.polling = false;
                return Poll::Pending;
            }
            Poll::Ready(result) => result,
        };
        drop(this.child.take());
        this.retirement.finish(if result.is_ok() {
            core::TerminalReason::Completed
        } else {
            core::TerminalReason::BackendFailure
        });
        this.retirement.polling = false;
        Poll::Ready(result)
    }
}
impl Drop for ClaimRun {
    fn drop(&mut self) {
        drop(self.child.take());
        // The retirement field guard also runs if child destruction unwinds.
    }
}

#[derive(Clone)]
pub(crate) struct AttemptHandle {
    pub(crate) observation: core::Observation,
    terminal: Arc<Mutex<Option<core::TerminalReason>>>,
}
impl AttemptHandle {
    pub(crate) fn finish_as(&self, reason: core::TerminalReason) {
        self.terminal
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_or_insert(reason);
    }
    fn retire(&self, default: core::TerminalReason) {
        let reason = if default == core::TerminalReason::Panicked {
            default
        } else {
            self.terminal
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .unwrap_or(default)
        };
        let snapshot = self.observation.retire(reason);
        let archive = match snapshot.archive.knowledge {
            core::ArchiveKnowledge::NoCommitEntered => "not_entered",
            core::ArchiveKnowledge::CommitCallEntered(_) => "commit_entered",
            core::ArchiveKnowledge::ReceiptKnown(_) => "receipt_known",
        };
        tracing::debug!(target: "rust_xmpp_server::xmpp::mix_outbox_owner",
            archive, route=?snapshot.route, transfer_known=snapshot.transfer.is_some(),
            lease_lost=snapshot.lease_lost, settlement=?snapshot.settlement, terminal=?snapshot.terminal,
            "MIX worker attempt ownership retired");
    }
}

/// The raw DTO does not construct this wrapper. Only accepted observed claim
/// completion hands the runtime a consuming core attempt.
pub(crate) struct OwnedAttempt {
    attempt: Option<core::Attempt>,
    handle: AttemptHandle,
}
impl OwnedAttempt {
    pub(crate) fn new(attempt: core::Attempt) -> Self {
        let observation = attempt.observation();
        Self {
            attempt: Some(attempt),
            handle: AttemptHandle {
                observation,
                terminal: Arc::new(Mutex::new(None)),
            },
        }
    }
    #[cfg(test)]
    pub(crate) fn observation(&self) -> core::Observation {
        self.handle.observation.clone()
    }
    pub(crate) fn run<F>(
        mut self,
        child: impl FnOnce(core::Attempt, AttemptHandle) -> F + Send + 'static,
    ) -> AttemptRun
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        let attempt = self.attempt.take().expect("MIX attempt consumed once");
        let owner = self.handle.clone();
        let handle = owner.clone();
        let future = async move { child(attempt, handle).await };
        AttemptRun {
            child: Some(Box::pin(future)),
            retirement: AttemptRetirement {
                owner,
                polling: false,
                retired: false,
            },
        }
    }
}
impl Drop for OwnedAttempt {
    fn drop(&mut self) {
        // A queued attempt can be discarded without ever constructing its
        // route future. No effect or guessed lease release is invented.
        if self.attempt.take().is_some() {
            self.handle.retire(core::TerminalReason::Cancelled);
        }
    }
}
pub(crate) struct AttemptRun {
    child: Option<BoxFuture<'static, Result<()>>>,
    retirement: AttemptRetirement,
}
struct AttemptRetirement {
    owner: AttemptHandle,
    polling: bool,
    retired: bool,
}
impl AttemptRetirement {
    fn finish(&mut self, reason: core::TerminalReason) {
        self.owner.retire(reason);
        self.retired = true;
    }
}
impl Drop for AttemptRetirement {
    fn drop(&mut self) {
        if !self.retired {
            self.finish(if self.polling || std::thread::panicking() {
                core::TerminalReason::Panicked
            } else {
                core::TerminalReason::Cancelled
            });
        }
    }
}
impl Future for AttemptRun {
    type Output = Result<()>;
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.retirement.polling = true;
        let result = match this
            .child
            .as_mut()
            .expect("MIX attempt polled after completion")
            .as_mut()
            .poll(context)
        {
            Poll::Pending => {
                this.retirement.polling = false;
                return Poll::Pending;
            }
            Poll::Ready(result) => result,
        };
        drop(this.child.take());
        this.retirement.finish(if result.is_ok() {
            core::TerminalReason::Completed
        } else {
            core::TerminalReason::BackendFailure
        });
        this.retirement.polling = false;
        Poll::Ready(result)
    }
}
impl Drop for AttemptRun {
    fn drop(&mut self) {
        drop(self.child.take());
        // The retirement field guard also runs if child destruction unwinds.
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use uuid::Uuid;

    pub(crate) fn claimed_rows(archive: bool) -> core::Rows {
        rows(vec![ClaimedMixDelivery {
            delivery_id: Uuid::from_u128(91),
            event_id: Uuid::from_u128(92),
            channel_id: Uuid::from_u128(93),
            channel_jid: "room@mix.local.test".into(),
            recipient: crate::services::mix::MixParticipant {
                participant_id: Uuid::from_u128(94),
                jid: "bob@local.test".into(),
                nick: None,
            },
            stanza: "<message><body>owned</body></message>".into(),
            authoritative_stanza_id: archive.then_some(Uuid::from_u128(95)),
            archive,
            encrypted: false,
            attempt_count: 19,
            lease_token: Uuid::from_u128(96),
            route_wake_generation: 12,
        }])
    }
    pub(crate) fn attempt(archive: bool) -> core::Attempt {
        let observation = core::ClaimObservation::new(core::ClaimCommand {
            limit: 1,
            max_bytes: 8 * 1024 * 1024,
        });
        let request = observation.request().unwrap();
        request.start().unwrap();
        let entered = request.enter_statement().unwrap();
        let rows = claimed_rows(archive);
        request.received(entered, rows.clone()).unwrap();
        request.returned(rows).unwrap().pop().unwrap()
    }
    pub(crate) fn route(archive: bool) -> (core::Observation, core::RouteRequest) {
        let attempt = attempt(archive);
        let observation = attempt.observation();
        let request = attempt
            .route("<message to='bob@local.test'><body>owned</body></message>".into())
            .unwrap();
        request.start().unwrap();
        (observation, request)
    }
    pub(crate) fn settlement(
        kind: core::SettlementKind,
    ) -> (core::Observation, core::SettlementRequest) {
        let (owner, request) = route(false);
        let (result, command) = match kind {
            core::SettlementKind::Ack => (
                core::RouteResult::CompletedByWorker,
                core::SettlementCommand::Ack,
            ),
            core::SettlementKind::Defer => (
                core::RouteResult::Pending,
                core::SettlementCommand::Defer { delay_seconds: 30 },
            ),
            core::SettlementKind::Retry => (
                core::RouteResult::Retry,
                core::SettlementCommand::Retry {
                    error: "fixture".into(),
                },
            ),
            core::SettlementKind::DeadLetter => (
                core::RouteResult::Permanent,
                core::SettlementCommand::DeadLetter {
                    reason: "fixture".into(),
                    error: "fixture".into(),
                },
            ),
        };
        let closed = owner.close_renewal_scope().unwrap();
        let request = request
            .returned(result)
            .unwrap()
            .settlement(command, closed)
            .unwrap()
            .unwrap();
        (owner, request)
    }
    /// Inject a destructor-bearing child into the actual holder. This is a
    /// finite lifetime control, not an alternate production claim adapter.
    pub(crate) fn claim_probe(
        child: impl FnOnce(&core::ClaimObservation) -> BoxFuture<'static, Result<Vec<OwnedAttempt>>>,
    ) -> (core::ClaimObservation, ClaimRun) {
        let turn = ClaimTurn::new(1, 8 * 1024 * 1024).unwrap();
        let observation = turn.observation();
        let future = child(&observation);
        let run = ClaimRun {
            child: Some(future),
            retirement: ClaimRetirement {
                owner: turn.handle,
                polling: false,
                retired: false,
            },
        };
        (observation, run)
    }
    pub(crate) fn attempt_probe(
        child: impl FnOnce(&core::Observation) -> BoxFuture<'static, Result<()>>,
    ) -> (core::Observation, AttemptRun) {
        let mut owned = OwnedAttempt::new(attempt(false));
        let observation = owned.observation();
        let future = child(&observation);
        drop(owned.attempt.take());
        let run = AttemptRun {
            child: Some(future),
            retirement: AttemptRetirement {
                owner: owned.handle.clone(),
                polling: false,
                retired: false,
            },
        };
        (observation, run)
    }
}
