//! Private preparation binding, retained direct SQL witness, and bounded async
//! continuation through borrowed admission and routing capabilities.
//! Buffers stay with the original protocol preparation; this module parses no
//! XML and owns no AppState, clock, SQL, socket, task, or retry capability.
use crate::services::message_admission::{
    finalize_message_admission_with, witness::DirectOperationHandle, MessageAdmissionRepository,
    MessageAdmissionService,
};
use northstar_message_application::{direct_commit::*, direct_lifecycle::PreparationAdmission};
use northstar_message_core::{
    DirectPersonalMessageAdmission, DirectPostCommitMode, DirectSpoolEligibility,
    IdentityAuthority, MessageCommit, MessagePostCommit, PersonalMessageDestination,
    ValidatedPersonalMessage,
};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
#[error("direct transaction committed but its continuation did not complete")]
struct DirectContinuationError {
    receipt: Receipt,
    #[source]
    source: anyhow::Error,
}

pub(super) fn continuation_error(
    error: anyhow::Error,
    outcome: Option<ExecutionOutcome>,
) -> anyhow::Error {
    match outcome {
        Some(ExecutionOutcome::ReceiptPreserved(receipt)) => DirectContinuationError {
            receipt,
            source: error,
        }
        .into(),
        _ => error,
    }
}

pub(crate) fn preserved_transaction(error: &anyhow::Error) -> Option<&TransactionOutcome> {
    error
        .downcast_ref::<DirectContinuationError>()
        .map(|error| &error.receipt.prepared.outcome)
}

/// The actual application result and its original continuation cannot be
/// independently supplied or exchanged by the protocol or controlled caller.
pub(crate) struct AppliedLocalDirect<'live> {
    actual: anyhow::Result<DirectPersonalMessageAdmission>,
    continuation: LocalDirectContinuation<'live>,
}

pub(crate) enum ContinuedLocalDirect<'live> {
    Live(PreparedLiveDirect<'live>),
    Accepted,
    Reject(LocalDirectStanzaError),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LocalDirectStanzaError {
    InternalPostCommitShape,
    AccountUnavailable,
    Unconfirmed,
}
impl LocalDirectStanzaError {
    pub(crate) fn stanza_error(self) -> (&'static str, &'static str) {
        match self {
            Self::InternalPostCommitShape => ("wait", "internal-server-error"),
            Self::AccountUnavailable => ("cancel", "service-unavailable"),
            Self::Unconfirmed => ("wait", "resource-constraint"),
        }
    }
}

pub(crate) struct PreparedLiveDirect<'live> {
    archive_written: bool,
    // One allocation keeps the three-way disposition compact; the exact
    // grant and borrowed live view move together without a payload clone.
    handoff: Box<PreparedDirectHandoff<'live>>,
}
impl PreparedLiveDirect<'_> {
    pub(crate) fn archive_written(&self) -> bool {
        self.archive_written
    }
    pub(crate) fn source(&self) -> crate::xmpp::outbound::DurableDelivery {
        self.handoff.grant.source()
    }

    pub(crate) async fn route_with<P: super::DirectMessageRoutePort>(
        self,
        port: &P,
        approved_targets: &[(String, P::Session)],
    ) -> Result<super::DirectRouteOutcome, super::direct_route::DirectRouteError> {
        let live = &self.handoff.live;
        let request = super::DirectRouteRequest {
            message_type: live.message_type,
            target: if live.target == live.target_bare {
                super::DirectRouteTarget::Bare(live.target)
            } else {
                super::DirectRouteTarget::Full {
                    jid: live.target,
                    bare: live.target_bare,
                }
            },
            sender: live.sender,
            recipient_id: live.recipient_id,
            stanza: live.stanza,
            delivery: super::DirectRouteDelivery::Committed(self.source()),
            approved_targets,
            enforce_direct_health: true,
        };
        super::DirectMessageRouter::route_prepared(port, request, *self.handoff).await
    }
}

pub(crate) async fn commit_prepared_application<'command, 'live, R>(
    app: &northstar_message_application::MessageApplication<R>,
    prepared: PreparedLocalDirect<'command, 'live>,
) -> AppliedLocalDirect<'live>
where
    R: DirectCommitRepository<Error = anyhow::Error>,
{
    let actual = app
        .commit_direct(prepared.command(), prepared.eligibility(), Some(&prepared))
        .await
        .map_err(super::direct_commit_error);
    AppliedLocalDirect {
        actual,
        continuation: prepared.into_continuation(),
    }
}

pub(crate) async fn continue_prepared_local_direct<'live, A, P, F>(
    applied: AppliedLocalDirect<'live>,
    lease: &mut Option<crate::security::abuse::MessageAdmissionLease>,
    admission: &MessageAdmissionService<A>,
    route: &P,
    enter_followup: F,
) -> ContinuedLocalDirect<'live>
where
    A: MessageAdmissionRepository,
    P: super::DirectMessageRoutePort,
    F: Fn() + Sync,
{
    let AppliedLocalDirect {
        actual,
        continuation,
    } = applied;
    match actual {
        Ok(DirectPersonalMessageAdmission {
            commit:
                MessageCommit::Stored {
                    archive_written,
                    post_commit,
                },
            mode,
            ..
        }) => {
            let MessagePostCommit::RouteLocalDelivery { delivery_id, .. } = post_commit else {
                return ContinuedLocalDirect::Reject(
                    LocalDirectStanzaError::InternalPostCommitShape,
                );
            };
            tracing::debug!(target: "rust_xmpp_server::xmpp::protocol::messaging",
                recipient_id = %continuation.live.recipient_id,
                message_id = %delivery_id,
                target = %continuation.live.target,
                "committed durable C2S delivery before route attempt");
            finalize_message_admission_with(
                admission,
                lease,
                if mode == DirectPostCommitMode::Live {
                    "local-durable-c2s"
                } else {
                    "local-durable-c2s-spooled"
                },
                || Some(continuation.owner.clone()),
                &enter_followup,
                || route.post_accept_failed(),
            )
            .await;
            match continuation.after_finalize(|| route.direct_route_mode()) {
                Ok(PreparedHandoffNext::Route(handoff)) => {
                    ContinuedLocalDirect::Live(PreparedLiveDirect {
                        archive_written,
                        handoff: Box::new(handoff),
                    })
                }
                Ok(PreparedHandoffNext::Recover(recovery)) => {
                    super::DirectMessageRouter::recover_prepared(route, recovery).await;
                    ContinuedLocalDirect::Accepted
                }
                Err(error) => {
                    route.post_accept_failed();
                    tracing::warn!(target: "rust_xmpp_server::xmpp::protocol::messaging", ?error,
                        "stored direct handoff could not be issued; row remains recoverable");
                    ContinuedLocalDirect::Accepted
                }
            }
        }
        Ok(DirectPersonalMessageAdmission {
            commit: MessageCommit::Replay,
            ..
        }) => {
            finalize_message_admission_with(
                admission,
                lease,
                "local-durable-c2s-replay",
                || Some(continuation.owner.clone()),
                enter_followup,
                || route.post_accept_failed(),
            )
            .await;
            ContinuedLocalDirect::Accepted
        }
        Ok(DirectPersonalMessageAdmission {
            commit: MessageCommit::AccountUnavailable,
            ..
        }) => ContinuedLocalDirect::Reject(LocalDirectStanzaError::AccountUnavailable),
        Err(error) => match preserved_transaction(&error) {
            Some(TransactionOutcome::Stored { .. }) => {
                route.post_accept_failed();
                finalize_message_admission_with(
                    admission,
                    lease,
                    "local-durable-c2s-continuation-unknown",
                    || Some(continuation.owner.clone()),
                    enter_followup,
                    || route.post_accept_failed(),
                )
                .await;
                match continuation.after_finalize(|| route.direct_route_mode()) {
                    Ok(PreparedHandoffNext::Recover(recovery)) => {
                        super::DirectMessageRouter::recover_prepared(route, recovery).await
                    }
                    Ok(PreparedHandoffNext::Route(_)) | Err(_) => route.post_accept_failed(),
                }
                ContinuedLocalDirect::Accepted
            }
            Some(TransactionOutcome::Replay { .. }) => {
                finalize_message_admission_with(
                    admission,
                    lease,
                    "local-durable-c2s-replay-continuation-unknown",
                    || Some(continuation.owner.clone()),
                    enter_followup,
                    || route.post_accept_failed(),
                )
                .await;
                ContinuedLocalDirect::Accepted
            }
            Some(TransactionOutcome::AccountUnavailable) => {
                ContinuedLocalDirect::Reject(LocalDirectStanzaError::AccountUnavailable)
            }
            None => {
                tracing::warn!(target: "rust_xmpp_server::xmpp::protocol::messaging", ?error,
                    recipient_id = %continuation.live.recipient_id,
                    "local history/C2S admission did not return a confirmed result");
                ContinuedLocalDirect::Reject(LocalDirectStanzaError::Unconfirmed)
            }
        },
    }
}

/// Actual purpose-specific views derived by OriginalDirectMessage. These are
/// private runtime inputs, never caller-supplied fingerprints or preparation IDs.
pub(crate) struct LocalPreparation<'a> {
    pub(crate) actor_id: Uuid,
    pub(crate) sender_bare: &'a str,
    pub(crate) sender_full: &'a str,
    pub(crate) target_bare: &'a str,
    pub(crate) target_full: &'a str,
    pub(crate) message_type: &'a str,
    pub(crate) live_stanza: &'a str,
    pub(crate) origin_id: Option<&'a str>,
    pub(crate) identity_payload: &'a str,
    pub(crate) stored_stanza: &'a str,
    pub(crate) admission: PreparationAdmission<'a>,
}

/// Borrowed live view of the same original that produced the stored command.
/// Kept separately from the command lifetime so delayed/archive buffers can end.
pub(crate) struct LiveDirectBinding<'a> {
    pub(crate) sender: &'a str,
    pub(crate) target: &'a str,
    pub(crate) target_bare: &'a str,
    pub(crate) message_type: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) recipient_id: Uuid,
}

pub(crate) struct PreparedLocalDirect<'a, 'live> {
    owner: DirectOperationHandle,
    effect: DirectEffect,
    command: ValidatedPersonalMessage<'a>,
    eligibility: DirectSpoolEligibility,
    live: LiveDirectBinding<'live>,
}

impl std::fmt::Debug for PreparedLocalDirect<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedLocalDirect { authority: [redacted] }")
    }
}

impl<'a, 'live> PreparedLocalDirect<'a, 'live> {
    pub(crate) fn bind(
        owner: DirectOperationHandle,
        original: LocalPreparation<'_>,
        command: ValidatedPersonalMessage<'a>,
        eligibility: DirectSpoolEligibility,
        live: LiveDirectBinding<'live>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            command.local_actor_id == Some(original.actor_id),
            "direct preparation actor mismatch"
        );
        let PersonalMessageDestination::Local(destination) = command.destination else {
            anyhow::bail!("direct preparation requires local destination");
        };
        anyhow::ensure!(
            destination.sender_jid == original.sender_full
                && destination.recipient_bare_jid == original.target_bare,
            "direct preparation source/target mismatch"
        );
        anyhow::ensure!(
            live.sender == original.sender_full
                && live.target == original.target_full
                && live.target_bare == original.target_bare
                && live
                    .target
                    .split_once('/')
                    .map_or(live.target, |(bare, _)| bare)
                    == live.target_bare
                && live
                    .sender
                    .split_once('/')
                    .map_or(live.sender, |(bare, _)| bare)
                    == original.sender_bare
                && live.message_type == original.message_type
                && live.recipient_id == destination.recipient_id
                && live.stanza == original.live_stanza,
            "direct preparation live projection mismatch"
        );
        anyhow::ensure!(
            destination.stanza == original.stored_stanza,
            "direct preparation stored projection mismatch"
        );
        match (command.identity, original.origin_id) {
            (Some(identity), Some(origin)) => anyhow::ensure!(
                identity.authority == IdentityAuthority::LocalOrigin
                    && identity.actor_scope_raw == original.sender_bare
                    && identity.actor_scope == original.sender_bare
                    && identity.target_scope == original.target_bare
                    && identity.value == origin
                    && identity.payload == original.identity_payload,
                "direct preparation identity/payload mismatch"
            ),
            (None, None) => {}
            _ => anyhow::bail!("direct preparation origin identity mismatch"),
        }
        anyhow::ensure!(
            command
                .archives
                .iter()
                .all(|projection| projection.owner_id == original.actor_id
                    || projection.owner_id == destination.recipient_id),
            "direct preparation archive owner mismatch"
        );
        let facts = DirectCommandFacts::for_local(&command, eligibility)?;
        let effect = owner.prepare_direct(original.admission, facts)?;
        Ok(Self {
            owner,
            effect,
            command,
            eligibility,
            live,
        })
    }

    pub(crate) fn into_continuation(self) -> LocalDirectContinuation<'live> {
        LocalDirectContinuation {
            owner: self.owner,
            live: self.live,
        }
    }

    pub(crate) fn command(&self) -> &ValidatedPersonalMessage<'a> {
        &self.command
    }
    pub(crate) fn eligibility(&self) -> DirectSpoolEligibility {
        self.eligibility
    }
}

impl DirectCommitObserver for PreparedLocalDirect<'_, '_> {
    fn start(
        &self,
        command: &ValidatedPersonalMessage<'_>,
        eligibility: DirectSpoolEligibility,
    ) -> Result<(), Rejected> {
        // Equality is between the same prepared purpose-specific command, not
        // between its intentionally different admission/live/stored projections.
        if *command != self.command || eligibility != self.eligibility {
            return Err(Rejected::Command);
        }
        self.owner.start_direct(&self.effect)
    }
    fn prepare(
        &self,
        outcome: TransactionOutcome,
        admitted_mode: DirectPostCommitMode,
    ) -> Result<PreparedCommit, Rejected> {
        let prepared = PreparedCommit {
            correlation: self.effect.correlation(),
            outcome,
            admitted_mode,
        };
        self.owner
            .prepare_direct_commit(&self.effect, prepared.clone())?;
        Ok(prepared)
    }
    fn received(&self, prepared: PreparedCommit) -> Result<(), Rejected> {
        self.owner.receive_direct_commit(&self.effect, prepared)
    }
    fn complete(
        &self,
        result: Option<DirectPersonalMessageAdmission>,
    ) -> Result<ExecutionOutcome, Rejected> {
        self.owner.complete_direct(&self.effect, result)
    }
}

pub(crate) struct LocalDirectContinuation<'a> {
    owner: DirectOperationHandle,
    live: LiveDirectBinding<'a>,
}

pub(crate) enum PreparedHandoffNext<'a> {
    Route(PreparedDirectHandoff<'a>),
    Recover(PreparedDirectRecovery),
}

pub(crate) struct PreparedDirectHandoff<'a> {
    owner: DirectOperationHandle,
    grant: northstar_message_application::direct_handoff::RouteGrant,
    live: LiveDirectBinding<'a>,
}

pub(crate) struct PreparedDirectRecovery {
    pub(super) source: crate::xmpp::outbound::DurableDelivery,
    pub(super) witness: northstar_message_application::direct_handoff::HandoffHandle,
}

impl<'a> LocalDirectContinuation<'a> {
    /// The closure preserves the old short circuit: a returned spool mode or
    /// unknown continuation never performs the second health read.
    pub(crate) fn after_finalize(
        self,
        read_health: impl FnOnce() -> DirectPostCommitMode,
    ) -> anyhow::Result<PreparedHandoffNext<'a>> {
        use northstar_message_application::direct_handoff::Next;
        let next = match self.owner.begin_handoff()? {
            Next::CheckHealth(permit) => {
                self.owner.observe_handoff_health(permit, read_health())?
            }
            next => next,
        };
        Ok(match next {
            Next::Route(grant) => PreparedHandoffNext::Route(PreparedDirectHandoff {
                owner: self.owner,
                grant,
                live: self.live,
            }),
            Next::Recover(grant) => {
                let source = grant.source();
                let witness = self.owner.consume_recovery(grant)?;
                PreparedHandoffNext::Recover(PreparedDirectRecovery { source, witness })
            }
            Next::CheckHealth(_) => unreachable!("health observed once"),
        })
    }
}

impl PreparedDirectHandoff<'_> {
    pub(super) fn bind_route<S>(
        self,
        request: &super::DirectRouteRequest<'_, S>,
    ) -> anyhow::Result<(
        crate::xmpp::outbound::OutboundItem,
        northstar_message_application::direct_handoff::HandoffHandle,
    )> {
        let source = self.grant.source();
        anyhow::ensure!(
            request.sender == self.live.sender
                && request.target.jid() == self.live.target
                && match request.target {
                    super::DirectRouteTarget::Bare(jid) => jid == self.live.target_bare,
                    super::DirectRouteTarget::Full { bare, .. } =>
                        bare == self.live.target_bare && self.live.target != bare,
                }
                && request.enforce_direct_health
                && request.message_type == self.live.message_type
                && request.recipient_id == self.live.recipient_id
                && request.stanza == self.live.stanza
                && request.delivery == super::DirectRouteDelivery::Committed(source),
            "direct handoff live binding mismatch"
        );
        let witness = self.owner.consume_route(self.grant, source)?;
        Ok((
            crate::xmpp::outbound::OutboundItem::durable(self.live.stanza.to_owned(), source),
            witness,
        ))
    }
}

/// The real archive caller supplies transaction.commit(); fake-port tests can
/// choose each cut without executing SQL. A call boundary is not a DB receipt.
pub(crate) async fn commit_observed<E>(
    commit: impl std::future::Future<Output = Result<(), E>>,
    observer: &dyn DirectCommitObserver,
    outcome: TransactionOutcome,
    admitted_mode: DirectPostCommitMode,
) -> anyhow::Result<()>
where
    E: Into<anyhow::Error>,
{
    let prepared = observer.prepare(outcome, admitted_mode)?;
    commit.await.map_err(Into::into)?;
    // No await, mode read, logging or result mapping before the receipt.
    observer.received(prepared)?;
    Ok(())
}

#[cfg(test)]
mod continuation_tests;

#[cfg(test)]
mod tests;
