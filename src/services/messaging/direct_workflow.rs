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
    pub(crate) fn source(&self) -> crate::outbound::DurableDelivery {
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
    lease: &mut Option<crate::abuse::MessageAdmissionLease>,
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
    pub(super) source: crate::outbound::DurableDelivery,
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
        crate::outbound::OutboundItem,
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
            crate::outbound::OutboundItem::durable(self.live.stanza.to_owned(), source),
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
mod continuation_tests {
    use super::super::{
        DirectMessageRoutePort, DirectRouteOutcome, FullJidFallbackPort, OnlineRoutePort,
        OnlineRouteResult,
    };
    use super::*;
    use crate::{
        abuse::{MessageAdmissionLease, MessageAdmissionStart},
        outbound::{DurableDelivery, OutboundSender, RouteEnqueue, RouteSendError},
        services::message_admission::continuation_fixture::{
            self as admission_fixture, Admission, Events, FinalizeCut,
        },
    };
    use northstar_message_application::{
        direct_lifecycle::{OriginalAdmission, TerminalReason},
        MessageApplication, PersonalMessageCommitRepository,
    };
    use northstar_message_core::{LocalDelivery, MessageIdentity};
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    const LIVE: &str = "<message id='live'><body>private live</body></message>";
    const UNRATED_LIVE: &str = "<message id='live' type='chat' from='alice@example.test/device' to='bob@example.test'><store xmlns='urn:xmpp:hints'/></message>";
    fn live_for(mode: Admission) -> &'static str {
        if mode == Admission::NotRated {
            UNRATED_LIVE
        } else {
            LIVE
        }
    }
    type AdmissionService = MessageAdmissionService<admission_fixture::Repository>;
    async fn admit(
        owner: &DirectOperationHandle,
        mode: Admission,
        cut: FinalizeCut,
        events: Events,
    ) -> (AdmissionService, Option<MessageAdmissionLease>) {
        let service = MessageAdmissionService::new(admission_fixture::Repository {
            admission: mode,
            cut,
            events,
        });
        let lease = if mode == Admission::NotRated {
            None
        } else {
            let request = admission_fixture::request();
            let retained = owner.begin(&request).unwrap();
            let MessageAdmissionStart::Proceed { lease, .. } = service
                .begin_message_admission_retained(&request, &retained)
                .await
                .unwrap()
            else {
                panic!("fixture admission rejected");
            };
            lease
        };
        (service, lease)
    }
    fn prepared<'command>(
        owner: &DirectOperationHandle,
        mode: Admission,
        stored: &'command str,
    ) -> PreparedLocalDirect<'command, 'static> {
        let request = admission_fixture::request();
        let live = live_for(mode);
        let parsed = roxmltree::Document::parse(live).unwrap();
        assert_eq!(
            crate::xmpp::xml_util::is_abuse_rated_message(parsed.root_element()),
            mode != Admission::NotRated,
        );
        let command = ValidatedPersonalMessage {
            local_actor_id: Some(request.actor_id),
            identity: Some(MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: request.account_bare,
                actor_scope: request.account_bare,
                target_scope: "bob@example.test",
                value: "origin",
                payload: "private-identity-stanza",
            }),
            archives: &[],
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: Uuid::from_u128(2),
                recipient_id: Uuid::from_u128(5),
                recipient_bare_jid: "bob@example.test",
                sender_jid: "alice@example.test/device",
                stanza: stored,
                encrypted: false,
                mam_backed: false,
            }),
        };
        PreparedLocalDirect::bind(
            owner.clone(),
            LocalPreparation {
                actor_id: request.actor_id,
                sender_bare: request.account_bare,
                sender_full: "alice@example.test/device",
                target_bare: "bob@example.test",
                target_full: request.normalized_target,
                message_type: "chat",
                live_stanza: live,
                origin_id: request.origin_id,
                identity_payload: "private-identity-stanza",
                stored_stanza: stored,
                admission: if mode == Admission::NotRated {
                    PreparationAdmission::NoAdmissionRequired
                } else {
                    PreparationAdmission::Rated(OriginalAdmission {
                        actor_id: request.actor_id,
                        account_bare: request.account_bare,
                        normalized_target: request.normalized_target,
                        origin_id: request.origin_id,
                        normalized_payload: request.normalized_payload,
                    })
                },
            },
            command,
            DirectSpoolEligibility::Eligible,
            LiveDirectBinding {
                sender: "alice@example.test/device",
                target: "bob@example.test",
                target_bare: "bob@example.test",
                message_type: "chat",
                stanza: live,
                recipient_id: Uuid::from_u128(5),
            },
        )
        .unwrap()
    }
    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    enum DirectCut {
        #[default]
        Success,
        PreCommitError,
        CommitError,
        CommitPending,
        AfterReceiptError,
    }
    #[derive(Clone, Copy, Default)]
    enum Outcome {
        #[default]
        Stored,
        Replay,
        Unavailable,
    }
    struct Repository {
        cut: DirectCut,
        outcome: Outcome,
        admitted: DirectPostCommitMode,
        returned: DirectPostCommitMode,
        events: Events,
    }
    impl Repository {
        fn stored(events: Events) -> Self {
            Self {
                cut: DirectCut::Success,
                outcome: Outcome::Stored,
                admitted: DirectPostCommitMode::Live,
                returned: DirectPostCommitMode::Live,
                events,
            }
        }
    }
    impl PersonalMessageCommitRepository for Repository {
        type Error = anyhow::Error;
        async fn commit<'a>(
            &'a self,
            _: &'a ValidatedPersonalMessage<'a>,
        ) -> anyhow::Result<MessageCommit> {
            panic!("prepared application used legacy commit");
        }
    }
    impl DirectCommitRepository for Repository {
        type Error = anyhow::Error;
        async fn commit_direct<'a>(
            &'a self,
            command: &'a ValidatedPersonalMessage<'a>,
            _: DirectSpoolEligibility,
            observer: Option<&'a dyn DirectCommitObserver>,
        ) -> anyhow::Result<DirectPersonalMessageAdmission> {
            self.events.lock().unwrap().push("direct");
            if self.cut == DirectCut::PreCommitError {
                anyhow::bail!("controlled pre-COMMIT direct error");
            }
            let PersonalMessageDestination::Local(destination) = command.destination else {
                panic!("wrong destination");
            };
            let claim = (self.admitted == DirectPostCommitMode::Live
                && matches!(self.outcome, Outcome::Stored))
            .then_some(destination.delivery_id);
            let fact = match self.outcome {
                Outcome::Stored => TransactionOutcome::Stored {
                    recipient_id: destination.recipient_id,
                    delivery_id: destination.delivery_id,
                    archive_ids: command.archives.iter().map(|write| write.id).collect(),
                    live_claim_id: claim,
                },
                Outcome::Replay => TransactionOutcome::Replay {
                    archive_ids: vec![Uuid::from_u128(909)],
                },
                Outcome::Unavailable => TransactionOutcome::AccountUnavailable,
            };
            // Actual MessageApplication has already started the observer. Only
            // the same production COMMIT wrapper records these controlled cuts.
            commit_observed(
                async {
                    self.events.lock().unwrap().push("direct_commit");
                    if self.cut == DirectCut::CommitPending {
                        std::future::pending::<()>().await;
                    }
                    if self.cut == DirectCut::CommitError {
                        anyhow::bail!("controlled direct COMMIT reply loss");
                    }
                    Ok::<_, anyhow::Error>(())
                },
                observer.expect("prepared observer"),
                fact,
                self.admitted,
            )
            .await?;
            self.events.lock().unwrap().push("direct_receipt");
            if self.cut == DirectCut::AfterReceiptError {
                anyhow::bail!("controlled post-receipt mapping error");
            }
            Ok(DirectPersonalMessageAdmission {
                commit: match self.outcome {
                    Outcome::Stored => MessageCommit::Stored {
                        archive_written: !command.archives.is_empty(),
                        post_commit: MessagePostCommit::RouteLocalDelivery {
                            delivery_id: destination.delivery_id,
                            recipient_id: destination.recipient_id,
                        },
                    },
                    Outcome::Replay => MessageCommit::Replay,
                    Outcome::Unavailable => MessageCommit::AccountUnavailable,
                },
                mode: self.returned,
                live_claim_id: claim,
            })
        }
    }
    struct Port {
        owner: DirectOperationHandle,
        mode: DirectPostCommitMode,
        events: Events,
        rearmed: Mutex<Vec<DurableDelivery>>,
    }
    impl Port {
        fn new(owner: &DirectOperationHandle, events: Events) -> Self {
            Self {
                owner: owner.clone(),
                mode: DirectPostCommitMode::Live,
                events,
                rearmed: Mutex::new(vec![]),
            }
        }
    }
    impl OnlineRoutePort for Port {
        type Session = OutboundSender;
        fn try_local(
            &self,
            session: &Self::Session,
            item: RouteEnqueue,
        ) -> Result<(), RouteSendError> {
            self.events.lock().unwrap().push("enqueue");
            session.try_send_route_item(item)
        }
        fn record_local_accept(&self, _: bool) {
            assert!(self.owner.snapshot().handoff.unwrap().local_accepted);
            self.events.lock().unwrap().push("accepted");
        }
        async fn route_available_remote(
            &self,
            _: &str,
            _: &str,
            _: Option<DurableDelivery>,
        ) -> bool {
            self.events.lock().unwrap().push("remote");
            false
        }
        async fn route_remote_primary(
            &self,
            _: &str,
            _: &str,
            _: Option<DurableDelivery>,
        ) -> OnlineRouteResult {
            self.events.lock().unwrap().push("remote");
            OnlineRouteResult::default()
        }
    }
    impl FullJidFallbackPort for Port {
        fn fallback_sessions(&self, _: &str) -> Vec<(String, Self::Session)> {
            vec![]
        }
        fn available_priority(&self, _: &Self::Session) -> Option<i16> {
            Some(0)
        }
        fn priority(&self, _: &Self::Session) -> i16 {
            0
        }
        async fn privacy_allows_fallback(
            &self,
            _: &Self::Session,
            _: &str,
        ) -> anyhow::Result<bool> {
            Ok(true)
        }
        fn post_accept_failed(&self) {
            self.events.lock().unwrap().push("failed");
        }
    }
    impl DirectMessageRoutePort for Port {
        fn direct_route_mode(&self) -> DirectPostCommitMode {
            self.events.lock().unwrap().push("health");
            self.mode
        }
        fn clustered_direct_routes(&self) -> bool {
            true
        }
        async fn rearm_direct_route(&self, source: DurableDelivery) {
            self.events.lock().unwrap().push("rearm");
            self.rearmed.lock().unwrap().push(source);
        }
    }
    fn count(events: &Events, name: &str) -> usize {
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|value| **value == name)
            .count()
    }
    fn followup(owner: &DirectOperationHandle, events: &Events) {
        let snapshot = owner.snapshot();
        assert!(snapshot.finalization.is_some());
        assert!(!snapshot.finalization.unwrap().effect_started);
        events.lock().unwrap().push("followup");
    }
    #[derive(Clone, Default)]
    struct Trace(Arc<Mutex<Vec<u8>>>);
    impl Write for Trace {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Trace {
        fn install() -> (Self, tracing::subscriber::DefaultGuard) {
            let trace = Self::default();
            let writer = trace.clone();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .json()
                .with_ansi(false)
                .with_target(true)
                .with_env_filter("off,rust_xmpp_server::xmpp::protocol::messaging=debug")
                .with_writer(move || writer.clone())
                .finish();
            (trace, tracing::subscriber::set_default(subscriber))
        }
        fn events(&self) -> Vec<serde_json::Value> {
            std::str::from_utf8(&self.0.lock().unwrap())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        fn assert_finalize_warning(&self, label: &str) {
            let events = self.events();
            let warnings = events
                .iter()
                .filter(|event| {
                    event["fields"]["message"]
                        == "accepted message PoW admission could not be finalized"
                })
                .collect::<Vec<_>>();
            assert_eq!(warnings.len(), 1);
            assert_eq!(
                warnings[0]["target"],
                "rust_xmpp_server::xmpp::protocol::messaging"
            );
            assert_eq!(warnings[0]["level"], "WARN");
            assert_eq!(warnings[0]["fields"]["route"], label);
        }
    }

    #[tokio::test]
    async fn stored_live_finalizes_before_returning_one_use_route() {
        for mode in [
            Admission::Reserved,
            Admission::GuardOnly,
            Admission::NotRated,
        ] {
            let (trace, _guard) = Trace::install();
            let owner = DirectOperationHandle::new(Uuid::new_v4());
            let events = Events::default();
            let (service, mut lease) =
                admit(&owner, mode, FinalizeCut::Success, events.clone()).await;
            let begin = owner.snapshot().reservation;
            events.lock().unwrap().clear();
            let app = MessageApplication::new(Repository::stored(events.clone()));
            let delayed = String::from("<message><delay xmlns='urn:xmpp:delay'/></message>");
            let applied = commit_prepared_application(&app, prepared(&owner, mode, &delayed)).await;
            drop(delayed); // The opaque pair retains only the original live view.
            let port = Port::new(&owner, events.clone());
            let next = continue_prepared_local_direct(applied, &mut lease, &service, &port, || {
                followup(&owner, &events)
            })
            .await;
            let ContinuedLocalDirect::Live(live) = next else {
                panic!("stored live result did not produce route");
            };
            assert!(!live.archive_written());
            assert_eq!(live.source().message_id, Uuid::from_u128(2));
            assert!(lease.is_none());
            assert_eq!(owner.snapshot().reservation, begin);
            assert_eq!(
                count(&events, "followup"),
                usize::from(mode == Admission::Reserved)
            );
            assert_eq!(
                count(&events, "accept"),
                usize::from(mode == Admission::Reserved)
            );
            assert_eq!(count(&events, "health"), 1);
            assert_eq!(count(&events, "enqueue"), 0);
            if mode == Admission::Reserved {
                assert_eq!(
                    *events.lock().unwrap(),
                    [
                        "direct",
                        "direct_commit",
                        "direct_receipt",
                        "followup",
                        "accept",
                        "finalize_commit",
                        "finalize_receipt",
                        "health"
                    ]
                );
            }
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let targets = [(
                "bob@example.test/device".to_owned(),
                OutboundSender::new(tx),
            )];
            assert!(rx.try_recv().is_err());
            assert!(matches!(
                live.route_with(&port, &targets).await.unwrap(),
                DirectRouteOutcome::Routed { .. }
            ));
            let item = rx.try_recv().unwrap();
            assert_eq!(item.stanza, live_for(mode));
            assert_eq!(
                item.c2s_delivery().unwrap().claim_id,
                Some(Uuid::from_u128(2))
            );
            assert_eq!(count(&events, "enqueue"), 1);
            assert_eq!(count(&events, "failed"), 0);
            let debug = trace.events();
            let event = debug
                .iter()
                .find(|event| {
                    event["fields"]["message"]
                        == "committed durable C2S delivery before route attempt"
                })
                .unwrap();
            assert_eq!(
                event["target"],
                "rust_xmpp_server::xmpp::protocol::messaging"
            );
            assert_eq!(
                event["fields"]["recipient_id"],
                Uuid::from_u128(5).to_string()
            );
            assert_eq!(
                event["fields"]["message_id"],
                Uuid::from_u128(2).to_string()
            );
            assert_eq!(event["fields"]["target"], "bob@example.test");
        }
    }

    #[tokio::test]
    async fn spooled_and_degraded_modes_keep_distinct_health_and_rearm_short_circuits() {
        for case in 0..3 {
            let (trace, _guard) = Trace::install();
            let owner = DirectOperationHandle::new(Uuid::new_v4());
            let events = Events::default();
            let (service, mut lease) = admit(
                &owner,
                Admission::Reserved,
                FinalizeCut::PreCommitError,
                events.clone(),
            )
            .await;
            let app = MessageApplication::new(Repository {
                admitted: if case == 0 {
                    DirectPostCommitMode::SpoolOnly
                } else {
                    DirectPostCommitMode::Live
                },
                returned: if case < 2 {
                    DirectPostCommitMode::SpoolOnly
                } else {
                    DirectPostCommitMode::Live
                },
                ..Repository::stored(events.clone())
            });
            let applied =
                commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                    .await;
            let mut port = Port::new(&owner, events.clone());
            port.mode = DirectPostCommitMode::SpoolOnly;
            assert!(matches!(
                continue_prepared_local_direct(applied, &mut lease, &service, &port, || followup(
                    &owner, &events
                ))
                .await,
                ContinuedLocalDirect::Accepted
            ));
            assert_eq!(count(&events, "health"), usize::from(case == 2));
            assert_eq!(count(&events, "rearm"), usize::from(case != 0));
            assert_eq!(count(&events, "enqueue"), 0);
            assert_eq!(count(&events, "failed"), 1);
            trace.assert_finalize_warning(if case < 2 {
                "local-durable-c2s-spooled"
            } else {
                "local-durable-c2s"
            });
            let snapshot = owner.snapshot();
            assert!(snapshot.finalization.is_some());
            assert_eq!(
                snapshot.handoff.unwrap().rearm,
                if case == 0 {
                    northstar_message_application::direct_handoff::RearmKnowledge::NotRequested
                } else {
                    northstar_message_application::direct_handoff::RearmKnowledge::CallReturned
                }
            );
        }
    }

    #[tokio::test]
    async fn returned_finalize_error_continues_but_pending_finalize_blocks() {
        for cut in [
            FinalizeCut::PreCommitError,
            FinalizeCut::CommitError,
            FinalizeCut::AfterReceiptError,
            FinalizeCut::PendingBeforeCommit,
            FinalizeCut::PendingCommit,
        ] {
            let (trace, _guard) = Trace::install();
            let owner = DirectOperationHandle::new(Uuid::new_v4());
            let events = Events::default();
            let (service, mut lease) =
                admit(&owner, Admission::Reserved, cut, events.clone()).await;
            let app = MessageApplication::new(Repository::stored(events.clone()));
            let applied =
                commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                    .await;
            let before = owner.snapshot();
            let port = Port::new(&owner, events.clone());
            let pending = matches!(
                cut,
                FinalizeCut::PendingBeforeCommit | FinalizeCut::PendingCommit
            );
            let mut future = Box::pin(continue_prepared_local_direct(
                applied,
                &mut lease,
                &service,
                &port,
                || followup(&owner, &events),
            ));
            let result = futures::poll!(&mut future);
            if pending {
                assert!(result.is_pending());
            } else {
                assert!(matches!(
                    result,
                    std::task::Poll::Ready(ContinuedLocalDirect::Live(_))
                ));
            }
            drop(future);
            assert!(lease.is_none());
            assert_eq!(count(&events, "followup"), 1);
            assert_eq!(count(&events, "accept"), 1);
            assert_eq!(count(&events, "health"), usize::from(!pending));
            assert_eq!(count(&events, "failed"), usize::from(!pending));
            assert_eq!(count(&events, "enqueue"), 0);
            assert_eq!(count(&events, "rearm"), 0);
            let after = owner.snapshot();
            assert_eq!(after.reservation, before.reservation);
            assert_eq!(after.direct, before.direct);
            use northstar_abuse_policy::admission_execution::Knowledge as AdmissionKnowledge;
            let finalization = after.finalization.unwrap();
            assert!(match cut {
                FinalizeCut::PreCommitError | FinalizeCut::PendingBeforeCommit => matches!(
                    finalization.witness.knowledge(),
                    AdmissionKnowledge::NoCommitRequested
                ),
                FinalizeCut::CommitError | FinalizeCut::PendingCommit => matches!(
                    finalization.witness.knowledge(),
                    AdmissionKnowledge::CommitCallEntered(_)
                ),
                FinalizeCut::AfterReceiptError => matches!(
                    finalization.witness.knowledge(),
                    AdmissionKnowledge::ReceiptKnown(_)
                ),
                FinalizeCut::Success => unreachable!(),
            });
            if !pending {
                trace.assert_finalize_warning("local-durable-c2s");
            }
        }
    }

    #[tokio::test]
    async fn replay_results_finalize_without_live_authority() {
        for cut in [DirectCut::Success, DirectCut::AfterReceiptError] {
            let (trace, _guard) = Trace::install();
            let owner = DirectOperationHandle::new(Uuid::new_v4());
            let other = DirectOperationHandle::new(Uuid::new_v4());
            let events = Events::default();
            let (service, mut lease) = admit(
                &owner,
                Admission::Reserved,
                FinalizeCut::PreCommitError,
                events.clone(),
            )
            .await;
            let (_other_service, other_lease) = admit(
                &other,
                Admission::Reserved,
                FinalizeCut::Success,
                Events::default(),
            )
            .await;
            let _other_prepared = prepared(&other, Admission::Reserved, "other-delayed");
            let untouched = other.snapshot();
            let app = MessageApplication::new(Repository {
                cut,
                outcome: Outcome::Replay,
                ..Repository::stored(events.clone())
            });
            let applied =
                commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                    .await;
            let port = Port::new(&owner, events.clone());
            assert!(matches!(
                continue_prepared_local_direct(applied, &mut lease, &service, &port, || followup(
                    &owner, &events
                ))
                .await,
                ContinuedLocalDirect::Accepted
            ));
            assert!(lease.is_none());
            assert!(other_lease.is_some());
            assert_eq!(other.snapshot(), untouched);
            assert_eq!(count(&events, "health"), 0);
            assert_eq!(count(&events, "rearm"), 0);
            assert_eq!(count(&events, "enqueue"), 0);
            assert_eq!(count(&events, "failed"), 1);
            trace.assert_finalize_warning(if cut == DirectCut::Success {
                "local-durable-c2s-replay"
            } else {
                "local-durable-c2s-replay-continuation-unknown"
            });
            let snapshot = owner.snapshot();
            assert!(snapshot.handoff.is_none());
            let direct = snapshot.direct.unwrap();
            let Knowledge::ReceiptKnown(receipt) = &direct.knowledge else {
                panic!("Replay receipt lost");
            };
            assert_eq!(
                receipt.prepared.outcome,
                TransactionOutcome::Replay {
                    archive_ids: vec![Uuid::from_u128(909)]
                }
            );
        }
    }

    #[tokio::test]
    async fn unavailable_results_leave_finalization_and_route_untouched() {
        for cut in [DirectCut::Success, DirectCut::AfterReceiptError] {
            let owner = DirectOperationHandle::new(Uuid::new_v4());
            let other = DirectOperationHandle::new(Uuid::new_v4());
            let events = Events::default();
            let (service, mut lease) = admit(
                &owner,
                Admission::Reserved,
                FinalizeCut::Success,
                events.clone(),
            )
            .await;
            let (_other_service, other_lease) = admit(
                &other,
                Admission::Reserved,
                FinalizeCut::Success,
                Events::default(),
            )
            .await;
            let _other_prepared = prepared(&other, Admission::Reserved, "other-delayed");
            let untouched = other.snapshot();
            let app = MessageApplication::new(Repository {
                cut,
                outcome: Outcome::Unavailable,
                ..Repository::stored(events.clone())
            });
            let applied =
                commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                    .await;
            let port = Port::new(&owner, events.clone());
            let ContinuedLocalDirect::Reject(error) =
                continue_prepared_local_direct(applied, &mut lease, &service, &port, || {
                    followup(&owner, &events)
                })
                .await
            else {
                panic!("unavailable result accepted");
            };
            assert_eq!(error.stanza_error(), ("cancel", "service-unavailable"));
            assert!(lease.is_some());
            assert!(other_lease.is_some());
            assert_eq!(other.snapshot(), untouched);
            for event in ["followup", "accept", "health", "enqueue", "rearm", "failed"] {
                assert_eq!(count(&events, event), 0);
            }
            let snapshot = owner.snapshot();
            assert!(snapshot.finalization.is_none());
            assert!(snapshot.handoff.is_none());
        }
    }

    #[tokio::test]
    async fn stored_receipt_without_returned_mode_recovers_without_health() {
        let (trace, _guard) = Trace::install();
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = admit(
            &owner,
            Admission::Reserved,
            FinalizeCut::PreCommitError,
            events.clone(),
        )
        .await;
        let app = MessageApplication::new(Repository {
            cut: DirectCut::AfterReceiptError,
            ..Repository::stored(events.clone())
        });
        let applied =
            commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                .await;
        let port = Port::new(&owner, events.clone());
        assert!(matches!(
            continue_prepared_local_direct(applied, &mut lease, &service, &port, || followup(
                &owner, &events
            ))
            .await,
            ContinuedLocalDirect::Accepted
        ));
        assert!(lease.is_none());
        assert_eq!(count(&events, "failed"), 2);
        assert_eq!(count(&events, "health"), 0);
        assert_eq!(count(&events, "rearm"), 1);
        assert_eq!(count(&events, "enqueue"), 0);
        trace.assert_finalize_warning("local-durable-c2s-continuation-unknown");
        assert_eq!(
            port.rearmed.lock().unwrap().as_slice(),
            [DurableDelivery {
                recipient_id: Uuid::from_u128(5),
                message_id: Uuid::from_u128(2),
                claim_id: Some(Uuid::from_u128(2))
            }]
        );
        assert!(matches!(
            owner.snapshot().direct.unwrap().outcome,
            Some(ExecutionOutcome::ReceiptPreserved(_))
        ));
    }

    #[tokio::test]
    async fn unconfirmed_errors_keep_precommit_and_commit_unknown_separate() {
        for cut in [DirectCut::PreCommitError, DirectCut::CommitError] {
            let (trace, _guard) = Trace::install();
            let owner = DirectOperationHandle::new(Uuid::new_v4());
            let events = Events::default();
            let (service, mut lease) = admit(
                &owner,
                Admission::Reserved,
                FinalizeCut::Success,
                events.clone(),
            )
            .await;
            let app = MessageApplication::new(Repository {
                cut,
                ..Repository::stored(events.clone())
            });
            let applied =
                commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                    .await;
            let port = Port::new(&owner, events.clone());
            let ContinuedLocalDirect::Reject(error) =
                continue_prepared_local_direct(applied, &mut lease, &service, &port, || {
                    followup(&owner, &events)
                })
                .await
            else {
                panic!("unconfirmed error accepted");
            };
            assert_eq!(error.stanza_error(), ("wait", "resource-constraint"));
            assert!(lease.is_some());
            for event in ["followup", "accept", "health", "enqueue", "rearm", "failed"] {
                assert_eq!(count(&events, event), 0);
            }
            let snapshot = owner.snapshot();
            assert!(snapshot.finalization.is_none());
            assert!(snapshot.handoff.is_none());
            let direct = snapshot.direct.unwrap();
            assert!(matches!(
                (&direct.knowledge, cut),
                (Knowledge::NoCommitRequested, DirectCut::PreCommitError)
                    | (Knowledge::CommitCallEntered(_), DirectCut::CommitError)
            ));
            let warnings = trace.events();
            assert_eq!(warnings.len(), 1);
            assert_eq!(
                warnings[0]["target"],
                "rust_xmpp_server::xmpp::protocol::messaging"
            );
            assert_eq!(
                warnings[0]["fields"]["message"],
                "local history/C2S admission did not return a confirmed result"
            );
        }
        let events = Events::default();
        let child_events = events.clone();
        let pair_returned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let child_returned = pair_returned.clone();
        let (owner, runner) =
            crate::xmpp::protocol::ProtocolSession::retained_direct_frame_for_test(
                move |owner| async move {
                    let (service, mut lease) = admit(
                        &owner,
                        Admission::Reserved,
                        FinalizeCut::Success,
                        child_events.clone(),
                    )
                    .await;
                    let app = MessageApplication::new(Repository {
                        cut: DirectCut::CommitPending,
                        ..Repository::stored(child_events.clone())
                    });
                    let applied = commit_prepared_application(
                        &app,
                        prepared(&owner, Admission::Reserved, "delayed"),
                    )
                    .await;
                    child_returned.store(true, std::sync::atomic::Ordering::SeqCst);
                    let port = Port::new(&owner, child_events.clone());
                    let _ = continue_prepared_local_direct(
                        applied,
                        &mut lease,
                        &service,
                        &port,
                        || followup(&owner, &child_events),
                    )
                    .await;
                    Ok(())
                },
            );
        assert!(owner.snapshot().direct.is_none());
        let mut runner = Box::pin(runner);
        assert!(futures::poll!(&mut runner).is_pending());
        drop(runner);
        let snapshot = owner.snapshot();
        assert_eq!(snapshot.terminal, Some(TerminalReason::Cancelled));
        assert!(matches!(
            snapshot.direct.unwrap().knowledge,
            Knowledge::CommitCallEntered(_)
        ));
        assert!(snapshot
            .reservation
            .unwrap()
            .has_durable_reservation_receipt());
        assert!(snapshot.finalization.is_none());
        assert!(snapshot.handoff.is_none());
        assert!(!pair_returned.load(std::sync::atomic::Ordering::SeqCst));
        for event in ["followup", "accept", "health", "enqueue", "rearm"] {
            assert_eq!(count(&events, event), 0);
        }
    }

    #[tokio::test]
    async fn finalization_orders_missing_invalid_and_unretained_leases() {
        for case in 0..4 {
            let (trace, _guard) = Trace::install();
            let owner = DirectOperationHandle::new(Uuid::new_v4());
            let events = Events::default();
            let (service, mut lease) = if case == 1 || case == 2 {
                admit(
                    &owner,
                    Admission::Reserved,
                    FinalizeCut::Success,
                    events.clone(),
                )
                .await
            } else {
                (
                    MessageAdmissionService::new(admission_fixture::Repository {
                        admission: Admission::NotRated,
                        cut: FinalizeCut::Success,
                        events: events.clone(),
                    }),
                    (case == 3).then(|| admission_fixture::lease(3)),
                )
            };
            if case == 1 {
                lease = Some(admission_fixture::lease(99));
            }
            events.lock().unwrap().clear();
            finalize_message_admission_with(
                &service,
                &mut lease,
                "fixture-finalize",
                || {
                    events.lock().unwrap().push("lookup");
                    (case != 3).then(|| owner.clone())
                },
                || {
                    if case == 2 {
                        followup(&owner, &events);
                    } else {
                        assert!(owner.snapshot().finalization.is_none());
                        events.lock().unwrap().push("followup");
                    }
                },
                || events.lock().unwrap().push("failed"),
            )
            .await;
            assert!(lease.is_none());
            match case {
                0 => assert!(events.lock().unwrap().is_empty()),
                1 => {
                    assert_eq!(*events.lock().unwrap(), ["lookup", "followup", "failed"]);
                    trace.assert_finalize_warning("fixture-finalize");
                }
                _ => assert_eq!(
                    *events.lock().unwrap(),
                    [
                        "lookup",
                        "followup",
                        "accept",
                        "finalize_commit",
                        "finalize_receipt"
                    ]
                ),
            }
            if case != 1 {
                assert!(trace.events().is_empty());
            }
            assert_eq!(owner.snapshot().finalization.is_some(), case == 2);
        }
    }

    #[tokio::test]
    async fn continuation_rejection_never_turns_known_storage_into_live_route() {
        let (trace, _guard) = Trace::install();
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = admit(
            &owner,
            Admission::Reserved,
            FinalizeCut::Success,
            events.clone(),
        )
        .await;
        let app = MessageApplication::new(Repository::stored(events.clone()));
        let applied =
            commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                .await;
        // Complete the actual shared finalization, then retire the original
        // owner. No forged result or changed handoff fact supplies this cut.
        finalize_message_admission_with(
            &service,
            &mut lease,
            "fixture-finalize",
            || Some(owner.clone()),
            || followup(&owner, &events),
            || events.lock().unwrap().push("failed"),
        )
        .await;
        owner.retire(TerminalReason::Cancelled);
        let before = owner.snapshot();
        let port = Port::new(&owner, events.clone());
        assert!(matches!(
            continue_prepared_local_direct(applied, &mut lease, &service, &port, || panic!(
                "missing lease entered followup"
            ))
            .await,
            ContinuedLocalDirect::Accepted
        ));
        assert_eq!(owner.snapshot(), before);
        assert_eq!(count(&events, "failed"), 1);
        assert_eq!(count(&events, "accept"), 1);
        for event in ["health", "enqueue", "rearm"] {
            assert_eq!(count(&events, event), 0);
        }
        assert!(matches!(
            before.direct.unwrap().knowledge,
            Knowledge::ReceiptKnown(_)
        ));
        let trace = trace.events();
        let warning = trace
            .iter()
            .find(|event| {
                event["fields"]["message"]
                    == "stored direct handoff could not be issued; row remains recoverable"
            })
            .unwrap();
        assert_eq!(
            warning["target"],
            "rust_xmpp_server::xmpp::protocol::messaging"
        );
    }

    #[tokio::test]
    async fn defensive_stored_shape_retains_existing_internal_error() {
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = admit(
            &owner,
            Admission::Reserved,
            FinalizeCut::Success,
            events.clone(),
        )
        .await;
        let continuation = prepared(&owner, Admission::Reserved, "delayed").into_continuation();
        let before = owner.snapshot();
        // Deliberately synthetic module-private defensive input. No public pair
        // constructor or application-composition claim is introduced here.
        let malformed = AppliedLocalDirect {
            actual: Ok(DirectPersonalMessageAdmission {
                commit: MessageCommit::Stored {
                    archive_written: true,
                    post_commit: MessagePostCommit::WakeFederationOutbox,
                },
                mode: DirectPostCommitMode::Live,
                live_claim_id: None,
            }),
            continuation,
        };
        let port = Port::new(&owner, events.clone());
        let ContinuedLocalDirect::Reject(error) =
            continue_prepared_local_direct(malformed, &mut lease, &service, &port, || {
                panic!("malformed stored result finalized")
            })
            .await
        else {
            panic!("malformed stored result accepted");
        };
        assert_eq!(error.stanza_error(), ("wait", "internal-server-error"));
        assert!(lease.is_some());
        assert_eq!(owner.snapshot(), before);
        for event in ["followup", "accept", "health", "enqueue", "rearm", "failed"] {
            assert_eq!(count(&events, event), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_message_application::direct_lifecycle::{DirectOutcomeClass, TerminalReason};
    use northstar_message_core::LocalDelivery;

    fn prepared() -> (DirectOperationHandle, PreparedLocalDirect<'static, 'static>) {
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let command = ValidatedPersonalMessage {
            local_actor_id: Some(Uuid::from_u128(1)),
            identity: None,
            archives: &[],
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: Uuid::from_u128(2),
                recipient_id: Uuid::from_u128(3),
                recipient_bare_jid: "bob@example.test",
                sender_jid: "alice@example.test/device",
                stanza: "private-stored-stanza",
                encrypted: false,
                mam_backed: false,
            }),
        };
        let prepared = PreparedLocalDirect::bind(
            owner.clone(),
            LocalPreparation {
                actor_id: Uuid::from_u128(1),
                sender_bare: "alice@example.test",
                sender_full: "alice@example.test/device",
                target_bare: "bob@example.test",
                target_full: "bob@example.test",
                message_type: "chat",
                live_stanza: "private-live-stanza",
                origin_id: None,
                identity_payload: "private-identity-stanza",
                stored_stanza: "private-stored-stanza",
                admission: PreparationAdmission::NoAdmissionRequired,
            },
            command,
            DirectSpoolEligibility::Eligible,
            LiveDirectBinding {
                sender: "alice@example.test/device",
                target: "bob@example.test",
                target_bare: "bob@example.test",
                message_type: "chat",
                stanza: "private-live-stanza",
                recipient_id: Uuid::from_u128(3),
            },
        )
        .unwrap();
        (owner, prepared)
    }
    fn stored() -> TransactionOutcome {
        TransactionOutcome::Stored {
            recipient_id: Uuid::from_u128(3),
            delivery_id: Uuid::from_u128(2),
            archive_ids: vec![],
            live_claim_id: Some(Uuid::from_u128(2)),
        }
    }

    #[tokio::test]
    async fn real_commit_wrapper_preserves_every_cancellation_cut_in_outer_owner() {
        for cut in 0..4 {
            let (owner, prepared) = prepared();
            let mut future = Box::pin(async {
                prepared
                    .start(prepared.command(), prepared.eligibility())
                    .unwrap();
                if cut == 1 {
                    std::future::pending::<()>().await;
                }
                commit_observed(
                    async {
                        if cut == 2 {
                            std::future::pending::<()>().await;
                        }
                        Ok::<(), anyhow::Error>(())
                    },
                    &prepared,
                    stored(),
                    DirectPostCommitMode::Live,
                )
                .await
                .unwrap();
                std::future::pending::<()>().await;
            });
            if cut != 0 {
                assert!(futures::poll!(&mut future).is_pending());
            }
            drop(future);
            drop(prepared);
            let snapshot = owner.snapshot().direct.unwrap();
            assert_eq!(snapshot.started, cut != 0);
            assert!(matches!(
                (&snapshot.knowledge, cut),
                (Knowledge::NoCommitRequested, 0 | 1)
                    | (Knowledge::CommitCallEntered(_), 2)
                    | (Knowledge::ReceiptKnown(_), 3)
            ));
            assert_eq!(snapshot.outcome, None);
            let summary = owner.retire(TerminalReason::Cancelled).direct.unwrap();
            assert_eq!(
                summary.confirmed_outcome,
                (cut == 3).then_some(DirectOutcomeClass::Stored)
            );
            assert_eq!(summary.returned_mode, None);
        }
    }

    #[test]
    fn prepared_command_is_immutable_at_the_actual_application_observer_entry() {
        let (owner, prepared) = prepared();
        let mut changed = *prepared.command();
        let PersonalMessageDestination::Local(mut destination) = changed.destination else {
            unreachable!()
        };
        destination.stanza = "substituted stored payload";
        changed.destination = PersonalMessageDestination::Local(destination);
        let before = owner.snapshot();
        assert_eq!(
            prepared.start(&changed, prepared.eligibility()),
            Err(Rejected::Command)
        );
        assert_eq!(owner.snapshot(), before);
        prepared
            .start(prepared.command(), prepared.eligibility())
            .unwrap();
        assert_eq!(
            prepared.start(prepared.command(), prepared.eligibility()),
            Err(Rejected::AlreadyStarted)
        );
        assert!(!format!("{prepared:?}").contains("private-"));
    }

    #[tokio::test]
    async fn known_transaction_outcome_survives_mapping_error_without_fabricating_mode_or_delivery()
    {
        for fact in [
            stored(),
            TransactionOutcome::Replay {
                archive_ids: vec![Uuid::from_u128(99)],
            },
            TransactionOutcome::AccountUnavailable,
        ] {
            let (owner, prepared) = prepared();
            prepared
                .start(prepared.command(), prepared.eligibility())
                .unwrap();
            commit_observed(
                async { Ok::<(), anyhow::Error>(()) },
                &prepared,
                fact.clone(),
                DirectPostCommitMode::Live,
            )
            .await
            .unwrap();
            let outcome = prepared.complete(None).unwrap();
            let error = continuation_error(
                anyhow::anyhow!("injected continuation failure"),
                Some(outcome),
            );
            assert_eq!(preserved_transaction(&error), Some(&fact));
            assert_eq!(
                owner
                    .retire(TerminalReason::Completed)
                    .direct
                    .unwrap()
                    .returned_mode,
                None
            );
        }
    }

    fn complete_stored(prepared: &PreparedLocalDirect<'_, '_>, mode: Option<DirectPostCommitMode>) {
        use northstar_message_core::{MessageCommit, MessagePostCommit};
        prepared
            .start(prepared.command(), prepared.eligibility())
            .unwrap();
        let transaction = prepared
            .prepare(stored(), DirectPostCommitMode::Live)
            .unwrap();
        prepared.received(transaction).unwrap();
        prepared
            .complete(mode.map(|mode| DirectPersonalMessageAdmission {
                commit: MessageCommit::Stored {
                    archive_written: false,
                    post_commit: MessagePostCommit::RouteLocalDelivery {
                        recipient_id: Uuid::from_u128(3),
                        delivery_id: Uuid::from_u128(2),
                    },
                },
                mode,
                live_claim_id: Some(Uuid::from_u128(2)),
            }))
            .unwrap();
    }
    fn route_request<S>(targets: &[(String, S)]) -> super::super::DirectRouteRequest<'_, S> {
        super::super::DirectRouteRequest {
            message_type: "chat",
            target: super::super::DirectRouteTarget::Bare("bob@example.test"),
            sender: "alice@example.test/device",
            recipient_id: Uuid::from_u128(3),
            stanza: "private-live-stanza",
            delivery: super::super::DirectRouteDelivery::Committed(
                crate::outbound::DurableDelivery {
                    recipient_id: Uuid::from_u128(3),
                    message_id: Uuid::from_u128(2),
                    claim_id: Some(Uuid::from_u128(2)),
                },
            ),
            approved_targets: targets,
            enforce_direct_health: true,
        }
    }
    fn handoff() -> (DirectOperationHandle, PreparedDirectHandoff<'static>) {
        let (owner, prepared) = prepared();
        complete_stored(&prepared, Some(DirectPostCommitMode::Live));
        let PreparedHandoffNext::Route(handoff) = prepared
            .into_continuation()
            .after_finalize(|| DirectPostCommitMode::Live)
            .unwrap()
        else {
            unreachable!()
        };
        (owner, handoff)
    }

    #[test]
    fn retained_continuation_keeps_the_actual_mode_read_short_circuit() {
        for returned in [
            None,
            Some(DirectPostCommitMode::SpoolOnly),
            Some(DirectPostCommitMode::Live),
        ] {
            let (_, prepared) = prepared();
            complete_stored(&prepared, returned);
            let reads = std::cell::Cell::new(0);
            let next = prepared
                .into_continuation()
                .after_finalize(|| {
                    reads.set(reads.get() + 1);
                    DirectPostCommitMode::Live
                })
                .unwrap();
            assert_eq!(
                reads.get(),
                usize::from(returned == Some(DirectPostCommitMode::Live))
            );
            assert_eq!(
                matches!(next, PreparedHandoffNext::Route(_)),
                returned == Some(DirectPostCommitMode::Live)
            );
        }
    }

    #[test]
    fn actual_prepared_router_binding_rejects_changed_live_authority_before_consumption() {
        for mutation in 0..8 {
            let (owner, handoff) = handoff();
            let before = owner.snapshot();
            let mut request = route_request::<()>(&[]);
            match mutation {
                0 => request.sender = "mallory@example.test/device",
                1 => request.recipient_id = Uuid::from_u128(99),
                2 => request.stanza = "changed live payload",
                3 => request.target = super::super::DirectRouteTarget::Bare("mallory@example.test"),
                4 => {
                    request.target = super::super::DirectRouteTarget::Full {
                        jid: "bob@example.test",
                        bare: "mallory@example.test",
                    }
                }
                5 => {
                    request.target = super::super::DirectRouteTarget::Full {
                        jid: "bob@example.test",
                        bare: "bob@example.test",
                    }
                }
                6 => request.enforce_direct_health = false,
                _ => request.message_type = "headline",
            }
            assert!(handoff.bind_route(&request).is_err());
            assert_eq!(owner.snapshot(), before);
        }
        let (owner, handoff) = handoff();
        let (item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
        assert_eq!(item.stanza, "private-live-stanza");
        assert!(owner.snapshot().reservation.is_none());
        assert_eq!(witness.snapshot().source, item.c2s_delivery().unwrap());
    }

    #[test]
    fn real_enqueue_gate_refuses_wrong_source_and_same_ids_changed_payload_without_sending() {
        use crate::outbound::{OutboundItem, OutboundSender, RouteEnqueue};
        for changed_source in [true, false] {
            let (_, handoff) = handoff();
            let (mut item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
            let source = item.c2s_delivery().unwrap();
            let permit = witness.local_permit(source).unwrap();
            if changed_source {
                item = OutboundItem::durable(
                    item.stanza,
                    crate::outbound::DurableDelivery {
                        message_id: Uuid::from_u128(99),
                        ..source
                    },
                );
            } else {
                item.stanza = "changed private payload".into();
            }
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let sender = OutboundSender::new(tx);
            let rejected =
                RouteEnqueue::bind(item, Some(permit), "private-live-stanza").unwrap_err();
            assert!(!format!("{rejected:?}").contains("private"));
            assert!(!witness.snapshot().local_accepted);
            assert_eq!(
                witness.snapshot().local_call,
                northstar_message_application::direct_handoff::LocalKnowledge::NotRequested
            );
            assert!(witness.local_permit(source).is_ok());
            assert!(rx.try_recv().is_err());
            assert!(!sender.backpressure_disconnect().is_cancelled());
        }
    }

    #[test]
    fn actual_full_and_closed_refusals_preserve_item_channels_and_disconnect_order() {
        use crate::outbound::{OutboundSender, RouteEnqueue};
        use northstar_message_application::direct_handoff::Refusal;
        for closed in [false, true] {
            let (_, handoff) = handoff();
            let (mut item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
            let source = item.c2s_delivery().unwrap();
            let (receipt, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
            item.transport_receipt = Some(receipt);
            let address = item.stanza.as_ptr();
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let sender = OutboundSender::new(tx);
            if closed {
                rx.close();
            } else {
                sender.try_send("occupied".into()).unwrap();
            }
            let enqueue = RouteEnqueue::bind(
                item,
                Some(witness.local_permit(source).unwrap()),
                "private-live-stanza",
            )
            .unwrap();
            let refused = sender.try_send_route_item(enqueue).unwrap_err();
            let item = match refused {
                crate::outbound::RouteSendError::Full(item) => {
                    assert!(!closed);
                    assert!(sender.backpressure_disconnect().is_cancelled());
                    item
                }
                crate::outbound::RouteSendError::Closed(item) => {
                    assert!(closed);
                    item
                }
                crate::outbound::RouteSendError::Binding(_) => panic!("valid item rejected"),
            };
            assert_eq!(item.stanza.as_ptr(), address);
            assert_eq!(item.c2s_delivery(), Some(source));
            assert_eq!(
                witness.snapshot().last_local_refusal,
                Some(if closed {
                    Refusal::Closed
                } else {
                    Refusal::Full
                })
            );
            assert!(receipt_rx.try_recv().is_err());
            let (tx, mut accepted_rx) = tokio::sync::mpsc::channel(1);
            let next = OutboundSender::new(tx);
            next.try_send_route_item(
                RouteEnqueue::bind(
                    item,
                    Some(witness.local_permit(source).unwrap()),
                    "private-live-stanza",
                )
                .unwrap(),
            )
            .unwrap();
            assert!(witness.snapshot().local_accepted);
            let received = accepted_rx.try_recv().unwrap();
            assert_eq!(received.stanza.as_ptr(), address);
            received.confirm_transport_ownership();
            assert_eq!(receipt_rx.try_recv(), Ok(()));
        }
    }

    struct RealQueuePort {
        owner: DirectOperationHandle,
        events: std::sync::Mutex<Vec<&'static str>>,
        pending_rearm: bool,
    }
    impl super::super::OnlineRoutePort for RealQueuePort {
        type Session = crate::outbound::OutboundSender;
        fn try_local(
            &self,
            session: &Self::Session,
            enqueue: crate::outbound::RouteEnqueue,
        ) -> Result<(), crate::outbound::RouteSendError> {
            self.events.lock().unwrap().push("enqueue");
            session.try_send_route_item(enqueue)
        }
        fn record_local_accept(&self, _: bool) {
            assert!(self.owner.snapshot().handoff.unwrap().local_accepted);
            self.events.lock().unwrap().push("accepted");
        }
        async fn route_available_remote(
            &self,
            _: &str,
            _: &str,
            _: Option<crate::outbound::DurableDelivery>,
        ) -> bool {
            false
        }
        async fn route_remote_primary(
            &self,
            _: &str,
            _: &str,
            _: Option<crate::outbound::DurableDelivery>,
        ) -> super::super::OnlineRouteResult {
            self.events.lock().unwrap().push("remote");
            super::super::OnlineRouteResult::default()
        }
    }
    impl super::super::FullJidFallbackPort for RealQueuePort {
        fn fallback_sessions(&self, _: &str) -> Vec<(String, Self::Session)> {
            vec![]
        }
        fn available_priority(&self, _: &Self::Session) -> Option<i16> {
            Some(0)
        }
        fn priority(&self, _: &Self::Session) -> i16 {
            0
        }
        async fn privacy_allows_fallback(
            &self,
            _: &Self::Session,
            _: &str,
        ) -> anyhow::Result<bool> {
            Ok(true)
        }
        fn post_accept_failed(&self) {
            self.events.lock().unwrap().push("failed");
        }
    }
    impl super::super::DirectMessageRoutePort for RealQueuePort {
        fn direct_route_mode(&self) -> DirectPostCommitMode {
            self.events.lock().unwrap().push("health");
            DirectPostCommitMode::Live
        }
        fn clustered_direct_routes(&self) -> bool {
            true
        }
        async fn rearm_direct_route(&self, _: crate::outbound::DurableDelivery) {
            self.events.lock().unwrap().push("rearm");
            if self.pending_rearm {
                std::future::pending::<()>().await;
            }
        }
    }

    #[tokio::test]
    async fn real_router_sender_queue_fact_survives_a_later_outer_continuation_cancel() {
        let (owner, handoff) = handoff();
        let port = RealQueuePort {
            owner: owner.clone(),
            events: Default::default(),
            pending_rearm: false,
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let targets = [(
            "bob@example.test/device".into(),
            crate::outbound::OutboundSender::new(tx),
        )];
        let mut future = Box::pin(async {
            let outcome = super::super::DirectMessageRouter::route_prepared(
                &port,
                route_request(&targets),
                handoff,
            )
            .await
            .unwrap();
            assert!(matches!(
                outcome,
                super::super::DirectRouteOutcome::Routed { .. }
            ));
            // Controlled outer-followup suspension, after the real router has
            // returned; the local-success router itself need not suspend.
            std::future::pending::<()>().await;
        });
        assert!(futures::poll!(&mut future).is_pending());
        drop(future);
        let summary = owner.retire(TerminalReason::Cancelled);
        assert!(summary.handoff.unwrap().local_accepted);
        assert_eq!(
            summary.handoff.unwrap().route_end,
            northstar_message_application::direct_handoff::RouteEnd::Returned
        );
        let item = rx.try_recv().unwrap();
        assert_eq!(item.stanza, "private-live-stanza");
        assert_eq!(
            item.c2s_delivery().unwrap().claim_id,
            Some(Uuid::from_u128(2))
        );
        assert_eq!(
            *port.events.lock().unwrap(),
            ["health", "enqueue", "accepted", "health"]
        );
    }

    #[tokio::test]
    async fn real_router_rearm_entry_survives_cancellation_without_claiming_release() {
        let (owner, handoff) = handoff();
        let port = RealQueuePort {
            owner: owner.clone(),
            events: Default::default(),
            pending_rearm: true,
        };
        let mut future = Box::pin(super::super::DirectMessageRouter::route_prepared(
            &port,
            route_request(&[]),
            handoff,
        ));
        assert!(futures::poll!(&mut future).is_pending());
        drop(future);
        let snapshot = owner.snapshot().handoff.unwrap();
        assert_eq!(
            snapshot.rearm,
            northstar_message_application::direct_handoff::RearmKnowledge::CallEntered
        );
        assert_eq!(
            snapshot.route_end,
            northstar_message_application::direct_handoff::RouteEnd::Dropped
        );
        assert!(snapshot.prior_remote_uncertain);
        assert!(!snapshot.local_accepted);
        assert_eq!(*port.events.lock().unwrap(), ["health", "remote", "rearm"]);
    }

    #[test]
    fn refused_item_is_rechecked_against_the_original_live_projection_before_retry() {
        let (owner, handoff) = handoff();
        let (item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
        let port = RealQueuePort {
            owner: owner.clone(),
            events: Default::default(),
            pending_rearm: false,
        };
        let mut payload =
            super::super::RoutePayload::prepared("private-live-stanza", item, witness.clone());
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let sender = crate::outbound::OutboundSender::new(tx);
        rx.close();
        assert!(!payload.enqueue(&port, &sender));
        let before = owner.snapshot();
        // Deliberately corrupt only the refused value in this controlled test;
        // production keeps this value private between attempts.
        payload.item.as_mut().unwrap().stanza = "same IDs, substituted payload".into();
        let (tx, mut accepted_rx) = tokio::sync::mpsc::channel(1);
        let next = crate::outbound::OutboundSender::new(tx);
        assert!(!payload.enqueue(&port, &next));
        assert!(payload.binding_rejected);
        assert_eq!(owner.snapshot(), before);
        assert!(accepted_rx.try_recv().is_err());
        assert_eq!(*port.events.lock().unwrap(), ["enqueue"]);
    }

    #[test]
    fn live_preparation_comparison_rejects_substituted_projection_before_direct_effect() {
        for mutation in 0..5 {
            let (_, template) = prepared();
            let owner = DirectOperationHandle::new(Uuid::new_v4());
            let mut live = LiveDirectBinding {
                sender: "alice@example.test/device",
                target: "bob@example.test",
                target_bare: "bob@example.test",
                message_type: "chat",
                stanza: "private-live-stanza",
                recipient_id: Uuid::from_u128(3),
            };
            match mutation {
                0 => live.sender = "mallory@example.test/device",
                1 => live.target = "bob@example.test/other",
                2 => live.recipient_id = Uuid::from_u128(99),
                3 => live.stanza = "substituted-live-stanza",
                _ => live.target_bare = "mallory@example.test",
            }
            let before = owner.snapshot();
            let result = PreparedLocalDirect::bind(
                owner.clone(),
                LocalPreparation {
                    actor_id: Uuid::from_u128(1),
                    sender_bare: "alice@example.test",
                    sender_full: "alice@example.test/device",
                    target_bare: "bob@example.test",
                    target_full: "bob@example.test",
                    message_type: "chat",
                    live_stanza: "private-live-stanza",
                    origin_id: None,
                    identity_payload: "private-identity-stanza",
                    stored_stanza: "private-stored-stanza",
                    admission: PreparationAdmission::NoAdmissionRequired,
                },
                *template.command(),
                DirectSpoolEligibility::Eligible,
                live,
            );
            assert!(result.is_err());
            assert_eq!(owner.snapshot(), before);
        }
    }

    #[test]
    fn held_enqueue_permit_cannot_start_after_frame_retirement() {
        use crate::outbound::{OutboundSender, RouteEnqueue, RouteSendError};
        let (owner, handoff) = handoff();
        let (item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
        let permit = witness.local_permit(item.c2s_delivery().unwrap()).unwrap();
        let enqueue = RouteEnqueue::bind(item, Some(permit), "private-live-stanza").unwrap();
        owner.retire(TerminalReason::Cancelled);
        let before = owner.snapshot();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let sender = OutboundSender::new(tx);
        assert!(matches!(
            sender.try_send_route_item(enqueue),
            Err(RouteSendError::Binding(_))
        ));
        assert_eq!(owner.snapshot(), before);
        assert!(rx.try_recv().is_err());
    }
}
