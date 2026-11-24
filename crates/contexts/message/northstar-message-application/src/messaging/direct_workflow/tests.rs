//! Module-private defensive input and owner tests for the actual application,
//! admission finalization and immutable live continuation.
use super::*;
use crate::direct_lifecycle::OriginalAdmission;
use crate::message_admission::continuation_fixture::{
    self as admission_fixture, Admission, Events, FinalizeCut,
};
use crate::message_admission::{self as admission_service, witness::AdmissionWitness};
use crate::messaging as messaging_service;
use crate::messaging::{
    DirectMessageRoutePort, FullJidFallbackPort, OnlineRoutePort, OnlineRouteResult,
};
use crate::test_queue::TestItem;

mod direct_invitation_stub;
use northstar_abuse_policy::admission_execution::{
    AdmissionCommitObserver, CommitFact, FinalizeSuccess, TransactionScope,
};
use northstar_abuse_policy::admission_transaction::{AdmissionFence, FinalizeDecision};
use northstar_abuse_policy::message_admission::{
    acceptance_fence, MessageAdmissionAcceptance, MessageAdmissionLease, MessageAdmissionStart,
};
use northstar_abuse_policy::MessageAdmissionRequest;
use northstar_delivery_core::DurableDelivery;
use northstar_message_core::route_item::{RouteEnqueue, RouteItem as _, RouteSendError};
use northstar_message_core::{
    ArchiveCandidate, ArchiveDirection, ArchiveProjection, LocalDelivery, MessageIdentity,
};
use std::sync::{Arc, Mutex};

struct CloneProbe<T>(std::marker::PhantomData<T>);
trait NotClone {
    fn is_clone(&self) -> bool {
        false
    }
}
impl<T> NotClone for CloneProbe<T> {}
impl<T: Clone> CloneProbe<T> {
    fn is_clone(&self) -> bool {
        true
    }
}

#[test]
fn applied_local_direct_is_not_cloneable() {
    assert!(!CloneProbe::<AppliedLocalDirect<'static>>(std::marker::PhantomData).is_clone());
    assert!(CloneProbe::<String>(std::marker::PhantomData).is_clone());
}

const LIVE: &str = "<message id='live'><body>private live</body></message>";

fn prepared<'command>(
    owner: &DirectOperationHandle,
    stored: &'command str,
) -> PreparedLocalDirect<'command, 'static> {
    let request = admission_fixture::request();
    let command = ValidatedPersonalMessage {
        local_actor_id: Some(request.actor_id),
        local_actor_fence: None,
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
            live_stanza: LIVE,
            origin_id: request.origin_id,
            identity_payload: "private-identity-stanza",
            stored_stanza: stored,
            admission: PreparationAdmission::Rated(OriginalAdmission {
                actor_id: request.actor_id,
                account_bare: request.account_bare,
                normalized_target: request.normalized_target,
                origin_id: request.origin_id,
                normalized_payload: request.normalized_payload,
            }),
        },
        command,
        DirectSpoolEligibility::Eligible,
        LiveDirectBinding {
            sender: "alice@example.test/device",
            target: "bob@example.test",
            target_bare: "bob@example.test",
            message_type: "chat",
            stanza: LIVE,
            recipient_id: Uuid::from_u128(5),
        },
    )
    .unwrap()
}

/// Records every call. The test requires that none of them is made.
struct Port(Events);
impl OnlineRoutePort for Port {
    type Item = TestItem;
    type Session = ();
    fn try_local(&self, _: &(), _: RouteEnqueue<TestItem>) -> Result<(), RouteSendError<TestItem>> {
        self.0.lock().unwrap().push("enqueue");
        Ok(())
    }
    fn record_local_accept(&self, _: bool) {
        self.0.lock().unwrap().push("accepted");
    }
    async fn route_available_remote(&self, _: &str, _: &str, _: Option<DurableDelivery>) -> bool {
        self.0.lock().unwrap().push("remote");
        false
    }
    async fn route_remote_primary(
        &self,
        _: &str,
        _: &str,
        _: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.0.lock().unwrap().push("remote");
        OnlineRouteResult::default()
    }
}
impl FullJidFallbackPort for Port {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, ())> {
        vec![]
    }
    fn available_priority(&self, _: &()) -> Option<i16> {
        Some(0)
    }
    fn priority(&self, _: &()) -> i16 {
        0
    }
    async fn privacy_allows_fallback(&self, _: &(), _: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
    fn post_accept_failed(&self) {
        self.0.lock().unwrap().push("failed");
    }
}
impl DirectMessageRoutePort for Port {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        self.0.lock().unwrap().push("health");
        DirectPostCommitMode::Live
    }
    fn clustered_direct_routes(&self) -> bool {
        true
    }
    async fn rearm_direct_route(&self, _: DurableDelivery) {
        self.0.lock().unwrap().push("rearm");
    }
}

#[tokio::test]
async fn defensive_stored_shape_retains_existing_internal_error() {
    let owner = DirectOperationHandle::new(Uuid::new_v4());
    let events = Events::default();
    let service = MessageAdmissionService::new(admission_fixture::Repository {
        admission: Admission::Reserved,
        cut: FinalizeCut::Success,
        events: events.clone(),
    });
    let request = admission_fixture::request();
    let retained = owner.begin(&request).unwrap();
    let MessageAdmissionStart::Proceed { mut lease, .. } = service
        .begin_message_admission_retained(&request, &retained)
        .await
        .unwrap()
    else {
        panic!("fixture admission rejected");
    };
    let continuation = prepared(&owner, "delayed").into_continuation();
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
    let port = Port(events.clone());
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
        assert!(!events.lock().unwrap().contains(&event));
    }
}

/// The sender controls the exact completion cut after the service has entered
/// acceptance. Tests poll the same future again, without spawning a task.
#[derive(Clone)]
struct RecordingAdmission {
    events: Events,
    fences: Arc<Mutex<Vec<AdmissionFence>>>,
    release: Arc<Mutex<Option<tokio::sync::oneshot::Receiver<FinalizeCut>>>>,
    admission: Admission,
    cut: FinalizeCut,
}

impl RecordingAdmission {
    fn new(events: Events, admission: Admission, cut: FinalizeCut) -> Self {
        Self {
            events,
            fences: Arc::default(),
            release: Arc::default(),
            admission,
            cut,
        }
    }

    fn hold(&self) -> tokio::sync::oneshot::Sender<FinalizeCut> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        *self.release.lock().unwrap() = Some(receiver);
        sender
    }
}

impl MessageAdmissionRepository for RecordingAdmission {
    async fn begin(
        &self,
        request: &MessageAdmissionRequest<'_>,
        witness: &AdmissionWitness,
    ) -> anyhow::Result<MessageAdmissionStart> {
        assert_eq!(
            admission_service::begin_command(request)?,
            witness.snapshot().effect().command
        );
        admission_fixture::Repository {
            admission: self.admission,
            cut: FinalizeCut::Success,
            events: self.events.clone(),
        }
        .begin(request, witness)
        .await
    }

    async fn accept(
        &self,
        acceptance: &MessageAdmissionAcceptance<'_>,
        witness: &AdmissionWitness,
    ) -> anyhow::Result<FinalizeDecision> {
        let fence = acceptance_fence(acceptance);
        assert_eq!(
            witness.snapshot().effect().command,
            northstar_abuse_policy::admission_execution::Command::Finalize(fence.clone())
        );
        self.fences.lock().unwrap().push(fence.clone());
        self.events.lock().unwrap().push("accept");
        let release = self.release.lock().unwrap().take();
        let cut = match release {
            Some(receiver) => receiver.await.expect("test supplies finalization result"),
            None => self.cut,
        };
        if cut == FinalizeCut::PreCommitError {
            anyhow::bail!("controlled finalization failure before commit");
        }
        let prepared = witness.prepare(
            TransactionScope::AdmissionFinalize,
            CommitFact::Finalized {
                fence,
                result: FinalizeSuccess::PendingAccepted,
            },
        )?;
        self.events.lock().unwrap().push("finalize_commit");
        if cut == FinalizeCut::CommitError {
            anyhow::bail!("controlled finalization commit reply loss");
        }
        witness.received(prepared);
        self.events.lock().unwrap().push("finalize_receipt");
        if cut == FinalizeCut::AfterReceiptError {
            anyhow::bail!("controlled finalization failure after receipt");
        }
        Ok(FinalizeDecision::AcceptPending)
    }

    async fn reconcile(
        &self,
        _: &northstar_abuse_policy::admission_execution::Effect,
    ) -> anyhow::Result<northstar_abuse_policy::admission_execution::ReconcileResult> {
        panic!("continuation scheduled reconciliation");
    }
}

async fn issue_admission(
    owner: &DirectOperationHandle,
    repository: RecordingAdmission,
    request: &MessageAdmissionRequest<'_>,
) -> (
    MessageAdmissionService<RecordingAdmission>,
    Option<MessageAdmissionLease>,
) {
    let admission = repository.admission;
    let service = MessageAdmissionService::new(repository);
    let lease = if admission == Admission::NotRated {
        None
    } else {
        let retained = owner.begin(request).unwrap();
        let MessageAdmissionStart::Proceed { lease, .. } = service
            .begin_message_admission_retained(request, &retained)
            .await
            .unwrap()
        else {
            panic!("fixture admission rejected");
        };
        lease
    };
    (service, lease)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Transaction {
    Stored,
    Replay,
    Unavailable,
    Unconfirmed,
}

#[derive(Clone)]
struct RecordingCommit {
    events: Events,
    transaction: Transaction,
    mode: DirectPostCommitMode,
    after_receipt_error: bool,
    stored: String,
    archive_ids: Vec<Uuid>,
    eligibility: DirectSpoolEligibility,
}

impl RecordingCommit {
    fn stored(events: Events) -> Self {
        Self {
            events,
            transaction: Transaction::Stored,
            mode: DirectPostCommitMode::Live,
            after_receipt_error: false,
            stored: "delayed stored projection".into(),
            archive_ids: vec![],
            eligibility: DirectSpoolEligibility::Eligible,
        }
    }
}

impl crate::PersonalMessageCommitRepository for RecordingCommit {
    type Error = anyhow::Error;
    async fn commit<'a>(
        &'a self,
        _: &'a ValidatedPersonalMessage<'a>,
    ) -> anyhow::Result<MessageCommit> {
        panic!("prepared application used legacy commit");
    }
}

impl DirectCommitRepository for RecordingCommit {
    type Error = anyhow::Error;
    async fn commit_direct<'a>(
        &'a self,
        command: &'a ValidatedPersonalMessage<'a>,
        eligibility: DirectSpoolEligibility,
        observer: Option<&'a dyn DirectCommitObserver>,
    ) -> anyhow::Result<DirectPersonalMessageAdmission> {
        self.events.lock().unwrap().push("direct");
        assert_eq!(command.local_actor_id, Some(Uuid::from_u128(1)));
        assert_eq!(
            command.identity,
            Some(MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: "alice@example.test",
                actor_scope: "alice@example.test",
                target_scope: "bob@example.test",
                value: "origin",
                payload: "private-identity-stanza",
            })
        );
        let archives: Vec<_> = self
            .archive_ids
            .iter()
            .map(|id| ArchiveCandidate {
                direction: ArchiveDirection::Outbound,
                projection: ArchiveProjection {
                    id: *id,
                    owner_id: Uuid::from_u128(1),
                    peer_jid: "bob@example.test",
                    stanza: &self.stored,
                    encrypted: false,
                    stanza_id: Some("origin"),
                },
            })
            .collect();
        assert_eq!(command.archives, archives.as_slice());
        assert_eq!(eligibility, self.eligibility);
        let PersonalMessageDestination::Local(destination) = command.destination else {
            panic!("prepared command changed destination");
        };
        assert_eq!(
            destination,
            LocalDelivery {
                delivery_id: Uuid::from_u128(2),
                recipient_id: Uuid::from_u128(5),
                recipient_bare_jid: "bob@example.test",
                sender_jid: "alice@example.test/device",
                stanza: &self.stored,
                encrypted: false,
            }
        );
        if self.transaction == Transaction::Unconfirmed {
            anyhow::bail!("controlled unconfirmed direct result");
        }
        let claim = (self.transaction == Transaction::Stored
            && self.mode == DirectPostCommitMode::Live)
            .then_some(destination.delivery_id);
        let outcome = match self.transaction {
            Transaction::Stored => TransactionOutcome::Stored {
                recipient_id: destination.recipient_id,
                delivery_id: destination.delivery_id,
                archive_ids: self.archive_ids.clone(),
                live_claim_id: claim,
            },
            Transaction::Replay => TransactionOutcome::Replay {
                archive_ids: vec![Uuid::from_u128(90)],
            },
            Transaction::Unavailable => TransactionOutcome::AccountUnavailable,
            Transaction::Unconfirmed => unreachable!(),
        };
        commit_observed(
            async {
                self.events.lock().unwrap().push("direct_commit");
                Ok::<_, anyhow::Error>(())
            },
            observer.expect("application forwards the prepared observer"),
            outcome,
            self.mode,
        )
        .await?;
        self.events.lock().unwrap().push("direct_receipt");
        if self.after_receipt_error {
            anyhow::bail!("controlled error mapping the committed result");
        }
        Ok(DirectPersonalMessageAdmission {
            commit: match self.transaction {
                Transaction::Stored => MessageCommit::Stored {
                    archive_written: !self.archive_ids.is_empty(),
                    post_commit: MessagePostCommit::RouteLocalDelivery {
                        delivery_id: destination.delivery_id,
                        recipient_id: destination.recipient_id,
                    },
                },
                Transaction::Replay => MessageCommit::Replay,
                Transaction::Unavailable => MessageCommit::AccountUnavailable,
                Transaction::Unconfirmed => unreachable!(),
            },
            mode: self.mode,
            live_claim_id: claim,
        })
    }
}

// Every other MessageService capability is a tripwire: this entry point only
// needs the owned prepared application bridge.
impl messaging_service::MessageRepository for RecordingCommit {
    fn direct_mode(&self) -> DirectPostCommitMode {
        panic!("unprepared mode read")
    }
    fn clustered_direct_admission_enabled(&self) -> bool {
        panic!("unprepared cluster read")
    }
    async fn release_live_direct_claim(&self, _: Uuid, _: Uuid, _: Uuid) -> anyhow::Result<bool> {
        panic!("service released claim")
    }
    async fn authorize_outbound_message(
        &self,
        _: Uuid,
        _: &str,
        _: Option<&str>,
        _: &str,
    ) -> anyhow::Result<messaging_service::OutboundPolicyDecision> {
        panic!("service repeated outbound authorization")
    }
    async fn resolve_local_recipient(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> anyhow::Result<messaging_service::LocalRecipientDecision> {
        panic!("service repeated recipient lookup")
    }
    async fn default_recipient_privacy_denies(&self, _: Uuid, _: &str) -> anyhow::Result<bool> {
        panic!("service repeated privacy lookup")
    }
    async fn privacy_allows_session(
        &self,
        _: Uuid,
        _: Uuid,
        _: Option<&str>,
        _: &str,
        _: northstar_xep_0016::PrivacyStanzaKind,
    ) -> anyhow::Result<bool> {
        panic!("service repeated session privacy lookup")
    }
    async fn admit_remote_muc_invite(
        &self,
        _: &messaging_service::RemoteMucInviteAdmission<'_>,
    ) -> anyhow::Result<messaging_service::RemoteMucInviteAdmissionOutcome> {
        panic!("service admitted remote invite")
    }
    async fn admit_local_muc_invite(
        &self,
        _: &messaging_service::LocalMucInviteAdmission<'_>,
    ) -> anyhow::Result<northstar_room_core::DurableMucInviteOutcome> {
        panic!("service admitted local invite")
    }
    async fn admit_history(
        &self,
        _: &[ArchiveCandidate<'_>],
    ) -> anyhow::Result<messaging_service::ArchiveAdmissionOutcome> {
        panic!("service used separate history transaction")
    }
    async fn store_offline(
        &self,
        _: messaging_service::OfflineMessageAdmission<'_>,
    ) -> anyhow::Result<messaging_service::OfflineAdmissionOutcome> {
        panic!("service used offline admission")
    }
}

type RouteCalls = Vec<(String, String, Option<DurableDelivery>)>;

struct RecordingRoute {
    events: Events,
    health: Mutex<DirectPostCommitMode>,
    calls: Mutex<RouteCalls>,
    rearmed: Mutex<Vec<DurableDelivery>>,
    fallback: bool,
    privacy: Mutex<Vec<(String, String)>>,
}

impl RecordingRoute {
    fn new(events: Events) -> Self {
        Self {
            events,
            health: Mutex::new(DirectPostCommitMode::Live),
            calls: Mutex::default(),
            rearmed: Mutex::default(),
            fallback: false,
            privacy: Mutex::default(),
        }
    }
}

impl OnlineRoutePort for RecordingRoute {
    type Item = TestItem;
    type Session = &'static str;
    fn try_local(
        &self,
        session: &Self::Session,
        enqueue: RouteEnqueue<TestItem>,
    ) -> Result<(), RouteSendError<TestItem>> {
        self.events.lock().unwrap().push("enqueue");
        self.calls.lock().unwrap().push((
            (*session).to_owned(),
            enqueue.item().stanza.clone(),
            enqueue.item().c2s_delivery(),
        ));
        enqueue.complete_for_fake(true)
    }
    fn record_local_accept(&self, durable: bool) {
        assert!(durable);
        self.events.lock().unwrap().push("accepted");
    }
    async fn route_available_remote(&self, _: &str, _: &str, _: Option<DurableDelivery>) -> bool {
        panic!("direct chat became headline fanout");
    }
    async fn route_remote_primary(
        &self,
        target: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.events.lock().unwrap().push("remote");
        self.calls
            .lock()
            .unwrap()
            .push((target.to_owned(), stanza.to_owned(), delivery));
        OnlineRouteResult::default()
    }
}

impl FullJidFallbackPort for RecordingRoute {
    fn fallback_sessions(&self, bare: &str) -> Vec<(String, Self::Session)> {
        assert_eq!(bare, "bob@example.test");
        self.events.lock().unwrap().push("fallback");
        if self.fallback {
            vec![(
                "bob@example.test/fallback".into(),
                "bob@example.test/fallback",
            )]
        } else {
            vec![]
        }
    }
    fn available_priority(&self, _: &Self::Session) -> Option<i16> {
        self.events.lock().unwrap().push("available");
        Some(0)
    }
    fn priority(&self, _: &Self::Session) -> i16 {
        self.events.lock().unwrap().push("priority");
        0
    }
    async fn privacy_allows_fallback(
        &self,
        session: &Self::Session,
        sender: &str,
    ) -> anyhow::Result<bool> {
        self.events.lock().unwrap().push("privacy");
        self.privacy
            .lock()
            .unwrap()
            .push(((*session).to_owned(), sender.to_owned()));
        Ok(true)
    }
    fn post_accept_failed(&self) {
        self.events.lock().unwrap().push("failed");
    }
}

impl DirectMessageRoutePort for RecordingRoute {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        self.events.lock().unwrap().push("health");
        *self.health.lock().unwrap()
    }
    fn clustered_direct_routes(&self) -> bool {
        self.events.lock().unwrap().push("cluster");
        true
    }
    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        self.events.lock().unwrap().push("rearm");
        self.rearmed.lock().unwrap().push(delivery);
    }
}

fn committed_source() -> DurableDelivery {
    DurableDelivery {
        recipient_id: Uuid::from_u128(5),
        message_id: Uuid::from_u128(2),
        claim_id: Some(Uuid::from_u128(2)),
    }
}

#[tokio::test]
async fn finalization_looks_up_owner_lazily_and_consumes_the_exact_lease_once() {
    let events = Events::default();
    let repository =
        RecordingAdmission::new(events.clone(), Admission::Reserved, FinalizeCut::Success);
    let service = MessageAdmissionService::new(repository.clone());
    admission_service::finalize_message_admission_with(
        &service,
        &mut None,
        "test",
        || panic!("absent lease looked up owner"),
        || panic!("absent lease entered followup"),
        || panic!("absent lease reported failure"),
    )
    .await;
    assert!(events.lock().unwrap().is_empty());
    assert!(repository.fences.lock().unwrap().is_empty());

    for (label, retained_owner) in [("retained owner", true), ("standalone acceptance", false)] {
        for (cut_label, cut) in [
            ("receipt", FinalizeCut::Success),
            ("precommit failure", FinalizeCut::PreCommitError),
            ("commit reply loss", FinalizeCut::CommitError),
            ("postreceipt failure", FinalizeCut::AfterReceiptError),
        ] {
            let label = format!("{label}, {cut_label}");
            let events = Events::default();
            let owner = DirectOperationHandle::new(Uuid::from_u128(101));
            let repository = RecordingAdmission::new(events.clone(), Admission::Reserved, cut);
            let (service, mut lease) =
                issue_admission(&owner, repository.clone(), &admission_fixture::request()).await;
            let fence = acceptance_fence(&lease.as_ref().unwrap().acceptance());
            let reservation = owner.snapshot().reservation;
            events.lock().unwrap().clear();
            let release = repository.hold();
            let mut future = Box::pin(admission_service::finalize_message_admission_with(
                &service,
                &mut lease,
                "test",
                || {
                    events.lock().unwrap().push("owner");
                    retained_owner.then(|| owner.clone())
                },
                || {
                    if retained_owner {
                        let issued = owner.snapshot().finalization.unwrap();
                        assert!(
                            !issued.effect_started,
                            "{label}: repository started before followup"
                        );
                        assert_eq!(
                            issued.witness.effect().command,
                            northstar_abuse_policy::admission_execution::Command::Finalize(
                                fence.clone()
                            ),
                            "{label}: preparation must precede followup"
                        );
                    }
                    events.lock().unwrap().push("followup");
                },
                || events.lock().unwrap().push("failed"),
            ));
            assert!(futures::poll!(&mut future).is_pending(), "{label}");
            assert_eq!(
                *events.lock().unwrap(),
                ["owner", "followup", "accept"],
                "{label}"
            );
            assert_eq!(
                repository.fences.lock().unwrap().as_slice(),
                std::slice::from_ref(&fence),
                "{label}"
            );
            release
                .send(cut)
                .unwrap_or_else(|_| panic!("{label}: acceptance was not retained"));
            future.await;
            assert!(
                lease.is_none(),
                "{label}: lease survived acceptance attempt"
            );
            let mut expected = vec!["owner", "followup", "accept"];
            if cut != FinalizeCut::PreCommitError {
                expected.push("finalize_commit");
                if cut != FinalizeCut::CommitError {
                    expected.push("finalize_receipt");
                }
            }
            if cut != FinalizeCut::Success {
                expected.push("failed");
            }
            assert_eq!(*events.lock().unwrap(), expected, "{label}");
            assert_eq!(owner.snapshot().reservation, reservation, "{label}");
            assert_eq!(
                repository.fences.lock().unwrap().len(),
                1,
                "{label}: acceptance retried"
            );
        }
    }

    for (label, complete_reservation) in [
        ("missing reservation", false),
        ("foreign lease fence", true),
    ] {
        let events = Events::default();
        let owner = DirectOperationHandle::new(Uuid::from_u128(102));
        let repository =
            RecordingAdmission::new(events.clone(), Admission::Reserved, FinalizeCut::Success);
        let service = if complete_reservation {
            issue_admission(&owner, repository.clone(), &admission_fixture::request())
                .await
                .0
        } else {
            MessageAdmissionService::new(repository.clone())
        };
        let before = owner.snapshot();
        let mut lease = Some(admission_fixture::lease(999));
        events.lock().unwrap().clear();
        admission_service::finalize_message_admission_with(
            &service,
            &mut lease,
            "test",
            || {
                events.lock().unwrap().push("owner");
                Some(owner.clone())
            },
            || events.lock().unwrap().push("followup"),
            || events.lock().unwrap().push("failed"),
        )
        .await;
        assert_eq!(
            *events.lock().unwrap(),
            ["owner", "followup", "failed"],
            "{label}"
        );
        assert!(lease.is_none(), "{label}");
        assert!(
            repository.fences.lock().unwrap().is_empty(),
            "{label}: failed construction reached repository"
        );
        assert_eq!(owner.snapshot(), before, "{label}");
    }
}

#[tokio::test]
async fn application_bridge_keeps_actual_disposition_with_its_original_owner() {
    for (label, transaction, after_receipt_error) in [
        ("stored", Transaction::Stored, false),
        ("replay", Transaction::Replay, false),
        ("unavailable", Transaction::Unavailable, false),
        ("unconfirmed", Transaction::Unconfirmed, false),
        (
            "stored receipt survives mapping failure",
            Transaction::Stored,
            true,
        ),
        (
            "replay receipt survives mapping failure",
            Transaction::Replay,
            true,
        ),
        (
            "unavailable receipt survives mapping failure",
            Transaction::Unavailable,
            true,
        ),
    ] {
        let events = Events::default();
        let owner = DirectOperationHandle::new(Uuid::from_u128(103));
        let repository =
            RecordingAdmission::new(events.clone(), Admission::Reserved, FinalizeCut::Success);
        let (service, mut lease) =
            issue_admission(&owner, repository.clone(), &admission_fixture::request()).await;
        let mut commit = RecordingCommit::stored(events.clone());
        commit.transaction = transaction;
        commit.after_receipt_error = after_receipt_error;
        let applied = {
            let stored = commit.stored.clone();
            let message_service = messaging_service::MessageService::new(commit, false);
            message_service
                .admit_prepared_personal_message_with_mode(prepared(&owner, &stored))
                .await
        };
        let direct = owner.snapshot().direct.unwrap();
        if after_receipt_error {
            assert!(
                matches!(direct.outcome, Some(ExecutionOutcome::ReceiptPreserved(_))),
                "{label}"
            );
        } else if transaction == Transaction::Unconfirmed {
            assert_eq!(
                direct.outcome,
                Some(ExecutionOutcome::PreCommitFailure),
                "{label}"
            );
        } else {
            assert!(
                matches!(direct.outcome, Some(ExecutionOutcome::Completed(_))),
                "{label}"
            );
        }
        let route = RecordingRoute::new(events.clone());
        let disposition =
            continue_prepared_local_direct(applied, &mut lease, &service, &route, || {
                events.lock().unwrap().push("followup")
            })
            .await;
        match (transaction, after_receipt_error, disposition) {
            (Transaction::Stored, false, ContinuedLocalDirect::Live(live)) => {
                assert_eq!(live.source(), committed_source(), "{label}");
                assert!(!live.archive_written(), "{label}");
            }
            (Transaction::Stored | Transaction::Replay, _, ContinuedLocalDirect::Accepted) => {}
            (Transaction::Unavailable, _, ContinuedLocalDirect::Reject(error)) => {
                assert_eq!(
                    error.stanza_error(),
                    ("cancel", "service-unavailable"),
                    "{label}"
                );
            }
            (Transaction::Unconfirmed, _, ContinuedLocalDirect::Reject(error)) => {
                assert_eq!(
                    error.stanza_error(),
                    ("wait", "resource-constraint"),
                    "{label}"
                );
            }
            _ => panic!("{label}: application result and continuation disagreed"),
        }
        let accepted = matches!(transaction, Transaction::Stored | Transaction::Replay);
        assert_eq!(lease.is_none(), accepted, "{label}");
        assert_eq!(
            repository.fences.lock().unwrap().len(),
            usize::from(accepted),
            "{label}"
        );
        let mut expected = vec!["begin", "direct"];
        if transaction != Transaction::Unconfirmed {
            expected.extend(["direct_commit", "direct_receipt"]);
        }
        if transaction == Transaction::Stored && after_receipt_error {
            expected.push("failed");
        }
        if accepted {
            expected.extend(["followup", "accept", "finalize_commit", "finalize_receipt"]);
        }
        if transaction == Transaction::Stored {
            expected.push(if after_receipt_error {
                "rearm"
            } else {
                "health"
            });
        }
        assert_eq!(*events.lock().unwrap(), expected, "{label}");
        assert!(
            route.calls.lock().unwrap().is_empty(),
            "{label}: continuation routed early"
        );
    }
}

#[tokio::test]
async fn guard_only_completion_issues_no_reservation_and_skips_finalization() {
    let events = Events::default();
    let owner = DirectOperationHandle::new(Uuid::from_u128(107));
    let repository =
        RecordingAdmission::new(events.clone(), Admission::GuardOnly, FinalizeCut::Success);
    let service = MessageAdmissionService::new(repository.clone());
    let request = admission_fixture::request();
    let retained = owner.begin(&request).unwrap();
    assert!(retained.admission_grant().is_none());
    let MessageAdmissionStart::Proceed { mut lease, .. } = service
        .begin_message_admission_retained(&request, &retained)
        .await
        .unwrap()
    else {
        panic!("guard-only admission was rejected");
    };
    assert!(matches!(
        retained.admission_grant(),
        Some(crate::direct_lifecycle::AdmissionGrant::GuardOnly(_))
    ));
    assert!(lease.is_none());
    assert!(owner.finalize(&admission_fixture::lease(3)).is_err());
    let commit = RecordingCommit::stored(events.clone());
    let app = crate::MessageApplication::new(commit.clone());
    let applied = commit_prepared_application(&app, prepared(&owner, &commit.stored)).await;
    let route = RecordingRoute::new(events.clone());
    let ContinuedLocalDirect::Live(live) =
        continue_prepared_local_direct(applied, &mut lease, &service, &route, || {
            panic!("guard-only continuation entered finalization")
        })
        .await
    else {
        panic!("guard-only continuation lost confirmed storage");
    };
    assert_eq!(live.source(), committed_source());
    assert!(owner.snapshot().finalization.is_none());
    assert!(repository.fences.lock().unwrap().is_empty());
    assert!(route.calls.lock().unwrap().is_empty());
    assert_eq!(
        *events.lock().unwrap(),
        [
            "begin",
            "direct",
            "direct_commit",
            "direct_receipt",
            "health"
        ]
    );
}

#[tokio::test]
async fn continuation_waits_for_finalization_before_reading_current_health() {
    use DirectPostCommitMode::{Live, Rejected, SpoolOnly};
    for (label, mode, after_receipt_error, cut, health) in [
        ("receipt then live", Live, false, FinalizeCut::Success, Live),
        (
            "precommit failure then live",
            Live,
            false,
            FinalizeCut::PreCommitError,
            Live,
        ),
        (
            "commit loss then live",
            Live,
            false,
            FinalizeCut::CommitError,
            Live,
        ),
        (
            "postreceipt failure then live",
            Live,
            false,
            FinalizeCut::AfterReceiptError,
            Live,
        ),
        (
            "health degrades while finalizing",
            Live,
            false,
            FinalizeCut::Success,
            SpoolOnly,
        ),
        (
            "health rejects while finalizing",
            Live,
            false,
            FinalizeCut::PreCommitError,
            Rejected,
        ),
        (
            "spooled result skips health",
            SpoolOnly,
            false,
            FinalizeCut::Success,
            Live,
        ),
        (
            "stored mapping failure skips health",
            Live,
            true,
            FinalizeCut::Success,
            Live,
        ),
    ] {
        let events = Events::default();
        let owner = DirectOperationHandle::new(Uuid::from_u128(105));
        let repository = RecordingAdmission::new(events.clone(), Admission::Reserved, cut);
        let release = repository.hold();
        let (service, mut lease) =
            issue_admission(&owner, repository.clone(), &admission_fixture::request()).await;
        let mut commit = RecordingCommit::stored(events.clone());
        commit.mode = mode;
        commit.after_receipt_error = after_receipt_error;
        let app = crate::MessageApplication::new(commit.clone());
        let applied = commit_prepared_application(&app, prepared(&owner, &commit.stored)).await;
        let reservation = owner.snapshot().reservation;
        events.lock().unwrap().clear();
        let route = RecordingRoute::new(events.clone());
        *route.health.lock().unwrap() = Rejected;
        let mut future = Box::pin(continue_prepared_local_direct(
            applied,
            &mut lease,
            &service,
            &route,
            || events.lock().unwrap().push("followup"),
        ));
        assert!(futures::poll!(&mut future).is_pending(), "{label}");
        let mut expected = Vec::new();
        if after_receipt_error {
            expected.push("failed");
        }
        expected.extend(["followup", "accept"]);
        assert_eq!(
            *events.lock().unwrap(),
            expected,
            "{label}: work escaped finalization boundary"
        );
        assert!(route.calls.lock().unwrap().is_empty(), "{label}");
        assert!(route.rearmed.lock().unwrap().is_empty(), "{label}");
        let waiting = owner.snapshot().finalization.unwrap();
        assert!(waiting.effect_started, "{label}");
        assert_eq!(
            *waiting.witness.knowledge(),
            northstar_abuse_policy::admission_execution::Knowledge::NoCommitRequested,
            "{label}"
        );
        *route.health.lock().unwrap() = health;
        release
            .send(cut)
            .unwrap_or_else(|_| panic!("{label}: finalization future dropped"));
        let disposition = future.await;
        let reads_health = mode == Live && !after_receipt_error;
        let routes = reads_health && health == Live;
        assert!(
            matches!(
                (&disposition, routes),
                (ContinuedLocalDirect::Live(_), true) | (ContinuedLocalDirect::Accepted, false)
            ),
            "{label}"
        );
        if let ContinuedLocalDirect::Live(live) = disposition {
            assert_eq!(live.source(), committed_source(), "{label}");
        }
        if cut != FinalizeCut::PreCommitError {
            expected.push("finalize_commit");
            if cut != FinalizeCut::CommitError {
                expected.push("finalize_receipt");
            }
        }
        if cut != FinalizeCut::Success {
            expected.push("failed");
        }
        if reads_health {
            expected.push("health");
        }
        let rearms = !routes && mode == Live;
        if rearms {
            expected.push("rearm");
        }
        assert_eq!(*events.lock().unwrap(), expected, "{label}");
        assert_eq!(
            *route.rearmed.lock().unwrap(),
            if rearms {
                vec![committed_source()]
            } else {
                vec![]
            },
            "{label}"
        );
        assert!(
            route.calls.lock().unwrap().is_empty(),
            "{label}: continuation dispatched before route_with"
        );
        assert!(lease.is_none(), "{label}");
        assert_eq!(owner.snapshot().reservation, reservation, "{label}");
        assert!(
            matches!(
                owner.snapshot().finalization.unwrap().state,
                northstar_abuse_policy::admission_execution::ExecutionState::Finished(_)
            ),
            "{label}"
        );
    }
}

fn prepare_envelope<'command, 'live>(
    owner: &DirectOperationHandle,
    request: &MessageAdmissionRequest<'live>,
    stored: &'command str,
    archives: &'command [ArchiveCandidate<'command>],
    live: &'live str,
    message_type: &'live str,
    eligibility: DirectSpoolEligibility,
) -> PreparedLocalDirect<'command, 'live> {
    PreparedLocalDirect::bind(
        owner.clone(),
        LocalPreparation {
            actor_id: request.actor_id,
            sender_bare: request.account_bare,
            sender_full: "alice@example.test/device",
            target_bare: "bob@example.test",
            target_full: request.normalized_target,
            message_type,
            live_stanza: live,
            origin_id: request.origin_id,
            identity_payload: "private-identity-stanza",
            stored_stanza: stored,
            admission: PreparationAdmission::Rated(OriginalAdmission {
                actor_id: request.actor_id,
                account_bare: request.account_bare,
                normalized_target: request.normalized_target,
                origin_id: request.origin_id,
                normalized_payload: request.normalized_payload,
            }),
        },
        ValidatedPersonalMessage {
            local_actor_id: Some(request.actor_id),
            local_actor_fence: None,
            identity: Some(MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: "alice@example.test",
                actor_scope: "alice@example.test",
                target_scope: "bob@example.test",
                value: "origin",
                payload: "private-identity-stanza",
            }),
            archives,
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: Uuid::from_u128(2),
                recipient_id: Uuid::from_u128(5),
                recipient_bare_jid: "bob@example.test",
                sender_jid: "alice@example.test/device",
                stanza: stored,
                encrypted: false,
            }),
        },
        eligibility,
        LiveDirectBinding {
            sender: "alice@example.test/device",
            target: request.normalized_target,
            target_bare: "bob@example.test",
            message_type,
            stanza: live,
            recipient_id: Uuid::from_u128(5),
        },
    )
    .unwrap()
}

#[tokio::test]
async fn prepared_live_routes_only_the_original_envelope_and_committed_source() {
    for (label, target, message_type, approved, fallback) in [
        (
            "bare approved target",
            "bob@example.test",
            "chat",
            true,
            false,
        ),
        (
            "full approved target",
            "bob@example.test/original",
            "chat",
            true,
            false,
        ),
        (
            "full chat privacy fallback",
            "bob@example.test/original",
            "chat",
            false,
            true,
        ),
        (
            "full normal remains resource affine",
            "bob@example.test/original",
            "normal",
            false,
            false,
        ),
    ] {
        let events = Events::default();
        let owner = DirectOperationHandle::new(Uuid::from_u128(106));
        let repository =
            RecordingAdmission::new(events.clone(), Admission::Reserved, FinalizeCut::Success);
        let request = MessageAdmissionRequest {
            normalized_target: target,
            ..admission_fixture::request()
        };
        let (admission, mut lease) = issue_admission(&owner, repository, &request).await;
        let live_stanza = format!("<message type='{message_type}' to='{target}'><body>original live bytes</body></message>");
        let eligibility = if target.contains('/') {
            DirectSpoolEligibility::LiveOnly
        } else {
            DirectSpoolEligibility::Eligible
        };
        let applied = {
            let stored = String::from("delayed stored projection");
            let archives = [ArchiveCandidate {
                direction: ArchiveDirection::Outbound,
                projection: ArchiveProjection {
                    id: Uuid::from_u128(8),
                    owner_id: request.actor_id,
                    peer_jid: "bob@example.test",
                    stanza: &stored,
                    encrypted: false,
                    stanza_id: Some("origin"),
                },
            }];
            let mut repository = RecordingCommit::stored(events.clone());
            repository.eligibility = eligibility;
            repository.archive_ids = vec![Uuid::from_u128(8)];
            let service = messaging_service::MessageService::new(repository, false);
            service
                .admit_prepared_personal_message_with_mode(prepare_envelope(
                    &owner,
                    &request,
                    &stored,
                    &archives,
                    &live_stanza,
                    message_type,
                    eligibility,
                ))
                .await
        };
        let route = RecordingRoute {
            fallback,
            ..RecordingRoute::new(events.clone())
        };
        let ContinuedLocalDirect::Live(live) =
            continue_prepared_local_direct(applied, &mut lease, &admission, &route, || {
                events.lock().unwrap().push("followup")
            })
            .await
        else {
            panic!("{label}: committed live result lost");
        };
        assert_eq!(live.source(), committed_source(), "{label}");
        assert!(live.archive_written(), "{label}");
        assert!(
            route.calls.lock().unwrap().is_empty(),
            "{label}: early route"
        );
        let approved_key = if target.contains('/') {
            target
        } else {
            "bob@example.test/approved"
        };
        let targets = if approved {
            vec![(approved_key.to_owned(), approved_key)]
        } else {
            vec![]
        };
        let outcome = live.route_with(&route, &targets).await.unwrap();
        let destinations = if approved {
            vec![approved_key]
        } else if fallback {
            vec![target, "bob@example.test/fallback"]
        } else {
            vec![target]
        };
        assert_eq!(
            *route.calls.lock().unwrap(),
            destinations
                .iter()
                .map(|target| (
                    target.to_string(),
                    live_stanza.clone(),
                    Some(committed_source())
                ))
                .collect::<Vec<_>>(),
            "{label}: live envelope or durable fence changed"
        );
        let expected_key = if approved {
            Some(approved_key)
        } else if fallback {
            Some("bob@example.test/fallback")
        } else {
            None
        };
        assert_eq!(
            outcome,
            match expected_key {
                Some(key) => messaging_service::DirectRouteOutcome::Routed {
                    accepted_full_jid: Some(key.into()),
                },
                None => messaging_service::DirectRouteOutcome::Unrouted,
            },
            "{label}"
        );
        assert_eq!(
            *route.privacy.lock().unwrap(),
            if fallback {
                vec![(
                    "bob@example.test/fallback".into(),
                    "alice@example.test/device".into(),
                )]
            } else {
                vec![]
            },
            "{label}: original sender lost before privacy"
        );
        assert_eq!(
            *route.rearmed.lock().unwrap(),
            if expected_key.is_none() {
                vec![committed_source()]
            } else {
                vec![]
            },
            "{label}"
        );
    }
}
