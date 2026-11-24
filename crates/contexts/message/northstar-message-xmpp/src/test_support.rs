//! Recording ports for the actual client and federation message pipelines.

use crate::ports::{
    DirectInviteRoom, FederatedMessageHost, MessageFrameStage, MessageHost, MessageSession,
};
use anyhow::Result;
use northstar_abuse_policy::admission_execution::{
    AdmissionCommitObserver, BeginCommitPurpose, BeginRequest, CommitFact, Effect, FinalizeSuccess,
    ReconcileResult, TransactionScope,
};
use northstar_abuse_policy::admission_transaction::{AdmissionFence, FinalizeDecision};
use northstar_abuse_policy::content_identity::PersonalRetractionContentKeyring;
use northstar_abuse_policy::message_admission::{
    acceptance_fence, MessageAdmissionAcceptance, MessageAdmissionLease, MessageAdmissionStart,
};
use northstar_abuse_policy::{MessageAdmissionRequest, MessageDedupeIdentity, WorkRequirement};
use northstar_federation_core::S2sOutboxPolicy;
use northstar_message_application::direct_commit::{
    DirectCommitObserver, DirectCommitRepository, TransactionOutcome,
};
use northstar_message_application::message_admission::witness::{
    AdmissionWitness, DirectOperationHandle,
};
use northstar_message_application::message_admission::{
    MessageAdmissionRepository, MessageAdmissionService,
};
use northstar_message_application::message_carbons::{CarbonDeliveryPort, Direction};
use northstar_message_application::messaging::{
    ArchiveAdmissionOutcome, ArchiveCandidate, ArchiveDirection, DirectMessageRoutePort,
    FullJidFallbackPort, LocalMucInviteAdmission, LocalRecipient, LocalRecipientDecision,
    MessageRepository, MessageService, OfflineAdmissionOutcome, OfflineMessageAdmission,
    OnlineRoutePort, OnlineRouteResult, OutboundPolicyDecision, RemoteMucInviteAdmission,
    RemoteMucInviteAdmissionOutcome,
};
use northstar_message_application::retractions::{
    PreparedRetraction, RetractionOutcome, RetractionRepository, RetractionService,
};
use northstar_message_application::telemetry::{
    PersonalMessageTelemetry, PersonalMessageTelemetryCells,
};
use northstar_message_application::PersonalMessageCommitRepository;
use northstar_message_core::route_item::QueueRefusal;
use northstar_message_core::{
    ActorGenerationFence, AuthenticatedMessageActor, DirectPersonalMessageAdmission,
    DirectPostCommitMode, DirectSpoolEligibility, MessageCommit, MessageEventSource,
    MessagePostCommit, OfflineDeliveryLimits, PersonalMessageDestination, ValidatedPersonalMessage,
};
use northstar_room_core::{
    ClusterMucAffiliationSubject, ClusterMucInviteAuthority, DurableMucInviteOutcome,
};
use northstar_stream::local_routes::session::{test_online_session, OnlineSession};
use northstar_stream::outbound::{DurableDelivery, OutboundItem, RouteEnqueue, RouteSendError};
use northstar_stream::transport::Action;
use northstar_telemetry::metrics::DurationHistogram;
use northstar_time::{DateTime, Utc};
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Node;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll, Waker};
use tokio::sync::oneshot;
use uuid::Uuid;

pub(crate) const ACTOR: Uuid = Uuid::from_u128(1);
pub(crate) const ACTOR_GENERATION: i64 = 17;
pub(crate) const ACTOR_CONNECTION: Uuid = Uuid::from_u128(5);
pub(crate) const RECIPIENT: Uuid = Uuid::from_u128(2);
pub(crate) const CLAIM: Uuid = Uuid::from_u128(3);
pub(crate) const OPERATION: Uuid = Uuid::from_u128(4);
pub(crate) const SENDER: &str = "alice@example.test/laptop";
pub(crate) const TARGET: &str = "bob@example.test";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitAnswer {
    Stored,
    Replay,
    Unavailable,
    Error,
    ReceiptThenError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueueAnswer {
    Accepted,
    Full,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredEnvelope {
    pub actor: Option<Uuid>,
    pub actor_fence: Option<ActorGenerationFence>,
    pub source: DurableDelivery,
    pub sender: String,
    pub recipient: String,
    pub stanza: String,
    pub identity: Option<(String, String, String, String)>,
    pub archives: Vec<(Uuid, Uuid, String, String)>,
    pub candidates: Vec<(ArchiveDirection, Uuid, String)>,
    pub eligibility: DirectSpoolEligibility,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Event {
    Stage(MessageFrameStage),
    Begin(BeginRequest, bool),
    Finalize(AdmissionFence, bool),
    Finalized,
    Authorize(Uuid, String, Option<String>, String),
    Mix(String),
    Commit(StoredEnvelope, bool),
    Health,
    Privacy(Uuid, String),
    Local(Uuid, String, Option<DurableDelivery>),
    LocalAccepted(bool),
    FederationAccepted(bool),
    Primary(String, String, Option<DurableDelivery>),
    Available(String, String, Option<DurableDelivery>),
    Rearm(DurableDelivery),
    Carbon(String, Option<String>, String),
    SentCarbon(String, String, String),
    Push(Uuid),
    Routed,
    PostAcceptFailed,
    History(Vec<(ArchiveDirection, Uuid, String)>),
    OutboundCommit(Vec<(ArchiveDirection, Uuid, String)>),
    Retraction(Vec<Uuid>),
    WakeOutbox,
}

pub(crate) struct State {
    pub events: Mutex<Vec<Event>>,
    pub mode: Mutex<DirectPostCommitMode>,
    pub answer: CommitAnswer,
    pub queue: QueueAnswer,
    pub admission_conflict: bool,
    pub finalize_error: bool,
    pub finalize_gate: Mutex<Option<oneshot::Receiver<()>>>,
    pub remote_gate: Mutex<Option<oneshot::Receiver<()>>>,
    pub remote_result: Mutex<OnlineRouteResult>,
    pub archive: bool,
    pub history_error: bool,
    pub archive_requires_encryption: bool,
    pub expect_retraction: bool,
    pub committed: Mutex<Option<StoredEnvelope>>,
    pub sessions: Vec<(String, OnlineSession)>,
    pub deny_connection: Option<Uuid>,
    pub fallback_error: bool,
}

impl State {
    pub fn record(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }

    pub fn events(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

fn archive_facts(candidates: &[ArchiveCandidate<'_>]) -> Vec<(ArchiveDirection, Uuid, String)> {
    candidates
        .iter()
        .map(|candidate| {
            (
                candidate.direction,
                candidate.projection.owner_id,
                candidate.projection.peer_jid.to_owned(),
            )
        })
        .collect()
}

#[derive(Clone)]
pub(crate) struct Repository(pub Arc<State>);

mod direct_invitation_stub;

impl PersonalMessageCommitRepository for Repository {
    type Error = anyhow::Error;

    async fn commit<'a>(
        &'a self,
        command: &'a ValidatedPersonalMessage<'a>,
    ) -> Result<MessageCommit> {
        assert!(matches!(
            command.destination,
            PersonalMessageDestination::Federation(_)
        ));
        self.0
            .record(Event::OutboundCommit(archive_facts(command.archives)));
        Ok(MessageCommit::Stored {
            archive_written: self.0.archive && !command.archives.is_empty(),
            post_commit: MessagePostCommit::WakeFederationOutbox,
        })
    }
}

impl DirectCommitRepository for Repository {
    type Error = anyhow::Error;

    async fn commit_direct<'a>(
        &'a self,
        command: &'a ValidatedPersonalMessage<'a>,
        eligibility: DirectSpoolEligibility,
        observer: Option<&'a dyn DirectCommitObserver>,
    ) -> Result<DirectPersonalMessageAdmission> {
        let PersonalMessageDestination::Local(local) = command.destination else {
            panic!("unexpected federation commit")
        };
        let envelope = StoredEnvelope {
            actor: command.local_actor_id,
            actor_fence: command.local_actor_fence,
            source: DurableDelivery {
                recipient_id: local.recipient_id,
                message_id: local.delivery_id,
                claim_id: Some(local.delivery_id),
            },
            sender: local.sender_jid.to_owned(),
            recipient: local.recipient_bare_jid.to_owned(),
            stanza: local.stanza.to_owned(),
            identity: command.identity.map(|identity| {
                (
                    identity.actor_scope.to_owned(),
                    identity.target_scope.to_owned(),
                    identity.value.to_owned(),
                    identity.payload.to_owned(),
                )
            }),
            archives: command
                .archives
                .iter()
                .filter(|_| self.0.archive)
                .map(|candidate| &candidate.projection)
                .map(|archive| {
                    (
                        archive.id,
                        archive.owner_id,
                        archive.peer_jid.to_owned(),
                        archive.stanza.to_owned(),
                    )
                })
                .collect(),
            candidates: archive_facts(command.archives),
            eligibility,
        };
        self.0
            .record(Event::Commit(envelope.clone(), observer.is_some()));
        *self.0.committed.lock().unwrap() = Some(envelope);
        if self.0.answer == CommitAnswer::Error {
            anyhow::bail!("commit refused before receipt");
        }
        let outcome = match self.0.answer {
            CommitAnswer::Replay => TransactionOutcome::Replay {
                archive_ids: vec![],
            },
            CommitAnswer::Unavailable => TransactionOutcome::AccountUnavailable,
            _ => TransactionOutcome::Stored {
                recipient_id: local.recipient_id,
                delivery_id: local.delivery_id,
                archive_ids: command
                    .archives
                    .iter()
                    .filter(|_| self.0.archive)
                    .map(|candidate| candidate.projection.id)
                    .collect(),
                live_claim_id: Some(local.delivery_id),
            },
        };
        if let Some(observer) = observer {
            let prepared = observer.prepare(outcome, DirectPostCommitMode::Live)?;
            observer.received(prepared)?;
        }
        if self.0.answer == CommitAnswer::ReceiptThenError {
            anyhow::bail!("commit returned an error after its receipt");
        }
        let commit = match self.0.answer {
            CommitAnswer::Replay => MessageCommit::Replay,
            CommitAnswer::Unavailable => MessageCommit::AccountUnavailable,
            _ => MessageCommit::Stored {
                archive_written: self.0.archive && !command.archives.is_empty(),
                post_commit: MessagePostCommit::RouteLocalDelivery {
                    delivery_id: local.delivery_id,
                    recipient_id: local.recipient_id,
                },
            },
        };
        Ok(DirectPersonalMessageAdmission {
            commit,
            mode: DirectPostCommitMode::Live,
            live_claim_id: matches!(self.0.answer, CommitAnswer::Stored)
                .then_some(local.delivery_id),
        })
    }
}

impl MessageRepository for Repository {
    fn direct_mode(&self) -> DirectPostCommitMode {
        *self.0.mode.lock().unwrap()
    }
    fn clustered_direct_admission_enabled(&self) -> bool {
        true
    }
    async fn release_live_direct_claim(
        &self,
        recipient_id: Uuid,
        message_id: Uuid,
        claim_id: Uuid,
    ) -> Result<bool> {
        self.0.record(Event::Rearm(DurableDelivery {
            recipient_id,
            message_id,
            claim_id: Some(claim_id),
        }));
        Ok(true)
    }
    async fn authorize_outbound_message(
        &self,
        owner: Uuid,
        bare: &str,
        privacy: Option<&str>,
        target: &str,
    ) -> Result<OutboundPolicyDecision> {
        self.0.record(Event::Authorize(
            owner,
            bare.to_owned(),
            privacy.map(str::to_owned),
            target.to_owned(),
        ));
        Ok(OutboundPolicyDecision::Allowed)
    }
    async fn resolve_local_recipient(
        &self,
        username: &str,
        domain: &str,
        _: &str,
    ) -> Result<LocalRecipientDecision> {
        assert_eq!((username, domain), ("bob", "example.test"));
        Ok(LocalRecipientDecision::Deliver(LocalRecipient {
            id: RECIPIENT,
            username: "bob".to_owned(),
        }))
    }
    async fn default_recipient_privacy_denies(&self, recipient: Uuid, _: &str) -> Result<bool> {
        assert_eq!(recipient, RECIPIENT);
        Ok(false)
    }
    async fn privacy_allows_session(
        &self,
        _: Uuid,
        _: Uuid,
        _: Option<&str>,
        _: &str,
        _: PrivacyStanzaKind,
    ) -> Result<bool> {
        panic!("unexpected repository session privacy lookup")
    }
    async fn admit_remote_muc_invite(
        &self,
        _: &RemoteMucInviteAdmission<'_>,
    ) -> Result<RemoteMucInviteAdmissionOutcome> {
        panic!("unexpected remote invite")
    }
    async fn admit_local_muc_invite(
        &self,
        _: &LocalMucInviteAdmission<'_>,
    ) -> Result<DurableMucInviteOutcome> {
        panic!("unexpected local invite")
    }
    async fn admit_history(
        &self,
        candidates: &[ArchiveCandidate<'_>],
    ) -> Result<ArchiveAdmissionOutcome> {
        self.0.record(Event::History(archive_facts(candidates)));
        anyhow::ensure!(!self.0.history_error, "history write failed after route");
        let ids = candidates
            .iter()
            .filter(|_| self.0.archive)
            .map(|candidate| candidate.projection.id)
            .collect();
        Ok(ArchiveAdmissionOutcome::Projected(ids))
    }
    async fn store_offline(
        &self,
        _: OfflineMessageAdmission<'_>,
    ) -> Result<OfflineAdmissionOutcome> {
        panic!("unexpected offline admission")
    }
}

pub(crate) fn lease() -> MessageAdmissionLease {
    MessageAdmissionLease::new(
        vec![11; 32],
        vec![12; 32],
        Uuid::from_u128(13),
        MessageDedupeIdentity {
            identity_digest: vec![14; 32],
            candidates: vec![],
        },
    )
}

impl MessageAdmissionRepository for Repository {
    async fn begin(
        &self,
        request: &MessageAdmissionRequest<'_>,
        witness: &AdmissionWitness,
    ) -> Result<MessageAdmissionStart> {
        self.0.record(Event::Begin(
            BeginRequest::from(*request),
            matches!(witness, AdmissionWitness::Retained(_)),
        ));
        if self.0.admission_conflict {
            return Ok(MessageAdmissionStart::Conflict);
        }
        let lease = lease();
        let prepared = witness.prepare(
            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
            CommitFact::Reserved(acceptance_fence(&lease.acceptance())),
        )?;
        witness.received(prepared);
        Ok(MessageAdmissionStart::Proceed {
            lease: Some(lease),
            requirement: WorkRequirement {
                action: "message".to_owned(),
                step: 0,
                work_factor: 1,
                max_work_factor: 1,
                hard_wait_seconds: 0,
                retry_after_seconds: 0,
                cooldown_seconds: 0,
                approximate_max_device_seconds: 0,
                notice: String::new(),
            },
        })
    }
    async fn accept(
        &self,
        acceptance: &MessageAdmissionAcceptance<'_>,
        witness: &AdmissionWitness,
    ) -> Result<FinalizeDecision> {
        self.0.record(Event::Finalize(
            acceptance_fence(acceptance),
            matches!(witness, AdmissionWitness::Retained(_)),
        ));
        assert_eq!(
            acceptance_fence(acceptance),
            acceptance_fence(&lease().acceptance())
        );
        let gate = self.0.finalize_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.await.expect("release finalization");
        }
        if self.0.finalize_error {
            anyhow::bail!("finalization refused");
        }
        let prepared = witness.prepare(
            TransactionScope::AdmissionFinalize,
            CommitFact::Finalized {
                fence: acceptance_fence(acceptance),
                result: FinalizeSuccess::PendingAccepted,
            },
        )?;
        witness.received(prepared);
        self.0.record(Event::Finalized);
        Ok(FinalizeDecision::AcceptPending)
    }
    async fn reconcile(&self, _: &Effect) -> Result<ReconcileResult> {
        panic!("unexpected reconciliation")
    }
}

impl RetractionRepository for Repository {
    async fn apply_prepared(&self, prepared: PreparedRetraction<'_>) -> Result<RetractionOutcome> {
        assert!(self.0.expect_retraction, "unexpected retraction");
        self.0.record(Event::Retraction(
            prepared
                .normalized_writes
                .iter()
                .map(|write| write.write.owner_id)
                .collect(),
        ));
        Ok(RetractionOutcome::Applied {
            tombstones: 0,
            live_claim_id: None,
        })
    }
}

#[derive(Default)]
struct TestMessageEvents {
    next_id: AtomicU64,
}

impl MessageEventSource for TestMessageEvents {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(978_307_200, 0).expect("fixed test timestamp")
    }

    fn new_stanza_id(&self) -> Uuid {
        Uuid::from_u128(0x100 + u128::from(self.next_id.fetch_add(1, Ordering::Relaxed)))
    }
}

pub(crate) struct Host {
    pub state: Arc<State>,
    messages: MessageService<Repository>,
    admissions: MessageAdmissionService<Repository>,
    retractions: RetractionService<Repository>,
    message_events: TestMessageEvents,
    histogram: DurationHistogram,
    pub counters: [AtomicU64; 9],
}

impl Host {
    pub fn new(state: State) -> Self {
        let state = Arc::new(state);
        Self {
            messages: MessageService::new(
                Repository(state.clone()),
                state.archive_requires_encryption,
            ),
            admissions: MessageAdmissionService::new(Repository(state.clone())),
            retractions: RetractionService::new(
                Repository(state.clone()),
                PersonalRetractionContentKeyring::new(Arc::default()),
                "example.test",
            ),
            message_events: TestMessageEvents::default(),
            state,
            histogram: DurationHistogram::default(),
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl Default for State {
    fn default() -> Self {
        let sessions = [("phone", 21, 10), ("tablet", 22, 5), ("blocked", 23, 20)]
            .into_iter()
            .map(|(resource, connection, priority)| {
                let (session, _) =
                    test_online_session(RECIPIENT, 7, Uuid::from_u128(connection), resource, 1);
                session.available.store(true, Ordering::Relaxed);
                session.priority.store(priority, Ordering::Relaxed);
                (format!("{TARGET}/{resource}"), session)
            })
            .collect();
        Self {
            events: Mutex::new(vec![]),
            mode: Mutex::new(DirectPostCommitMode::Live),
            answer: CommitAnswer::Stored,
            queue: QueueAnswer::Accepted,
            admission_conflict: false,
            finalize_error: false,
            finalize_gate: Mutex::new(None),
            remote_gate: Mutex::new(None),
            remote_result: Mutex::new(OnlineRouteResult::default()),
            archive: true,
            history_error: false,
            archive_requires_encryption: false,
            expect_retraction: false,
            committed: Mutex::new(None),
            sessions,
            deny_connection: Some(Uuid::from_u128(23)),
            fallback_error: false,
        }
    }
}

impl MessageHost for Host {
    type Messages = Repository;
    type Admissions = Repository;
    type Retractions = Repository;
    fn message_service(&self) -> &MessageService<Repository> {
        &self.messages
    }
    fn message_admission_service(&self) -> &MessageAdmissionService<Repository> {
        &self.admissions
    }
    fn retraction_service(&self) -> &RetractionService<Repository> {
        &self.retractions
    }
    fn personal_message_telemetry(&self) -> PersonalMessageTelemetry<'_> {
        PersonalMessageTelemetry::new(PersonalMessageTelemetryCells {
            routing_duration: &self.histogram,
            rate_limited: &self.counters[0],
            abuse_backend_failures: &self.counters[1],
            messages_routed: &self.counters[2],
            post_accept_failures: &self.counters[3],
            durable_queue_acceptances: &self.counters[4],
            volatile_queue_acceptances: &self.counters[5],
            carbon_delivery_failures: &self.counters[6],
            carbon_target_timeouts: &self.counters[7],
            cluster_legacy_acceptances: &self.counters[8],
        })
    }
    fn validate_routed_message(&self, _: Node<'_, '_>) -> Result<(), &'static str> {
        Ok(())
    }
    fn local_domain(&self) -> &str {
        "example.test"
    }
    fn archive_requires_encryption(&self) -> bool {
        self.state.archive_requires_encryption
    }
    fn offline_delivery_limits(&self) -> OfflineDeliveryLimits {
        OfflineDeliveryLimits {
            max_messages: 10,
            max_bytes: 4096,
            ttl_days: 1,
        }
    }
    fn xmpp_external_route_domain_allowed(&self, _: &str) -> bool {
        true
    }
    fn federation_outbox_policy(&self) -> S2sOutboxPolicy {
        S2sOutboxPolicy::new(60, 10, 4096, 10)
    }
    fn wake_federation_outbox(&self) {
        self.state.record(Event::WakeOutbox);
    }
    async fn send_volatile(&self, _: &str, _: &str, _: String) -> bool {
        panic!("unexpected volatile federation")
    }
    async fn personal_message_remote_resource_exists(&self, _: &str) -> bool {
        false
    }
    async fn dispatch_push_notification(&self, recipient: Uuid) -> Result<()> {
        self.state.record(Event::Push(recipient));
        Ok(())
    }
    async fn direct_invite_room(&self, _: &str) -> Result<Option<DirectInviteRoom>> {
        panic!("unexpected invite lookup")
    }
    async fn direct_invite_affiliation(&self, _: Uuid, _: Uuid) -> Result<Option<String>> {
        panic!("unexpected invite affiliation")
    }
    fn direct_muc_invite_cluster_authority(
        &self,
        _: Uuid,
        _: Uuid,
        _: i64,
        _: Uuid,
        _: &str,
        _: ClusterMucAffiliationSubject,
    ) -> Result<Option<ClusterMucInviteAuthority>> {
        panic!("unexpected invite authority")
    }
    async fn wake_committed_direct_muc_invite(&self, _: Uuid) -> Result<()> {
        panic!("unexpected invite wake")
    }
    fn message_events(&self) -> &dyn MessageEventSource {
        &self.message_events
    }
}

impl OnlineRoutePort for Host {
    type Session = OnlineSession;
    type Item = OutboundItem;
    // The refusal type is the production route queue's; the closure only hands the item back.
    #[allow(clippy::result_large_err)]
    fn try_local(
        &self,
        session: &OnlineSession,
        enqueue: RouteEnqueue,
    ) -> Result<(), RouteSendError> {
        enqueue.send_with(|item| {
            self.state.record(Event::Local(
                session.connection_id,
                item.stanza.clone(),
                item.c2s_delivery(),
            ));
            match self.state.queue {
                QueueAnswer::Accepted => Ok(()),
                QueueAnswer::Full => Err(QueueRefusal::Full(item)),
                QueueAnswer::Closed => Err(QueueRefusal::Closed(item)),
            }
        })
    }
    fn record_local_accept(&self, durable: bool) {
        self.state.record(Event::LocalAccepted(durable));
    }
    async fn route_available_remote(&self, _: &str, _: &str, _: Option<DurableDelivery>) -> bool {
        panic!("federation used generic fanout")
    }
    async fn route_remote_primary(
        &self,
        _: &str,
        _: &str,
        _: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        panic!("unexpected generic primary")
    }
}

impl FullJidFallbackPort for Host {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, OnlineSession)> {
        self.state.sessions.clone()
    }
    fn available_priority(&self, session: &OnlineSession) -> Option<i16> {
        session
            .available
            .load(Ordering::Relaxed)
            .then(|| session.priority.load(Ordering::Relaxed))
            .filter(|priority| *priority >= 0)
    }
    fn priority(&self, session: &OnlineSession) -> i16 {
        session.priority.load(Ordering::Relaxed)
    }
    async fn privacy_allows_fallback(&self, session: &OnlineSession, sender: &str) -> Result<bool> {
        self.state
            .record(Event::Privacy(session.connection_id, sender.to_owned()));
        if self.state.fallback_error {
            anyhow::bail!("fallback privacy failed");
        }
        Ok(self.state.deny_connection != Some(session.connection_id))
    }
    fn post_accept_failed(&self) {
        self.state.record(Event::PostAcceptFailed);
    }
}

impl DirectMessageRoutePort for Host {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        self.state.record(Event::Health);
        *self.state.mode.lock().unwrap()
    }
    fn clustered_direct_routes(&self) -> bool {
        true
    }
    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        self.state.record(Event::Rearm(delivery));
    }
}

impl CarbonDeliveryPort for Host {
    type Session = OnlineSession;
    fn enabled(&self) -> bool {
        true
    }
    fn sessions(&self, _: &str) -> Vec<(String, OnlineSession)> {
        vec![]
    }
    fn carbon_enabled(&self, _: &OnlineSession) -> bool {
        true
    }
    fn in_muc_scope(&self, _: &OnlineSession, _: &str, _: &str) -> bool {
        false
    }
    fn wrap(&self, _: Direction, _: &str, _: &str, _: &str) -> Option<String> {
        panic!("unexpected local Carbon")
    }
    async fn privacy_allows(
        &self,
        _: &OnlineSession,
        _: &str,
        _: PrivacyStanzaKind,
    ) -> Result<bool> {
        panic!("unexpected Carbon privacy")
    }
    async fn enqueue(&self, _: &OnlineSession, _: String) -> bool {
        panic!("unexpected local Carbon enqueue")
    }
    async fn route_sent_remote(
        &self,
        bare: &str,
        forwarded: &str,
        current: &str,
        _: Option<&str>,
        _: Option<(&str, &str)>,
    ) {
        self.state.record(Event::SentCarbon(
            bare.to_owned(),
            forwarded.to_owned(),
            current.to_owned(),
        ));
    }
    async fn route_received_remote(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) {
        self.state.record(Event::Carbon(
            recipient.to_owned(),
            delivered.map(str::to_owned),
            forwarded.to_owned(),
        ));
    }
    fn delivery_failed(&self) {
        panic!("unexpected Carbon failure")
    }
    fn target_timed_out(&self) {
        panic!("unexpected Carbon timeout")
    }
}

impl FederatedMessageHost for Host {
    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        self.state
            .sessions
            .iter()
            .filter(|(key, _)| !jid.contains('/') || key == jid)
            .cloned()
            .collect()
    }
    async fn s2s_remote_recipient_route_exists(&self, _: &str) -> bool {
        true
    }
    async fn handle_push_disable(&self, _: Node<'_, '_>, _: &str, _: &str) -> Result<bool> {
        Ok(false)
    }
    fn record_s2s_post_accept_failure(&self) {
        self.state.record(Event::PostAcceptFailed);
    }
    fn record_s2s_message_routed(&self) {
        self.state.record(Event::Routed);
    }
    fn record_s2s_online_accept(&self, durable: bool) {
        self.state.record(Event::FederationAccepted(durable));
    }
    async fn route_s2s_message_to_available_remote_resources(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        self.state.record(Event::Available(
            jid.to_owned(),
            stanza.to_owned(),
            delivery,
        ));
        self.state.remote_result.lock().unwrap().delivered
    }
    async fn route_s2s_message_to_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.state
            .record(Event::Primary(jid.to_owned(), stanza.to_owned(), delivery));
        let gate = self.state.remote_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.await.expect("release remote route");
        }
        std::mem::take(&mut *self.state.remote_result.lock().unwrap())
    }
}

pub(crate) struct Session {
    pub host: Host,
    pub operation: Mutex<Option<DirectOperationHandle>>,
    pub mix: bool,
}

impl Session {
    pub fn new(state: State, retained: bool) -> Self {
        Self {
            host: Host::new(state),
            operation: Mutex::new(retained.then(|| DirectOperationHandle::new(OPERATION))),
            mix: false,
        }
    }
}

impl MessageSession for Session {
    type Host = Host;
    type Action = Action;
    fn host(&self) -> &Host {
        &self.host
    }
    fn enter_frame_stage(&self, stage: MessageFrameStage) {
        self.host.state.record(Event::Stage(stage));
    }
    fn account_id(&self) -> Option<Uuid> {
        Some(ACTOR)
    }
    fn full_jid(&self) -> Option<&str> {
        Some(SENDER)
    }
    fn peer_ip(&self) -> IpAddr {
        Ipv4Addr::new(192, 0, 2, 1).into()
    }
    fn muc_domain(&self) -> String {
        "conference.example.test".to_owned()
    }
    fn upload_domain(&self) -> String {
        "upload.example.test".to_owned()
    }
    fn pubsub_domain(&self) -> String {
        "pubsub.example.test".to_owned()
    }
    fn message_operation(&self) -> Option<DirectOperationHandle> {
        self.operation.lock().unwrap().clone()
    }
    fn active_privacy(&self) -> Option<String> {
        Some("sender-policy".to_owned())
    }
    fn joined_room_nick(&self, _: &str) -> Option<String> {
        None
    }
    async fn pubsub_authorization_response(&self, _: Node<'_, '_>) -> Result<bool> {
        Ok(false)
    }
    async fn push_disable_message(&self, _: Node<'_, '_>, _: &str, _: &str) -> Result<bool> {
        Ok(false)
    }
    async fn try_mix_message(&self, _: Node<'_, '_>, raw: &str) -> Result<Option<Action>> {
        self.host.state.record(Event::Mix(raw.to_owned()));
        Ok(self.mix.then_some(Action::None))
    }
    async fn muc_message(&self, _: Node<'_, '_>, _: &str) -> Result<Action> {
        panic!("unexpected MUC dispatch")
    }
    fn message_actor(&self) -> Option<AuthenticatedMessageActor> {
        Some(AuthenticatedMessageActor {
            account_id: self.account_id()?,
            auth_generation: ACTOR_GENERATION,
            connection_id: ACTOR_CONNECTION,
            full_jid: CanonicalJid::parse(self.full_jid()?).ok()?,
        })
    }
}

pub(crate) fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
