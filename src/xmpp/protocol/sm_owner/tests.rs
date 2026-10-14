use super::*;
use crate::{
    services::sm::{SmMixLeaseRotation, SmQueueOwnershipResolution},
    services::sm_capacity::SmCapacityMetrics,
    xmpp::outbound::{DurableDelivery, MixDelivery},
};
use northstar_delivery_core::sm_ownership::{
    CommitFact, HDecision, Knowledge, KnowledgeClass, MixRotation,
};
use std::{
    sync::{atomic::AtomicU64, Mutex},
    task::Waker,
};

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum Cut {
    #[default]
    Success,
    BeforeCommit,
    DuringCommit,
    CommitError,
    TypedAfterCommitError,
    TypedAfterReceipt,
    AfterReceiptPending,
    AfterReceiptError,
    RollbackPending,
    RollbackError,
    RolledBack,
    Superseded,
    WrongReturnedRotation,
    MissingMix,
}
#[derive(Clone)]
struct FakePort {
    governor: Arc<SmMemoryGovernor>,
    events: Arc<Mutex<Vec<&'static str>>>,
    cut: Cut,
    rotate: bool,
    absent_unclaimed: bool,
    injected_shrink_error: bool,
}
impl FakePort {
    fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }
    fn event(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }
    fn mislabeled_supersession(&self, request: &sm_ownership::Request) -> anyhow::Error {
        let message_id = request
            .binding()
            .remaining
            .iter()
            .flatten()
            .find_map(|source| source.c2s())
            .unwrap()
            .message_id;
        crate::xmpp::outbound::DurableDeliverySuperseded { message_id }.into()
    }
    async fn commit(&self, request: &sm_ownership::Request, fact: CommitFact) -> Result<()> {
        self.event("commit");
        let committed = sm_ownership::commit_observed(
            async {
                if self.cut == Cut::DuringCommit {
                    std::future::pending::<()>().await;
                }
                if matches!(self.cut, Cut::CommitError | Cut::TypedAfterCommitError) {
                    return Err(std::io::Error::other("injected COMMIT response loss"));
                }
                Ok(())
            },
            request,
            fact,
        )
        .await;
        if self.cut == Cut::TypedAfterCommitError {
            assert!(committed.is_err());
            return Err(self.mislabeled_supersession(request));
        }
        committed?;
        self.event("receipt");
        if self.cut == Cut::TypedAfterReceipt {
            return Err(self.mislabeled_supersession(request));
        }
        // These cuts are synthetic: the current SQL adapter has no await
        // between its successful COMMIT callback and outcome conversion.
        if self.cut == Cut::AfterReceiptPending {
            std::future::pending::<()>().await;
        }
        if self.cut == Cut::AfterReceiptError {
            anyhow::bail!("injected post-receipt continuation error");
        }
        Ok(())
    }
}
impl SmOwnerPort for FakePort {
    fn recorded(&self) {
        self.event("record");
    }
    fn reserve_snapshot(&self, bytes: usize) -> Result<SmCapacityLease> {
        self.event("reserve_snapshot");
        Ok(self.governor.try_reserve_live(bytes)?)
    }
    fn grow(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()> {
        self.event("grow");
        Ok(lease.try_grow_to(bytes)?)
    }
    fn shrink(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()> {
        self.event("shrink");
        anyhow::ensure!(
            !self.injected_shrink_error,
            "injected capacity continuation failure"
        );
        Ok(lease.shrink_to(bytes)?)
    }
    async fn checkpoint(&self, prepared: &PreparedCheckpoint<'_>) -> Result<SmCheckpointOutcome> {
        self.event("checkpoint");
        prepared.validate_projection(
            prepared.session_id(),
            prepared.connection_id(),
            crate::services::sm::ownership::SnapshotProjection::from(prepared.snapshot()),
            prepared.acknowledged(),
            prepared.policy(),
        )?;
        if self.cut == Cut::Superseded {
            let message_id = prepared
                .snapshot()
                .unacked
                .iter()
                .find_map(|entry| entry.source.and_then(TransportOwnershipSource::c2s))
                .unwrap()
                .message_id;
            return Err(crate::xmpp::outbound::DurableDeliverySuperseded { message_id }.into());
        }
        if self.cut == Cut::BeforeCommit {
            anyhow::bail!("injected pre-COMMIT failure");
        }
        if matches!(
            self.cut,
            Cut::RollbackPending | Cut::RollbackError | Cut::RolledBack
        ) {
            self.event("rollback");
            sm_ownership::rollback_observed(
                async {
                    if self.cut == Cut::RollbackPending {
                        std::future::pending::<()>().await;
                    }
                    if self.cut == Cut::RollbackError {
                        return Err(std::io::Error::other("injected rollback response loss"));
                    }
                    Ok(())
                },
                prepared.request(),
            )
            .await?;
            return Ok(SmCheckpointOutcome {
                updated: false,
                ownership: SmQueueOwnershipResolution::default(),
            });
        }
        let rotations = if self.rotate {
            prepared
                .snapshot()
                .unacked
                .iter()
                .filter_map(|entry| entry.source.and_then(TransportOwnershipSource::mix))
                .map(|previous| MixRotation {
                    previous,
                    current: MixDelivery {
                        lease_token: Uuid::from_u128(999),
                        ..previous
                    },
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        self.commit(
            prepared.request(),
            CommitFact::Checkpoint {
                rotations: rotations.clone(),
                settled: prepared
                    .acknowledged()
                    .iter()
                    .filter_map(|entry| entry.source)
                    .collect(),
            },
        )
        .await?;
        let mut returned = rotations;
        if self.cut == Cut::WrongReturnedRotation {
            returned[0].current.lease_token = Uuid::from_u128(998);
        }
        Ok(SmCheckpointOutcome {
            updated: true,
            ownership: SmQueueOwnershipResolution {
                mix_rotations: returned
                    .into_iter()
                    .map(|rotation| SmMixLeaseRotation {
                        previous: rotation.previous,
                        current: rotation.current,
                    })
                    .collect(),
            },
        })
    }
    async fn acknowledge_batch(&self, prepared: &PreparedBatch<'_>) -> Result<()> {
        self.event("batch");
        prepared.validate_sources(prepared.sources())?;
        if prepared.sources().is_empty() {
            prepared.request().no_persistence()?;
            return Ok(());
        }
        if self.cut == Cut::BeforeCommit || self.cut == Cut::MissingMix {
            anyhow::bail!("injected exact source authority rejection");
        }
        let mut deleted = vec![];
        let mut absent_unclaimed = vec![];
        for source in prepared.sources() {
            match source {
                TransportOwnershipSource::C2s(delivery)
                    if self.absent_unclaimed && delivery.claim_id.is_none() =>
                {
                    absent_unclaimed.push(*delivery)
                }
                _ => deleted.push(*source),
            }
        }
        self.commit(
            prepared.request(),
            CommitFact::UnpersistedAck {
                deleted,
                absent_unclaimed,
            },
        )
        .await
    }
}
#[derive(Default)]
struct Metadata {
    available: Option<Arc<AtomicBool>>,
    carbons: AtomicBool,
    priority: AtomicI16,
    blocklist: AtomicBool,
    roster: AtomicBool,
    privacy: RwLock<Option<String>>,
    privacy_requested: AtomicBool,
    rooms: dashmap::DashMap<String, JoinedMucMembership>,
    directed: dashmap::DashSet<String>,
    presence: RwLock<Option<String>>,
}
impl Metadata {
    fn view(&self) -> SmSnapshotView<'_> {
        SmSnapshotView {
            available: &self.available,
            carbons: &self.carbons,
            priority: &self.priority,
            blocklist_requested: &self.blocklist,
            roster_requested: &self.roster,
            privacy_active: &self.privacy,
            privacy_requested: &self.privacy_requested,
            peer_ip: &TEST_IP,
            user_agent_id: &None,
            joined_rooms: &self.rooms,
            directed_presence: &self.directed,
            last_presence: &self.presence,
        }
    }
}
const TEST_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
struct Fixture {
    sm: SmSubstate,
    metadata: Metadata,
    policy: SmRuntimePolicy,
    port: FakePort,
}
impl Fixture {
    fn new(persisted: bool, queue: Vec<SmUnackedStanza>) -> Self {
        let governor = SmMemoryGovernor::new(
            65_536,
            32_768,
            4,
            32_768,
            Arc::new(SmCapacityMetrics::default()),
        )
        .unwrap();
        let metadata = Metadata::default();
        let mut sm = SmSubstate {
            enabled: true,
            db_id: persisted.then(|| Uuid::from_u128(401)),
            resume_allowed: true,
            resume_timeout_seconds: 60,
            inbound_h: 2,
            outbound_h: 10 + queue.len() as u32,
            acked_h: 10,
            unacked: queue.into(),
            ..SmSubstate::default()
        };
        sm.capacity = Some(
            governor
                .try_reserve_live(metadata.view().resident_bytes(&sm).unwrap())
                .unwrap(),
        );
        Self {
            sm,
            metadata,
            policy: SmRuntimePolicy {
                session: crate::state::SmSessionPolicy {
                    require_same_device: true,
                    resume_timeout_seconds: 60,
                    live_lease_seconds: 30,
                    claim_lease_seconds: 10,
                    max_per_account: 4,
                    max_global: 100,
                },
                buffer: crate::state::SmBufferLimits {
                    max_unacked_stanzas: 32,
                    max_unacked_bytes: 16_384,
                    max_snapshot_bytes: 32_768,
                },
                ip_binding: "none".to_owned(),
            },
            port: FakePort {
                governor,
                events: Arc::new(Mutex::new(vec![])),
                cut: Cut::Success,
                rotate: false,
                absent_unclaimed: false,
                injected_shrink_error: false,
            },
        }
    }
    fn turn(&mut self) -> SmTransportTurn<'_, FakePort> {
        SmTransportTurn {
            sm: &mut self.sm,
            view: self.metadata.view(),
            policy: &self.policy,
            connection_id: Uuid::from_u128(402),
            port: self.port.clone(),
        }
    }
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        let mut turn = self.turn();
        let observation = turn.start(Purpose::Record);
        SmTurnRunner::new(observation.clone(), async move {
            let result = turn.record_item(item, &observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await
    }
    async fn ack(&mut self, h: u32) -> Result<bool> {
        let mut turn = self.turn();
        let observation = turn.start(Purpose::Acknowledge { h });
        SmTurnRunner::new(observation.clone(), async move {
            let result = turn.acknowledge(h, &observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await
    }
    fn snapshot(&self) -> sm_ownership::Snapshot {
        self.sm.current_operation.as_ref().unwrap().snapshot()
    }
}
fn c2s() -> DurableDelivery {
    DurableDelivery {
        recipient_id: Uuid::from_u128(501),
        message_id: Uuid::from_u128(502),
        claim_id: Some(Uuid::from_u128(503)),
    }
}
fn mix() -> MixDelivery {
    MixDelivery {
        delivery_id: Uuid::from_u128(601),
        lease_token: Uuid::from_u128(602),
    }
}
fn c2s_item() -> OutboundItem {
    OutboundItem::durable(
        "<message id='private-payload'><body>hello</body></message>".to_owned(),
        c2s(),
    )
}
fn plain() -> SmUnackedStanza {
    SmUnackedStanza::plain("<presence/>".to_owned())
}
fn mixed_queue() -> Vec<SmUnackedStanza> {
    vec![
        plain(),
        SmUnackedStanza::with_source(
            "<message id='c2s'/>".to_owned(),
            Some(TransportOwnershipSource::C2s(c2s())),
        ),
        plain(),
        SmUnackedStanza::with_source(
            "<message id='mix'/>".to_owned(),
            Some(TransportOwnershipSource::Mix(mix())),
        ),
    ]
}
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut TaskContext::from_waker(Waker::noop()))
}

#[tokio::test]
async fn record_limits_and_real_governor_reject_before_append_or_persistence() {
    for limit in 0..3 {
        let mut fixture = Fixture::new(true, vec![]);
        let before_h = fixture.sm.outbound_h;
        let _pressure = if limit == 2 {
            let available = 65_536 - fixture.sm.capacity.as_ref().unwrap().reserved_bytes();
            Some(
                fixture
                    .port
                    .governor
                    .try_reserve_transient(available)
                    .unwrap(),
            )
        } else {
            None
        };
        if limit == 0 {
            fixture.policy.buffer.max_unacked_stanzas = 0;
        }
        if limit == 1 {
            fixture.policy.buffer.max_unacked_bytes = 0;
        }
        assert!(fixture.record(&c2s_item()).await.is_err());
        assert!(fixture.sm.unacked.is_empty());
        assert_eq!(fixture.sm.outbound_h, before_h);
        assert!(!fixture.sm.resume_allowed);
        assert!(!fixture.port.events().contains(&"checkpoint"));
        assert!(!fixture.snapshot().appended);
    }
}
#[tokio::test]
async fn nonpersisted_record_keeps_fifo_without_claiming_sm_ownership() {
    let mut fixture = Fixture::new(false, vec![]);
    let (receipt_tx, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut item = c2s_item();
    item.transport_receipt = Some(receipt_tx);
    assert!(!fixture.record(&item).await.unwrap());
    assert_eq!(fixture.sm.unacked.len(), 1);
    assert_eq!(fixture.sm.outbound_h, 11);
    assert_eq!(fixture.snapshot().knowledge, Knowledge::NotRequested);
    assert!(!fixture.snapshot().notification_attempted);
    assert!(receipt_rx.try_recv().is_err());
    assert_eq!(fixture.port.events(), vec!["record", "grow"]);
}
#[tokio::test]
async fn record_wraps_h_and_restores_only_typed_supersession() {
    for cut in [
        Cut::Superseded,
        Cut::BeforeCommit,
        Cut::RolledBack,
        Cut::Success,
    ] {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.sm.outbound_h = u32::MAX;
        fixture.sm.acked_h = u32::MAX;
        fixture.port.cut = cut;
        let item = c2s_item();
        let result = fixture.record(&item).await;
        assert_eq!(result.is_ok(), cut == Cut::Success);
        assert_eq!(
            fixture.sm.unacked.len(),
            usize::from(cut != Cut::Superseded)
        );
        assert_eq!(
            fixture.sm.outbound_h,
            if cut == Cut::Superseded { u32::MAX } else { 0 }
        );
        assert_eq!(fixture.snapshot().restored, cut == Cut::Superseded);
        assert!(fixture.snapshot().appended);
        if cut == Cut::RolledBack {
            assert_eq!(fixture.snapshot().knowledge, Knowledge::RollbackKnown);
        }
        if cut == Cut::Success {
            assert_eq!(
                fixture.port.events(),
                vec![
                    "record",
                    "grow",
                    "reserve_snapshot",
                    "grow",
                    "checkpoint",
                    "commit",
                    "receipt"
                ]
            );
        }
    }
}
#[tokio::test]
async fn record_drop_preserves_append_and_exact_commit_or_rollback_knowledge() {
    for cut in [
        Cut::DuringCommit,
        Cut::AfterReceiptPending,
        Cut::RollbackPending,
    ] {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.port.cut = cut;
        let item = c2s_item();
        let mut future = Box::pin(fixture.record(&item));
        assert!(poll_once(future.as_mut()).is_pending());
        drop(future);
        assert_eq!(fixture.sm.unacked.len(), 1);
        assert_eq!(fixture.sm.outbound_h, 11);
        let snapshot = fixture.snapshot();
        assert!(snapshot.appended);
        assert!(!snapshot.restored);
        assert!(!snapshot.notification_attempted);
        assert_eq!(snapshot.terminal, Some(Terminal::Cancelled));
        assert_eq!(
            snapshot.summary().knowledge,
            match cut {
                Cut::DuringCommit => KnowledgeClass::CommitCallEntered,
                Cut::AfterReceiptPending => KnowledgeClass::ReceiptKnown,
                _ => KnowledgeClass::RollbackCallEntered,
            }
        );
    }
}
#[tokio::test]
async fn record_rotations_precede_actual_mix_notification_and_wrong_return_is_rejected() {
    for wrong in [false, true] {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.port.rotate = true;
        if wrong {
            fixture.port.cut = Cut::WrongReturnedRotation;
        }
        let (item, mut receipt) =
            OutboundItem::durable_mix("<message id='mix'/>".to_owned(), mix());
        let result = fixture.record(&item).await;
        assert_eq!(result.is_ok(), !wrong);
        assert_eq!(
            fixture.sm.unacked[0]
                .source
                .unwrap()
                .mix()
                .unwrap()
                .lease_token,
            Uuid::from_u128(if wrong { 602 } else { 999 })
        );
        if wrong {
            assert!(receipt.try_recv().is_err());
            assert!(!fixture.snapshot().ownership_applied);
        } else {
            assert_eq!(
                receipt.try_recv().unwrap(),
                crate::xmpp::outbound::MixTransportCompletion::SmPersisted {
                    session_id: fixture.sm.db_id.unwrap()
                }
            );
        }
        assert_eq!(fixture.snapshot().notification_attempted, !wrong);
        assert_eq!(
            fixture.snapshot().summary().knowledge,
            KnowledgeClass::ReceiptKnown
        );
    }
}
#[tokio::test]
async fn acknowledgement_uses_existing_h_rules_for_invalid_zero_delta_and_wrap() {
    for h in [9, 15, u32::MAX] {
        let mut fixture = Fixture::new(true, mixed_queue());
        let before = fixture.sm.unacked.clone();
        assert!(!fixture.ack(h).await.unwrap());
        assert_eq!(fixture.sm.unacked, before);
        assert_eq!(fixture.snapshot().h_decision, HDecision::Invalid);
        assert!(fixture.port.events().is_empty());
    }
    let mut zero = Fixture::new(true, vec![plain()]);
    assert!(zero.ack(10).await.unwrap());
    assert_eq!(zero.sm.unacked.len(), 1);
    assert!(zero.port.events().contains(&"commit"));
    let mut wrap = Fixture::new(true, vec![plain(), plain(), plain()]);
    wrap.sm.acked_h = u32::MAX - 1;
    wrap.sm.outbound_h = 1;
    assert!(wrap.ack(1).await.unwrap());
    assert!(wrap.sm.unacked.is_empty());
    assert_eq!(wrap.sm.acked_h, 1);
}
#[tokio::test]
async fn acknowledgement_binds_mixed_prefix_plain_slots_and_returned_suffix_rotations() {
    let mut fixture = Fixture::new(true, mixed_queue());
    fixture.port.rotate = true;
    assert!(fixture.ack(12).await.unwrap());
    assert_eq!(fixture.sm.acked_h, 12);
    assert_eq!(fixture.sm.unacked.len(), 2);
    assert_eq!(fixture.sm.unacked[0], plain());
    assert_eq!(
        fixture.sm.unacked[1]
            .source
            .unwrap()
            .mix()
            .unwrap()
            .lease_token,
        Uuid::from_u128(999)
    );
    let snapshot = fixture.snapshot();
    let binding = snapshot.binding.as_ref().unwrap();
    assert_eq!(
        binding.whole,
        vec![
            None,
            Some(TransportOwnershipSource::C2s(c2s())),
            None,
            Some(TransportOwnershipSource::Mix(mix()))
        ]
    );
    assert_eq!(binding.acknowledged.len(), 2);
    assert_eq!(snapshot.acknowledged_h_applied, Some(12));
    assert_eq!(snapshot.summary().committed_settled, Some(1));
    assert_eq!(
        fixture.port.events(),
        vec![
            "reserve_snapshot",
            "checkpoint",
            "commit",
            "receipt",
            "shrink"
        ]
    );
}
#[tokio::test]
async fn acknowledgement_failure_and_drop_never_erase_known_transaction_receipt() {
    for cut in [
        Cut::BeforeCommit,
        Cut::DuringCommit,
        Cut::CommitError,
        Cut::AfterReceiptPending,
        Cut::AfterReceiptError,
        Cut::RollbackPending,
        Cut::RollbackError,
        Cut::RolledBack,
    ] {
        let mut fixture = Fixture::new(true, mixed_queue());
        fixture.port.cut = cut;
        let original = fixture.sm.unacked.clone();
        let mut future = Box::pin(fixture.ack(12));
        let result = poll_once(future.as_mut());
        assert_eq!(
            result.is_pending(),
            matches!(
                cut,
                Cut::DuringCommit | Cut::AfterReceiptPending | Cut::RollbackPending
            )
        );
        if let Poll::Ready(result) = result {
            assert!(result.is_err());
        }
        drop(future);
        assert_eq!(fixture.sm.unacked, original);
        assert_eq!(fixture.sm.acked_h, 10);
        assert_eq!(fixture.snapshot().acknowledged_h_applied, None);
        assert_eq!(
            fixture.snapshot().summary().knowledge,
            match cut {
                Cut::BeforeCommit => KnowledgeClass::NoCommitRequested,
                Cut::DuringCommit | Cut::CommitError => KnowledgeClass::CommitCallEntered,
                Cut::AfterReceiptPending | Cut::AfterReceiptError => KnowledgeClass::ReceiptKnown,
                Cut::RolledBack => KnowledgeClass::RollbackKnown,
                _ => KnowledgeClass::RollbackCallEntered,
            }
        );
    }
}
#[tokio::test]
async fn injected_post_ack_capacity_failure_keeps_committed_fifo_and_h() {
    let mut fixture = Fixture::new(true, mixed_queue());
    fixture.port.injected_shrink_error = true;
    assert!(fixture.ack(12).await.is_err());
    assert_eq!(fixture.sm.acked_h, 12);
    assert_eq!(fixture.sm.unacked.len(), 2);
    let snapshot = fixture.snapshot();
    assert_eq!(snapshot.acknowledged_h_applied, Some(12));
    assert_eq!(snapshot.capacity_completed, Some(false));
    assert_eq!(snapshot.summary().knowledge, KnowledgeClass::ReceiptKnown);
}
#[tokio::test]
async fn nonpersisted_plain_ack_skips_commit_while_persisted_plain_ack_commits() {
    for persisted in [false, true] {
        let mut fixture = Fixture::new(persisted, vec![plain()]);
        assert!(fixture.ack(11).await.unwrap());
        assert_eq!(fixture.port.events().contains(&"commit"), persisted);
        assert_eq!(
            fixture.snapshot().summary().knowledge,
            if persisted {
                KnowledgeClass::ReceiptKnown
            } else {
                KnowledgeClass::NoPersistence
            }
        );
    }
}
#[tokio::test]
async fn nonpersisted_fake_authority_distinguishes_absent_c2s_and_strict_mix_failure() {
    // This is a fake repository compatibility case, not SQL qualification.
    let delivery = DurableDelivery {
        claim_id: None,
        ..c2s()
    };
    let mut fixture = Fixture::new(
        false,
        vec![SmUnackedStanza::with_source(
            "<message/>".to_owned(),
            Some(TransportOwnershipSource::C2s(delivery)),
        )],
    );
    fixture.port.absent_unclaimed = true;
    assert!(fixture.ack(11).await.unwrap());
    assert_eq!(
        fixture.snapshot().summary().committed_absent_unclaimed,
        Some(1)
    );
    assert_eq!(fixture.snapshot().summary().committed_settled, Some(0));
    let mut mixed = Fixture::new(false, mixed_queue());
    mixed.port.cut = Cut::MissingMix;
    let before = mixed.sm.unacked.clone();
    assert!(mixed.ack(14).await.is_err());
    assert_eq!(mixed.sm.unacked, before);
    assert_eq!(mixed.sm.acked_h, 10);
    assert!(!mixed.port.events().contains(&"commit"));
}
#[test]
fn private_preparation_rejects_changed_epoch_whole_cut_payload_and_projection() {
    let mut fixture = Fixture::new(true, mixed_queue());
    let observation = fixture.turn().start(Purpose::Acknowledge { h: 12 });
    observation.h_decision(Some(2));
    let acknowledged = fixture
        .sm
        .unacked
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    let mut snapshot = fixture.metadata.view().snapshot(
        &fixture.sm,
        fixture.sm.unacked.iter().skip(2).cloned().collect(),
    );
    snapshot.acked_h = 12;
    let policy = CheckpointPolicy {
        ttl_seconds: 60,
        live_lease_seconds: 30,
        max_stanzas: 32,
        max_bytes: 16_384,
    };
    let session = fixture.sm.db_id.unwrap();
    let connection = Uuid::from_u128(402);
    let before = observation.snapshot();
    for change in 0..5 {
        let mut altered = snapshot.clone();
        let mut session = session;
        let mut connection = connection;
        let mut prefix = acknowledged.clone();
        match change {
            0 => session = Uuid::nil(),
            1 => connection = Uuid::nil(),
            2 => altered.acked_h = 13,
            3 => altered.unacked[0].stanza = "<presence type='unavailable'/>".to_owned(),
            _ => prefix.swap(0, 1),
        }
        assert!(PreparedCheckpoint::bind(
            &observation,
            session,
            connection,
            &fixture.sm.unacked,
            &altered,
            &prefix,
            policy
        )
        .is_err());
        assert_eq!(observation.snapshot(), before);
    }
    let prepared = PreparedCheckpoint::bind(
        &observation,
        session,
        connection,
        &fixture.sm.unacked,
        &snapshot,
        &acknowledged,
        policy,
    )
    .unwrap();
    let before = observation.snapshot();
    for change in 0..4 {
        let mut altered = snapshot.clone();
        let mut policy = policy;
        match change {
            0 => altered.unacked[0].stanza = "<message>changed</message>".to_owned(),
            1 => altered.active_privacy_list = Some("changed-private-policy".to_owned()),
            2 => altered.user_agent_id = Some(Uuid::nil()),
            _ => policy.ttl_seconds += 1,
        }
        assert!(prepared
            .validate_projection(
                session,
                connection,
                crate::services::sm::ownership::SnapshotProjection::from(&altered),
                &acknowledged,
                policy
            )
            .is_err());
        assert_eq!(observation.snapshot(), before);
    }
    assert!(fixture.port.events().is_empty());
    let debug = format!("{prepared:?} {observation:?} {:?}", observation.snapshot());
    assert!(!debug.contains("<presence"));
    assert!(!debug.contains("private-policy"));
    assert!(!debug.contains(&c2s().claim_id.unwrap().to_string()));
}
#[tokio::test]
async fn replaced_turn_slot_keeps_old_receipt_and_full_snapshot_independent() {
    let mut fixture = Fixture::new(true, vec![]);
    fixture.record(&c2s_item()).await.unwrap();
    let old = fixture.sm.current_operation.as_ref().unwrap().clone();
    let before = old.snapshot();
    let mut turn = fixture.turn();
    let current = turn.start(Purpose::Checkpoint);
    SmTurnRunner::new(current.clone(), async {
        turn.checkpoint_in_turn(&current).await
    })
    .await
    .unwrap();
    assert_eq!(old.snapshot(), before);
    assert_eq!(current.snapshot().scope.purpose, Purpose::Checkpoint);
    assert_eq!(current.snapshot().terminal, Some(Terminal::Returned));
    assert_eq!(old.snapshot().scope.purpose, Purpose::Record);
    assert!(matches!(
        old.snapshot().knowledge,
        Knowledge::ReceiptKnown(_)
    ));
}
struct DropProbe {
    observation: Observation,
    dropped: Arc<AtomicBool>,
    panic_poll: bool,
    panic_drop: bool,
    ready: bool,
}
impl Future for DropProbe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<()> {
        if self.panic_poll {
            panic!("SM child poll panic");
        }
        if self.ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
impl Drop for DropProbe {
    fn drop(&mut self) {
        assert!(self.observation.snapshot().terminal.is_none());
        self.dropped.store(true, Ordering::SeqCst);
        if self.panic_drop {
            panic!("SM child drop panic");
        }
    }
}
#[test]
fn turn_owner_drops_child_before_summary_and_preserves_caught_panic() {
    for case in 0..5 {
        let mut fixture = Fixture::new(true, vec![]);
        let observation = fixture.turn().start(Purpose::Checkpoint);
        let dropped = Arc::new(AtomicBool::new(false));
        let child = DropProbe {
            observation: observation.clone(),
            dropped: dropped.clone(),
            panic_poll: case == 3,
            panic_drop: case == 4,
            ready: case == 2 || case == 4,
        };
        let mut future = Box::pin(SmTurnRunner::new(observation.clone(), child));
        if case != 0 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                poll_once(future.as_mut())
            }));
            if case >= 3 {
                let payload = result.unwrap_err();
                assert_eq!(
                    payload.downcast_ref::<&str>().copied(),
                    Some(if case == 3 {
                        "SM child poll panic"
                    } else {
                        "SM child drop panic"
                    })
                );
            } else {
                assert_eq!(result.unwrap().is_ready(), case == 2);
            }
        }
        drop(future);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(
            observation.snapshot().terminal,
            Some(if case >= 3 {
                Terminal::Panicked
            } else if case == 2 {
                Terminal::Returned
            } else {
                Terminal::Cancelled
            })
        );
    }
}
struct NativeSm<'a> {
    turn: SmTransportTurn<'a, FakePort>,
    native_calls: AtomicU64,
}
impl crate::xmpp::direct_delivery::DirectWritePort for NativeSm<'_> {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        let observation = self.turn.start(Purpose::Record);
        SmTurnRunner::new(
            observation.clone(),
            self.turn.record_item(item, &observation),
        )
        .await
    }
    async fn fence_c2s(&self, _: DurableDelivery) -> Result<DurableDelivery> {
        self.native_calls.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("unexpected native C2S fence")
    }
    async fn fence_mix(&self, _: MixDelivery) -> Result<MixDelivery> {
        self.native_calls.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("unexpected native MIX fence")
    }
    async fn acknowledge_c2s(
        &self,
        _: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<()> {
        self.native_calls.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("unexpected native C2S ACK")
    }
    async fn acknowledge_mix(
        &self,
        _: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<bool> {
        self.native_calls.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("unexpected native MIX ACK")
    }
    fn connection_id(&self) -> Uuid {
        self.turn.connection_id
    }
}
#[tokio::test]
async fn real_sm_record_composes_with_native_lease_without_native_fence_or_ack() {
    for use_mix in [false, true] {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.port.rotate = use_mix;
        let (item, mut mix_receipt) = if use_mix {
            let (item, receipt) =
                OutboundItem::durable_mix("<message id='actual-mix'/>".to_owned(), mix());
            (item, Some(receipt))
        } else {
            (c2s_item(), None)
        };
        let (ownership_tx, mut ownership_rx) = tokio::sync::mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut item = item;
        item.transport_receipt = Some(ownership_tx);
        item.transport_write_receipt = Some(write_tx);
        let native = northstar_delivery_core::native_write::Observation::new(item.durable_source);
        let mut port = NativeSm {
            turn: fixture.turn(),
            native_calls: AtomicU64::new(0),
        };
        let lease =
            crate::xmpp::direct_delivery::DirectWriteLease::prepare_with(&mut port, &item, &native)
                .await
                .unwrap();
        assert!(
            port.turn
                .sm
                .current_operation
                .as_ref()
                .unwrap()
                .snapshot()
                .notification_attempted
        );
        if let Some(receipt) = mix_receipt.as_mut() {
            assert_eq!(
                receipt.try_recv().unwrap(),
                crate::xmpp::outbound::MixTransportCompletion::SmPersisted {
                    session_id: port.turn.sm.db_id.unwrap()
                }
            );
            assert!(ownership_rx.try_recv().is_err());
        } else {
            ownership_rx.try_recv().unwrap();
        }
        assert!(write_rx.try_recv().is_err());
        let expected = item.stanza.as_str();
        let written = lease
            .write(|stanza| async move {
                assert_eq!(stanza, expected);
                Ok(())
            })
            .await
            .unwrap();
        written.settle_with(&port).await;
        write_rx.try_recv().unwrap();
        assert_eq!(port.native_calls.load(Ordering::Relaxed), 0);
        assert!(ownership_rx.try_recv().is_err());
        assert_eq!(native.snapshot().managed_by_sm, Some(true));
        assert_eq!(
            native.snapshot().ack,
            northstar_delivery_core::native_write::AckKnowledge::NotRequested
        );
    }
}
impl crate::bosh::BoshRecordPort for NativeSm<'_> {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        <Self as crate::xmpp::direct_delivery::DirectWritePort>::record(self, item).await
    }
}
#[tokio::test]
async fn actual_sm_record_clears_bosh_source_before_fifo_and_preserves_prior_sm_ownership_on_refusal(
) {
    for full in [false, true] {
        for use_mix in [false, true] {
            let mut fixture = Fixture::new(true, vec![]);
            fixture.port.rotate = use_mix;
            let (item, mut mix_receipt) = if use_mix {
                let (item, receipt) =
                    OutboundItem::durable_mix("<message id='sm-bosh-mix'/>".to_owned(), mix());
                (item, Some(receipt))
            } else {
                (c2s_item(), None)
            };
            let (tx, mut c2s_receipt) = tokio::sync::mpsc::unbounded_channel();
            let mut item = item;
            item.transport_receipt = Some(tx);
            let pointer = item.stanza.as_ptr();
            let size = item.stanza.len();
            let mut record = NativeSm {
                turn: fixture.turn(),
                native_calls: AtomicU64::new(0),
            };
            let (accepted, items, bytes, bosh) =
                crate::bosh::sm_record_composition(&mut record, item, full).await;
            assert_eq!(accepted, !full);
            assert_eq!(record.turn.sm.unacked.len(), 1);
            assert_eq!(record.turn.sm.outbound_h, 11);
            let sm = record
                .turn
                .sm
                .current_operation
                .as_ref()
                .unwrap()
                .snapshot();
            assert_eq!(sm.summary().knowledge, KnowledgeClass::ReceiptKnown);
            assert!(sm.notification_attempted);
            if let Some(receipt) = mix_receipt.as_mut() {
                assert_eq!(
                    record.turn.sm.unacked[0]
                        .source
                        .unwrap()
                        .mix()
                        .unwrap()
                        .lease_token,
                    Uuid::from_u128(999)
                );
                assert_eq!(
                    receipt.try_recv().unwrap(),
                    crate::xmpp::outbound::MixTransportCompletion::SmPersisted {
                        session_id: record.turn.sm.db_id.unwrap()
                    }
                );
                assert!(c2s_receipt.try_recv().is_err());
            } else {
                assert_eq!(
                    record.turn.sm.unacked[0].source,
                    Some(TransportOwnershipSource::C2s(c2s()))
                );
                c2s_receipt.try_recv().unwrap();
            }
            let bosh = bosh.snapshot();
            assert!(bosh.transfers.is_empty());
            assert_eq!(bosh.keep_running, Some(!full));
            if full {
                assert_eq!(items.len(), 2);
                assert_eq!(bytes, "<presence/>".len() * 2);
            } else {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].stanza.as_ptr(), pointer);
                assert_eq!(bytes, size);
                assert!(items[0].durable_source.is_none());
                assert!(items[0].mix_handoff.is_none());
                assert!(items[0].transport_receipt.is_some());
            }
        }
    }
}

#[tokio::test]
async fn mislabeled_typed_supersession_after_commit_keeps_fifo_h_and_original_error() {
    // Adapter-mismatch hardening. Current SQL emits this typed error only
    // before COMMIT; the fake drives the real wrapper before relabeling.
    for cut in [
        Cut::Superseded,
        Cut::TypedAfterCommitError,
        Cut::TypedAfterReceipt,
    ] {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.port.cut = cut;
        let error = fixture.record(&c2s_item()).await.unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<crate::xmpp::outbound::DurableDeliverySuperseded>()
                .unwrap()
                .message_id,
            c2s().message_id
        );
        let restored = cut == Cut::Superseded;
        assert_eq!(fixture.sm.unacked.len(), usize::from(!restored));
        assert_eq!(fixture.sm.outbound_h, if restored { 10 } else { 11 });
        assert_eq!(fixture.sm.acked_h, 10);
        let snapshot = fixture.snapshot();
        assert_eq!(snapshot.restored, restored);
        assert!(!snapshot.notification_attempted);
        assert_eq!(
            snapshot.summary().knowledge,
            match cut {
                Cut::Superseded => KnowledgeClass::NoCommitRequested,
                Cut::TypedAfterCommitError => KnowledgeClass::CommitCallEntered,
                _ => KnowledgeClass::ReceiptKnown,
            }
        );
        assert_eq!(fixture.port.events().contains(&"commit"), !restored);
        assert_eq!(
            fixture.port.events().contains(&"receipt"),
            cut == Cut::TypedAfterReceipt
        );
        assert_eq!(fixture.port.events().contains(&"shrink"), restored);
    }
}
