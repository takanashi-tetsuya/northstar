use super::*;
use northstar_room_application::{
    cluster_muc_delivery_item::*, cluster_muc_delivery_read::*, cluster_muc_outbox_claim::*,
    cluster_muc_outbox_housekeeping::*, cluster_muc_outbox_preclaim::*,
    cluster_muc_outbox_settlement::*, cluster_muc_receipt_claim::*, muc_delivery::*,
};
use northstar_room_core::{
    ClusterMucAudienceSnapshot, ClusterMucEventContext, ClusterMucOutboxDelivery,
};
use northstar_runtime::{durable_outbox::DurableOutboxDatabaseAdmission, workers::*};
use northstar_stream::{
    local_routes::muc::{MucOccupant, MucOccupantEndpoint},
    outbound::OutboundItem,
};
use northstar_telemetry::metrics::Metrics;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

mod unused_ports;
use authority::AuthorityPorts;
use unused_ports::{MessagePorts, UnusedPorts};

struct Adapters;

impl ClusterAdapters for Adapters {
    type ClusterAuthority = AuthorityPorts;
    type ReplayMaintenance = AuthorityPorts;
    type RouteMaintenance = AuthorityPorts;
    type SessionAuthoritySweep = AuthorityPorts;
    type NodeMessageProjection = durable_recipient_identity::Projection;
    type SessionTermination = UnusedPorts;
    type Replay = northstar_session_postgres::replay_repository::PostgresReplayRepository;
    type RecoveryReplay =
        northstar_session_postgres::replay_repository::PostgresRecoveryReplayStore;
    type MucOccupancyMaintenance = AuthorityPorts;
    type MucOutboxPreclaim = Ports;
    type MucOutboxClaim = Ports;
    type MucOutboxSettlement = Ports;
    type MucOutboxHousekeeping = Ports;
    type MucDeliveryRead = Ports;
    type MucDeliveryItem = Ports;
    type MucDelivery = Ports;
    type MucReceiptClaim = Ports;
    type Mix = UnusedPorts;
    type SmTeardownMuc = UnusedPorts;
    type Message = MessagePorts;
    type DirectSpoolWake = UnusedPorts;
    type Presence = UnusedPorts;
    type Federation = UnusedPorts;
}

#[derive(Clone)]
struct Ports(Arc<Recording>);

struct Recording {
    admission: DurableOutboxDatabaseAdmission,
    calls: Mutex<Vec<&'static str>>,
    gates: Mutex<HashMap<&'static str, oneshot::Receiver<()>>>,
    row: ClusterMucOutboxDelivery,
    context: Mutex<ClusterMucEventContext>,
    snapshot: Mutex<Option<ClusterMucAudienceSnapshot>>,
    original: ClusterMucAudienceSnapshot,
    current: AtomicBool,
    claimed: AtomicBool,
    ack: Mutex<std::result::Result<bool, &'static str>>,
    retry: Mutex<std::result::Result<bool, &'static str>>,
    complete: AtomicBool,
    stale_reservation: AtomicBool,
    render_items: i32,
    metrics: Arc<Metrics>,
}

impl Ports {
    fn gate(&self, step: &'static str) -> oneshot::Sender<()> {
        let (send, receive) = oneshot::channel();
        assert!(self.0.gates.lock().unwrap().insert(step, receive).is_none());
        send
    }

    async fn enter(&self, step: &'static str) {
        self.0.calls.lock().unwrap().push(step);
        let gate = self.0.gates.lock().unwrap().remove(step);
        if let Some(gate) = gate {
            gate.await.expect("test controls the repository barrier");
        }
    }

    async fn database(&self, step: &'static str) {
        assert_eq!(
            self.0.admission.available_permits(),
            0,
            "{step} must own admission"
        );
        self.enter(step).await;
    }

    fn exact(&self, row: &ClusterMucOutboxDelivery) {
        // The Debug representation includes every immutable row field and the claim token.
        assert_eq!(format!("{row:?}"), format!("{:?}", self.0.row));
    }

    fn calls(&self) -> Vec<&'static str> {
        self.0.calls.lock().unwrap().clone()
    }

    fn counters(&self) -> (u64, u64) {
        (
            self.0
                .metrics
                .cluster_muc_outbox_deliveries_total
                .load(Ordering::Relaxed),
            self.0
                .metrics
                .cluster_muc_outbox_retries_total
                .load(Ordering::Relaxed),
        )
    }
}

impl ClusterMucOutboxPreclaimRepository for Ports {
    async fn expire_occupancies(&self, limit: i64) -> Result<u64> {
        assert_eq!(limit, 32);
        self.database("expire").await;
        Ok(0)
    }

    async fn dead_letter_expired(&self, limit: i64) -> Result<u64> {
        assert_eq!(limit, 256);
        self.database("dead-letter").await;
        Ok(0)
    }
}

impl ClusterMucOutboxClaimRepository for Ports {
    type Delivery = ClusterMucOutboxDelivery;

    async fn claim_batch(
        &self,
        node: &str,
        limit: i64,
        lease: Duration,
    ) -> Result<Vec<Self::Delivery>> {
        assert_eq!(node, "outbox-node");
        assert_eq!(limit, 16);
        assert_eq!(lease, Duration::from_secs(30));
        self.database("claim").await;
        Ok(if self.0.claimed.swap(true, Ordering::Relaxed) {
            Vec::new()
        } else {
            vec![self.0.row.clone()]
        })
    }
}

impl ClusterMucDeliveryReadRepository for Ports {
    type Delivery = ClusterMucOutboxDelivery;
    type EventContext = ClusterMucEventContext;
    type AudienceSnapshot = ClusterMucAudienceSnapshot;

    async fn event_context(&self, operation: Uuid) -> Result<Option<Self::EventContext>> {
        assert_eq!(operation, self.0.row.operation_id);
        self.database("context").await;
        Ok(Some(self.0.context.lock().unwrap().clone()))
    }

    async fn recipient_snapshot(
        &self,
        row: &Self::Delivery,
    ) -> Result<Option<Self::AudienceSnapshot>> {
        self.exact(row);
        self.database("snapshot").await;
        Ok(self.0.snapshot.lock().unwrap().clone())
    }

    async fn audience_is_current(&self, row: &Self::Delivery) -> Result<bool> {
        self.exact(row);
        self.database("current").await;
        Ok(self.0.current.load(Ordering::Relaxed))
    }

    async fn original_audience_snapshot(
        &self,
        row: &Self::Delivery,
    ) -> Result<Option<Self::AudienceSnapshot>> {
        self.exact(row);
        self.database("original").await;
        Ok(Some(self.0.original.clone()))
    }
}

impl ClusterMucDeliveryItemRepository for Ports {
    type Delivery = ClusterMucOutboxDelivery;

    async fn completed(&self, id: Uuid, ordinal: i32, stable: &str) -> Result<bool> {
        if self.0.render_items != 1 {
            assert_eq!(id, self.0.row.delivery_id);
            self.check_render_item(ordinal, stable);
            self.database("completed").await;
            return Ok(false);
        }
        assert_eq!(
            (id, ordinal, stable),
            (
                self.0.row.delivery_id,
                0,
                format!("{}:0", self.0.row.event_id).as_str()
            )
        );
        self.database("completed").await;
        Ok(false)
    }

    async fn reserve_item_exact(
        &self,
        row: &Self::Delivery,
        ordinal: i32,
        stable: &str,
    ) -> Result<northstar_room_application::cluster_muc_delivery_item::ItemAdmission> {
        use northstar_room_application::cluster_muc_delivery_item::ItemAdmission;
        self.exact(row);
        let completed = self.completed(row.delivery_id, ordinal, stable).await?;
        Ok(if self.0.stale_reservation.load(Ordering::Relaxed) {
            ItemAdmission::Stale
        } else if completed {
            ItemAdmission::Completed
        } else {
            ItemAdmission::Ready
        })
    }

    async fn complete_exact(
        &self,
        row: &Self::Delivery,
        ordinal: i32,
        stable: &str,
    ) -> Result<bool> {
        self.exact(row);
        if self.0.render_items == 1 {
            assert_eq!(
                (ordinal, stable),
                (0, format!("{}:0", row.event_id).as_str())
            );
        } else {
            self.check_render_item(ordinal, stable);
        }
        self.database("complete").await;
        Ok(self.0.complete.load(Ordering::Relaxed))
    }
}

impl ClusterMucReceiptClaimRepository for Ports {
    type Delivery = ClusterMucOutboxDelivery;

    async fn renew_exact(&self, row: &Self::Delivery, lease: Duration) -> Result<bool> {
        self.exact(row);
        assert_eq!(lease, Duration::from_secs(30));
        assert_eq!(
            self.0.admission.available_permits(),
            1,
            "receipt wait retains no database turn"
        );
        self.enter("receipt-renew").await;
        Ok(true)
    }
}

impl ClusterMucOutboxSettlementRepository for Ports {
    type Delivery = ClusterMucOutboxDelivery;

    async fn ack_exact(&self, row: &Self::Delivery) -> Result<bool> {
        self.exact(row);
        self.database("ack").await;
        (*self.0.ack.lock().unwrap()).map_err(anyhow::Error::msg)
    }

    async fn record_retry(&self, row: &Self::Delivery, error: &str) -> Result<bool> {
        self.exact(row);
        assert_eq!(
            error,
            "exact MUC audience transport did not reach a durable ownership/write boundary"
        );
        self.database("retry").await;
        (*self.0.retry.lock().unwrap()).map_err(anyhow::Error::msg)
    }
}

impl ClusterMucOutboxHousekeepingRepository for Ports {
    async fn purge_expired_dead_letters(&self, limit: i64) -> Result<u64> {
        assert_eq!(limit, 256);
        self.database("purge-dead-letters").await;
        Ok(0)
    }

    async fn purge_history(&self, days: i64, limit: i64) -> Result<(u64, u64)> {
        assert_eq!((days, limit), (90, 256));
        self.database("purge-history").await;
        Ok((0, 0))
    }

    async fn snapshot(&self) -> Result<ClusterMucOutboxGaugeSnapshot> {
        self.database("gauges").await;
        Ok(ClusterMucOutboxGaugeSnapshot {
            queued_rows: 0,
            dead_letter_rows: 0,
            oldest_age_seconds: 0,
        })
    }
}

impl MucDeliveryRepository for Ports {
    async fn current_muc_moderators(
        &self,
        _: &str,
        _: &[northstar_room_core::occupancy::MucOccupantRoute],
    ) -> Result<Vec<northstar_room_core::occupancy::MucOccupantRoute>> {
        panic!("unexpected MUC moderator read")
    }

    async fn blocked_local_accounts(
        &self,
        domain: &str,
        recipients: &[String],
        senders: &[String],
    ) -> Result<HashSet<String>> {
        assert_eq!(domain, "example.test");
        assert_eq!(recipients, ["alice@example.test/Phone"]);
        if self.0.context.lock().unwrap().operation_kind == "subject" {
            assert_eq!(senders, ["room@conference.example.test"]);
        } else {
            assert!(senders.iter().any(|sender| {
                sender == "room@conference.example.test"
                    || sender.starts_with("room@conference.example.test/")
            }));
        }
        assert_eq!(self.0.admission.available_permits(), 1);
        self.enter("blocking").await;
        Ok(HashSet::new())
    }

    async fn privacy_allows_session(
        &self,
        user: Uuid,
        connection: Uuid,
        active: Option<&str>,
        peer: &str,
        kind: northstar_xep_0016::PrivacyStanzaKind,
    ) -> Result<bool> {
        assert_eq!(
            (user, connection, active),
            (Uuid::from_u128(10), Uuid::from_u128(11), None)
        );
        if self.0.context.lock().unwrap().operation_kind == "subject"
            || peer == "room@conference.example.test"
        {
            assert_eq!(peer, "room@conference.example.test");
            assert_eq!(kind, northstar_xep_0016::PrivacyStanzaKind::Message);
        } else {
            assert!(peer.starts_with("room@conference.example.test/"));
            assert_eq!(kind, northstar_xep_0016::PrivacyStanzaKind::PresenceIn);
        }
        self.enter("privacy").await;
        Ok(true)
    }

    async fn suspended_privacy_denies(
        &self,
        _: Uuid,
        _: &str,
        _: northstar_xep_0016::PrivacyStanzaKind,
    ) -> Result<Option<bool>> {
        panic!("unexpected suspended fallback");
    }

    async fn append_suspended_stanza(
        &self,
        _: Uuid,
        _: Uuid,
        _: &str,
        _: usize,
        _: usize,
    ) -> Result<bool> {
        panic!("unexpected suspended append");
    }
}

impl northstar_federation_core::FederationOutboxAdmission for UnusedPorts {
    async fn admit<'a>(&'a self, _: &'a str, _: String) -> bool {
        panic!("unexpected federation admission");
    }
}

impl northstar_federation_core::FederationRoute for UnusedPorts {
    fn outbox_policy(&self) -> northstar_federation_core::S2sOutboxPolicy {
        panic!("unexpected federation policy");
    }

    fn wake_outbox(&self) {
        panic!("unexpected federation wake");
    }

    async fn send(&self, _: &str, _: String, _: Option<String>) -> bool {
        panic!("unexpected federated endpoint");
    }
}

struct Fixture {
    worker: Arc<muc_outbox_worker::ClusterMucOutboxWorkerContext<Adapters>>,
    ports: Ports,
    output: mpsc::Receiver<OutboundItem>,
    recipient: MucOccupant,
}

impl Fixture {
    fn new() -> Self {
        Self::for_render(1, "participant", false)
    }

    fn for_render(render_items: i32, committed_role: &str, record_original: bool) -> Self {
        let (live, output) = northstar_stream::local_routes::session::test_online_session(
            Uuid::from_u128(10),
            7,
            Uuid::from_u128(11),
            "Phone",
            4,
        );
        let recipient = MucOccupant {
            full_jid: "alice@example.test/Phone".into(),
            room_jid: "room@conference.example.test".into(),
            nick: "Alice".into(),
            endpoint: MucOccupantEndpoint::Local(live.sender.clone()),
            affiliation: "member".into(),
            role: "participant".into(),
            room_non_anonymous: false,
            occupant_id: "opaque".into(),
            cluster_epoch: Uuid::from_u128(12),
            connection_id: Uuid::from_u128(11),
            sm_session_id: None,
            payload: String::new(),
        };
        let payload = serde_json::json!({"operation_id": Uuid::from_u128(1), "event_id": Uuid::from_u128(2), "event_sequence": 17}).to_string();
        let mut row = ClusterMucOutboxDelivery {
            delivery_id: Uuid::from_u128(3),
            operation_id: Uuid::from_u128(1),
            room_id: Uuid::from_u128(4),
            room_epoch: Uuid::from_u128(5),
            event_sequence: 17,
            event_id: Uuid::from_u128(2),
            audience_kind: "occupant".into(),
            target_node_id: "outbox-node".into(),
            recipient_full_jid: Some(recipient.full_jid.clone()),
            recipient_nick: Some(recipient.nick.clone()),
            recipient_occupant_incarnation: Some(recipient.cluster_epoch),
            recipient_occupancy_epoch: Some(23),
            recipient_connection_uuid: Some(recipient.connection_id),
            recipient_connection_epoch: Some(29),
            payload_digest: sha2::Sha256::digest(payload.as_bytes()).to_vec(),
            payload,
            attempt_count: 2,
            claim_token: Uuid::from_u128(6),
            handoff_version: 31,
        };
        let original = ClusterMucAudienceSnapshot {
            room_id: row.room_id,
            room_epoch: row.room_epoch,
            identity_kind: "local".into(),
            local_user_id: Some(Uuid::from_u128(10)),
            bare_jid: "alice@example.test".into(),
            full_jid: recipient.full_jid.clone(),
            nick: recipient.nick.clone(),
            authenticated_domain: None,
            owner_node_id: "outbox-node".into(),
            occupant_incarnation: recipient.cluster_epoch,
            occupancy_epoch: 23,
            connection_uuid: recipient.connection_id,
            connection_epoch: 29,
            sm_session_id: None,
            role: committed_role.into(),
            affiliation: "member".into(),
        };
        if record_original {
            let mut payload: serde_json::Value = serde_json::from_str(&row.payload).unwrap();
            payload["original_audience"] = serde_json::to_value(&original).unwrap();
            row.payload = payload.to_string();
            row.payload_digest = sha2::Sha256::digest(row.payload.as_bytes()).to_vec();
        }
        let ports = Ports(Arc::new(Recording {
            admission: DurableOutboxDatabaseAdmission::for_primary_pool(2),
            calls: Mutex::new(Vec::new()),
            gates: Mutex::new(HashMap::new()),
            row,
            context: Mutex::new(ClusterMucEventContext {
                operation_kind: "subject".into(),
                room_localpart: "room".into(),
                room_epoch: Uuid::from_u128(5),
                room_non_anonymous: false,
                occupant_id_secret: vec![7; 32],
                actor_full_jid: None,
                actor_affiliation: None,
                details: serde_json::json!({"stanza": "<message xmlns='jabber:client' type='groupchat'><subject>original</subject></message>"}),
                target: None,
            }),
            snapshot: Mutex::new(Some(original.clone())),
            original,
            current: AtomicBool::new(false),
            claimed: AtomicBool::new(false),
            ack: Mutex::new(Ok(true)),
            retry: Mutex::new(Ok(true)),
            complete: AtomicBool::new(true),
            stale_reservation: AtomicBool::new(false),
            render_items,
            metrics: Arc::default(),
        }));
        let sessions = Arc::new(dashmap::DashMap::new());
        sessions.insert(recipient.full_jid.clone(), live);
        let occupants = Arc::new(dashmap::DashMap::new());
        occupants.insert(
            northstar_room_core::stanza::muc_occupant_key(&recipient.room_jid, &recipient.nick),
            recipient.clone(),
        );
        let worker = Arc::new(muc_outbox_worker::ClusterMucOutboxWorkerContext {
            signal: ClusterMucOutboxSignal {
                node_id: "outbox-node".into(),
                wake: Arc::default(),
            },
            domain: "example.test".into(),
            endpoints: muc_delivery_endpoints::ClusterMucDeliveryEndpoints {
                sessions: Arc::clone(&sessions),
                occupants: Arc::clone(&occupants),
            },
            delivery: northstar_stream::muc_delivery::MucDeliveryContext {
                repository: ports.clone(),
                receipt_claim: ClusterMucReceiptClaimService::new(ports.clone()),
                local_domain: "example.test".into(),
                sessions,
                muc_occupants: occupants,
                suspended_muc_sessions: Arc::default(),
                sm_memory_governor:
                    northstar_session_application::sm_capacity::SmMemoryGovernor::new(
                        4096,
                        4096,
                        1,
                        1024,
                        Arc::default(),
                    )
                    .unwrap(),
                sm_max_unacked_stanzas: 8,
                sm_max_unacked_bytes: 4096,
                federation_outbox: UnusedPorts,
            },
            preclaim: ClusterMucOutboxPreclaimService::new(ports.clone()),
            claim: ClusterMucOutboxClaimService::new(ports.clone()),
            settlement: ClusterMucOutboxSettlementService::new(ports.clone()),
            housekeeping: ClusterMucOutboxHousekeepingService::new(ports.clone()),
            delivery_read: ClusterMucDeliveryReadService::new(ports.clone()),
            delivery_item: ClusterMucDeliveryItemService::new(ports.clone()),
            admission: ports.0.admission.clone(),
            metrics: Arc::clone(&ports.0.metrics),
        });
        Self {
            worker,
            ports,
            output,
            recipient,
        }
    }
}

// Borrow a real heartbeat while driving the subject worker by manual polling.
// The retained supervisor is explicitly cancelled and joined by each test.
struct HeartbeatFixture {
    registry: Arc<WorkerRegistry>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
}

impl HeartbeatFixture {
    async fn new() -> Self {
        let registry = WorkerRegistry::new();
        let cancel = CancellationToken::new();
        let (sent, mut received) = mpsc::unbounded_channel();
        registry.supervise(
            "contract-heartbeat",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            None,
            cancel.clone(),
            move |heartbeat| {
                sent.send(heartbeat)
                    .unwrap_or_else(|_| panic!("heartbeat receiver remains live"));
                std::future::pending::<Result<()>>()
            },
        );
        let heartbeat = received.recv().await.unwrap();
        heartbeat.error("awaiting durable turn");
        Self {
            registry,
            cancel,
            heartbeat,
        }
    }

    fn waiting(&self) {
        assert_eq!(
            self.registry
                .observer_last_error_for_test("contract-heartbeat")
                .as_deref(),
            Some("awaiting durable turn")
        );
    }

    fn succeeded(&self) {
        assert_eq!(
            self.registry
                .observer_last_error_for_test("contract-heartbeat"),
            None
        );
    }

    async fn finish(self) {
        assert!(self
            .registry
            .shutdown_and_join(&self.cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }
}

fn ready<T>(poll: std::task::Poll<T>, message: &str) -> T {
    match poll {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("{message}"),
    }
}

#[tokio::test(start_paused = true)]
async fn muc_preclaim_and_claim_release_db_before_delivery() {
    let mut fixture = Fixture::new();
    let heartbeat = HeartbeatFixture::new().await;
    let preclaim = fixture.ports.gate("dead-letter");
    let claim = fixture.ports.gate("claim");
    let cancel = CancellationToken::new();
    let run = run_muc_outbox_delivery(
        Arc::clone(&fixture.worker),
        cancel.clone(),
        heartbeat.heartbeat.clone(),
    );
    tokio::pin!(run);
    assert!(futures::poll!(run.as_mut()).is_pending());
    assert_eq!(fixture.ports.calls(), ["expire", "dead-letter"]);
    let admission = fixture.worker.admission.clone();
    let foreground = admission.acquire();
    tokio::pin!(foreground);
    assert!(futures::poll!(foreground.as_mut()).is_pending());
    preclaim.send(()).unwrap();
    assert!(futures::poll!(run.as_mut()).is_pending());
    assert_eq!(fixture.ports.calls(), ["expire", "dead-letter"]);
    let permit = ready(
        futures::poll!(foreground.as_mut()),
        "preclaim released its turn",
    );
    drop(permit);
    assert!(futures::poll!(run.as_mut()).is_pending());
    assert_eq!(fixture.ports.calls(), ["expire", "dead-letter", "claim"]);

    let foreground = admission.acquire();
    tokio::pin!(foreground);
    assert!(futures::poll!(foreground.as_mut()).is_pending());
    claim.send(()).unwrap();
    assert!(futures::poll!(run.as_mut()).is_pending());
    assert_eq!(fixture.ports.calls(), ["expire", "dead-letter", "claim"]);
    drop(ready(
        futures::poll!(foreground.as_mut()),
        "claim released its turn",
    ));
    assert!(futures::poll!(run.as_mut()).is_pending());
    let output = fixture.output.try_recv().expect("transport reached");
    assert!(output.transport_receipt.is_some());
    assert_eq!(admission.available_permits(), 1);
    let foreground = admission.acquire().await;
    assert_eq!(fixture.ports.counters(), (0, 0));
    heartbeat.waiting();
    drop(foreground);
    output.confirm_transport_ownership();
    assert!(futures::poll!(run.as_mut()).is_pending());
    assert_eq!(fixture.ports.counters(), (1, 0));
    heartbeat.succeeded();
    cancel.cancel();
    run.await.unwrap();
    heartbeat.finish().await;
}

#[tokio::test(start_paused = true)]
async fn muc_cached_recipient_avoids_snapshot_reads() {
    for (label, cache, snapshot, current, batch, expected, error) in [
        (
            "exact cache",
            "exact",
            true,
            false,
            false,
            vec!["context"],
            None,
        ),
        (
            "different full jid",
            "jid",
            true,
            false,
            false,
            vec!["context", "snapshot"],
            None,
        ),
        (
            "different incarnation",
            "incarnation",
            true,
            false,
            false,
            vec!["context", "snapshot"],
            None,
        ),
        (
            "different connection",
            "connection",
            true,
            false,
            false,
            vec!["context", "snapshot"],
            None,
        ),
        (
            "different nickname",
            "nick",
            true,
            false,
            false,
            vec!["context", "snapshot"],
            None,
        ),
        (
            "missing cache",
            "missing",
            true,
            false,
            false,
            vec!["context", "snapshot"],
            None,
        ),
        (
            "departed audience",
            "missing",
            false,
            false,
            false,
            vec!["context", "snapshot", "current"],
            None,
        ),
        (
            "lost current snapshot",
            "missing",
            false,
            true,
            false,
            vec!["context", "snapshot", "current"],
            Some("authoritative MUC audience snapshot disappeared"),
        ),
        (
            "original batch policy",
            "missing",
            true,
            false,
            true,
            vec!["context", "snapshot", "original"],
            None,
        ),
    ] {
        let fixture = Fixture::new();
        let key = northstar_room_core::stanza::muc_occupant_key(
            &fixture.recipient.room_jid,
            &fixture.recipient.nick,
        );
        let mut recipient = fixture.recipient.clone();
        match cache {
            "jid" => recipient.full_jid = "replacement@example.test/Phone".into(),
            "incarnation" => recipient.cluster_epoch = Uuid::from_u128(99),
            "connection" => recipient.connection_id = Uuid::from_u128(99),
            "nick" => recipient.nick = "Replacement".into(),
            "exact" | "missing" => {}
            _ => unreachable!(),
        }
        fixture
            .worker
            .endpoints
            .occupants
            .insert(key.clone(), recipient);
        if cache == "missing" {
            fixture.worker.endpoints.occupants.remove(&key);
        }
        if !snapshot {
            *fixture.ports.0.snapshot.lock().unwrap() = None;
        }
        fixture.ports.0.current.store(current, Ordering::Relaxed);
        // No stanza is needed to test the audience reads. A batch additionally
        // loads the committed visibility policy from its original audience.
        {
            let mut context = fixture.ports.0.context.lock().unwrap();
            context.operation_kind = if batch { "admin_batch" } else { "suspend" }.into();
            context.details = serde_json::json!({"non_anonymous": false, "request_change_count": 1, "changes": []});
        }
        let gates = expected
            .iter()
            .map(|step| fixture.ports.gate(step))
            .collect::<Vec<_>>();
        let delivery = deliver_cluster_muc_event(&fixture.worker, &fixture.ports.0.row);
        tokio::pin!(delivery);
        let admission = fixture.worker.admission.clone();
        for (index, gate) in gates.into_iter().enumerate() {
            assert!(futures::poll!(delivery.as_mut()).is_pending(), "{label}");
            assert_eq!(fixture.ports.calls(), expected[..=index], "{label}");
            let competing = admission.acquire();
            tokio::pin!(competing);
            assert!(futures::poll!(competing.as_mut()).is_pending(), "{label}");
            gate.send(()).unwrap();
            if index + 1 < expected.len() {
                assert!(futures::poll!(delivery.as_mut()).is_pending(), "{label}");
                assert_eq!(
                    fixture.ports.calls(),
                    expected[..=index],
                    "{label}: next read must wait for a new turn"
                );
            }
            let permit = if index + 1 < expected.len() {
                ready(
                    futures::poll!(competing.as_mut()),
                    "independent read released admission",
                )
            } else {
                // The last read can finish the whole delivery immediately.
                let result = ready(
                    futures::poll!(delivery.as_mut()),
                    "last read completes delivery",
                );
                match error {
                    Some(message) => {
                        assert_eq!(result.unwrap_err().to_string(), message, "{label}")
                    }
                    None => result.unwrap(),
                }
                ready(
                    futures::poll!(competing.as_mut()),
                    "final read released admission",
                )
            };
            drop(permit);
        }
        assert_eq!(fixture.ports.calls(), expected, "{label}");
        assert_eq!(admission.available_permits(), 1, "{label}");
    }
}

#[tokio::test(start_paused = true)]
async fn muc_item_complete_follows_receipt() {
    for (label, receipt, completes) in [
        ("successful receipt", true, true),
        ("closed receipt", false, false),
    ] {
        let mut fixture = Fixture::new();
        let complete = fixture.ports.gate("complete");
        let delivery = deliver_cluster_muc_event(&fixture.worker, &fixture.ports.0.row);
        tokio::pin!(delivery);
        assert!(futures::poll!(delivery.as_mut()).is_pending(), "{label}");
        let output = fixture.output.try_recv().unwrap();
        {
            let document = roxmltree::Document::parse(&output.stanza).unwrap();
            assert_eq!(
                document.root_element().attribute("to"),
                Some("alice@example.test/Phone"),
                "{label}"
            );
            assert_eq!(
                document.root_element().attribute("from"),
                Some("room@conference.example.test"),
                "{label}"
            );
        }
        assert!(
            output.stanza.contains("<subject>original</subject>"),
            "{label}"
        );
        assert!(
            output
                .stanza
                .contains(&fixture.ports.0.row.event_id.to_string()),
            "{label}"
        );
        assert!(!fixture.ports.calls().contains(&"complete"), "{label}");
        assert_eq!(fixture.worker.admission.available_permits(), 1, "{label}");
        if receipt {
            output.confirm_transport_ownership();
        }
        drop(output);
        if completes {
            let held = fixture.worker.admission.acquire().await;
            assert!(
                futures::poll!(delivery.as_mut()).is_pending(),
                "completion must reacquire admission"
            );
            assert!(!fixture.ports.calls().contains(&"complete"));
            drop(held);
            assert!(futures::poll!(delivery.as_mut()).is_pending());
            assert_eq!(
                fixture
                    .ports
                    .calls()
                    .iter()
                    .filter(|step| **step == "complete")
                    .count(),
                1
            );
            complete.send(()).unwrap();
            delivery.await.unwrap();
        } else {
            assert_eq!(
                delivery.await.unwrap_err().to_string(),
                "exact MUC audience transport did not reach a durable ownership/write boundary",
                "{label}"
            );
            assert!(!fixture.ports.calls().contains(&"complete"), "{label}");
            drop(complete);
        }
        assert_eq!(fixture.worker.admission.available_permits(), 1, "{label}");
    }
}

#[tokio::test(start_paused = true)]
async fn muc_lost_ack_never_counts_success() {
    for (label, ack, expected) in [
        ("acknowledged", Ok(true), None),
        (
            "lost claim",
            Ok(false),
            Some("cluster MUC outbox ACK lost its exact claim lease"),
        ),
        (
            "ack failed",
            Err("ack storage failed"),
            Some("ack storage failed"),
        ),
    ] {
        let mut fixture = Fixture::new();
        *fixture.ports.0.ack.lock().unwrap() = ack;
        let ack_gate = fixture.ports.gate("ack");
        let heartbeat = HeartbeatFixture::new().await;
        let cancel = CancellationToken::new();
        let run = run_muc_outbox_delivery(
            Arc::clone(&fixture.worker),
            cancel.clone(),
            heartbeat.heartbeat.clone(),
        );
        tokio::pin!(run);
        assert!(futures::poll!(run.as_mut()).is_pending(), "{label}");
        fixture
            .output
            .try_recv()
            .unwrap()
            .confirm_transport_ownership();
        assert!(futures::poll!(run.as_mut()).is_pending(), "{label}");
        assert_eq!(fixture.ports.calls().last(), Some(&"ack"), "{label}");
        assert_eq!(fixture.ports.counters(), (0, 0), "{label}");
        heartbeat.waiting();
        ack_gate.send(()).unwrap();
        if let Some(expected) = expected {
            assert_eq!(run.await.unwrap_err().to_string(), expected, "{label}");
            assert_eq!(fixture.ports.counters(), (0, 0), "{label}");
            heartbeat.waiting();
            assert!(!fixture.ports.calls().contains(&"retry"), "{label}");
        } else {
            assert!(futures::poll!(run.as_mut()).is_pending(), "{label}");
            assert_eq!(fixture.ports.counters(), (1, 0), "{label}");
            heartbeat.succeeded();
            cancel.cancel();
            run.await.unwrap();
        }
        assert_eq!(fixture.worker.admission.available_permits(), 1, "{label}");
        heartbeat.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn muc_retry_counts_only_after_durable_turn() {
    for (label, retry, fails) in [
        ("retry committed", Ok(true), false),
        ("claim already gone", Ok(false), false),
        ("retry failed", Err("retry storage failed"), true),
    ] {
        let mut fixture = Fixture::new();
        *fixture.ports.0.retry.lock().unwrap() = retry;
        let retry_gate = fixture.ports.gate("retry");
        let heartbeat = HeartbeatFixture::new().await;
        let cancel = CancellationToken::new();
        let run = run_muc_outbox_delivery(
            Arc::clone(&fixture.worker),
            cancel.clone(),
            heartbeat.heartbeat.clone(),
        );
        tokio::pin!(run);
        assert!(futures::poll!(run.as_mut()).is_pending(), "{label}");
        drop(fixture.output.try_recv().unwrap());
        assert!(futures::poll!(run.as_mut()).is_pending(), "{label}");
        assert_eq!(fixture.ports.calls().last(), Some(&"retry"), "{label}");
        assert_eq!(fixture.ports.counters(), (0, 0), "{label}");
        heartbeat.waiting();
        retry_gate.send(()).unwrap();
        if fails {
            assert_eq!(
                run.await.unwrap_err().to_string(),
                "retry storage failed",
                "{label}"
            );
            assert_eq!(fixture.ports.counters(), (0, 0), "{label}");
            heartbeat.waiting();
        } else {
            assert!(futures::poll!(run.as_mut()).is_pending(), "{label}");
            assert_eq!(fixture.ports.counters(), (0, 1), "{label}");
            heartbeat.succeeded();
            cancel.cancel();
            run.await.unwrap();
        }
        assert!(!fixture.ports.calls().contains(&"ack"), "{label}");
        assert!(!fixture.ports.calls().contains(&"complete"), "{label}");
        assert_eq!(fixture.worker.admission.available_permits(), 1, "{label}");
        heartbeat.finish().await;
    }
}

mod authority;
#[path = "durable_recipient_identity.rs"]
mod durable_recipient_identity;
mod roster;

#[cfg(test)]
mod muc_render_receipts;
