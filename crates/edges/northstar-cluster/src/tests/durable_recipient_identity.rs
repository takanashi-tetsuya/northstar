use super::*;
use crate::{
    listener_dispatch::ClusterListenerDispatch, listener_mix_caps::ClusterListenerMixCaps,
};
use northstar_abuse_policy::content_identity::{
    MixMessageContentKeyring, MixRetractionContentKeyring,
};
use northstar_message_application::messaging::MessageService;
use northstar_room_application::mix_service::MixService;
use northstar_roster_application::presence::PresenceService;
use northstar_session_application::{
    node_message_contract_verifier::{
        MixDeliveryProjection, NodeMessageContractVerifier, NodeMessageProjectionRepository,
    },
    session_termination_authority::{
        SessionRouteAuthority, SessionTerminationAuthorityRepository,
        SessionTerminationAuthorityService,
    },
};
use northstar_stream::{
    local_routes::session::{test_online_session, AccountRevocationRoutes},
    outbound::{DurableDelivery, TransportOwnershipSource},
};

const ORIGINAL: Uuid = Uuid::from_u128(10);
const RECREATED: Uuid = Uuid::from_u128(20);
const MESSAGE: Uuid = Uuid::from_u128(30);
const TARGET: &str = "bob@example.test";
const ORIGINAL_JID: &str = "bob@example.test/Phone";
const RECREATED_JID: &str = "bob@example.test/Laptop";
const STANZA: &str = "<message xmlns='jabber:client' from='alice@example.test/Tablet' \
    to='bob@example.test' type='chat'><body>hello</body>\
    <stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.test' \
    id='00000000-0000-0000-0000-000000000040'/></message>";
const DURABLE: NodeDeliveryContract = NodeDeliveryContract::DurableC2s {
    recipient_id: ORIGINAL,
    message_id: MESSAGE,
};

pub(super) struct Projection(Arc<Mutex<Option<Uuid>>>);

impl NodeMessageProjectionRepository for Projection {
    async fn durable_c2s_stanza(
        &self,
        recipient_id: Uuid,
        message_id: Uuid,
    ) -> Result<Option<(String, Option<Uuid>)>> {
        assert_eq!((recipient_id, message_id), (ORIGINAL, MESSAGE));
        Ok(Some((STANZA.to_owned(), *self.0.lock().unwrap())))
    }

    async fn durable_mix_projection(
        &self,
        _: Uuid,
        _: Uuid,
    ) -> Result<Option<MixDeliveryProjection>> {
        panic!("unexpected MIX projection read");
    }

    async fn legacy_c2s_projection(&self, _: Uuid) -> Result<Option<(Uuid, String)>> {
        panic!("unexpected legacy projection read");
    }
}

impl SessionTerminationAuthorityRepository for UnusedPorts {
    async fn route_authority(&self, _: &str, _: &str) -> Result<Option<SessionRouteAuthority>> {
        panic!("unexpected session termination authority read");
    }
}

struct DirectDeliveryFixture {
    admission: ClusterListenerAdmission,
    dispatch: ClusterListenerDispatch<Adapters>,
    mix_caps: ClusterListenerMixCaps,
    policy: ClusterListenerMessagePolicy<Adapters>,
    message_ports: MessagePorts,
}

impl DirectDeliveryFixture {
    fn new() -> Self {
        Self::with_claim(Arc::default())
    }

    fn with_claim(claim: Arc<Mutex<Option<Uuid>>>) -> Self {
        let namespace = "durable-recipient.test";
        let (_, security) = northstar_security::cluster_bus::test_configuration_pair(namespace);
        let cluster = verification_manager(namespace, security);
        let sessions = Arc::new(dashmap::DashMap::new());
        let message_ports = MessagePorts(Arc::default(), Arc::default());
        let generations = Arc::new(Vec::new());
        Self {
            admission: cluster.listener_admission(),
            dispatch: ClusterListenerDispatch {
                muc_outbox: cluster.muc_outbox_signal(),
                muc_projection: cluster.listener_muc_projection(),
                presence_routes: cluster.listener_presence_routes(),
                account_routes: AccountRevocationRoutes::new(Arc::clone(&sessions)),
                session_identity: cluster.session_termination_identity(),
                session_authority: SessionTerminationAuthorityService::new(UnusedPorts),
            },
            mix_caps: ClusterListenerMixCaps {
                sessions,
                verified: Arc::default(),
                pending: Arc::default(),
            },
            policy: ClusterListenerMessagePolicy {
                local_domain: "example.test".into(),
                presence: PresenceService::new(UnusedPorts),
                message: MessageService::new(message_ports.clone(), false),
                notification: UnusedPorts,
                mix: MixService::new(
                    UnusedPorts,
                    MixMessageContentKeyring::new(Arc::clone(&generations)),
                    MixRetractionContentKeyring::new(generations),
                    2,
                    "public".into(),
                )
                .unwrap(),
                verifier: NodeMessageContractVerifier::new(Projection(claim)),
                metrics: Arc::default(),
            },
            message_ports,
        }
    }

    fn add_session(&self, jid: &str, user_id: Uuid, priority: i16) -> mpsc::Receiver<OutboundItem> {
        let (_, resource) = jid.split_once('/').unwrap();
        let (session, output) = test_online_session(user_id, 1, user_id, resource, 4);
        session.available.store(true, Ordering::Relaxed);
        session.priority.store(priority, Ordering::Relaxed);
        assert!(self
            .mix_caps
            .sessions
            .insert(jid.to_owned(), session)
            .is_none());
        output
    }

    async fn deliver(&self, contract: NodeDeliveryContract) -> (usize, Option<String>) {
        let json = serde_json::json!({
            "protocol_version": NODE_PROTOCOL_VERSION,
            "target": TARGET,
            "stanza": STANZA,
            "delivery": contract,
            "primary_one_to_one": true
        });
        let (delivered, recipient, echoed_contract) = self
            .dispatch
            .test_direct_message_delivery(&self.admission, &self.policy, &self.mix_caps, &json)
            .await;
        assert_eq!(echoed_contract, Some(contract));
        (delivered, recipient)
    }

    fn privacy_calls(&self) -> Vec<Uuid> {
        self.message_ports.0.lock().unwrap().clone()
    }

    fn acceptances(&self) -> (u64, u64) {
        let metrics = &self.policy.metrics;
        (
            metrics
                .online_queue_durable_acceptances_total
                .load(Ordering::Relaxed),
            metrics
                .online_queue_volatile_acceptances_total
                .load(Ordering::Relaxed),
        )
    }
}

#[tokio::test]
async fn durable_message_with_only_recreated_session_has_no_live_acceptance() {
    let fixture = DirectDeliveryFixture::new();
    let no_live_route = fixture.deliver(DURABLE).await;
    assert_eq!(no_live_route, (0, None));
    let mut recreated = fixture.add_session(RECREATED_JID, RECREATED, 10);

    assert_eq!(fixture.deliver(DURABLE).await, no_live_route);
    assert!(matches!(
        recreated.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(fixture.privacy_calls().is_empty());
    assert_eq!(fixture.acceptances(), (0, 0));
}

#[tokio::test]
async fn durable_primary_skips_recreated_session_and_accepts_original_session() {
    let fixture = DirectDeliveryFixture::new();
    let mut recreated = fixture.add_session(RECREATED_JID, RECREATED, 10);
    let mut original = fixture.add_session(ORIGINAL_JID, ORIGINAL, 1);

    assert_eq!(
        fixture.deliver(DURABLE).await,
        (1, Some(ORIGINAL_JID.into()))
    );
    assert!(matches!(
        recreated.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let item = original.try_recv().unwrap();
    assert_eq!(item.stanza, STANZA);
    assert_eq!(
        item.durable_source,
        Some(TransportOwnershipSource::C2s(DurableDelivery {
            recipient_id: ORIGINAL,
            message_id: MESSAGE,
            claim_id: None,
        }))
    );
    assert_eq!(fixture.privacy_calls(), [ORIGINAL]);
    assert_eq!(fixture.acceptances(), (1, 0));
}

#[tokio::test]
async fn volatile_primary_keeps_priority_order_unlike_durable_primary() {
    let fixture = DirectDeliveryFixture::new();
    let mut recreated = fixture.add_session(RECREATED_JID, RECREATED, 10);
    let mut original = fixture.add_session(ORIGINAL_JID, ORIGINAL, 1);

    assert_eq!(
        fixture.deliver(NodeDeliveryContract::Volatile {}).await,
        (1, Some(RECREATED_JID.into()))
    );
    let item = recreated.try_recv().unwrap();
    assert_eq!(item.stanza, STANZA);
    assert!(item.durable_source.is_none());
    assert!(matches!(
        original.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(fixture.privacy_calls(), [RECREATED]);
    assert_eq!(fixture.acceptances(), (0, 1));

    assert_eq!(
        fixture.deliver(DURABLE).await,
        (1, Some(ORIGINAL_JID.into()))
    );
}

#[path = "cluster_live_handoff.rs"]
mod cluster_live_handoff;

#[path = "carbon_audience.rs"]
mod carbon_audience;

#[path = "exact_iq_visibility.rs"]
mod exact_iq_visibility;

#[path = "exact_control_contract.rs"]
mod exact_control_contract;
