use super::presence_service::IsolatedDatabase;
use northstar_auth_postgres::users::create_user;
use northstar_cluster::{
    presence_routing::{FederatedPresenceOwner, FederatedPresenceRequest},
    ClusterManager, ExactControlKind,
};
use northstar_federation_core::{FederationOutboxAdmission, FederationRoute, S2sOutboxPolicy};
use northstar_roster_application::{
    presence::{
        InboundSubscriptionRequest, InboundSubscriptionTransition, PresenceMutation,
        PresenceService,
    },
    probe_decision::{PresenceRoute, ProbeStatus},
};
use northstar_roster_core::{
    ExactPresenceRoute, InboundRemotePresenceEffect, PresenceAccount, SubscriptionAction,
};
use northstar_roster_postgres::roster::{block_jids, BlockJidsUpdate};
use northstar_session_application::replay::ReplayService;
use northstar_session_postgres::replay_repository::PostgresReplayRepository;
use northstar_stream::{
    local_routes::{session::test_online_session, session_table::LocalSessionTable},
    outbound::OutboundItem,
};
use northstar_workflows::{
    presence_repository::PostgresPresenceRepository,
    roster::transition_remote_presence_subscription,
};
use std::sync::{atomic::Ordering, Mutex};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

const LOCAL: &str = "example.test";
const TARGET: &str = "bob@example.test";
const PEER: &str = "remote.test";
const CONTACT: &str = "alice@remote.test";
const SENDER: &str = "alice@remote.test/Phone";
const PROBE: &str =
    "<presence type='probe' id='p' from='alice@remote.test/Phone' to='bob@example.test'/>";
const SUBSCRIBE: &str =
    "<presence type='subscribe' from='alice@remote.test' to='bob@example.test'/>";
const SUBSCRIBED: &str =
    "<presence type='subscribed' from='alice@remote.test' to='bob@example.test'/>";
const AVAILABLE: &str =
    "<presence from='alice@remote.test/Phone' to='bob@example.test'><show>away</show></presence>";

#[derive(Default)]
struct Outbox(Mutex<Vec<String>>);

impl FederationOutboxAdmission for Outbox {
    async fn admit(&self, target_domain: &str, stanza: String) -> bool {
        assert_eq!(target_domain, PEER);
        self.0.lock().unwrap().push(stanza);
        true
    }
}

impl FederationRoute for Outbox {
    fn outbox_policy(&self) -> S2sOutboxPolicy {
        unreachable!("fixture exercises volatile presence admission")
    }

    fn wake_outbox(&self) {}

    async fn send(&self, target_domain: &str, stanza: String, bounce_to: Option<String>) -> bool {
        assert!(bounce_to.is_none());
        self.admit(target_domain, stanza).await
    }
}

struct Fixture {
    db: IsolatedDatabase,
    account: PresenceAccount,
    cluster: ClusterManager,
    sessions: LocalSessionTable,
    presence: PresenceService<PostgresPresenceRepository>,
    replay: ReplayService<PostgresReplayRepository>,
    outbox: Outbox,
}

impl Fixture {
    async fn new() -> Self {
        let db = IsolatedDatabase::create("federated_inbound").await;
        let user = create_user(
            &db.pool,
            "bob",
            "Initial password for test!42",
            false,
            true,
            4096,
            false,
        )
        .await
        .unwrap();
        Self {
            account: PresenceAccount {
                id: user.id,
                username: user.username.clone(),
                auth_generation: user.auth_generation,
            },
            cluster: ClusterManager::new(None, LOCAL, None, None, None, None)
                .await
                .unwrap(),
            sessions: LocalSessionTable::default(),
            presence: PresenceService::new(PostgresPresenceRepository::new(db.pool.clone())),
            replay: ReplayService::new(PostgresReplayRepository::new(db.pool.clone()), LOCAL, 30),
            outbox: Outbox::default(),
            db,
        }
    }

    fn route(
        &self,
        resource: &str,
        available: bool,
        interested: bool,
    ) -> (PresenceRoute, mpsc::Receiver<OutboundItem>) {
        let connection_id = Uuid::new_v4();
        let (session, receiver) = test_online_session(
            self.account.id,
            self.account.auth_generation,
            connection_id,
            resource,
            4,
        );
        session.available.store(available, Ordering::Release);
        session
            .roster_requested
            .store(interested, Ordering::Release);
        let full_jid = format!("{TARGET}/{resource}");
        self.sessions.insert(full_jid.clone(), session);
        (
            PresenceRoute {
                exact: ExactPresenceRoute {
                    account_id: self.account.id,
                    auth_generation: self.account.auth_generation,
                    connection_id,
                    full_jid,
                    node_id: None,
                },
                active_list: None,
            },
            receiver,
        )
    }

    async fn transition(&self, kind: &str, stanza: &str) -> InboundSubscriptionTransition {
        let mutation = self
            .presence
            .transition_inbound(InboundSubscriptionRequest {
                recipient: &self.account,
                local_domain: LOCAL,
                contact: CONTACT,
                action: SubscriptionAction::parse(kind).unwrap(),
                stanza,
                verified_peer: PEER,
                subscribed_reply: &reply("subscribed"),
                unsubscribed_reply: &reply("unsubscribed"),
                outbox_policy: S2sOutboxPolicy::new(300, 100, 1024 * 1024, 100),
            })
            .await
            .unwrap();
        let PresenceMutation::Transition(transition) = mutation else {
            panic!("unexpected transition: {mutation:?}");
        };
        transition
    }

    async fn block(&self, peer: &str) {
        assert_eq!(
            block_jids(&self.db.pool, self.account.id, &[peer.to_owned()])
                .await
                .unwrap(),
            BlockJidsUpdate::Changed(vec![peer.to_owned()]),
        );
    }

    async fn handoff(
        &self,
        request: FederatedPresenceRequest<'_>,
        routes: &[PresenceRoute],
    ) -> Option<ProbeStatus> {
        let owner = FederatedPresenceOwner::new(
            self.sessions.clone(),
            &self.presence,
            &self.replay,
            &self.outbox,
            LOCAL,
        );
        self.cluster
            .handoff_federated_presence(&owner, &self.account, request, routes)
            .await
            .unwrap()
    }
}

fn reply(kind: &str) -> String {
    format!("<presence xmlns='jabber:server' type='{kind}' from='{TARGET}' to='{CONTACT}'/>")
}

fn request(
    stanza: &str,
    kind: ExactControlKind,
    pending_created_at_micros: Option<i64>,
) -> FederatedPresenceRequest<'_> {
    FederatedPresenceRequest {
        target: TARGET,
        sender: SENDER,
        stanza,
        remote_peer: PEER,
        kind,
        pending_created_at_micros,
    }
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn blocked_federated_requester_probe_is_silent() {
    let fixture = Fixture::new().await;
    let (route, _receiver) = fixture.route("Tablet", true, false);
    let routes = [route];
    let probe = request(PROBE, ExactControlKind::ProbeResponse, None);
    assert_eq!(
        fixture.handoff(probe, &routes).await,
        Some(ProbeStatus::Unsubscribed)
    );
    assert_eq!(
        fixture.transition("subscribe", SUBSCRIBE).await.effect,
        InboundRemotePresenceEffect::Forward
    );
    assert!(
        transition_remote_presence_subscription(
            &fixture.db.pool,
            fixture.account.id,
            CONTACT,
            "subscribed"
        )
        .await
        .unwrap()
        .unwrap()
        .routed
    );
    assert_eq!(
        fixture.handoff(probe, &routes).await,
        Some(ProbeStatus::Available)
    );
    assert_eq!(fixture.outbox.0.lock().unwrap().len(), 1);
    fixture.block(SENDER).await;
    assert_eq!(
        fixture.handoff(probe, &routes).await,
        Some(ProbeStatus::Silent)
    );
    assert_eq!(fixture.handoff(probe, &[]).await, Some(ProbeStatus::Silent));
    assert_eq!(fixture.outbox.0.lock().unwrap().len(), 1);
    fixture.db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn federated_subscribe_and_subscribed_keep_their_resource_audiences() {
    let fixture = Fixture::new().await;
    let (tablet, mut interested) = fixture.route("Tablet", true, true);
    let (phone, mut other) = fixture.route("Phone", true, false);
    let (desk, mut unavailable) = fixture.route("Desk", false, true);
    let routes = [tablet, phone, desk];
    let subscribe = fixture.transition("subscribe", SUBSCRIBE).await;
    assert_eq!(subscribe.effect, InboundRemotePresenceEffect::Forward);
    let pending = subscribe
        .pending_created_at_micros
        .expect("persisted pending identity");
    let subscribe = request(
        SUBSCRIBE,
        ExactControlKind::FederatedInboundPresence,
        Some(pending),
    );
    fixture.handoff(subscribe, &routes).await;
    fixture.handoff(subscribe, &routes).await;
    for (receiver, route) in [(&mut interested, &routes[0]), (&mut other, &routes[1])] {
        let delivered = receiver.try_recv().unwrap().stanza;
        let document = roxmltree::Document::parse(&delivered).unwrap();
        assert_eq!(
            document.root_element().attribute("to"),
            Some(route.exact.full_jid.as_str())
        );
        assert!(receiver.try_recv().is_err());
    }
    assert!(unavailable.try_recv().is_err());

    assert!(
        transition_remote_presence_subscription(
            &fixture.db.pool,
            fixture.account.id,
            CONTACT,
            "subscribe"
        )
        .await
        .unwrap()
        .unwrap()
        .routed
    );
    assert_eq!(
        fixture.transition("subscribed", SUBSCRIBED).await.effect,
        InboundRemotePresenceEffect::Forward
    );
    fixture
        .handoff(
            request(SUBSCRIBED, ExactControlKind::FederatedInboundPresence, None),
            &routes,
        )
        .await;
    let delivered = interested.try_recv().unwrap().stanza;
    let document = roxmltree::Document::parse(&delivered).unwrap();
    assert_eq!(
        document.root_element().attribute("type"),
        Some("subscribed")
    );
    assert!(other.try_recv().is_err());
    assert!(unavailable.try_recv().is_err());
    fixture.db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn federated_owner_delivery_observes_a_block_committed_after_capture() {
    let fixture = Fixture::new().await;
    let (route, mut output) = fixture.route("Tablet", true, true);
    let available = request(AVAILABLE, ExactControlKind::FederatedInboundPresence, None);
    fixture
        .handoff(available, std::slice::from_ref(&route))
        .await;
    assert_eq!(output.try_recv().unwrap().stanza, AVAILABLE);

    let (captured, captured_rx) = oneshot::channel();
    let (resume, resume_rx) = oneshot::channel();
    // Pause the handoff after the ingress captures the route and before the
    // owner reads its policy.
    let owner_handoff = async {
        captured.send(()).unwrap();
        resume_rx.await.unwrap();
        fixture.handoff(available, &[route]).await;
    };
    let edit = async {
        captured_rx.await.unwrap();
        fixture.block(SENDER).await;
        resume.send(()).unwrap();
    };
    tokio::join!(owner_handoff, edit);
    assert!(output.try_recv().is_err());
    fixture.db.finish().await;
}
