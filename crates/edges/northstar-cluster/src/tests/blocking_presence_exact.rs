use super::{verification_manager, Adapters, UnusedPorts};
use crate::account_routing::send_blocking_pages;
use crate::listener_blocking::{
    wire::{checked_control, control, payload},
    ClusterListenerBlocking,
};
use dashmap::DashMap;
use northstar_roster_application::{
    blocking_mutation::BlockingPresenceTarget, CommunicationDecision, ExactPresenceRoute,
    InMemoryCommunicationPolicyReader, PolicyDirection,
};
use northstar_stream::{local_routes::session::test_online_session, outbound::OutboundItem};
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc::Receiver;
use uuid::Uuid;

const SOURCE: &str = "alice@example.test/Desktop";
const BARE: &str = "bob@example.test";
const RECIPIENT: &str = "bob@example.test/Phone";
const PRESENCE: &str = "<presence xmlns='jabber:client' from='alice@example.test/Desktop'><show>away</show></presence>";

fn route(account: u128, jid: &str) -> ExactPresenceRoute {
    ExactPresenceRoute {
        account_id: Uuid::from_u128(account),
        auth_generation: 1,
        connection_id: Uuid::new_v4(),
        full_jid: jid.into(),
        node_id: None,
    }
}

fn target() -> BlockingPresenceTarget {
    BlockingPresenceTarget {
        source: route(1, SOURCE),
        source_expects_active: false,
        recipient: Some(route(2, RECIPIENT)),
        recipient_expects_active: false,
        address: BARE.into(),
        directed: None,
    }
}

#[test]
fn v15_is_required_and_connection_map_must_name_the_exact_target() {
    let target = target();
    let recipient = target.recipient.unwrap();
    let old = json!({
        "blocking_presence_change": true,
        "protocol_version": "13",
        "target": BARE,
        "blocking_targets": [BARE],
        "available": true,
    });
    assert!(checked_control(&old, BARE, None).is_err());

    let exact = control(&target.source, &recipient);
    let mut current = payload(&exact, &recipient);
    assert_eq!(
        checked_control(&current, RECIPIENT, Some(PRESENCE)).unwrap(),
        exact
    );
    assert!(checked_control(&current, BARE, Some(PRESENCE)).is_err());
    current["protocol_version"] = "13".into();
    assert!(checked_control(&current, RECIPIENT, Some(PRESENCE)).is_err());
}

#[tokio::test]
async fn ordered_slices_continue_after_a_partial_failure() {
    let template = target();
    let targets = (0..1025)
        .map(|index| BlockingPresenceTarget {
            address: format!("user{index}@example.test"),
            ..template.clone()
        })
        .collect::<Vec<_>>();
    let mut recorded = Vec::new();
    let mut sizes = Vec::new();
    let failures = send_blocking_pages("node-b", &targets, |page| {
        sizes.push(page.len());
        recorded.extend(page.iter().cloned());
        std::future::ready(if sizes.len() == 2 {
            Err(anyhow::anyhow!("second page failed"))
        } else {
            Ok(())
        })
    })
    .await;
    assert_eq!(recorded, targets);
    assert_eq!(sizes[..16], [64; 16]);
    assert_eq!(sizes[16..], [1]);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].node_id, "node-b");
    assert_eq!(failures[0].error.to_string(), "second page failed");
}

struct Fixture {
    blocking: ClusterListenerBlocking<Adapters>,
    sessions: Arc<DashMap<String, northstar_stream::local_routes::session::OnlineSession>>,
    target: BlockingPresenceTarget,
    reblocked: Arc<AtomicBool>,
    receiver: Receiver<OutboundItem>,
    allowed: Arc<AtomicBool>,
}

impl Fixture {
    fn new(available: bool) -> Self {
        let target = target();
        let sessions = Arc::new(DashMap::new());
        let (source, _rx) = test_online_session(
            target.source.account_id,
            1,
            target.source.connection_id,
            "Desktop",
            2,
        );
        source.available.store(true, Ordering::Release);
        *source.last_presence.write().unwrap() = Some(PRESENCE.into());
        sessions.insert(SOURCE.into(), source);
        let route = target.recipient.as_ref().unwrap();
        let (recipient, receiver) =
            test_online_session(route.account_id, 1, route.connection_id, "Phone", 1);
        recipient.available.store(available, Ordering::Release);
        sessions.insert(RECIPIENT.into(), recipient);
        let reblocked = Arc::new(AtomicBool::new(false));
        let policy = Arc::clone(&reblocked);
        let allowed = Arc::new(AtomicBool::new(false));
        let domain_checked = Arc::clone(&allowed);
        let (security, _) =
            northstar_security::cluster_bus::test_configuration_pair("example.test");
        let blocking = ClusterListenerBlocking::new(
            Arc::clone(&sessions),
            verification_manager("example.test", security),
            "example.test".into(),
            Arc::new(move |domain| {
                assert_eq!(domain, "remote.test");
                domain_checked.store(true, Ordering::Release);
                false
            }),
            UnusedPorts,
            InMemoryCommunicationPolicyReader::new(move |query| {
                Ok(
                    if query.direction == PolicyDirection::Outbound
                        && policy.load(Ordering::Acquire)
                    {
                        CommunicationDecision::OwnerBlocks
                    } else {
                        CommunicationDecision::Allow
                    },
                )
            }),
            Arc::new(|_, _| Box::pin(async { Ok(true) })),
        );
        Self {
            blocking,
            sessions,
            target,
            reblocked,
            receiver,
            allowed,
        }
    }
}

#[tokio::test]
async fn restore_rechecks_route_availability_reblock_and_rebinding() {
    let mut fixture = Fixture::new(false);
    fixture
        .blocking
        .emit(fixture.target.clone(), true)
        .await
        .unwrap();
    assert!(fixture.receiver.try_recv().is_err());
    fixture
        .sessions
        .get(RECIPIENT)
        .unwrap()
        .available
        .store(true, Ordering::Release);
    fixture.reblocked.store(true, Ordering::Release);
    fixture
        .blocking
        .emit(fixture.target.clone(), true)
        .await
        .unwrap();
    assert!(fixture.receiver.try_recv().is_err());
    fixture.reblocked.store(false, Ordering::Release);

    fixture
        .blocking
        .emit(fixture.target.clone(), true)
        .await
        .unwrap();
    assert_eq!(
        fixture.receiver.try_recv().unwrap().stanza,
        northstar_xml_builder::rewrite::set_to(PRESENCE, BARE),
    );
    fixture.sessions.remove(RECIPIENT);
    let (replacement, mut replacement_rx) = test_online_session(
        fixture.target.recipient.as_ref().unwrap().account_id,
        1,
        Uuid::new_v4(),
        "Phone",
        1,
    );
    replacement.available.store(true, Ordering::Release);
    fixture.sessions.insert(RECIPIENT.into(), replacement);
    fixture.blocking.emit(fixture.target, true).await.unwrap();
    assert!(replacement_rx.try_recv().is_err());
}

#[tokio::test]
async fn explicit_unavailable_and_denied_federation_use_captured_addresses() {
    let mut fixture = Fixture::new(false);
    fixture.reblocked.store(true, Ordering::Release);
    let mut directed = fixture.target.clone();
    directed.address = RECIPIENT.into();
    directed.directed = Some(RECIPIENT.into());
    fixture.blocking.emit(directed, false).await.unwrap();
    let stanza = fixture.receiver.try_recv().unwrap().stanza;
    let document = roxmltree::Document::parse(&stanza).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("to"), Some(RECIPIENT));
    assert_eq!(root.attribute("from"), Some(SOURCE));
    assert_eq!(root.attribute("type"), Some("unavailable"));

    let external = BlockingPresenceTarget {
        recipient: None,
        address: "bob@remote.test/Phone".into(),
        ..fixture.target
    };
    fixture.reblocked.store(false, Ordering::Release);
    fixture.blocking.emit(external, true).await.unwrap();
    assert!(fixture.allowed.load(Ordering::Acquire));
}

#[tokio::test]
async fn a_full_recipient_queue_does_not_prevent_the_following_handoff() {
    let mut fixture = Fixture::new(true);
    fixture
        .sessions
        .get(RECIPIENT)
        .unwrap()
        .sender
        .try_send("older".into())
        .unwrap();
    let second_jid = "bob@example.test/Desk";
    let second_route = route(2, second_jid);
    let (second, mut receiver) = test_online_session(
        second_route.account_id,
        1,
        second_route.connection_id,
        "Desk",
        1,
    );
    second.available.store(true, Ordering::Release);
    fixture.sessions.insert(second_jid.into(), second);
    let second_target = BlockingPresenceTarget {
        recipient: Some(second_route),
        ..fixture.target.clone()
    };
    let failed = fixture
        .blocking
        .emit_slice([fixture.target, second_target], true)
        .await;
    assert_eq!(failed, 1);
    assert_eq!(fixture.receiver.try_recv().unwrap().stanza, "older");
    assert_eq!(
        receiver.try_recv().unwrap().stanza,
        northstar_xml_builder::rewrite::set_to(PRESENCE, BARE)
    );
}
