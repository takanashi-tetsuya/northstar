use super::*;

const ROOM: &str = "room@conference.local.test";
const SERVICE: &str = "conference.local.test";
const SENDER: &str = "tester@remote.test/phone";

fn stanza(to: &str) -> FederatedStanza {
    let raw = format!(
        "<iq type='get' id='request' from='{SENDER}' to='{to}'><ping xmlns='urn:xmpp:ping'/></iq>"
    );
    let document = roxmltree::Document::parse(&raw).unwrap();
    FederatedStanza::from_node(document.root_element(), &raw)
}

#[test]
fn service_and_bare_room_ping_use_the_liveness_address() {
    for address in [SERVICE, ROOM] {
        let reply = federated_liveness_reply(&stanza(address), address, SENDER);
        let document = roxmltree::Document::parse(&reply).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("from"), Some(address));
        assert_eq!(root.attribute("to"), Some(SENDER));
        assert_eq!(root.attribute("type"), Some("result"));
        assert_eq!(
            root.children().filter(roxmltree::Node::is_element).count(),
            0
        );
    }
}

#[test]
fn full_ping_requires_own_route_or_uses_the_ordinary_iq_path() {
    let address = format!("{ROOM}/Own");
    let request = stanza(&address);
    let mut actor = FederatedReadActor {
        full_jid: SENDER,
        bare_jid: "tester@remote.test",
        domain: "remote.test",
        node_id: "test-node",
        route: Some(MucOccupantRoute {
            full_jid: SENDER.to_owned(),
            nick: "Own".to_owned(),
            connection_id: uuid::Uuid::from_u128(1),
            cluster_epoch: uuid::Uuid::from_u128(2),
        }),
    };
    let own = actor.own_ping(true, "Own").unwrap();
    assert_eq!(own.authenticated_domain, Some("remote.test"));
    assert_eq!(
        own_ping_reply(&request, SENDER, true).unwrap(),
        federated_liveness_reply(&request, &address, SENDER)
    );
    assert!(actor.own_ping(true, "Another").is_none());
    assert!(actor.proof().is_some());
    assert!(actor.own_ping(false, "Own").is_none());
    actor.route = None;
    assert!(actor.own_ping(true, "Own").is_none());
    let reply = own_ping_reply(&request, SENDER, false).unwrap();
    let document = roxmltree::Document::parse(&reply).unwrap();
    let error = document.root_element().first_element_child().unwrap();
    assert_eq!(error.attribute("type"), Some("modify"));
    assert_eq!(
        error.first_element_child().unwrap().tag_name().name(),
        "not-acceptable"
    );
}

#[test]
fn committed_registration_succeeds_when_the_wake_fails() {
    let raw = format!("<iq type='set' id='register' from='{SENDER}' to='{ROOM}'><query xmlns='jabber:iq:register'/></iq>");
    let document = roxmltree::Document::parse(&raw).unwrap();
    let request = FederatedStanza::from_node(document.root_element(), &raw);
    let reply = futures::executor::block_on(committed_registration_reply(
        async { Err(anyhow::anyhow!("transport down")) },
        uuid::Uuid::from_u128(1),
        &request,
        ROOM,
        SENDER,
    ));
    assert_eq!(
        reply.unwrap(),
        federated_iq_result(&request, ROOM, SENDER, "")
    );
}
