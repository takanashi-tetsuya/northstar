use crate::test_support::{Event, Host, Session, State, SENDER, TARGET};
use northstar_stream::transport::Action;
use northstar_xml_builder::rewrite::set_from;
use roxmltree::Document;

#[tokio::test]
async fn message_wire_and_persistence_follow_policy_on_remote_and_local_routes() {
    let receipt = "<received xmlns='urn:xmpp:receipts' id='earlier'/>";
    let legacy_marker = "<received xmlns='urn:xmpp:chat-markers:0' id='earlier'/>";
    let body = "<body>content</body>";
    let store = "<store xmlns='urn:xmpp:hints'/>";
    let no_store = "<no-store xmlns='urn:xmpp:hints'/>";
    let temporary = "<no-permanent-store xmlns='urn:xmpp:hints'/>";
    let unavailable = Some(("wait", "service-unavailable"));
    let from_remote = "carol@remote.test/phone";

    for (kind, payload, hint, outbox, spool, remote_error, local_error) in [
        ("chat", body, "", true, true, None, None),
        ("normal", body, temporary, true, true, None, None),
        ("chat", receipt, "", false, false, None, None),
        ("chat", receipt, temporary, false, true, None, None),
        ("chat", receipt, store, true, true, None, None),
        ("chat", legacy_marker, "", false, false, None, None),
        ("error", body, store, false, false, None, None),
        (
            "headline",
            body,
            no_store,
            false,
            false,
            unavailable,
            unavailable,
        ),
        (
            "chat",
            receipt,
            no_store,
            false,
            false,
            unavailable,
            unavailable,
        ),
    ] {
        let error = if kind == "error" {
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
        } else {
            ""
        };
        let client = format!("<message xmlns='jabber:client' to='{from_remote}' type='{kind}' id='message'>{payload}{hint}{error}</message>");
        let routed = set_from(&client, SENDER);
        let document = Document::parse(&routed).unwrap();
        let session = Session::new(State::default(), true);
        let reply =
            match crate::messaging::message(&session, document.root_element(), &routed, &client)
                .await
                .unwrap()
            {
                Action::None => None,
                Action::Send(reply) => Some(reply),
                _ => panic!("unexpected C2S action for {client}"),
            };
        assert_wire_reply(reply.as_deref(), remote_error, &client);
        let events = session.host.state.events();
        assert_eq!(
            events
                .iter()
                .any(|event| matches!(event, Event::OutboundCommit(_))),
            outbox,
            "{client}"
        );
        assert_eq!(
            events.contains(&Event::VolatileFederation),
            !outbox,
            "{client}"
        );

        let inbound = format!("<message xmlns='jabber:client' from='{from_remote}' to='{TARGET}' type='{kind}' id='message'>{payload}{hint}{error}</message>");
        let document = Document::parse(&inbound).unwrap();
        let host = Host::new(State {
            sessions: Vec::new(),
            ..State::default()
        });
        let reply = crate::federated_message::route_inbound_message(
            &host,
            document.root_element(),
            &inbound,
            from_remote,
            TARGET,
            "remote.test",
        )
        .await
        .unwrap();
        assert_wire_reply(reply.as_deref(), local_error, &inbound);
        assert_eq!(
            host.state.committed.lock().unwrap().is_some(),
            spool,
            "{inbound}"
        );
        assert!(
            !host
                .state
                .events()
                .iter()
                .any(|event| matches!(event, Event::History(_))),
            "{inbound}"
        );
    }
}

fn assert_wire_reply(reply: Option<&str>, expected: Option<(&str, &str)>, raw: &str) {
    match (reply, expected) {
        (None, None) => {}
        (Some(reply), Some((kind, condition))) => {
            let document = Document::parse(reply).unwrap();
            let root = document.root_element();
            assert_eq!(root.attribute("type"), Some("error"), "{raw}");
            let error = root
                .children()
                .find(|child| child.is_element() && child.tag_name().name() == "error")
                .unwrap();
            assert_eq!(error.attribute("type"), Some(kind), "{raw}");
            assert!(
                error
                    .children()
                    .any(|node| node
                        .has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", condition))),
                "{raw}"
            );
        }
        _ => panic!("unexpected wire result for {raw}: {reply:?}"),
    }
}
