use super::route_component_message;
use roxmltree::Document;
use std::cell::Cell;

#[tokio::test]
async fn component_message_wire_effects_require_validation_and_live_acceptance() {
    let body = "<body>ordinary body</body>";
    let receipt = "<received xmlns='urn:xmpp:receipts' id='previous'/>";
    let store = "<store xmlns='urn:xmpp:hints'/>";
    let no_store = "<no-store xmlns='urn:xmpp:hints'/>";
    let temporary = "<no-permanent-store xmlns='urn:xmpp:hints'/>";

    for (kind, payload, hints, healthy, validation, accepted, durable, expected) in [
        ("chat", body, "", true, Ok(()), true, true, None),
        ("normal", body, temporary, true, Ok(()), true, true, None),
        ("chat", receipt, "", true, Ok(()), false, false, None),
        ("chat", receipt, temporary, true, Ok(()), false, false, None),
        ("chat", receipt, store, true, Ok(()), true, true, None),
        ("chat", receipt, store, false, Ok(()), false, false, None),
        ("error", body, store, true, Ok(()), false, false, None),
        ("headline", body, no_store, true, Ok(()), true, false, None),
        (
            "headline",
            body,
            no_store,
            true,
            Ok(()),
            false,
            false,
            Some(("wait", "service-unavailable")),
        ),
        (
            "groupchat",
            body,
            store,
            true,
            Err("bad-request"),
            false,
            false,
            Some(("modify", "bad-request")),
        ),
    ] {
        let error = if kind == "error" {
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
        } else {
            ""
        };
        let raw = format!("<message xmlns='jabber:client' from='alice@remote.test/phone' to='room@component.test' type='{kind}'>{payload}{hints}{error}</message>");
        let document = Document::parse(&raw).unwrap();
        let effect = Cell::new(None);
        let reply = route_component_message(
            document.root_element(),
            validation,
            healthy,
            async {
                effect.set(Some("outbox"));
                accepted
            },
            async {
                effect.set(Some("volatile"));
                accepted
            },
        )
        .await;
        assert_eq!(
            effect.get(),
            validation
                .ok()
                .map(|()| if durable { "outbox" } else { "volatile" }),
            "{raw}"
        );
        match (reply, expected) {
            (None, None) => {}
            (Some(reply), Some((kind, condition))) => {
                let reply = Document::parse(&reply).unwrap();
                let root = reply.root_element();
                assert_eq!(root.attribute("type"), Some("error"));
                let error = root
                    .children()
                    .find(|node| node.has_tag_name(("jabber:server", "error")))
                    .unwrap();
                assert_eq!(error.attribute("type"), Some(kind));
                assert!(error
                    .children()
                    .any(|node| node
                        .has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", condition))));
            }
            _ => panic!("unexpected wire result for {raw}"),
        }
    }
}
