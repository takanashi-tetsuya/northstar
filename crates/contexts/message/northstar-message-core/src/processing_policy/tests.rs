use super::{classify_message_effects, MessageDirection, MessageEffects};
use roxmltree::Document;
use MessageEffects::{NoStore, Persist, SignalOnly, VolatileOnly};

#[test]
fn processing_hints_select_effects_by_type_payload_and_direction() {
    let permanent = Persist { permanent: true };
    let temporary = Persist { permanent: false };
    let store = "<store xmlns='urn:xmpp:hints'/>";
    let no_permanent = "<no-permanent-store xmlns='urn:xmpp:hints'/>";
    let no_store = "<no-store xmlns='urn:xmpp:hints'/>";
    let no_copy = "<no-copy xmlns='urn:xmpp:hints'/>";
    let store_temporary = format!("{store}{no_permanent}");
    let overriding_no_store = format!("{store_temporary}{no_store}");
    let body = "<body>content</body>";
    let receipt = "<received xmlns='urn:xmpp:receipts' id='previous'/>";
    let composing = "<composing xmlns='http://jabber.org/protocol/chatstates'/>";
    let displayed = "<displayed xmlns='urn:xmpp:chat-markers:0' id='previous'/>";
    let legacy =
        "<acknowledged xmlns='urn:xmpp:chat-markers:0' id='previous'/><thread>thread</thread>";
    let receipt_with_metadata = format!("{receipt}<delay xmlns='urn:xmpp:delay' stamp='2001-01-01T00:00:00Z'/><private xmlns='urn:xmpp:carbons:2'/>");

    for kind in ["normal", "chat", "headline", "groupchat", "error"] {
        for (payload, hints, local, external, degraded_external) in [
            (body, "", permanent, permanent, permanent),
            (body, no_copy, permanent, permanent, permanent),
            (body, no_permanent, temporary, temporary, temporary),
            (body, no_store, NoStore, NoStore, NoStore),
            (body, &overriding_no_store, NoStore, NoStore, NoStore),
            (receipt, "", SignalOnly, SignalOnly, SignalOnly),
            (receipt, no_copy, SignalOnly, SignalOnly, SignalOnly),
            (receipt, no_permanent, temporary, SignalOnly, SignalOnly),
            (receipt, &store_temporary, temporary, temporary, SignalOnly),
            (receipt, no_store, NoStore, NoStore, NoStore),
            (
                &receipt_with_metadata,
                "",
                SignalOnly,
                SignalOnly,
                SignalOnly,
            ),
            (composing, store, permanent, permanent, SignalOnly),
            (displayed, "", SignalOnly, SignalOnly, SignalOnly),
            (legacy, "", SignalOnly, SignalOnly, SignalOnly),
        ] {
            let raw =
                format!("<message xmlns='jabber:server' type='{kind}'>{payload}{hints}</message>");
            let document = Document::parse(&raw).unwrap();
            for (direction, expected) in [
                (MessageDirection::Federation { healthy: true }, external),
                (MessageDirection::Local { healthy: true }, local),
                (MessageDirection::Component { healthy: true }, external),
                (
                    MessageDirection::Federation { healthy: false },
                    degraded_external,
                ),
                (
                    MessageDirection::Component { healthy: false },
                    degraded_external,
                ),
            ] {
                let expected = if kind == "error" {
                    VolatileOnly
                } else {
                    expected
                };
                let effects = classify_message_effects(document.root_element(), direction);
                assert_eq!(effects, expected, "{direction:?}: {raw}");
                assert_eq!(
                    effects.volatile_route_refusal(),
                    (expected == NoStore).then_some(("wait", "service-unavailable")),
                    "{direction:?}: {raw}",
                );
            }
        }
    }
}
