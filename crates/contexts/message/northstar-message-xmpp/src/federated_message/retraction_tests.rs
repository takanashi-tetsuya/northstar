use super::route_inbound_message;
use crate::test_support::{Host, State, TARGET};
use roxmltree::Document;

#[tokio::test]
async fn no_store_retraction_returns_wait_service_unavailable_before_admission() {
    let host = Host::new(State::default());
    let sender = "alice@remote.test/Phone";
    let raw = format!(
        "<message xmlns='jabber:client' from='{sender}' to='{TARGET}' id='action'>\
         <retract xmlns='urn:xmpp:message-retract:1' id='original'/>\
         <no-store xmlns='urn:xmpp:hints'/></message>"
    );
    let document = Document::parse(&raw).unwrap();
    let response = route_inbound_message(
        &host,
        document.root_element(),
        &raw,
        sender,
        TARGET,
        "remote.test",
    )
    .await
    .unwrap()
    .unwrap();
    let response = Document::parse(&response).unwrap();
    let error = response
        .root_element()
        .children()
        .find(|node| node.has_tag_name(("jabber:server", "error")))
        .unwrap();
    assert_eq!(error.attribute("type"), Some("wait"));
    assert!(error
        .children()
        .any(|node| node
            .has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable"))));
    assert!(host.state.events().is_empty());
}
