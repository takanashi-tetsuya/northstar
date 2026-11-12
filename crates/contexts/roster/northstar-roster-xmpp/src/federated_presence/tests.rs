use super::*;

#[test]
fn probe_status_responses_preserve_correlation_and_escape_addresses() {
    let response = presence_probe_status_response(
        "alice@local.test",
        "bob&carol@remote.test",
        "unavailable",
        Some("probe'1"),
    );
    assert_eq!(
        response,
        "<presence xmlns='jabber:server' from='alice@local.test' to='bob&amp;carol@remote.test' type='unavailable' id='probe&apos;1'/>"
    );
}

#[test]
fn persisted_federated_subscription_keeps_extensions_and_uses_bare_jids() {
    let raw = "<presence xmlns='jabber:server' type='subscribe' from='Alice@Remote.Test/Phone' to='Bob@Local.Test/Desktop'><status xml:lang='en'>Please add me</status><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>";
    let persisted = canonical_subscription_stanza(raw, "alice@remote.test", "bob@local.test");
    let document = Document::parse(&persisted).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("from"), Some("alice@remote.test"));
    assert_eq!(root.attribute("to"), Some("bob@local.test"));
    assert_eq!(root.tag_name().namespace(), Some("jabber:client"));
    assert!(!persisted.contains("jabber:server"));
    assert!(root.children().any(|child| {
        child.is_element()
            && child.tag_name().name() == "status"
            && child.text() == Some("Please add me")
    }));
    assert!(root.children().any(|child| {
        child.is_element()
            && child.tag_name().name() == "nick"
            && child.tag_name().namespace() == Some("http://jabber.org/protocol/nick")
            && child.text() == Some("Alice")
    }));
}
