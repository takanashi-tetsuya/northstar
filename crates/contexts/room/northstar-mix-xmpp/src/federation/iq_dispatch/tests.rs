use super::*;

#[test]
fn admission_and_replay_conflicts_use_the_same_stanza() {
    let request = parse_iq("<iq type='set' id='same'><leave xmlns='urn:xmpp:mix:core:1'/></iq>")
        .unwrap()
        .unwrap();
    let actor = authenticated_actor("guest@remote.test/console", "remote.test").unwrap();
    let channel = CanonicalJid::parse_bare("room@mix.example.test").unwrap();
    let conflict = anyhow::Error::new(FederatedMixIqConflict).context("repository admission");
    let admission = admission_conflict(&conflict).unwrap();
    assert_eq!(admission, FederatedMixIqReplay::Conflict);
    assert_eq!(
        admission_conflict(&anyhow::anyhow!("outbox unavailable")),
        None
    );

    let response = conflict_response(&request, &channel, &actor);
    let document = Document::parse(&response).unwrap();
    let iq = document.root_element();
    assert_eq!(iq.attribute("id"), Some("same"));
    assert_eq!(iq.attribute("from"), Some("room@mix.example.test"));
    assert_eq!(iq.attribute("to"), Some("guest@remote.test/console"));
    assert_eq!(iq.attribute("type"), Some("error"));
    let error = iq.first_element_child().unwrap();
    assert_eq!(error.attribute("type"), Some("cancel"));
    let condition = error.first_element_child().unwrap();
    assert!(condition.has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", "conflict")));
}
