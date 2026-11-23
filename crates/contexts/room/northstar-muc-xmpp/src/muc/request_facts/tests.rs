use super::*;
use northstar_room_core::{FixedMucClock, MucTimeSources, SequentialMucIds};
use std::sync::Arc;

fn facts() -> MucRequestFacts {
    MucTimeSources::new(
        Arc::new(FixedMucClock(northstar_time::DateTime::UNIX_EPOCH)),
        Arc::new(SequentialMucIds::default()),
    )
    .prepare_request()
}

#[test]
fn moderation_action_stamp_uses_the_fixed_command_instant() {
    let facts = facts();
    for id in [Some(facts.id), None] {
        let xml = moderated_retraction(facts, id, XmlElement::new("moderated")).finish();
        let document = roxmltree::Document::parse(&xml).unwrap();
        let root = document.root_element();
        let expected_id = id.map(|id| id.to_string());
        assert_eq!(root.attribute("id"), expected_id.as_deref());
        assert_eq!(root.attribute("stamp"), Some("1970-01-01T00:00:00Z"));
    }
}

#[test]
fn offline_delay_uses_the_fixed_command_instant_for_each_invitee() {
    let facts = facts();
    let room = "room@conference.local.test";
    for input in [
        "<message to='alice@local.test'/>",
        "<message to='bob@local.test'/>",
    ] {
        let xml = offline_delay(input, room, facts);
        let document = roxmltree::Document::parse(&xml).unwrap();
        let delay = document.root_element().first_element_child().unwrap();
        assert!(delay.has_tag_name(("urn:xmpp:delay", "delay")));
        assert_eq!(delay.attribute("from"), Some(room));
        assert_eq!(delay.attribute("stamp"), Some("1970-01-01T00:00:00Z"));
    }
}
