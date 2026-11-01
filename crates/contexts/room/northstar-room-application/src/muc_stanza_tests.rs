use crate::muc_service::SerializableMucOccupant;
use northstar_room_core::stanza::{
    add_muc_user_status, mam_muc_stanza, muc_occupant_id, muc_occupant_key,
    muc_presence_stanza_with_status, prepare_muc_nick, set_muc_occupant_id, valid_muc_nick,
};
use roxmltree::Document;

#[test]
fn muc_mam_payload_never_trusts_archived_identity_extensions() {
    let archived = "<message xmlns='jabber:client' from='room@conference.example.test/nick' to='alice@example.test/phone'><body>hi</body><x xmlns='http://jabber.org/protocol/muc#user'><item jid='forged@example.test'/></x><x xmlns='urn:northstar:muc:sender:0' jid='forged@example.test'/></message>";
    let hidden = mam_muc_stanza(archived, "real@example.test/phone", false);
    assert!(!hidden.contains(" to="));
    assert!(!hidden.contains("forged@example.test"));
    assert!(!hidden.contains("real@example.test"));

    let revealed = mam_muc_stanza(archived, "real@example.test/phone", true);
    assert!(!revealed.contains("forged@example.test"));
    assert!(revealed.contains("<item jid='real@example.test/phone'/>"));
    assert_eq!(
        revealed
            .matches("http://jabber.org/protocol/muc#user")
            .count(),
        1
    );
}

#[test]
fn occupant_ids_are_stable_and_scoped_to_a_room_secret() {
    let first = muc_occupant_id(&[7_u8; 32], "Alice@Example.test/phone");
    assert_eq!(
        first,
        muc_occupant_id(&[7_u8; 32], "alice@example.test/laptop")
    );
    assert_ne!(first, muc_occupant_id(&[8_u8; 32], "alice@example.test"));
    assert_eq!(first.len(), 64);
}

#[test]
fn authoritative_occupant_id_replaces_client_spoofing() {
    let stanza = set_muc_occupant_id(
        "<message><body>hello</body><occupant-id xmlns='urn:xmpp:occupant-id:0' id='spoofed'/></message>",
        "authoritative",
    );
    assert!(!stanza.contains("spoofed"));
    assert!(stanza.contains("id='authoritative'"));
    assert_eq!(stanza.matches("urn:xmpp:occupant-id:0").count(), 1);
}

#[test]
fn muc_removal_presence_carries_self_kick_and_occupant_identity() {
    let occupant = SerializableMucOccupant {
        full_jid: "alice@example.test/phone".to_owned(),
        room_jid: "room@conference.example.test".to_owned(),
        nick: "alice".to_owned(),
        affiliation: "member".to_owned(),
        role: "none".to_owned(),
        room_non_anonymous: false,
        occupant_id: "opaque-id".to_owned(),
        cluster_epoch: uuid::Uuid::new_v4(),
        connection_id: uuid::Uuid::new_v4(),
        federated_domain: None,
        sm_session_id: None,
        payload: String::new(),
    };
    let stanza = muc_presence_stanza_with_status(
        &occupant,
        &occupant.full_jid,
        true,
        true,
        false,
        Some("leave-1"),
        true,
        Some(307),
        Some("moderator"),
        Some("flooding"),
    );
    assert!(stanza.contains("<status code='110'/><status code='307'/>"));
    assert!(stanza.contains("<actor nick='moderator'/><reason>flooding</reason>"));
    assert!(stanza.contains("id='opaque-id'"));
}

#[test]
fn muc_status_insertion_handles_prefixed_self_closing_extensions() {
    let input = "<c:presence xmlns:c='jabber:client'><m:x xmlns:m='http://jabber.org/protocol/muc#user'/></c:presence>";
    let stanza = add_muc_user_status(input, 170);
    let document = Document::parse(&stanza).unwrap();
    let status = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "status")
        .unwrap();
    assert_eq!(
        status.tag_name().namespace(),
        Some("http://jabber.org/protocol/muc#user")
    );
    assert_eq!(status.attribute("code"), Some("170"));
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "status")
            .count(),
        1
    );
}

#[test]
fn muc_occupant_keys_preserve_precis_opaque_nickname_case() {
    let upper = muc_occupant_key("ROOM@Conference.Example.test", "Nick");
    let lower = muc_occupant_key("room@conference.example.test", "nick");
    assert_eq!(upper, "room@conference.example.test/Nick");
    assert_eq!(lower, "room@conference.example.test/nick");
    assert_ne!(upper, lower);
}

#[test]
fn muc_nickname_preparation_normalizes_without_trimming_or_case_mapping() {
    assert_eq!(prepare_muc_nick("A\u{30a}").unwrap(), "\u{c5}");
    assert_eq!(prepare_muc_nick(" Nick ").unwrap(), " Nick ");
    assert_ne!(
        prepare_muc_nick("Nick").unwrap(),
        prepare_muc_nick("nick").unwrap()
    );
    assert!(!valid_muc_nick(""));
    assert!(!valid_muc_nick("bad\u{0007}nick"));
}
