use super::{
    canonical_user_bare, mix_delivery_capacity_bucket, mix_presence_item_id, prepare_mix_nick,
    MixChannel,
};
use uuid::Uuid;

#[test]
fn mix_nicks_use_case_preserving_precis_opaque_string() {
    assert_eq!(prepare_mix_nick("Nick").unwrap(), "Nick");
    assert_eq!(prepare_mix_nick("nick").unwrap(), "nick");
    assert_ne!(
        prepare_mix_nick("Nick").unwrap(),
        prepare_mix_nick("nick").unwrap()
    );
    assert_eq!(prepare_mix_nick(" A ").unwrap(), " A ");
    assert_eq!(prepare_mix_nick("A\u{30a}").unwrap(), "\u{c5}");
    assert!(prepare_mix_nick("").is_err());
    assert!(prepare_mix_nick("bad\u{0007}nick").is_err());
}

#[test]
fn delivery_capacity_buckets_match_the_uuid_wire_prefix() {
    let low = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let high = Uuid::parse_str("ff112233-4455-6677-8899-aabbccddeeff").unwrap();
    assert_eq!(mix_delivery_capacity_bucket(low), 0);
    assert_eq!(mix_delivery_capacity_bucket(high), 63);
}

#[test]
fn presence_item_uses_encoded_stable_identity_not_real_jid() {
    let channel = MixChannel {
        id: Uuid::new_v4(),
        revision: 0,
        service_domain: "mix.example.test".to_owned(),
        localpart: "room".to_owned(),
        creator_jid: "owner@example.test".to_owned(),
        name: None,
        description: None,
        contacts: Vec::new(),
        access_model: "open".to_owned(),
        jid_visibility: "hidden".to_owned(),
        nick_required: true,
        max_participants: 1000,
        max_events: 10000,
        allow_private_messages: false,
        allow_participant_invites: false,
        allow_user_message_retraction: false,
        administrator_retraction_rights: "nobody".to_owned(),
        enforce_registered_nick: false,
    };
    let stable = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let item = mix_presence_item_id(&channel, stable, "Phone").unwrap();
    assert_eq!(
        item,
        "00112233-4455-6677-8899-aabbccddeeff#room@mix.example.test/Phone"
    );
    assert!(!item.contains("alice@example.test"));
    assert!(mix_presence_item_id(&channel, stable, "").is_err());
}

#[test]
fn participant_accounts_are_precis_idna_canonical_but_resources_are_validated() {
    assert_eq!(
        canonical_user_bare("ALICE@BÜCHER.example/Phone").unwrap(),
        "alice@bücher.example"
    );
    assert!(canonical_user_bare("alice@example.test/bad\u{0007}resource").is_err());
    assert!(canonical_user_bare("alice@example..test/Phone").is_err());
}
