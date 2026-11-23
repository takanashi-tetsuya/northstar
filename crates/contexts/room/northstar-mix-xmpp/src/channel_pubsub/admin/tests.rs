use super::*;
use northstar_room_application::mix_service::MixMutationAdmission;

#[test]
fn information_patch_keeps_explicit_empty_fields() {
    let mut fields = BTreeMap::from([
        ("Contact".to_owned(), Vec::new()),
        ("Name".to_owned(), vec![String::new()]),
        (
            "JID Visibility".to_owned(),
            vec!["jid-maybe-visible".to_owned()],
        ),
    ]);
    let patch = parse_info_patch(&fields).unwrap();
    assert_eq!(patch.name.as_deref(), Some(""));
    assert_eq!(patch.description, None);
    assert_eq!(patch.contacts, Some(Vec::new()));
    assert_eq!(patch.visibility, Some(MixJidVisibility::Maybe));
    fields.insert("JID Visibility".to_owned(), vec!["maybe".to_owned()]);
    assert_eq!(
        parse_info_patch(&fields).unwrap_err().to_string(),
        "unsupported MIX configuration value"
    );
}

#[test]
fn publication_reply_uses_committed_id_and_preserves_denials() {
    let channel = MixChannel {
        id: Uuid::nil(),
        revision: 1,
        service_domain: "mix.local.test".to_owned(),
        localpart: "room".to_owned(),
        creator_jid: "owner@local.test".to_owned(),
        name: None,
        description: None,
        contacts: Vec::new(),
        access_model: "open".to_owned(),
        jid_visibility: "visible".to_owned(),
        nick_required: true,
        max_participants: 1000,
        max_events: 10000,
        allow_private_messages: true,
        allow_participant_invites: false,
        allow_user_message_retraction: false,
        administrator_retraction_rights: "owners".to_owned(),
        enforce_registered_nick: false,
    };
    let reply_to = "owner@local.test/device";
    let result = publication_reply(
        "form",
        &channel,
        reply_to,
        NODE_INFO,
        MixMutationOutcome::Applied(Box::new(MixMutationAdmission {
            channel: channel.clone(),
            node: NODE_INFO.to_owned(),
            item_id: "1970-01-01T00:00:00.000000042Z".to_owned(),
            payload: "<x/>".to_owned(),
            recipients: Vec::new(),
        })),
    );
    assert_eq!(result, concat!(
        "<iq xmlns='jabber:client' type='result' from='room@mix.local.test' to='owner@local.test/device' id='form'>",
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:mix:nodes:info'>",
        "<item id='1970-01-01T00:00:00.000000042Z'/></publish></pubsub></iq>",
    ));
    for (outcome, kind, condition) in [
        (MixMutationOutcome::Forbidden, "auth", "forbidden"),
        (MixMutationOutcome::NotFound, "cancel", "item-not-found"),
        (MixMutationOutcome::Conflict, "cancel", "conflict"),
    ] {
        assert_eq!(
            publication_reply("form", &channel, reply_to, NODE_CONFIG, outcome),
            format!(concat!(
                "<iq xmlns='jabber:client' type='error' from='room@mix.local.test' to='owner@local.test/device' id='form'>",
                "<error type='{}'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
            ), kind, condition),
        );
    }
}
