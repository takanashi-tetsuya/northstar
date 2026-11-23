use super::*;
use uuid::Uuid;

fn channel() -> MixChannel {
    MixChannel {
        id: Uuid::nil(),
        revision: 4,
        service_domain: "mix.local.test".to_owned(),
        localpart: "room".to_owned(),
        creator_jid: "owner@local.test".to_owned(),
        name: None,
        description: None,
        contacts: Vec::new(),
        access_model: "allowlist".to_owned(),
        jid_visibility: "maybe".to_owned(),
        nick_required: true,
        max_participants: 17,
        max_events: 240,
        allow_private_messages: false,
        allow_participant_invites: true,
        allow_user_message_retraction: true,
        administrator_retraction_rights: "owners".to_owned(),
        enforce_registered_nick: false,
    }
}

#[test]
fn defaults_and_invalid_numbers_use_locked_values_not_submission_defaults() {
    let channel = channel();
    let patch = ConfigPatch {
        expected_revision: 3,
        fields: [
            (
                "max_participants".to_owned(),
                vec!["not-a-number".to_owned()],
            ),
            (
                "max_events".to_owned(),
                vec!["99999999999999999".to_owned()],
            ),
            (
                "Enforce Registered Nick".to_owned(),
                vec!["true".to_owned()],
            ),
        ]
        .into(),
    };
    let (update, roles) = resolve_config(&patch, "fixed-item", &channel).unwrap();
    assert_eq!(update.expected_revision, 3);
    assert_eq!(update.item_id, "fixed-item");
    assert_eq!(update.access_model, "allowlist");
    assert_eq!(update.jid_visibility, "maybe");
    assert_eq!(update.max_participants, 17);
    assert_eq!(update.max_events, 240);
    assert!(!update.allow_private_messages);
    assert!(update.allow_participant_invites);
    assert!(update.enforce_registered_nick);
    assert_eq!(update.administrator_retraction_rights, "owners");
    assert!(roles.owners.is_none() && roles.administrators.is_none());
}

#[test]
fn fixed_fields_precede_visibility_and_booleans() {
    let mut patch = ConfigPatch {
        expected_revision: 4,
        fields: [
            (
                "Information Node Subscription".to_owned(),
                vec!["anyone".to_owned()],
            ),
            ("JID Visibility".to_owned(), vec!["invalid".to_owned()]),
            ("Private Messages".to_owned(), vec!["invalid".to_owned()]),
        ]
        .into(),
    };
    let channel = channel();
    for (remove, expected) in [
        (
            "Information Node Subscription",
            "unsupported MIX configuration value",
        ),
        ("JID Visibility", "unsupported MIX JID visibility mode"),
        ("Private Messages", "invalid MIX boolean field"),
    ] {
        let Err(error) = resolve_config(&patch, "item", &channel) else {
            panic!("invalid form was accepted");
        };
        assert_eq!(error.to_string(), expected);
        patch.fields.remove(remove);
    }
}
