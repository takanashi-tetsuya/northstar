use super::*;
use northstar_pubsub_core::{PubSubAccount, PubSubPublishWrite, PubSubSubscribeWrite};

#[test]
fn bookmark_plan_uses_locked_snapshot_and_orders_retractions() {
    let previous = [
        ("z@conference.test", "old-z"),
        ("same@conference.test", "same"),
        ("a@conference.test", "old-a"),
        ("changed@conference.test", "old"),
    ];
    let current = [
        ("same@conference.test", "same"),
        ("changed@conference.test", "new"),
        ("added@conference.test", "added"),
    ];
    let plan = plan_pep_bookmark_event(&current, &previous);
    assert_eq!(
        plan.changed_items,
        [
            ("changed@conference.test", "new"),
            ("added@conference.test", "added")
        ]
    );
    assert_eq!(
        plan.retracted_item_ids,
        ["a@conference.test", "z@conference.test"]
    );
    assert!(plan_pep_bookmark_event(&current, &current).is_empty());
}

#[test]
fn legacy_bookmark_command_requires_valid_owner() {
    let owner = PubSubAccount {
        id: Uuid::new_v4(),
        username: "owner".to_owned(),
        auth_generation: 1,
    };
    let mut items = [];
    let valid = PepCommitLegacyBookmarksCommand {
        owner: &owner,
        connection_id: Uuid::new_v4(),
        private_xml: "<storage/>",
        items: &mut items,
        expected_previous_items: &[],
        max_private_bytes: 1024,
        quotas: PepQuotas {
            max_nodes: 10,
            max_storage_bytes: 1024,
        },
    };
    assert!(validate_pep_commit_legacy_bookmarks_command(&valid).is_ok());
    let invalid_owner = PubSubAccount {
        id: Uuid::nil(),
        username: "owner".to_owned(),
        auth_generation: 1,
    };
    assert!(
        validate_pep_commit_legacy_bookmarks_command(&PepCommitLegacyBookmarksCommand {
            owner: &invalid_owner,
            ..valid
        })
        .is_err()
    );
}

#[test]
fn pep_create_command_selects_node_policy_and_rejects_invalid_quota() {
    let owner = PubSubAccount {
        id: Uuid::new_v4(),
        username: "owner".to_owned(),
        auth_generation: 7,
    };
    let command = PepCreateNodeCommand::new(&owner, "urn:xmpp:bookmarks:1", 10);
    assert!(validate_pep_create_node_command(&command).is_ok());
    assert_eq!(command.owner.id, owner.id);
    assert_eq!(command.owner.username, owner.username);
    assert_eq!(command.owner.auth_generation, owner.auth_generation);
    assert_eq!(command.config.access_model, "whitelist");
    assert_eq!(command.config.send_last_published_item, "never");
    assert!(validate_pep_create_node_command(&PepCreateNodeCommand::new(
        &owner,
        "urn:xmpp:bookmarks:1",
        0,
    ))
    .is_err());
    assert!(validate_pep_create_node_command(&PepCreateNodeCommand::new(
        &PubSubAccount {
            id: Uuid::nil(),
            ..owner
        },
        "urn:xmpp:bookmarks:1",
        10,
    ))
    .is_err());
}

#[test]
fn pep_unsubscribe_batch_command_requires_changes() {
    let owner = PubSubAccount {
        id: Uuid::new_v4(),
        username: "owner".to_owned(),
        auth_generation: 1,
    };
    let changes = [("reader@example.test/phone".to_owned(), None)];
    let valid = PepUnsubscribeBatchCommand {
        owner: &owner,
        connection_id: Uuid::new_v4(),
        node: "urn:test:node",
        changes: &changes,
    };
    assert!(validate_pep_unsubscribe_batch_command(&valid).is_ok());
    assert!(
        validate_pep_unsubscribe_batch_command(&PepUnsubscribeBatchCommand {
            changes: &[],
            ..valid
        })
        .is_err()
    );
}

#[test]
fn subscription_authorization_accepts_omitted_subid_but_rejects_stale_forms() {
    assert_eq!(
        authorization_precheck("pending", "current", None, true),
        None
    );
    assert_eq!(
        authorization_precheck("pending", "current", Some("current"), true),
        None
    );
    assert_eq!(
        authorization_precheck("pending", "current", Some("old"), true),
        Some(SubscriptionAuthorizationOutcome::Stale)
    );
    assert_eq!(
        authorization_precheck("subscribed", "current", None, true),
        Some(SubscriptionAuthorizationOutcome::Stale)
    );
    assert_eq!(
        authorization_precheck("pending", "current", None, false),
        Some(SubscriptionAuthorizationOutcome::Forbidden)
    );
}

#[test]
fn subscription_authorization_rejects_empty_command_fields() {
    let valid = PubSubAuthorizeSubscriptionCommand {
        requester: "owner@example.test",
        node: "room-events",
        subscriber_jid: "reader@example.test/phone",
        echoed_subid: None,
        allow: true,
    };
    assert!(validate_pubsub_authorize_subscription_command(&valid).is_ok());
    for invalid in [
        PubSubAuthorizeSubscriptionCommand {
            requester: " ",
            ..valid
        },
        PubSubAuthorizeSubscriptionCommand { node: "", ..valid },
        PubSubAuthorizeSubscriptionCommand {
            subscriber_jid: "",
            ..valid
        },
    ] {
        assert!(validate_pubsub_authorize_subscription_command(&invalid).is_err());
    }
    // An empty echoed SubID is a stale form, not a malformed command.
    assert!(
        validate_pubsub_authorize_subscription_command(&PubSubAuthorizeSubscriptionCommand {
            echoed_subid: Some(""),
            ..valid
        })
        .is_ok()
    );
    assert_eq!(
        authorization_precheck("pending", "current", Some(""), true),
        Some(SubscriptionAuthorizationOutcome::Stale)
    );
}

#[test]
fn collection_edge_command_requires_named_child_and_requester() {
    let collection = northstar_pubsub_core::PubSubNode {
        id: Uuid::new_v4(),
        node: "parent".to_owned(),
        creator_jid: "owner@example.test".to_owned(),
        access_model: "open".to_owned(),
        publish_model: "publishers".to_owned(),
        max_items: 100,
        title: None,
        description: None,
        deliver_payloads: true,
        notify_delete: true,
        notify_retract: true,
        persist_items: true,
        send_last_published_item: "never".to_owned(),
        node_type: "collection".to_owned(),
        deliver_notifications: true,
        notify_config: true,
        notify_sub: true,
        language: None,
        payload_type: None,
        max_payload_size: 1_048_576,
        children_max: 100,
        children_association_policy: "owner".to_owned(),
        children_association_whitelist: Vec::new(),
        created_at: std::time::UNIX_EPOCH.into(),
    };
    let valid = PubSubCollectionEdgeCommand {
        requester: "owner@example.test",
        collection: &collection,
        child: "child",
        operation: PubSubCollectionEdgeOperation::Associate,
    };
    assert!(validate_pubsub_collection_edge_command(&valid).is_ok());
    for invalid in [
        PubSubCollectionEdgeCommand {
            requester: " ",
            ..valid
        },
        PubSubCollectionEdgeCommand { child: "", ..valid },
    ] {
        assert!(validate_pubsub_collection_edge_command(&invalid).is_err());
    }
    assert!(
        validate_pubsub_collection_edge_command(&PubSubCollectionEdgeCommand {
            operation: PubSubCollectionEdgeOperation::Dissociate,
            ..valid
        })
        .is_ok()
    );
}

#[test]
fn subscription_options_precheck_keeps_expiry_before_subid_errors() {
    assert_eq!(
        subscription_options_precheck(false, "current", None),
        PubSubSubscriptionOptionsPrecheck::Ready,
    );
    assert_eq!(
        subscription_options_precheck(false, "current", Some("stale")),
        PubSubSubscriptionOptionsPrecheck::InvalidSubid,
    );
    assert_eq!(
        subscription_options_precheck(true, "current", Some("stale")),
        PubSubSubscriptionOptionsPrecheck::NotSubscribed,
    );
}

#[test]
fn subscription_options_update_requires_a_snapshot_subid() {
    let options = PubSubSubscriptionOptions::for_node_type("leaf");
    let valid = PubSubUpdateSubscriptionOptionsCommand {
        node_id: Uuid::new_v4(),
        requester: "owner@example.test",
        subscriber_jid: "owner@example.test/phone",
        expected_subid: "current",
        options: &options,
    };
    assert!(validate_pubsub_update_subscription_options_command(&valid).is_ok());
    assert!(validate_pubsub_update_subscription_options_command(
        &PubSubUpdateSubscriptionOptionsCommand {
            expected_subid: "",
            ..valid
        }
    )
    .is_err());
}

#[test]
fn pubsub_publish_validation() {
    let write = PubSubPublishWrite {
        publisher_jid: "user@example.com",
        node: "princely_musings",
        items: &[],
        publish_options: None,
        max_storage_bytes_per_owner: 1024,
        max_nodes_per_owner: 10,
    };
    let cmd = PubSubPublishCommand::from(write);
    assert!(validate_pubsub_publish_command(&cmd).is_ok());

    let invalid_write = PubSubPublishWrite {
        publisher_jid: "",
        node: "node",
        items: &[],
        publish_options: None,
        max_storage_bytes_per_owner: 1024,
        max_nodes_per_owner: 10,
    };
    assert!(validate_pubsub_publish_command(&PubSubPublishCommand::from(invalid_write)).is_err());
}

#[test]
fn pubsub_subscribe_validation() {
    let write = PubSubSubscribeWrite {
        requester: "user@example.com",
        subscriber_jid: "user@example.com/phone",
        node: "princely_musings",
        options: None,
        max_subscriptions: 100,
    };
    assert!(validate_pubsub_subscribe_command(&PubSubSubscribeCommand::from(write)).is_ok());

    let invalid = PubSubSubscribeWrite {
        requester: "user@example.com",
        subscriber_jid: "",
        node: "node",
        options: None,
        max_subscriptions: 100,
    };
    assert!(validate_pubsub_subscribe_command(&PubSubSubscribeCommand::from(invalid)).is_err());
}

#[test]
fn pep_retract_and_delete_validation() {
    let owner = PubSubAccount {
        id: Uuid::new_v4(),
        username: "romeo".to_string(),
        auth_generation: 1,
    };
    let item_ids = vec!["item1".to_string()];
    let retract = PepRetractWrite {
        owner: &owner,
        connection_id: Uuid::new_v4(),
        node: "urn:xmpp:avatar:data",
        item_ids: &item_ids,
        notify: false,
    };
    assert!(validate_pep_retract_command(&PepRetractCommand::from(retract)).is_ok());

    let empty_items: Vec<String> = vec![];
    let invalid_retract = PepRetractWrite {
        owner: &owner,
        connection_id: Uuid::new_v4(),
        node: "urn:xmpp:avatar:data",
        item_ids: &empty_items,
        notify: false,
    };
    assert!(validate_pep_retract_command(&PepRetractCommand::from(invalid_retract)).is_err());

    let delete = PepDeleteNodeWrite {
        owner: &owner,
        connection_id: Uuid::new_v4(),
        node: "urn:xmpp:avatar:data",
    };
    assert!(validate_pep_delete_node_command(&PepDeleteNodeCommand::from(delete)).is_ok());
}
