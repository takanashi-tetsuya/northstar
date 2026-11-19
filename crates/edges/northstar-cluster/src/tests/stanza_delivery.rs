use super::*;

#[test]
fn muc_disconnect_outbox_renders_status_333_on_every_attempt() {
    let target = rename_occupant(uuid::Uuid::from_u128(1), "GatewayBot");
    let mut recipient = rename_occupant(uuid::Uuid::from_u128(2), "Alice");
    recipient.full_jid = "alice@example.test/Phone".to_owned();
    let details = serde_json::json!({"status": 333});
    let first = render_cluster_muc_departure_presence(
        &target,
        &recipient,
        "operation-id",
        true,
        "leave",
        &details,
    )
    .unwrap();
    let replay = render_cluster_muc_departure_presence(
        &target,
        &recipient,
        "operation-id",
        true,
        "leave",
        &details,
    )
    .unwrap();
    assert_eq!(first, replay);
    assert!(first.contains("type='unavailable'"));
    assert!(first.contains("code='333'"));
    assert!(first.contains("id='operation-id'"));

    let voluntary = render_cluster_muc_departure_presence(
        &target,
        &recipient,
        "ordinary-leave",
        true,
        "leave",
        &serde_json::json!({}),
    )
    .unwrap();
    assert!(!voluntary.contains("code='333'"));
}

#[test]
fn muc_admin_batch_preflights_every_projection_before_delivery() {
    let room_id = uuid::Uuid::from_u128(1);
    let room_epoch = uuid::Uuid::from_u128(2);
    let target = northstar_room_core::ClusterMucOccupancyTarget {
        room_id,
        room_epoch,
        occupant_incarnation: uuid::Uuid::from_u128(3),
        occupancy_epoch: 1,
        full_jid: "user@example.test/client".into(),
        nick: "visitor".into(),
        connection_uuid: uuid::Uuid::from_u128(4),
        connection_epoch: 1,
    };
    let snapshot = northstar_room_core::ClusterMucPolicySnapshot {
        room_id,
        room_epoch,
        occupant_incarnation: target.occupant_incarnation,
        occupancy_epoch: target.occupancy_epoch,
        full_jid: target.full_jid.clone(),
        bare_jid: "user@example.test".into(),
        nick: target.nick.clone(),
        connection_uuid: target.connection_uuid,
        connection_epoch: target.connection_epoch,
        sm_session_id: None,
        role: "none".into(),
        affiliation: "none".into(),
        state: "revoked".into(),
    };
    let mut details = serde_json::json!({
        "non_anonymous": true,
        "request_change_count":2,
        "changes": [
            {"kind":"presence","target":target,"snapshot":snapshot,
             "status":307,"reason":"removed"},
            {"kind":"offline_affiliation","bare_jid":"other@example.test",
             "affiliation":"member","nick":null,"reason":null}
        ]
    });
    assert!(validate_cluster_muc_admin_batch_details(&details, room_id, room_epoch).is_ok());
    details["changes"][1]["bare_jid"] = serde_json::json!("other@example.test/resource");
    assert!(validate_cluster_muc_admin_batch_details(&details, room_id, room_epoch).is_err());
    details["changes"][1]["bare_jid"] = serde_json::json!("other@example.test");
    details["non_anonymous"] = serde_json::json!(false);
    assert!(validate_cluster_muc_admin_batch_details(&details, room_id, room_epoch).is_err());
}

#[test]
fn muc_admin_batch_projection_count_fits_durable_receipts() {
    let room_id = uuid::Uuid::from_u128(1);
    let room_epoch = uuid::Uuid::from_u128(2);
    let notice = serde_json::json!({
        "kind":"offline_affiliation","bare_jid":"user@example.test",
        "affiliation":"member","nick":null,"reason":null
    });
    let details = serde_json::json!({
        "non_anonymous":true,"request_change_count":1,"changes":vec![notice; 64]
    });
    assert!(validate_cluster_muc_admin_batch_details(&details, room_id, room_epoch).is_err());
    let empty = serde_json::json!({
        "non_anonymous":false,"request_change_count":1,"changes":[]
    });
    assert!(validate_cluster_muc_admin_batch_details(&empty, room_id, room_epoch).is_ok());
}

#[test]
fn carbon_privacy_uses_the_forwarded_conversation_peer() {
    let received = roxmltree::Document::parse(
            "<message from='alice@example.test' to='alice@example.test/Tablet'>\
               <received xmlns='urn:xmpp:carbons:2'>\
                 <forwarded xmlns='urn:xmpp:forward:0'>\
                   <message xmlns='jabber:client' from='blocked@example.net/Phone' to='alice@example.test/Phone'/>\
                 </forwarded>\
               </received>\
             </message>",
        )
        .unwrap();
    assert_eq!(
        delivery_privacy_peer(&received, true),
        Some((
            "blocked@example.net/Phone".to_owned(),
            northstar_xep_0016::PrivacyStanzaKind::Message,
        ))
    );

    let sent = roxmltree::Document::parse(
            "<message from='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='alice@example.test/Phone' to='bob@example.net'/></forwarded></sent></message>",
        )
        .unwrap();
    assert_eq!(
        delivery_privacy_peer(&sent, true),
        Some((
            "bob@example.net".to_owned(),
            northstar_xep_0016::PrivacyStanzaKind::Message,
        ))
    );

    let malformed_received = roxmltree::Document::parse(
            "<message from='alice@example.test'><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'/></forwarded></received></message>",
        )
        .unwrap();
    assert_eq!(delivery_privacy_peer(&malformed_received, true), None);

    let missing_sent_recipient = roxmltree::Document::parse(
            "<message from='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='alice@example.test/Phone'/></forwarded></sent></message>",
        )
        .unwrap();
    assert_eq!(
        delivery_privacy_peer(&missing_sent_recipient, true),
        None,
        "a malformed sent Carbon must not fall back to its self-addressed wrapper"
    );

    let ambiguous = roxmltree::Document::parse(
            "<message from='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='alice@example.test/Phone' to='bob@example.net'/></forwarded></sent><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' from='mallory@example.net' to='alice@example.test/Phone'/></forwarded></received></message>",
        )
        .unwrap();
    assert_eq!(delivery_privacy_peer(&ambiguous, true), None);
}

#[test]
fn clustered_carbon_targets_each_exact_resource() {
    let wrapper = "<message xmlns='jabber:client' from='alice@example.test' to='alice@example.test'><sent xmlns='urn:xmpp:carbons:2'/></message>";
    let upper = node_delivery_stanza(wrapper, true, "alice@example.test/Phone");
    let lower = node_delivery_stanza(wrapper, true, "alice@example.test/phone");
    assert!(upper.contains("to='alice@example.test/Phone'"));
    assert!(lower.contains("to='alice@example.test/phone'"));
    assert_ne!(upper, lower);
}

#[test]
fn roster_delivery_rejects_a_recreated_account_with_the_same_jid() {
    let committed_owner = uuid::Uuid::from_u128(100);
    let recreated_owner = uuid::Uuid::from_u128(101);
    assert!(delivery_user_identity_matches(
        Some(committed_owner),
        Some(7),
        committed_owner,
        7,
    ));
    assert!(!delivery_user_identity_matches(
        Some(committed_owner),
        Some(7),
        recreated_owner,
        7,
    ));
    assert!(!delivery_user_identity_matches(
        Some(committed_owner),
        Some(7),
        committed_owner,
        8,
    ));
}

#[test]
fn presence_authority_is_versioned_complete_and_generation_fenced() {
    let owner = uuid::Uuid::from_u128(201);
    let recipient = uuid::Uuid::from_u128(202);
    let current = serde_json::json!({
        "presence_authority_version": 1,
        "presence_owner_id": owner,
        "presence_owner_auth_generation": 4,
        "presence_recipient_id": recipient,
        "presence_recipient_auth_generation": 9,
    });
    assert_eq!(
        presence_authority(&current).unwrap(),
        Some(ClusterPresenceAuthority {
            owner_id: owner,
            owner_auth_generation: 4,
            recipient_id: recipient,
            recipient_auth_generation: 9,
        })
    );
    assert!(presence_authority(&serde_json::json!({
        "presence_owner_id": owner,
        "presence_owner_auth_generation": 4,
        "presence_recipient_id": recipient,
        "presence_recipient_auth_generation": 9,
    }))
    .is_err());
    assert!(presence_authority(&serde_json::json!({
        "presence_authority_version": 1,
        "presence_owner_id": owner,
        "presence_owner_auth_generation": 4,
        "presence_recipient_id": recipient,
    }))
    .is_err());
    assert!(presence_authority(&serde_json::json!({
        "presence_authority_version": 2,
        "presence_owner_id": owner,
        "presence_owner_auth_generation": 4,
        "presence_recipient_id": recipient,
        "presence_recipient_auth_generation": 9,
    }))
    .is_err());
    assert_eq!(presence_authority(&serde_json::json!({})).unwrap(), None);
}

#[test]
fn presence_wire_shape_cannot_downgrade_subscription_into_generic_delivery() {
    let subscription = roxmltree::Document::parse(
            "<presence xmlns='jabber:client' from='a@example.test' to='b@example.test' type='subscribe'/>",
        )
        .unwrap();
    let current = roxmltree::Document::parse(
        "<presence xmlns='jabber:client' from='a@example.test/Phone' to='b@example.test'/>",
    )
    .unwrap();
    let message = roxmltree::Document::parse(
        "<message xmlns='jabber:client' from='a@example.test' to='b@example.test'/>",
    )
    .unwrap();
    assert!(is_presence_subscription_stanza(&subscription));
    assert!(presence_delivery_stanza_matches(
        &subscription,
        ClusterPresenceDelivery::Subscription,
    ));
    assert!(!presence_delivery_stanza_matches(
        &subscription,
        ClusterPresenceDelivery::CurrentReplay,
    ));
    assert!(presence_delivery_stanza_matches(
        &current,
        ClusterPresenceDelivery::CurrentReplay,
    ));
    assert!(!presence_delivery_stanza_matches(
        &message,
        ClusterPresenceDelivery::CurrentReplay,
    ));
}

#[test]
fn roster_delivery_shape_binds_the_signed_fence_to_the_stanza_version() {
    let plain = "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='42'><item jid='peer@example.test'/></query></iq>";
    let annotated = "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='42'><item jid='room@mix.example.test'><channel xmlns='urn:xmpp:mix:roster:0' participant-id='p1'/></item></query></iq>";
    assert_eq!(cluster_roster_push_version(plain), Some(42));
    assert_eq!(cluster_roster_push_version(annotated), Some(42));
    assert_ne!(cluster_roster_push_version(plain), Some(41));
    assert_eq!(
        cluster_roster_push_version(
            "<iq xmlns='jabber:client' type='get'><query xmlns='jabber:iq:roster' ver='42'/></iq>"
        ),
        None
    );
    assert_eq!(
            cluster_roster_push_version(
                "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='42'/><query xmlns='jabber:iq:roster' ver='42'/></iq>"
            ),
            None
        );
    assert_eq!(
            cluster_roster_push_version(
                "<iq xmlns='jabber:client' type='set'><query xmlns='jabber:iq:roster' ver='not-a-version'/></iq>"
            ),
            None
        );
}

#[test]
fn carbon_exclusions_preserve_exact_resources_and_legacy_primary() {
    let modern = serde_json::json!({
        "exclude_jid": "alice@example.test/Laptop",
        "exclude_jids": [
            "Alice@Example.test/Laptop",
            "alice@example.test/Phone"
        ]
    });
    let exclusions = delivery_exclusions(&modern);
    assert_eq!(exclusions.len(), 2);
    assert!(exclusions.contains("alice@example.test/Laptop"));
    assert!(exclusions.contains("alice@example.test/Phone"));

    let legacy = serde_json::json!({
        "exclude_jid": "Alice@Example.test/Laptop"
    });
    assert_eq!(
        delivery_exclusions(&legacy),
        HashSet::from(["alice@example.test/Laptop".to_owned()])
    );
}

#[test]
fn clustered_muc_carbon_scope_is_bounded_and_unambiguous() {
    let scoped = serde_json::json!({
        "carbon_muc_room": "Room@Conference.Example.test",
        "carbon_muc_nick": "Alice"
    });
    assert_eq!(
        delivery_carbon_muc_scope(&scoped),
        Ok(Some((
            "room@conference.example.test".to_owned(),
            "Alice".to_owned()
        )))
    );
    assert!(delivery_carbon_muc_scope(&serde_json::json!({
        "carbon_muc_room": "room@conference.example.test"
    }))
    .is_err());
}
