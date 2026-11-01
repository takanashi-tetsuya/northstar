use super::*;

#[tokio::test]
async fn validation_precedes_persistence_and_repository_failure_remains_an_error() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct UnavailableRepository(AtomicUsize);
    impl RetractionRepository for UnavailableRepository {
        async fn apply_prepared(
            &self,
            prepared: PreparedRetraction<'_>,
        ) -> Result<RetractionOutcome> {
            self.0.fetch_add(1, Ordering::SeqCst);
            assert_eq!(prepared.canonical_sender, "alice@local.test");
            assert_eq!(prepared.normalized_owners.len(), 1);
            assert_eq!(
                prepared.normalized_owners[0].peer_bare_jid,
                "bob@remote.test"
            );
            let primary = prepared.semantic_authenticators.primary();
            assert!(
                northstar_abuse_application::guard::test_personal_retraction_content_keyring()
                    .authenticators(&prepared.canonical_semantics)
                    .verifies(primary.key_id(), primary.mac())
            );
            anyhow::bail!("injected repository unavailable")
        }
    }

    let service = RetractionService::new(
        UnavailableRepository(AtomicUsize::new(0)),
        northstar_abuse_application::guard::test_personal_retraction_content_keyring(),
        "local.test",
    );
    let command = RetractionCommand {
        target_id: "original",
        action_id: "action",
        semantic_payload: "<message from='alice@local.test/Phone' to='bob@remote.test' id='action'><retract xmlns='urn:xmpp:message-retract:1' id='original'/></message>",
    };
    let owners = [OwnerProjection {
        owner_id: Uuid::new_v4(),
        peer_jid: "bob@remote.test/Tablet",
    }];
    assert!(service
        .apply(&[], "alice@local.test/Phone", &command, &[], None)
        .await
        .is_err());
    let invalid = RetractionCommand {
        target_id: "mismatch",
        ..command
    };
    assert!(service
        .apply(&owners, "alice@local.test/Phone", &invalid, &[], None)
        .await
        .is_err());
    assert_eq!(service.repository.0.load(Ordering::SeqCst), 0);
    let error = service
        .apply(&owners, "alice@local.test/Phone", &command, &[], None)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "injected repository unavailable");
    assert_eq!(service.repository.0.load(Ordering::SeqCst), 1);
}

#[test]
fn tombstone_preserves_only_structurally_valid_direct_stanza_ids() {
    let document = Document::parse(
        "<message xmlns='jabber:client' from='alice@example.test/Phone' to='alice@example.test' id='original'>\
         <body>secret</body>\
         <stanza-id xmlns='urn:xmpp:sid:0' id='account-id' by='alice@example.test'/>\
         <stanza-id xmlns='urn:xmpp:sid:0' id='remote-id' by='remote.test'></stanza-id>\
         <stanza-id xmlns='urn:xmpp:sid:0' id='extra-id' by='remote.test' extra='1'/>\
         <wrapper><stanza-id xmlns='urn:xmpp:sid:0' id='nested-id' by='alice@example.test'/></wrapper>\
         <stanza-id xmlns='urn:xmpp:sid:0' id='invalid-by' by='not a jid'/>\
         </message>",
    )
    .unwrap();

    let tombstone = tombstone_message(document.root_element(), "retraction-id");
    let tombstone_document = Document::parse(&tombstone).unwrap();
    let root = tombstone_document.root_element();
    let stanza_ids = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(NS_STANZA_ID)
                && node.tag_name().name() == "stanza-id"
        })
        .map(|node| {
            (
                node.attribute("id").unwrap().to_owned(),
                node.attribute("by").unwrap().to_owned(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        stanza_ids,
        vec![
            ("account-id".to_owned(), "alice@example.test".to_owned()),
            ("remote-id".to_owned(), "remote.test".to_owned()),
        ]
    );
    assert!(!tombstone.contains("secret"));
    assert!(!tombstone.contains("extra-id"));
    assert!(!tombstone.contains("nested-id"));
    assert!(!tombstone.contains("invalid-by"));
    assert!(root.children().any(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(NS_RETRACT)
            && node.tag_name().name() == "retracted"
            && node.attribute("id") == Some("retraction-id")
    }));
}

#[test]
fn advisory_lock_uses_a_domain_separated_digest_of_the_complete_identity() {
    let first = retraction_lock_key("alice@example.test", "action-1");
    assert_eq!(first, retraction_lock_key("alice@example.test", "action-1"));
    assert_ne!(first, retraction_lock_key("alice@example.test", "action-2"));
    assert_ne!(
        first,
        retraction_lock_key("mallory@example.test", "action-1")
    );
}

#[test]
fn validates_stable_id_bounds_and_control_characters() {
    assert!(validate_stable_id("normal-id-123", "test id").is_ok());
    assert!(validate_stable_id("", "empty id").is_err());
    let too_long = "a".repeat(1025);
    assert!(validate_stable_id(&too_long, "long id").is_err());
    let exact_max = "a".repeat(1024);
    assert!(validate_stable_id(&exact_max, "max id").is_ok());
    assert!(validate_stable_id("has\nnewline", "control char id").is_err());
    assert!(validate_stable_id("has\0null", "null byte id").is_err());
    assert!(validate_stable_id("has\ttab", "tab char id").is_err());
}

#[test]
fn bounded_action_digest_is_deterministic_and_separated() {
    let d1 = bounded_action_digest("action-1");
    let d2 = bounded_action_digest("action-1");
    let d3 = bounded_action_digest("action-2");
    assert_eq!(d1, d2);
    assert_ne!(d1, d3);
}

#[test]
fn canonical_retraction_semantics_excludes_transport_metadata_and_consumed_pow() {
    let first = "<message from='alice@example.test/Phone' id='action'><body>removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target'/><pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000001' nonce='one'/></message>";
    let retry = "<message from='alice@example.test/Tablet' id='action'><body>removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target'/><delay xmlns='urn:xmpp:delay' from='example.test' stamp='2026-08-31T00:00:00Z'/><pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000002' nonce='two'/></message>";
    let changed = "<message from='alice@example.test/Phone' id='action'><body>different</body><retract xmlns='urn:xmpp:message-retract:1' id='target'/><pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000003' nonce='three'/></message>";
    let canonical = |stanza| {
        canonical_retraction_semantics(stanza, "alice@example.test", "action", "target").unwrap()
    };
    assert_eq!(canonical(first), canonical(retry));
    assert_ne!(canonical(first), canonical(changed));
}

#[test]
fn canonical_owner_projection_formats_and_sorts() {
    let o1 = NormalizedOwner {
        owner_id: Uuid::nil(),
        peer_bare_jid: "bob@example.com".to_owned(),
    };
    let p1 = canonical_owner_projection(&[o1]);
    assert!(!p1.is_empty());
    assert!(p1.starts_with(b"northstar/retraction-owner-projection/v1\0"));
}

#[test]
fn federation_outbox_policy_conversions() {
    let p1 = FederationOutboxPolicy {
        ttl_seconds: 300,
        max_rows: 50,
        max_bytes: 100_000,
        max_per_domain: 20,
    };
    let db_policy: northstar_federation_core::S2sOutboxPolicy = p1.into();
    assert_eq!(db_policy.ttl_seconds, 300);
    assert_eq!(db_policy.max_rows, 50);
    assert_eq!(db_policy.max_bytes, 100_000);
    assert_eq!(db_policy.max_per_domain, 20);
    let p2: FederationOutboxPolicy = db_policy.into();
    assert_eq!(p1, p2);
}

#[test]
fn c2s_missing_to_uses_effective_self_recipient_without_rewriting_xml() {
    let actor_id = Uuid::new_v4();
    let stanza = "<message from='alice@local.test/Phone' id='self-action'><retract xmlns='urn:xmpp:message-retract:1' id='self-target'/></message>";
    let command = RetractionCommand {
        target_id: "self-target",
        action_id: "self-action",
        semantic_payload: stanza,
    };
    let local = DeliveryProjection {
        id: Uuid::new_v4(),
        recipient_id: actor_id,
        local_actor_id: Some(actor_id),
        sender_jid: "alice@local.test/Phone",
        stanza,
        encrypted: false,
        max_messages: 100,
        max_bytes: 1_000_000,
        ttl_days: 30,
        mam_backed: false,
    };
    let normalized =
        normalize_delivery_projection(&local, "alice@local.test", "local.test", &command).unwrap();
    assert_eq!(normalized.recipient_bare_jid, "alice@local.test");
    assert!(normalized.projection.stanza.contains("id='self-action'"));
    assert!(!normalized.projection.stanza.contains(" to="));

    let explicit_stanza = "<message from='alice@local.test/Phone' to='alice@local.test' id='self-action'><retract xmlns='urn:xmpp:message-retract:1' id='self-target'/></message>";
    let explicit = DeliveryProjection {
        stanza: explicit_stanza,
        ..local
    };
    let explicit_normalized =
        normalize_delivery_projection(&explicit, "alice@local.test", "local.test", &command)
            .unwrap();
    assert_eq!(normalized.commitment, explicit_normalized.commitment);

    let explicit_resource_stanza = "<message from='alice@local.test/Phone' to='alice@local.test/Tablet' id='self-action'><retract xmlns='urn:xmpp:message-retract:1' id='self-target'/></message>";
    let explicit_resource = DeliveryProjection {
        stanza: explicit_resource_stanza,
        ..local
    };
    let explicit_resource_normalized = normalize_delivery_projection(
        &explicit_resource,
        "alice@local.test",
        "local.test",
        &command,
    )
    .unwrap();
    assert_ne!(
        normalized.commitment,
        explicit_resource_normalized.commitment
    );

    let federated_stanza = "<message from='alice@remote.test/Phone' id='self-action'><retract xmlns='urn:xmpp:message-retract:1' id='self-target'/></message>";
    let federated_command = RetractionCommand {
        semantic_payload: federated_stanza,
        ..command
    };
    let federated = DeliveryProjection {
        local_actor_id: None,
        sender_jid: "alice@remote.test/Phone",
        stanza: federated_stanza,
        ..local
    };
    assert!(normalize_delivery_projection(
        &federated,
        "alice@remote.test",
        "local.test",
        &federated_command,
    )
    .is_err());
}

#[test]
fn inbound_s2s_full_normal_delivery_identity_binds_the_exact_resource() {
    let recipient_id = Uuid::new_v4();
    let phone_stanza = "<message from='alice@remote.test/Phone' to='bob@local.test/Phone' id='remote-action'><retract xmlns='urn:xmpp:message-retract:1' id='remote-target'/></message>";
    let tablet_stanza = "<message from='alice@remote.test/Tablet' to='bob@local.test/Tablet' id='remote-action'><retract xmlns='urn:xmpp:message-retract:1' id='remote-target'/></message>";
    let phone_command = RetractionCommand {
        target_id: "remote-target",
        action_id: "remote-action",
        semantic_payload: phone_stanza,
    };
    let tablet_command = RetractionCommand {
        semantic_payload: tablet_stanza,
        ..phone_command
    };
    let phone = DeliveryProjection {
        id: Uuid::new_v4(),
        recipient_id,
        local_actor_id: None,
        sender_jid: "alice@remote.test/Phone",
        stanza: phone_stanza,
        encrypted: false,
        max_messages: 100,
        max_bytes: 1_000_000,
        ttl_days: 30,
        mam_backed: false,
    };
    let tablet = DeliveryProjection {
        id: Uuid::new_v4(),
        sender_jid: "alice@remote.test/Tablet",
        stanza: tablet_stanza,
        ..phone
    };
    let phone =
        normalize_delivery_projection(&phone, "alice@remote.test", "local.test", &phone_command)
            .unwrap();
    let tablet =
        normalize_delivery_projection(&tablet, "alice@remote.test", "local.test", &tablet_command)
            .unwrap();
    assert_eq!(phone.recipient_bare_jid, "bob@local.test");
    assert_eq!(
        phone.target_full_jid.as_deref(),
        Some("bob@local.test/Phone")
    );
    assert_eq!(
        tablet.target_full_jid.as_deref(),
        Some("bob@local.test/Tablet")
    );
    assert_ne!(phone.commitment, tablet.commitment);
}

#[test]
fn outbound_projection_rejects_a_configured_local_target() {
    let command = RetractionCommand {
        target_id: "target",
        action_id: "action",
        semantic_payload: "<message from='alice@local.test/Phone' to='bob@local.test' id='action'><retract xmlns='urn:xmpp:message-retract:1' id='target'/></message>",
    };
    let semantics = canonical_retraction_semantics(
        command.semantic_payload,
        "alice@local.test",
        command.action_id,
        command.target_id,
    )
    .unwrap();
    let outbound = OutboundProjection {
        target_domain: "local.test",
        stanza: command.semantic_payload,
        bounce_to: Some("alice@local.test/Phone"),
        policy: FederationOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 50,
            max_bytes: 100_000,
            max_per_domain: 20,
        },
    };
    assert!(normalize_outbound_projection(
        &outbound,
        "alice@local.test",
        "local.test",
        &semantics,
        &command,
    )
    .is_err());

    let domain_command = RetractionCommand {
        semantic_payload: "<message from='alice@local.test/Phone' to='remote.test' id='action'><retract xmlns='urn:xmpp:message-retract:1' id='target'/></message>",
        ..command
    };
    let domain_semantics = canonical_retraction_semantics(
        domain_command.semantic_payload,
        "alice@local.test",
        domain_command.action_id,
        domain_command.target_id,
    )
    .unwrap();
    let domain_outbound = OutboundProjection {
        target_domain: "remote.test",
        stanza: domain_command.semantic_payload,
        ..outbound
    };
    assert!(normalize_outbound_projection(
        &domain_outbound,
        "alice@local.test",
        "local.test",
        &domain_semantics,
        &domain_command,
    )
    .is_err());
}

#[test]
fn personal_retraction_invocation_dto_contract() {
    let owner_id = Uuid::new_v4();
    let owners = [OwnerProjection {
        owner_id,
        peer_jid: "bob@example.com",
    }];
    let cmd = RetractionCommand {
        target_id: "target-1",
        action_id: "action-1",
        semantic_payload: "<message id='action-1'><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
    };
    let writes = [ArchiveWrite {
        id: Uuid::new_v4(),
        owner_id,
        peer_jid: "bob@example.com",
        stanza: "<message id='action-1'><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
        encrypted: false,
        stanza_id: Some("action-1"),
    }];
    let invocation = PersonalRetractionInvocation {
        owners: &owners,
        sender_jid: "alice@example.com",
        command: cmd,
        action_writes: &writes,
        delivery: None,
        outbound: None,
    };
    assert_eq!(invocation.owners.len(), 1);
    assert_eq!(invocation.sender_jid, "alice@example.com");
    assert_eq!(invocation.command.target_id, "target-1");
    assert_eq!(invocation.action_writes.len(), 1);
    assert!(invocation.delivery.is_none());
    assert!(invocation.outbound.is_none());
}
