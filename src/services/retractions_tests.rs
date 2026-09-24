use super::*;
use crate::db;
use sqlx::PgPool;

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
            assert!(crate::abuse::test_personal_retraction_content_keyring()
                .authenticators(&prepared.canonical_semantics)
                .verifies(primary.key_id(), primary.mac()));
            anyhow::bail!("injected repository unavailable")
        }
    }

    let service = RetractionService::new(
        UnavailableRepository(AtomicUsize::new(0)),
        crate::abuse::test_personal_retraction_content_keyring(),
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
fn owner_lookup_uses_peer_and_stanza_buckets_with_exists_collision_probe() {
    let migration = include_str!("../../migrations/0119_personal_retraction_owner_identity.sql");
    let source = include_str!("../db/retractions.rs");
    assert!(migration.contains("pg_catalog.md5(peer_jid)"));
    assert!(migration.contains("pg_catalog.md5(stanza_id)"));
    assert!(source.contains("pg_catalog.md5(peer_jid)=pg_catalog.md5($2::TEXT)"));
    assert!(source.contains("SELECT EXISTS("));
    assert!(!source.contains("SELECT COUNT(*) FROM message_archive\n                  WHERE owner_id=$1\n                    AND pg_catalog.md5(stanza_id)"));
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

async fn isolated_pool() -> (PgPool, PgPool, String) {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to the xmpp_test PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("retraction_service_test_{}", Uuid::new_v4().simple());
    eprintln!("isolated_schema={schema}");
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(60))
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    (admin, pool, schema)
}

async fn archive_original(pool: &PgPool, owner_id: Uuid, id: Uuid, stable_id: &str) {
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
         VALUES($1,$2,'bob@local.test','bob@local.test/Phone',$3,FALSE,$4)",
    )
    .bind(id)
    .bind(owner_id)
    .bind(format!(
        "<message from='alice@local.test/Laptop' to='bob@local.test/Phone' id='{stable_id}'><body>must remain private</body></message>"
    ))
    .bind(stable_id)
    .execute(pool)
    .await
    .unwrap();
}

fn action_write<'a>(
    id: Uuid,
    owner_id: Uuid,
    stanza: &'a str,
    action_id: &'a str,
) -> ArchiveWrite<'a> {
    ArchiveWrite {
        id,
        owner_id,
        peer_jid: "bob@local.test/Phone",
        stanza,
        encrypted: false,
        stanza_id: Some(action_id),
    }
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn c2s_projection_is_atomic_idempotent_and_retains_replay_intent() {
    let (admin, pool, schema) = isolated_pool().await;
    let owner_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'alice','test')")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
    let other_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'bob','test')")
        .bind(other_id)
        .execute(&pool)
        .await
        .unwrap();
    let service = RetractionService::new(
        crate::db::retractions::PostgresRetractionRepository::new(pool.clone()),
        crate::abuse::test_personal_retraction_content_keyring(),
        "local.test",
    );
    let owners = [OwnerProjection {
        owner_id,
        peer_jid: "alice@local.test/Phone",
    }];

    let target_row = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
         VALUES($1,$2,'alice@local.test','alice@local.test/Phone',$3,FALSE,'delivery-target')",
    )
    .bind(target_row)
    .bind(owner_id)
    .bind("<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='delivery-target'><body>must remain private</body></message>")
    .execute(&pool)
    .await
    .unwrap();
    let action = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='delivery-action'><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>";
    let command = RetractionCommand {
        target_id: "delivery-target",
        action_id: "delivery-action",
        semantic_payload: action,
    };
    let action_rows = [ArchiveWrite {
        id: Uuid::new_v4(),
        owner_id,
        peer_jid: "alice@local.test/Phone",
        stanza: action,
        encrypted: false,
        stanza_id: Some(command.action_id),
    }];
    let delivery_id = Uuid::new_v4();
    let delivery = DeliveryProjection {
        id: delivery_id,
        recipient_id: owner_id,
        local_actor_id: Some(owner_id),
        sender_jid: "alice@local.test/Laptop",
        stanza: action,
        encrypted: false,
        max_messages: 100,
        max_bytes: 1_000_000,
        ttl_days: 30,
        mam_backed: true,
    };
    assert_eq!(
        service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Laptop",
                &command,
                &action_rows,
                Some(&delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied { tombstones: 1 }
    );
    let committed: (i64, i64, i64, bool, Option<Uuid>) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM message_archive WHERE id=$1 AND stanza LIKE '%retracted%'),
           (SELECT COUNT(*) FROM message_archive WHERE stanza_id='delivery-action'),
           (SELECT COUNT(*) FROM offline_messages WHERE id=$2),
           intent.c2s_delivery_requested,intent.c2s_delivery_id
         FROM personal_retraction_intents intent
         WHERE intent.action_id='delivery-action'",
    )
    .bind(target_row)
    .bind(delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(committed, (1, 1, 1, true, Some(delivery_id)));
    assert!(sqlx::query(
        "UPDATE personal_retraction_intents
            SET c2s_projection_mac=decode(repeat('aa',32),'hex')
          WHERE action_id='delivery-action'",
    )
    .execute(&pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "UPDATE personal_retraction_intents
            SET owner_projection_mac=decode(repeat('bb',32),'hex')
          WHERE action_id='delivery-action'",
    )
    .execute(&pool)
    .await
    .is_err());

    let replay_delivery = DeliveryProjection {
        id: Uuid::new_v4(),
        ..delivery
    };
    assert_eq!(
        service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Other",
                &command,
                &action_rows,
                Some(&replay_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Replay
    );
    let delivery_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(delivery_count, 1, "exact replay must not fan out twice");
    let changed_action_archive = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='delivery-action'><body>changed fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>";
    sqlx::query(
        "UPDATE message_archive SET stanza=$1
          WHERE owner_id=$2 AND stanza_id='delivery-action'",
    )
    .bind(changed_action_archive)
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Other",
                &command,
                &action_rows,
                Some(&replay_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Conflict,
        "a syntactically valid but changed action archive must fail closed"
    );
    sqlx::query(
        "UPDATE message_archive SET stanza=$1
          WHERE owner_id=$2 AND stanza_id='delivery-action'",
    )
    .bind(action)
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE message_archive SET encrypted=TRUE
          WHERE owner_id=$1 AND stanza_id='delivery-action'",
    )
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Other",
                &command,
                &action_rows,
                Some(&replay_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Conflict,
        "the stored encrypted flag must agree with both XML and authenticated action"
    );
    sqlx::query(
        "UPDATE message_archive SET encrypted=FALSE
          WHERE owner_id=$1 AND stanza_id='delivery-action'",
    )
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();
    let changed_recipient_stanza = "<message from='alice@local.test/Laptop' to='alice@local.test/Tablet' id='delivery-action'><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>";
    let changed_recipient_delivery = DeliveryProjection {
        id: Uuid::new_v4(),
        stanza: changed_recipient_stanza,
        ..delivery
    };
    assert_eq!(
        service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Laptop",
                &command,
                &action_rows,
                Some(&changed_recipient_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Conflict,
        "changing the canonical delivery target must conflict before fanout"
    );
    let swapped_owners = [
        OwnerProjection {
            owner_id,
            peer_jid: "bob@local.test/Phone",
        },
        OwnerProjection {
            owner_id: other_id,
            peer_jid: "alice@local.test/Laptop",
        },
    ];
    let swapped_stanza = "<message from='alice@local.test/Laptop' to='bob@local.test/Phone' id='delivery-action'><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>";
    let swapped_delivery = DeliveryProjection {
        id: Uuid::new_v4(),
        recipient_id: other_id,
        local_actor_id: Some(owner_id),
        stanza: swapped_stanza,
        mam_backed: false,
        ..delivery
    };
    assert_eq!(
        service
            .apply_with_delivery(
                &swapped_owners,
                "alice@local.test/Laptop",
                &command,
                &[],
                Some(&swapped_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Conflict,
        "a retry cannot swap the recipient owner projection"
    );
    let forged_owners = [OwnerProjection {
        owner_id,
        peer_jid: "mallory@local.test/Phone",
    }];
    assert!(service
        .apply_with_delivery(
            &forged_owners,
            "alice@local.test/Laptop",
            &command,
            &[],
            Some(&replay_delivery),
            None,
        )
        .await
        .is_err());
    let missing_owner_delivery = DeliveryProjection {
        id: Uuid::new_v4(),
        recipient_id: Uuid::new_v4(),
        mam_backed: false,
        ..delivery
    };
    assert_eq!(
        service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Laptop",
                &command,
                &[],
                Some(&missing_owner_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::AccountUnavailable
    );
    let changed = RetractionCommand {
        semantic_payload: "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='delivery-action'><body>changed</body><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>",
        ..command
    };
    let changed_payload_rows = [ArchiveWrite {
        stanza: changed.semantic_payload,
        ..action_rows[0]
    }];
    let changed_payload_delivery = DeliveryProjection {
        id: Uuid::new_v4(),
        stanza: changed.semantic_payload,
        ..delivery
    };
    assert_eq!(
        service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Laptop",
                &changed,
                &changed_payload_rows,
                Some(&changed_payload_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Conflict
    );

    sqlx::query(
        "UPDATE personal_retraction_intents
            SET expires_at=clock_timestamp()-INTERVAL '1 day'
          WHERE action_id='delivery-action'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        db::purge_expired_retraction_intents(&pool, 10)
            .await
            .unwrap(),
        0
    );
    sqlx::query("DELETE FROM offline_messages WHERE id=$1")
        .bind(delivery_id)
        .execute(&pool)
        .await
        .unwrap();
    let cleared: (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT c2s_delivery_requested,c2s_delivery_id
           FROM personal_retraction_intents WHERE action_id='delivery-action'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cleared, (true, None));
    assert_eq!(
        db::purge_expired_retraction_intents(&pool, 10)
            .await
            .unwrap(),
        1
    );

    let capacity_target = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
         VALUES($1,$2,'alice@local.test','alice@local.test/Phone',$3,FALSE,'capacity-target')",
    )
    .bind(capacity_target)
    .bind(owner_id)
    .bind("<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='capacity-target'><body>must remain private</body></message>")
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,mam_backed)
         VALUES($1,$2,'seed@local.test','<message/>',FALSE,FALSE)",
    )
    .bind(Uuid::new_v4())
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();
    let capacity_action = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='capacity-action'><retract xmlns='urn:xmpp:message-retract:1' id='capacity-target'/></message>";
    let capacity_command = RetractionCommand {
        target_id: "capacity-target",
        action_id: "capacity-action",
        semantic_payload: capacity_action,
    };
    let capacity_delivery = DeliveryProjection {
        id: Uuid::new_v4(),
        recipient_id: owner_id,
        local_actor_id: Some(owner_id),
        sender_jid: "alice@local.test/Laptop",
        stanza: capacity_action,
        encrypted: false,
        max_messages: 1,
        max_bytes: 1_000_000,
        ttl_days: 30,
        mam_backed: false,
    };
    assert_eq!(
        service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Laptop",
                &capacity_command,
                &[],
                Some(&capacity_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::CapacityExceeded
    );
    let capacity_rollback: (String, i64) = sqlx::query_as(
        "SELECT
           (SELECT stanza FROM message_archive WHERE id=$1),
           (SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id='capacity-action')",
    )
    .bind(capacity_target)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(capacity_rollback.0.contains("must remain private"));
    assert_eq!(capacity_rollback.1, 0);

    let forbidden_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
         VALUES($1,$2,'alice@local.test','alice@local.test/Phone',$3,FALSE,'foreign-target')",
    )
    .bind(forbidden_id)
    .bind(owner_id)
    .bind("<message from='mallory@local.test/Phone' id='foreign-target'><body>foreign</body></message>")
    .execute(&pool)
    .await
    .unwrap();
    let forbidden_action = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='forbidden-action'><retract xmlns='urn:xmpp:message-retract:1' id='foreign-target'/></message>";
    let forbidden_command = RetractionCommand {
        target_id: "foreign-target",
        action_id: "forbidden-action",
        semantic_payload: forbidden_action,
    };
    let forbidden_delivery = DeliveryProjection {
        id: Uuid::new_v4(),
        stanza: forbidden_action,
        max_messages: 100,
        ..capacity_delivery
    };
    assert_eq!(
        service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Laptop",
                &forbidden_command,
                &[],
                Some(&forbidden_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Forbidden
    );
    let forbidden_projection: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(forbidden_delivery.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(forbidden_projection, 0);

    sqlx::query("DELETE FROM offline_messages")
        .execute(&pool)
        .await
        .unwrap();
    let failure_target = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
         VALUES($1,$2,'alice@local.test','alice@local.test/Phone',$3,FALSE,'failure-target')",
    )
    .bind(failure_target)
    .bind(owner_id)
    .bind("<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='failure-target'><body>must remain private</body></message>")
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE FUNCTION reject_retraction_delivery() RETURNS TRIGGER AS $$
         BEGIN RAISE EXCEPTION 'injected delivery failure'; END
         $$ LANGUAGE plpgsql",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_retraction_delivery AFTER INSERT ON offline_messages
         FOR EACH ROW EXECUTE FUNCTION reject_retraction_delivery()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let failure_action = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='failure-action'><retract xmlns='urn:xmpp:message-retract:1' id='failure-target'/></message>";
    let failure_command = RetractionCommand {
        target_id: "failure-target",
        action_id: "failure-action",
        semantic_payload: failure_action,
    };
    let failure_delivery = DeliveryProjection {
        id: Uuid::new_v4(),
        stanza: failure_action,
        max_messages: 100,
        ..capacity_delivery
    };
    assert!(service
        .apply_with_delivery(
            &owners,
            "alice@local.test/Laptop",
            &failure_command,
            &[],
            Some(&failure_delivery),
            None,
        )
        .await
        .is_err());
    let failure_rollback: (String, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT stanza FROM message_archive WHERE id=$1),
           (SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id='failure-action'),
           (SELECT COUNT(*) FROM offline_messages WHERE id=$2)",
    )
    .bind(failure_target)
    .bind(failure_delivery.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(failure_rollback.0.contains("must remain private"));
    assert_eq!((failure_rollback.1, failure_rollback.2), (0, 0));

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn exact_replay_conflict_and_outbox_failure_are_atomic() {
    let (admin, pool, schema) = isolated_pool().await;
    let owner_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'alice','test')")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();

    let service = RetractionService::new(
        crate::db::retractions::PostgresRetractionRepository::new(pool.clone()),
        crate::abuse::test_personal_retraction_content_keyring(),
        "local.test",
    );
    let owners = [OwnerProjection {
        owner_id,
        peer_jid: "bob@local.test/Phone",
    }];
    let outbound_owners = [OwnerProjection {
        owner_id,
        peer_jid: "bob@remote.test/Phone",
    }];
    let target_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
         VALUES($1,$2,'bob@remote.test','bob@remote.test/Phone',$3,FALSE,'target-1')",
    )
    .bind(target_id)
    .bind(owner_id)
    .bind("<message from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='target-1'><body>must remain private</body></message>")
    .execute(&pool)
    .await
    .unwrap();

    let accepted = "<message from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>";
    let archived = "<message xmlns='jabber:client' from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/><stanza-id xmlns='urn:xmpp:sid:0' by='local.test' id='server-one'/></message>";
    let command = RetractionCommand {
        target_id: "target-1",
        action_id: "action-1",
        semantic_payload: accepted,
    };
    let writes = [ArchiveWrite {
        id: Uuid::new_v4(),
        owner_id,
        peer_jid: "bob@remote.test/Phone",
        stanza: archived,
        encrypted: false,
        stanza_id: Some(command.action_id),
    }];
    let outbox = OutboundProjection {
        target_domain: "remote.test",
        stanza: "<message from='alice@local.test' to='bob@remote.test' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
        bounce_to: Some("alice@local.test/Laptop"),
        policy: FederationOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 100,
            max_bytes: 1_000_000,
            max_per_domain: 100,
        },
    };
    assert_eq!(
        service
            .apply(
                &outbound_owners,
                "alice@local.test/Laptop",
                &command,
                &writes,
                Some(&outbox),
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied { tombstones: 1 }
    );

    assert_eq!(
        service
            .apply(
                &outbound_owners,
                "alice@local.test/Laptop",
                &command,
                &[],
                Some(&outbox),
            )
            .await
            .unwrap(),
        RetractionOutcome::Replay,
        "disabling MAM after admission must not change replay identity"
    );

    let replay_archive = "<message xmlns='jabber:client' from='alice@local.test/Other' to='bob@remote.test/Tablet' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/><stanza-id xmlns='urn:xmpp:sid:0' by='local.test' id='server-two'/></message>";
    let replay_writes = [ArchiveWrite {
        id: Uuid::new_v4(),
        owner_id,
        peer_jid: "bob@remote.test/Tablet",
        stanza: replay_archive,
        encrypted: false,
        stanza_id: Some(command.action_id),
    }];
    assert_eq!(
        service
            .apply(
                &outbound_owners,
                "alice@local.test/Other",
                &command,
                &replay_writes,
                Some(&outbox),
            )
            .await
            .unwrap(),
        RetractionOutcome::Replay
    );
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM message_archive WHERE owner_id=$1 AND stanza_id='action-1'),
           (SELECT COUNT(*) FROM s2s_outbox)",
    )
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        counts,
        (1, 1),
        "exact replay must not duplicate projections"
    );

    let changed_payload = RetractionCommand {
        semantic_payload: "<message from='alice@local.test/Laptop' id='action-1'><body>changed fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
        ..command
    };
    let changed_payload_outbox = OutboundProjection {
        stanza: "<message from='alice@local.test' to='bob@remote.test' id='action-1'><body>changed fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
        ..outbox
    };
    assert_eq!(
        service
            .apply(
                &outbound_owners,
                "alice@local.test/Laptop",
                &changed_payload,
                &[],
                Some(&changed_payload_outbox),
            )
            .await
            .unwrap(),
        RetractionOutcome::Conflict
    );
    let changed_target = RetractionCommand {
        target_id: "different-target",
        semantic_payload: "<message from='alice@local.test/Laptop' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='different-target'/></message>",
        ..command
    };
    let changed_target_outbox = OutboundProjection {
        stanza: "<message from='alice@local.test' to='bob@remote.test' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='different-target'/></message>",
        ..outbox
    };
    assert_eq!(
        service
            .apply(
                &outbound_owners,
                "alice@local.test/Laptop",
                &changed_target,
                &[],
                Some(&changed_target_outbox),
            )
            .await
            .unwrap(),
        RetractionOutcome::Conflict
    );

    // Archiving may be disabled by policy. The independent intent row is
    // still the replay authority, so a tombstone never has to stand in for
    // the omitted action archive.
    let zero_target_id = Uuid::new_v4();
    archive_original(&pool, owner_id, zero_target_id, "zero-target").await;
    let zero_action = "<message from='alice@local.test/Laptop' id='zero-action'><body>private fallback must not be stored</body><retract xmlns='urn:xmpp:message-retract:1' id='zero-target'/></message>";
    let zero_command = RetractionCommand {
        target_id: "zero-target",
        action_id: "zero-action",
        semantic_payload: zero_action,
    };
    assert_eq!(
        service
            .apply(&owners, "alice@local.test/Laptop", &zero_command, &[], None,)
            .await
            .unwrap(),
        RetractionOutcome::Applied { tombstones: 1 }
    );
    // Emulate a row created by 0102 before keyed commitments existed.
    // The first exact replay must upgrade it and commit that upgrade even
    // though no message/outbox projection is added.
    let legacy_zero_semantic = canonical_retraction_semantics(
        zero_action,
        "alice@local.test",
        zero_command.action_id,
        zero_command.target_id,
    )
    .unwrap();
    sqlx::query(
        "UPDATE personal_retraction_intents
            SET semantic_key_id=NULL,semantic_mac=NULL,
                semantic_sha256=$2,semantic_sha512=$3,semantic_length=$4
          WHERE action_id=$1",
    )
    .bind(zero_command.action_id)
    .bind(Sha256::digest(&legacy_zero_semantic).to_vec())
    .bind(Sha512::digest(&legacy_zero_semantic).to_vec())
    .bind(i64::try_from(legacy_zero_semantic.len()).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    let newly_enabled_write = [action_write(
        Uuid::new_v4(),
        owner_id,
        zero_action,
        zero_command.action_id,
    )];
    assert_eq!(
        service
            .apply(
                &owners,
                "alice@local.test/Laptop",
                &zero_command,
                &newly_enabled_write,
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Replay,
        "enabling MAM after a zero-write admission must not add a projection"
    );
    type RetractionEvidenceColumns = (
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
    );
    let upgraded_zero_evidence: RetractionEvidenceColumns = sqlx::query_as(
        "SELECT semantic_key_id,semantic_mac,semantic_sha256,semantic_sha512,semantic_length
           FROM personal_retraction_intents WHERE action_id='zero-action'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(upgraded_zero_evidence.0.is_some());
    assert_eq!(
        upgraded_zero_evidence.1.as_deref().map(<[u8]>::len),
        Some(32)
    );
    assert_eq!(
        (
            upgraded_zero_evidence.2,
            upgraded_zero_evidence.3,
            upgraded_zero_evidence.4
        ),
        (None, None, None),
        "legacy unkeyed evidence must be irreversibly removed after upgrade"
    );

    // Rows created before 0119 cannot be proactively re-keyed without
    // recovering peer topology. An authorized exact replay supplies that
    // topology and performs the only owner-identity transition permitted
    // by the immutable database fence.
    let legacy_owner_action = "<message from='alice@local.test/Laptop' id='legacy-owner-action'><retract xmlns='urn:xmpp:message-retract:1' id='legacy-owner-target'/></message>";
    let legacy_owner_command = RetractionCommand {
        target_id: "legacy-owner-target",
        action_id: "legacy-owner-action",
        semantic_payload: legacy_owner_action,
    };
    let legacy_owner_semantics = canonical_retraction_semantics(
        legacy_owner_action,
        "alice@local.test",
        legacy_owner_command.action_id,
        legacy_owner_command.target_id,
    )
    .unwrap();
    let semantic_authenticators = service
        .content_identity
        .authenticators(&legacy_owner_semantics);
    let semantic_primary = semantic_authenticators.primary();
    let normalized_legacy_owners = [NormalizedOwner {
        owner_id,
        peer_bare_jid: "bob@local.test".to_owned(),
    }];
    let legacy_owner_value = canonical_owner_projection(&normalized_legacy_owners);
    let legacy_owner_intent_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO personal_retraction_intents(
             id,sender_bare_jid,action_id,action_digest,target_id,
             semantic_key_id,semantic_mac,
             owner_projection_sha256,owner_projection_sha512,
             owner_projection_length,outbound_requested)
         VALUES($1,'alice@local.test',$2,$3,$4,$5,$6,$7,$8,$9,FALSE)",
    )
    .bind(legacy_owner_intent_id)
    .bind(legacy_owner_command.action_id)
    .bind(bounded_action_digest(legacy_owner_command.action_id).to_vec())
    .bind(legacy_owner_command.target_id)
    .bind(semantic_primary.key_id())
    .bind(semantic_primary.mac().as_slice())
    .bind(Sha256::digest(&legacy_owner_value).to_vec())
    .bind(Sha512::digest(&legacy_owner_value).to_vec())
    .bind(i64::try_from(legacy_owner_value.len()).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        service
            .apply(
                &owners,
                "alice@local.test/Other",
                &legacy_owner_command,
                &[],
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Replay
    );
    type OwnerEvidenceColumns = (
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
    );
    let upgraded_owner_evidence: OwnerEvidenceColumns = sqlx::query_as(
        "SELECT owner_projection_key_id,owner_projection_mac,
                owner_projection_sha256,owner_projection_sha512,
                owner_projection_length
           FROM personal_retraction_intents WHERE id=$1",
    )
    .bind(legacy_owner_intent_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(upgraded_owner_evidence.0.is_some());
    assert_eq!(
        upgraded_owner_evidence.1.as_deref().map(<[u8]>::len),
        Some(32)
    );
    assert_eq!(
        (
            upgraded_owner_evidence.2,
            upgraded_owner_evidence.3,
            upgraded_owner_evidence.4
        ),
        (None, None, None)
    );
    let unexpected_zero_projection: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM message_archive WHERE owner_id=$1 AND stanza_id='zero-action'",
    )
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unexpected_zero_projection, 0);
    let zero_replay = RetractionCommand {
        semantic_payload: "<message from='alice@local.test/Other' id='zero-action'><body>private fallback must not be stored</body><retract xmlns='urn:xmpp:message-retract:1' id='zero-target'/><stanza-id xmlns='urn:xmpp:sid:0' by='local.test' id='ignored-server-id'/></message>",
        ..zero_command
    };
    assert_eq!(
        service
            .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
            .await
            .unwrap(),
        RetractionOutcome::Replay
    );
    let zero_changed_payload = RetractionCommand {
        semantic_payload: "<message from='alice@local.test/Laptop' id='zero-action'><body>changed private fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='zero-target'/></message>",
        ..zero_command
    };
    assert_eq!(
        service
            .apply(
                &owners,
                "alice@local.test/Laptop",
                &zero_changed_payload,
                &[],
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Conflict
    );
    let zero_changed_target = RetractionCommand {
        target_id: "changed-zero-target",
        semantic_payload: "<message from='alice@local.test/Laptop' id='zero-action'><body>private fallback must not be stored</body><retract xmlns='urn:xmpp:message-retract:1' id='changed-zero-target'/></message>",
        ..zero_command
    };
    assert_eq!(
        service
            .apply(
                &owners,
                "alice@local.test/Laptop",
                &zero_changed_target,
                &[],
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Conflict
    );
    sqlx::query(
        "UPDATE personal_retraction_intents
            SET semantic_mac=decode(repeat('cc',32),'hex')
          WHERE action_id='zero-action'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        service
            .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
            .await
            .unwrap(),
        RetractionOutcome::Conflict,
        "a known key ID with a changed semantic MAC must fail closed"
    );
    sqlx::query(
        "UPDATE personal_retraction_intents
            SET semantic_key_id=NULL,semantic_mac=NULL,
                semantic_sha256=$2,semantic_sha512=$3,semantic_length=$4
          WHERE action_id=$1",
    )
    .bind(zero_command.action_id)
    .bind(Sha256::digest(&legacy_zero_semantic).to_vec())
    .bind(Sha512::digest(&legacy_zero_semantic).to_vec())
    .bind(i64::try_from(legacy_zero_semantic.len()).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        service
            .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
            .await
            .unwrap(),
        RetractionOutcome::Replay
    );
    sqlx::query(
        "UPDATE personal_retraction_intents
            SET semantic_key_id='BBBBBBBBBBBBBBBB'
          WHERE action_id='zero-action'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        service
            .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
            .await
            .unwrap(),
        RetractionOutcome::Conflict,
        "an unknown content-key generation must fail closed"
    );
    assert!(
        sqlx::query(
            "UPDATE personal_retraction_intents
            SET semantic_key_id=NULL,semantic_sha256=NULL
          WHERE action_id='zero-action'",
        )
        .execute(&pool)
        .await
        .is_err(),
        "partial retraction evidence must fail the database constraint"
    );
    sqlx::query(
        "UPDATE personal_retraction_intents
            SET semantic_key_id=NULL,semantic_mac=NULL,
                semantic_sha256=$2,semantic_sha512=$3,semantic_length=$4
          WHERE action_id=$1",
    )
    .bind(zero_command.action_id)
    .bind(Sha256::digest(&legacy_zero_semantic).to_vec())
    .bind(Sha512::digest(&legacy_zero_semantic).to_vec())
    .bind(i64::try_from(legacy_zero_semantic.len()).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        service
            .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
            .await
            .unwrap(),
        RetractionOutcome::Replay
    );
    let plaintext_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
          WHERE table_schema=current_schema()
            AND table_name='personal_retraction_intents'
            AND column_name IN ('semantic_value','payload_value','stanza')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        plaintext_columns, 0,
        "intent evidence must never retain fallback XML"
    );
    let plaintext_row_marker: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM personal_retraction_intents AS intent
          WHERE row_to_json(intent)::TEXT LIKE '%private fallback must not be stored%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        plaintext_row_marker, 0,
        "a database dump of retraction intents must not contain fallback plaintext"
    );
    sqlx::query(
        "UPDATE personal_retraction_intents
            SET expires_at=clock_timestamp()-INTERVAL '1 day'
          WHERE action_id IN ('action-1','zero-action')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        db::purge_expired_retraction_intents(&pool, 10)
            .await
            .unwrap(),
        1
    );
    let retained_outbox_intent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id='action-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        retained_outbox_intent, 1,
        "expiry must not delete evidence while its durable outbox is pending"
    );

    // A two-owner replay is complete only when every expected action
    // archive projection exists. One surviving projection is a conflict,
    // never a successful replay.
    let second_owner_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'bob','test')")
        .bind(second_owner_id)
        .execute(&pool)
        .await
        .unwrap();
    let partial_targets = [Uuid::new_v4(), Uuid::new_v4()];
    for (id, owner, peer, full_peer) in [
        (
            partial_targets[0],
            owner_id,
            "bob@local.test",
            "bob@local.test/Phone",
        ),
        (
            partial_targets[1],
            second_owner_id,
            "alice@local.test",
            "alice@local.test/Laptop",
        ),
    ] {
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,$3,$4,$5,FALSE,'partial-target')",
        )
        .bind(id)
        .bind(owner)
        .bind(peer)
        .bind(full_peer)
        .bind("<message from='alice@local.test/Laptop' to='bob@local.test/Phone' id='partial-target'><body>two copies</body></message>")
        .execute(&pool)
        .await
        .unwrap();
    }
    let partial_owners = [
        OwnerProjection {
            owner_id,
            peer_jid: "bob@local.test/Phone",
        },
        OwnerProjection {
            owner_id: second_owner_id,
            peer_jid: "alice@local.test/Laptop",
        },
    ];
    let partial_action = "<message from='alice@local.test/Laptop' id='partial-action'><retract xmlns='urn:xmpp:message-retract:1' id='partial-target'/></message>";
    let partial_command = RetractionCommand {
        target_id: "partial-target",
        action_id: "partial-action",
        semantic_payload: partial_action,
    };
    let partial_action_ids = [Uuid::new_v4(), Uuid::new_v4()];
    let partial_writes = [
        ArchiveWrite {
            id: partial_action_ids[0],
            owner_id,
            peer_jid: "bob@local.test/Phone",
            stanza: partial_action,
            encrypted: false,
            stanza_id: Some("partial-action"),
        },
        ArchiveWrite {
            id: partial_action_ids[1],
            owner_id: second_owner_id,
            peer_jid: "alice@local.test/Laptop",
            stanza: partial_action,
            encrypted: false,
            stanza_id: Some("partial-action"),
        },
    ];
    assert_eq!(
        service
            .apply(
                &partial_owners,
                "alice@local.test/Laptop",
                &partial_command,
                &partial_writes,
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied { tombstones: 2 }
    );
    assert_eq!(
        service
            .apply(
                &partial_owners,
                "alice@local.test/Laptop",
                &partial_command,
                &[],
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Replay,
        "a two-write admission remains a replay after the current plan changes to zero"
    );
    sqlx::query("DELETE FROM message_archive WHERE id=$1")
        .bind(partial_action_ids[1])
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        service
            .apply(
                &partial_owners,
                "alice@local.test/Laptop",
                &partial_command,
                &[],
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Replay,
        "legitimate MAM retention may clear archive_id without changing the keyed replay plan"
    );

    let rollback_target_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
         VALUES($1,$2,'bob@remote.test','bob@remote.test/Phone',$3,FALSE,'rollback-target')",
    )
    .bind(rollback_target_id)
    .bind(owner_id)
    .bind("<message from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='rollback-target'><body>must remain private</body></message>")
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE FUNCTION reject_retraction_outbox() RETURNS TRIGGER AS $$
         BEGIN RAISE EXCEPTION 'injected outbox failure'; END
         $$ LANGUAGE plpgsql",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_retraction_outbox
         AFTER INSERT ON s2s_outbox
         FOR EACH ROW EXECUTE FUNCTION reject_retraction_outbox()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let rollback_action = "<message from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-target'/></message>";
    let rollback_command = RetractionCommand {
        target_id: "rollback-target",
        action_id: "rollback-action",
        semantic_payload: rollback_action,
    };
    let rollback_writes = [ArchiveWrite {
        id: Uuid::new_v4(),
        owner_id,
        peer_jid: "bob@remote.test/Phone",
        stanza: rollback_action,
        encrypted: false,
        stanza_id: Some(rollback_command.action_id),
    }];
    let rollback_outbox = OutboundProjection {
        stanza: "<message from='alice@local.test' to='bob@remote.test' id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-target'/></message>",
        ..outbox
    };
    assert!(service
        .apply(
            &outbound_owners,
            "alice@local.test/Laptop",
            &rollback_command,
            &rollback_writes,
            Some(&rollback_outbox),
        )
        .await
        .is_err());
    let rollback_stanza: String =
        sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=$1")
            .bind(rollback_target_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(rollback_stanza.contains("must remain private"));
    let rollback_counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM message_archive WHERE owner_id=$1 AND stanza_id='rollback-action'),
           (SELECT COUNT(*) FROM s2s_outbox),
           (SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id='rollback-action')",
    )
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        rollback_counts,
        (0, 1, 0),
        "failed transaction must preserve the original and roll back intent/action/outbox projections"
    );

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
