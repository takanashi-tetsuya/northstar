use northstar_message_application::retractions::{
    ArchiveWrite, DeliveryProjection, OwnerProjection, RetractionCommand, RetractionOutcome,
    RetractionService,
};
use roxmltree::Document;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn message_acceptance_boundary_prevents_mam_retraction_and_offline_ghosts() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("message_acceptance_test_{}", uuid::Uuid::new_v4().simple());
    eprintln!("isolated_schema={schema}");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    northstar_workflows::identity_migration::migrate_for_tests(&pool)
        .await
        .unwrap();

    let recipient_id = uuid::Uuid::new_v4();
    let sender_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO users(id, username, password_hash) VALUES($1, 'bob', 'test-only'), ($2, 'alice', 'test-only')")
        .bind(recipient_id)
        .bind(sender_id)
        .execute(&pool)
        .await
        .unwrap();
    let persisted_subscribe = "<presence xmlns='jabber:client' from='alice@remote.test' to='bob@local.test' type='subscribe'><status>hello</status></presence>";
    northstar_roster_postgres::roster::add_federated_presence_pending_with_stanza(
        &pool,
        recipient_id,
        "alice@remote.test",
        Some(persisted_subscribe),
    )
    .await
    .unwrap();
    let oversized_subscription = "x".repeat(65_537);
    assert!(
        northstar_roster_postgres::roster::add_federated_presence_pending_with_stanza(
            &pool,
            recipient_id,
            "mallory@remote.test",
            Some(&oversized_subscription),
        )
        .await
        .is_err()
    );
    let pending_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM federated_presence_pending")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending_rows, 1);
    let retained_subscription: String = sqlx::query_scalar(
        "SELECT stanza FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid='alice@remote.test'",
    )
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retained_subscription, persisted_subscribe);
    northstar_archive_postgres::archive_message(
        &pool,
        uuid::Uuid::new_v4(),
        recipient_id,
        "alice@remote.test/Phone",
        "<message from='alice@remote.test/Phone' to='bob@local.test' id='remote-original'><body>recipient original</body></message>",
        false,
        Some("remote-original"),
    )
    .await
    .unwrap();
    northstar_archive_postgres::archive_message(
        &pool,
        uuid::Uuid::new_v4(),
        sender_id,
        "carol@remote.test/Laptop",
        "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='outbound-original'><body>sender original</body></message>",
        false,
        Some("outbound-original"),
    )
    .await
    .unwrap();

    use northstar_message_core::{undelivered_disposition, UndeliveredDisposition};
    assert_eq!(
        undelivered_disposition("headline", true, true),
        UndeliveredDisposition::Drop
    );
    assert_eq!(
        undelivered_disposition("chat", false, true),
        UndeliveredDisposition::Drop
    );
    assert_eq!(
        undelivered_disposition("normal", true, false),
        UndeliveredDisposition::RejectWait
    );
    assert_eq!(
        undelivered_disposition("groupchat", true, true),
        UndeliveredDisposition::RejectCancel
    );

    sqlx::query("INSERT INTO offline_messages(id, recipient_id, sender_jid, stanza, encrypted) VALUES($1, $2, 'seed@remote.test', '<message/>', FALSE)")
        .bind(uuid::Uuid::new_v4())
        .bind(recipient_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        northstar_message_postgres::offline::store_offline(
            &pool,
            recipient_id,
            "alice@remote.test/Phone",
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>",
            false,
            northstar_message_postgres::offline::OfflineStorePolicy {
                max_messages: 1,
                max_bytes: 1_000_000,
                ttl_days: 30,
                mam_backed: false,
            },
        )
        .await
        .unwrap(),
        northstar_message_postgres::offline::OfflineStoreOutcome::QuotaExceeded
    );
    assert!(northstar_federation_postgres::enqueue_s2s_outbox(
        &pool,
        "remote.test",
        "<message from='alice@local.test' to='carol@remote.test'/>",
        Some("alice@local.test/Phone"),
        300,
        0,
        1_000_000,
        100,
    )
    .await
    .is_err());
    let rejected_archive_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_archive")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejected_archive_count, 2);
    let recipient_original: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='remote-original'",
    )
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(recipient_original.contains("recipient original"));
    let sender_original: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='outbound-original'",
    )
    .bind(sender_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(sender_original.contains("sender original"));
    let rejected_offline_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejected_offline_count, 1);

    let online_retraction = Document::parse(
        "<message id='online-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>",
    )
    .unwrap();
    let online_stable_id = uuid::Uuid::new_v4();
    let retraction_service = RetractionService::new(
        northstar_workflows::retraction_repository::PostgresRetractionRepository::new(pool.clone()),
        northstar_abuse_application::guard::test_personal_retraction_content_keyring(),
        "local.test",
    );
    let online_action = "<message from='alice@remote.test/Phone' to='bob@local.test' id='online-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>";
    let online_command = northstar_message_core::retraction::personal_retraction_command(
        online_retraction.root_element(),
    )
    .unwrap()
    .unwrap();
    let online_writes = [ArchiveWrite {
        id: online_stable_id,
        owner_id: recipient_id,
        peer_jid: "alice@remote.test/Phone",
        stanza: online_action,
        encrypted: false,
        stanza_id: Some("online-retraction"),
    }];
    let online_delivery = DeliveryProjection {
        id: online_stable_id,
        recipient_id,
        local_actor_id: None,
        sender_jid: "alice@remote.test/Phone",
        stanza: online_action,
        encrypted: false,
        max_messages: 100,
        max_bytes: 1_000_000,
        ttl_days: 30,
        mam_backed: true,
    };
    assert_eq!(
        retraction_service
            .apply_with_delivery(
                &[OwnerProjection {
                    owner_id: recipient_id,
                    peer_jid: "alice@remote.test/Phone",
                }],
                "alice@remote.test/Phone",
                &RetractionCommand {
                    target_id: &online_command.target_id,
                    action_id: &online_command.action_id,
                    semantic_payload: &online_command.semantic_payload,
                },
                &online_writes,
                Some(&online_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied {
            tombstones: 1,
            live_claim_id: None,
        }
    );
    let tombstone: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='remote-original'",
    )
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(tombstone.contains("urn:xmpp:message-retract:1"));
    assert!(!tombstone.contains("recipient original"));

    northstar_archive_postgres::archive_message(
        &pool,
        uuid::Uuid::new_v4(),
        recipient_id,
        "alice@remote.test/Phone",
        "<message from='alice@remote.test/Phone' to='bob@local.test' id='offline-original'><body>offline original</body></message>",
        false,
        Some("offline-original"),
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM offline_messages")
        .execute(&pool)
        .await
        .unwrap();
    let offline_retraction_xml = "<message from='alice@remote.test/Phone' to='bob@local.test' id='offline-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='offline-original'/></message>";
    let offline_retraction = Document::parse(offline_retraction_xml).unwrap();
    let offline_command = northstar_message_core::retraction::personal_retraction_command(
        offline_retraction.root_element(),
    )
    .unwrap()
    .unwrap();
    let offline_delivery_id = uuid::Uuid::new_v4();
    let offline_writes = [ArchiveWrite {
        id: uuid::Uuid::new_v4(),
        owner_id: recipient_id,
        peer_jid: "alice@remote.test/Phone",
        stanza: offline_retraction_xml,
        encrypted: false,
        stanza_id: Some("offline-retraction"),
    }];
    let offline_delivery = DeliveryProjection {
        id: offline_delivery_id,
        recipient_id,
        local_actor_id: None,
        sender_jid: "alice@remote.test/Phone",
        stanza: offline_retraction_xml,
        encrypted: false,
        max_messages: 100,
        max_bytes: 1_000_000,
        ttl_days: 30,
        mam_backed: true,
    };
    assert_eq!(
        retraction_service
            .apply_with_delivery(
                &[OwnerProjection {
                    owner_id: recipient_id,
                    peer_jid: "alice@remote.test/Phone",
                }],
                "alice@remote.test/Phone",
                &RetractionCommand {
                    target_id: &offline_command.target_id,
                    action_id: &offline_command.action_id,
                    semantic_payload: &offline_command.semantic_payload,
                },
                &offline_writes,
                Some(&offline_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied {
            tombstones: 1,
            live_claim_id: None,
        }
    );
    let offline_tombstone: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='offline-original'",
    )
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(offline_tombstone.contains("urn:xmpp:message-retract:1"));
    let accepted_offline_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(accepted_offline_count, 1);

    northstar_federation_postgres::enqueue_s2s_outbox(
        &pool,
        "remote.test",
        "<message from='alice@local.test' to='carol@remote.test'><retract xmlns='urn:xmpp:message-retract:1' id='outbound-original'/></message>",
        Some("alice@local.test/Phone"),
        300,
        100,
        1_000_000,
        100,
    )
    .await
    .unwrap();
    let outbound_retraction = Document::parse(
        "<message id='outbound-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='outbound-original'/></message>",
    )
    .unwrap();
    let outbound_action = "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='outbound-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='outbound-original'/></message>";
    let outbound_action_write = [ArchiveWrite {
        id: uuid::Uuid::new_v4(),
        owner_id: sender_id,
        peer_jid: "carol@remote.test/Laptop",
        stanza: outbound_action,
        encrypted: false,
        stanza_id: Some("outbound-retraction"),
    }];
    let outbound_command = northstar_message_core::retraction::personal_retraction_command(
        outbound_retraction.root_element(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        retraction_service
            .apply(
                &[OwnerProjection {
                    owner_id: sender_id,
                    peer_jid: "carol@remote.test/Laptop",
                }],
                "alice@local.test/Phone",
                &RetractionCommand {
                    target_id: &outbound_command.target_id,
                    action_id: &outbound_command.action_id,
                    semantic_payload: &outbound_command.semantic_payload,
                },
                &outbound_action_write,
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied {
            tombstones: 1,
            live_claim_id: None,
        }
    );
    let rollback_original_id = uuid::Uuid::new_v4();
    northstar_archive_postgres::archive_message(
        &pool,
        rollback_original_id,
        sender_id,
        "carol@remote.test/Laptop",
        "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='rollback-original'><body>must survive rollback</body></message>",
        false,
        Some("rollback-original"),
    )
    .await
    .unwrap();
    let rollback_retraction = Document::parse(
        "<message id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-original'/></message>",
    )
    .unwrap();
    let conflicting_action = [ArchiveWrite {
        id: rollback_original_id,
        owner_id: sender_id,
        peer_jid: "carol@remote.test/Laptop",
        stanza: "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-original'/></message>",
        encrypted: false,
        stanza_id: Some("rollback-action"),
    }];
    let rollback_command = northstar_message_core::retraction::personal_retraction_command(
        rollback_retraction.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(retraction_service
        .apply(
            &[OwnerProjection {
                owner_id: sender_id,
                peer_jid: "carol@remote.test/Laptop",
            }],
            "alice@local.test/Phone",
            &RetractionCommand {
                target_id: &rollback_command.target_id,
                action_id: &rollback_command.action_id,
                semantic_payload: &rollback_command.semantic_payload,
            },
            &conflicting_action,
            None,
        )
        .await
        .is_err());
    let rollback_original: String =
        sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=$1 AND owner_id=$2")
            .bind(rollback_original_id)
            .bind(sender_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(rollback_original.contains("must survive rollback"));
    let outbound_tombstone: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='outbound-original'",
    )
    .bind(sender_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(outbound_tombstone.contains("urn:xmpp:message-retract:1"));
    let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM s2s_outbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(outbox_count, 1);

    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
