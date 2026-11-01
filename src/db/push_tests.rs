use crate::db;
use northstar_message_postgres::push::*;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn quota_upsert_and_durable_claim_are_atomic() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("push{}", &suffix[..12]);
    let user = northstar_auth_postgres::users::create_user(
        &pool,
        &username,
        "test-password-long-enough",
        false,
        false,
        4096,
        false,
    )
    .await
    .unwrap();
    for index in 0..MAX_PUSH_SUBSCRIPTIONS_PER_USER {
        assert_eq!(
            enable_push_subscription(
                &pool,
                user.id,
                "push.example.test",
                &format!("node-{index}"),
                None,
            )
            .await
            .unwrap(),
            PushEnableOutcome::Enabled
        );
    }
    assert_eq!(
        enable_push_subscription(&pool, user.id, "push.example.test", "over-quota", None,)
            .await
            .unwrap(),
        PushEnableOutcome::QuotaExceeded
    );
    // Updating an existing target never consumes an additional slot.
    assert_eq!(
        enable_push_subscription(
            &pool,
            user.id,
            "push.example.test",
            "node-0",
            Some("<x xmlns='jabber:x:data' type='submit'/>")
        )
        .await
        .unwrap(),
        PushEnableOutcome::Enabled
    );
    let first = claim_push_deliveries(&pool, user.id).await.unwrap();
    assert_eq!(first.len(), MAX_PUSH_SUBSCRIPTIONS_PER_USER as usize);
    assert!(claim_push_deliveries(&pool, user.id)
        .await
        .unwrap()
        .is_empty());
    let request_id = first[0].request_id;
    assert_eq!(
        complete_push_response(
            &pool,
            request_id,
            "attacker.example.test",
            PushResponseKind::Success
        )
        .await
        .unwrap(),
        PushResponseOutcome::SenderMismatch
    );
    assert_eq!(
        enable_push_subscription(
            &pool,
            user.id,
            "push.example.test",
            "node-0",
            Some("<x xmlns='jabber:x:data' type='submit'/>")
        )
        .await
        .unwrap(),
        PushEnableOutcome::Enabled
    );
    // An old correlated error/result cannot alter a freshly re-enabled
    // target or its new publish credentials.
    assert_eq!(
        complete_push_response(
            &pool,
            request_id,
            "push.example.test",
            PushResponseKind::Success
        )
        .await
        .unwrap(),
        PushResponseOutcome::Unknown
    );
    let renewed = claim_push_deliveries(&pool, user.id).await.unwrap();
    assert_eq!(renewed.len(), 1);
    assert_eq!(renewed[0].node, "node-0");
    assert_eq!(
        complete_push_response(
            &pool,
            renewed[0].request_id,
            "push.example.test",
            PushResponseKind::Success
        )
        .await
        .unwrap(),
        PushResponseOutcome::Completed
    );

    // Migration 0073 permits the wire-level omitted-node sentinel while
    // protocol parsing continues to reject an explicit node=''. It is a
    // distinct unique key and serializes without a fake empty attribute.
    assert_eq!(
        disable_push_subscriptions(&pool, user.id, "push.example.test", Some("node-15"))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        enable_push_subscription(&pool, user.id, "push.example.test", "", None)
            .await
            .unwrap(),
        PushEnableOutcome::Enabled
    );
    let optional = claim_push_deliveries(&pool, user.id).await.unwrap();
    assert_eq!(optional.len(), 1);
    assert!(optional[0].node.is_empty());
    let optional_request_id = optional[0].request_id;
    // Delivery correlation is PostgreSQL authority, not process memory:
    // an IQ error received after a server restart must still disable the
    // exact JID/omitted-node generation.
    pool.close().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    assert_eq!(
        complete_push_response(
            &pool,
            optional_request_id,
            "push.example.test",
            PushResponseKind::PermanentError,
        )
        .await
        .unwrap(),
        PushResponseOutcome::SubscriptionDisabled
    );
    assert!(list_push_targets(&pool, user.id)
        .await
        .unwrap()
        .iter()
        .all(|target| target.service_jid == "push.example.test" && !target.node.is_empty()));
    northstar_workflows::account_lifecycle::delete_user_with_roster(
        &crate::db::roster::RootRosterEffects,
        &pool,
        user.id,
        "example.test",
    )
    .await
    .unwrap();
}
