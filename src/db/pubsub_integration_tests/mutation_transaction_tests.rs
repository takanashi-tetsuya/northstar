//! Mutation transaction timeouts, authority and stale preconditions.

use super::*;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn timed_out_mutation_begin_rolls_back_before_releasing_connection() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let (released_tx, mut released_rx) = tokio::sync::mpsc::unbounded_channel();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let released_tx = released_tx.clone();
            Box::pin(async move {
                let _ = released_tx.send(());
                Ok(true)
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    while released_rx.try_recv().is_ok() {}

    // Force BEGIN to complete after the admission deadline without changing
    // PostgreSQL settings or relying on a timing-sensitive server stall.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    let delayed_begin = async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Transaction::begin(connection, None).await
    };
    let error = match finish_bounded_pubsub_begin(deadline, delayed_begin).await {
        Ok(_) => panic!("a late BEGIN unexpectedly passed admission"),
        Err(error) => error,
    };
    assert!(error.downcast_ref::<PubSubMutationBusy>().is_some());

    tokio::time::timeout(Duration::from_secs(5), released_rx.recv())
        .await
        .expect("timed-out BEGIN did not release its connection")
        .expect("pool release observer closed");
    let state: String = sqlx::query_scalar("SELECT state FROM pg_stat_activity WHERE pid = $1")
        .bind(backend_pid)
        .fetch_one(&observer)
        .await
        .unwrap();
    assert_eq!(state, "idle");
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn timed_out_mutation_acquire_leaves_no_detached_waiter() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let (released_tx, mut released_rx) = tokio::sync::mpsc::unbounded_channel();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let released_tx = released_tx.clone();
            Box::pin(async move {
                let _ = released_tx.send(());
                Ok(true)
            })
        })
        .connect(&url)
        .await
        .unwrap();
    // Exhausting the pool must time out at acquisition, without leaving a
    // detached task to begin a transaction when the connection is released.
    let held = pool.acquire().await.unwrap();
    while released_rx.try_recv().is_ok() {}
    let error =
        match begin_bounded_pubsub_mutation_with_timeout(&pool, Duration::from_millis(20)).await {
            Ok(_) => panic!("a blocked mutation unexpectedly acquired the pool"),
            Err(error) => error,
        };
    assert!(error.downcast_ref::<PubSubMutationBusy>().is_some());
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), released_rx.recv())
        .await
        .expect("holder did not release its connection")
        .expect("pool release observer closed");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), released_rx.recv())
            .await
            .is_err(),
        "timed-out acquisition left a detached pool waiter"
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mutation_authority_and_stale_preconditions_are_checked_in_transaction() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let renderer = crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test");

    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}@example.test");
    let publisher = format!("publisher-{suffix}@example.test");
    let intruder = format!("intruder-{suffix}@example.test");
    let subscriber = format!("subscriber-{suffix}@example.test/desktop");
    let node_name = format!("authority-{suffix}");
    let node_id = match create_node(&pool, &node_name, &owner, &PubSubNodeConfig::default(), 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected create outcome: {other:?}"),
    };
    let stale_node = get_node_by_id(&pool, node_id).await.unwrap().unwrap();

    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &stale_node,
            &intruder,
            &[("forbidden".to_owned(), "<item id='forbidden'/>".to_owned())],
            true,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Forbidden,
        "a protocol-supplied owner boolean must never authorize publication"
    );
    assert!(matches!(
        set_affiliations_with_outbox(
            &pool,
            node_id,
            &owner,
            &[(publisher.clone(), "publisher".to_owned())],
            None,
            None,
            &[],
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &stale_node,
            &publisher,
            &[("allowed".to_owned(), "<item id='allowed'/>".to_owned())],
            false,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );

    let mut changed_config = stale_node.config();
    // Change a publication-semantic field, not display-only metadata.
    // A stale handler must not retain an obsolete persistence decision.
    changed_config.persist_items = false;
    assert_eq!(
        update_node_config_and_graph(&pool, &stale_node, &owner, &changed_config,)
            .await
            .unwrap(),
        PubSubConfigOutcome::Updated
    );
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &stale_node,
            &publisher,
            &[("stale".to_owned(), "<item id='stale'/>".to_owned())],
            false,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::PreconditionFailed,
        "validation against an old node configuration must not authorize a write"
    );

    assert_eq!(
        set_subscriptions_with_outbox(
            &pool,
            node_id,
            &intruder,
            &[(subscriber.clone(), "subscribed".to_owned(), None)],
            None,
            &[],
        )
        .await
        .unwrap(),
        SetSubscriptionsOutcome::Forbidden
    );
    assert_eq!(
        set_affiliations_with_outbox(
            &pool,
            node_id,
            &intruder,
            &[(intruder.clone(), "owner".to_owned())],
            None,
            None,
            &[],
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Forbidden
    );
    assert_eq!(
        purge_node_as_owner_with_outbox(&pool, node_id, &intruder, &renderer)
            .await
            .unwrap(),
        OwnerMutationOutcome::Forbidden
    );

    set_subscription(&pool, node_id, &subscriber, "pending")
        .await
        .unwrap();
    let pending = get_subscription(&pool, node_id, &subscriber)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resolve_pending_subscription_with_outbox(
            &pool,
            node_id,
            &intruder,
            &subscriber,
            &pending.subid,
            true,
            &[],
        )
        .await
        .unwrap(),
        SubscriptionAuthorizationOutcome::Forbidden
    );
    assert_eq!(
        resolve_pending_subscription_with_outbox(
            &pool,
            node_id,
            &owner,
            &subscriber,
            "stale-subid",
            true,
            &[],
        )
        .await
        .unwrap(),
        SubscriptionAuthorizationOutcome::Stale
    );
    assert_eq!(
        resolve_pending_subscription_with_outbox(
            &pool,
            node_id,
            &owner,
            &subscriber,
            &pending.subid,
            true,
            &[],
        )
        .await
        .unwrap(),
        SubscriptionAuthorizationOutcome::Applied
    );

    let current = get_node_by_id(&pool, node_id).await.unwrap().unwrap();
    assert_eq!(
        delete_node_as_owner_with_redirect_and_outbox(
            &pool, current.id, &intruder, None, &renderer,
        )
        .await
        .unwrap(),
        OwnerMutationOutcome::Forbidden
    );
    assert_eq!(
        delete_node_as_owner_with_redirect_and_outbox(&pool, current.id, &owner, None, &renderer,)
            .await
            .unwrap(),
        OwnerMutationOutcome::Applied
    );
}
