//! Subscription and option rechecks after a lock wait.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn subscription_and_option_retries_do_not_emit_transitions_after_lock_wait() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("retry-owner-{suffix}@example.test");
    let subscriber = format!("retry-subscriber-{suffix}@example.test/desktop");
    let requester = northstar_xmpp_types::jid::canonical_bare_key(&subscriber).unwrap();
    let node = create_default_test_node(&pool, &format!("retry-{suffix}"), &owner).await;
    assert_eq!(
        publish_items(
            &pool,
            &node,
            &owner,
            &[("last".to_owned(), "<item id='last'/>".to_owned())],
            false,
            1_000_000,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let mut options = PubSubSubscriptionOptions::for_node_type("leaf");
    options.include_body = false;
    let original = match set_subscription_limited_with_options_and_renderer(
        &pool,
        "example.test",
        node.id,
        &requester,
        &subscriber,
        "subscribed",
        &node.node_type,
        &node.access_model,
        100,
        Some(&options),
        &format!("original-{suffix}"),
        &NoopMutationOutboxRenderer,
    )
    .await
    .unwrap()
    {
        SubscribeOutcome::Subscribed(subscription) => subscription,
        other => panic!("unexpected initial subscription outcome: {other:?}"),
    };

    let mut node_blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(node.id)
        .execute(&mut *node_blocker)
        .await
        .unwrap();
    let application = format!("ps-options-retry-{}", &suffix[..8]);
    let retry_pool = named_single_connection_pool(&url, &application).await;
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let renderer = Arc::new(RaceMutationRenderer {
        inner: crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test"),
        observations: observation_tx,
        gate: None,
    });
    let retry_task = tokio::spawn({
        let retry_pool = retry_pool.clone();
        let retry_node = node.clone();
        let retry_requester = requester.clone();
        let retry_subscriber = subscriber.clone();
        let retry_options = options.clone();
        let renderer = Arc::clone(&renderer);
        async move {
            set_subscription_limited_with_options_and_renderer(
                &retry_pool,
                "example.test",
                retry_node.id,
                &retry_requester,
                &retry_subscriber,
                "subscribed",
                &retry_node.node_type,
                &retry_node.access_model,
                100,
                Some(&retry_options),
                &format!("retry-{suffix}"),
                &*renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    node_blocker.commit().await.unwrap();
    let retried = match retry_task.await.unwrap().unwrap() {
        SubscribeOutcome::Subscribed(subscription) => subscription,
        other => panic!("unexpected retry subscription outcome: {other:?}"),
    };
    assert_eq!(retried.subid, original.subid);
    assert!(observation_rx.try_recv().is_err());

    assert_eq!(
        set_subscriptions_with_renderer(
            &pool,
            node.id,
            &owner,
            &[(subscriber.clone(), "subscribed".to_owned(), None)],
            None,
            &*renderer,
        )
        .await
        .unwrap(),
        SetSubscriptionsOutcome::Updated(Vec::new())
    );
    assert!(matches!(
        set_affiliations_with_renderer(
            &pool,
            node.id,
            &owner,
            &[(owner.clone(), "owner".to_owned())],
            None,
            None,
            &*renderer,
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated {
            ref revoked_subscriptions,
            ref approved_subscriptions,
        } if revoked_subscriptions.is_empty() && approved_subscriptions.is_empty()
    ));
    assert_eq!(
        update_subscription_options_checked(
            &pool,
            "example.test",
            node.id,
            &requester,
            &subscriber,
            Some(&original.subid),
            &options,
        )
        .await
        .unwrap(),
        SubscriptionOptionsOutcome::Updated
    );
    assert_eq!(
        update_subscription_options_checked(
            &pool,
            "example.test",
            node.id,
            &requester,
            &subscriber,
            Some(&original.subid),
            &options,
        )
        .await
        .unwrap(),
        SubscriptionOptionsOutcome::Updated
    );
    assert!(observation_rx.try_recv().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE source_node=$1 AND recipient_jid=$2",
        )
        .bind(&node.node)
        .bind(&subscriber)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    retry_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn subscription_options_recheck_node_policy_after_lock_wait() {
    let (url, pool) = integration_pool(8).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("options-owner-{suffix}@example.test");
    let subscriber = format!("options-reader-{suffix}@example.test/phone");
    let requester = northstar_xmpp_types::jid::canonical_bare_key(&subscriber).unwrap();
    let node = create_default_test_node(&pool, &format!("options-{suffix}"), &owner).await;
    let atom = "http://www.w3.org/2005/Atom";
    sqlx::query("UPDATE pubsub_nodes SET payload_type=$2 WHERE id=$1")
        .bind(node.id)
        .bind(atom)
        .execute(&pool)
        .await
        .unwrap();
    let original = set_subscription_limited_with_options(
        &pool,
        "example.test",
        node.id,
        &subscriber,
        "subscribed",
        100,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    let node_id = node.id;

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("UPDATE pubsub_nodes SET payload_type=NULL WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let application = format!("ps-options-policy-{}", &suffix[..8]);
    let retry_pool = named_single_connection_pool(&url, &application).await;
    let mut requested = PubSubSubscriptionOptions::for_node_type("leaf");
    requested.subscription_depth = original.subscription_depth;
    requested.include_body = true;
    let task = tokio::spawn({
        let retry_pool = retry_pool.clone();
        let requester = requester.clone();
        let subscriber = subscriber.clone();
        let subid = original.subid.clone();
        let requested = requested.clone();
        async move {
            update_subscription_options_checked(
                &retry_pool,
                "example.test",
                node_id,
                &requester,
                &subscriber,
                Some(&subid),
                &requested,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    blocker.commit().await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap(),
        SubscriptionOptionsOutcome::InvalidOptions
    );
    assert_eq!(
        update_subscription_options_checked(
            &pool,
            "example.test",
            node.id,
            &requester,
            &subscriber,
            Some("stale-subid"),
            &requested,
        )
        .await
        .unwrap(),
        SubscriptionOptionsOutcome::InvalidSubid,
        "a stale SubID must still take precedence over changed node policy"
    );
    let include_body: bool = sqlx::query_scalar(
        "SELECT include_body FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2",
    )
    .bind(node.id)
    .bind(&subscriber)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!include_body);

    // A subscribe form parsed against an Atom node must not write include_body
    // after the node's payload type changes while the transaction waits.
    sqlx::query("UPDATE pubsub_nodes SET payload_type=$2, notify_sub=true WHERE id=$1")
        .bind(node.id)
        .bind(atom)
        .execute(&pool)
        .await
        .unwrap();
    let subscribe_jid = format!("options-new-{suffix}@example.test/phone");
    let subscribe_requester =
        northstar_xmpp_types::jid::canonical_bare_key(&subscribe_jid).unwrap();
    let before_outbox: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node.node)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("UPDATE pubsub_nodes SET payload_type=NULL WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let application = format!("ps-subscribe-payload-{}", &suffix[..8]);
    let subscribe_pool = named_single_connection_pool(&url, &application).await;
    let mut subscribe_options = PubSubSubscriptionOptions::for_node_type("leaf");
    subscribe_options.include_body = true;
    let renderer = crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test");
    let expected_node_type = node.node_type.clone();
    let expected_access_model = node.access_model.clone();
    let subid = format!("payload-{suffix}");
    let task = tokio::spawn({
        let subscribe_pool = subscribe_pool.clone();
        let subscribe_requester = subscribe_requester.clone();
        let subscribe_jid = subscribe_jid.clone();
        async move {
            set_subscription_limited_with_options_and_renderer(
                &subscribe_pool,
                "example.test",
                node_id,
                &subscribe_requester,
                &subscribe_jid,
                "subscribed",
                &expected_node_type,
                &expected_access_model,
                100,
                Some(&subscribe_options),
                &subid,
                &renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    blocker.commit().await.unwrap();
    assert!(matches!(
        task.await.unwrap().unwrap(),
        SubscribeOutcome::InvalidOptions
    ));
    let subscription_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2")
            .bind(node.id)
            .bind(&subscribe_jid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(subscription_count, 0);
    let after_outbox: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node.node)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after_outbox, before_outbox);
    subscribe_pool.close().await;

    sqlx::query("UPDATE pubsub_nodes SET node_type='collection' WHERE id=$1")
        .bind(node.id)
        .execute(&pool)
        .await
        .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("UPDATE pubsub_nodes SET node_type='leaf' WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let application = format!("ps-options-type-{}", &suffix[..8]);
    let type_pool = named_single_connection_pool(&url, &application).await;
    requested.include_body = false;
    requested.subscription_type = "nodes".to_owned();
    let task = tokio::spawn({
        let type_pool = type_pool.clone();
        let requester = requester.clone();
        let subscriber = subscriber.clone();
        let subid = original.subid.clone();
        async move {
            update_subscription_options_checked(
                &type_pool,
                "example.test",
                node_id,
                &requester,
                &subscriber,
                Some(&subid),
                &requested,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    blocker.commit().await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap(),
        SubscriptionOptionsOutcome::InvalidOptions
    );
    let subscription_type: String = sqlx::query_scalar(
        "SELECT subscription_type FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2",
    )
    .bind(node.id)
    .bind(&subscriber)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(subscription_type, "items");

    let remote = format!("remote-options-{suffix}@remote.test/phone");
    let remote_bare = northstar_xmpp_types::jid::canonical_bare_key(&remote).unwrap();
    let remote_subscription = set_subscription_limited_with_options(
        &pool,
        "example.test",
        node.id,
        &remote,
        "subscribed",
        100,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    let mut remote_options = PubSubSubscriptionOptions::for_node_type("leaf");
    remote_options.subscription_depth = remote_subscription.subscription_depth;
    remote_options.show_values = vec!["online".to_owned()];
    assert_eq!(
        update_subscription_options_checked(
            &pool,
            "example.test",
            node.id,
            &remote_bare,
            &remote,
            Some(&remote_subscription.subid),
            &remote_options,
        )
        .await
        .unwrap(),
        SubscriptionOptionsOutcome::InvalidOptions
    );
    assert_eq!(
        update_subscription_options_checked(
            &pool,
            "example.test",
            node.id,
            &remote_bare,
            &remote,
            Some("stale-subid"),
            &remote_options,
        )
        .await
        .unwrap(),
        SubscriptionOptionsOutcome::InvalidSubid
    );
    remote_options.show_values = PubSubSubscriptionOptions::for_node_type("leaf").show_values;
    assert_eq!(
        update_subscription_options_checked(
            &pool,
            "example.test",
            node.id,
            &remote_bare,
            &remote,
            Some(&remote_subscription.subid),
            &remote_options,
        )
        .await
        .unwrap(),
        SubscriptionOptionsOutcome::Updated
    );

    retry_pool.close().await;
    type_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn subscribe_options_recheck_remote_show_values_after_lock_wait() {
    let (url, pool) = integration_pool(8).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("show-owner-{suffix}@example.test");
    let subscriber = format!("show-reader-{suffix}@remote.test/phone");
    let requester = northstar_xmpp_types::jid::canonical_bare_key(&subscriber).unwrap();
    let node = create_default_test_node(&pool, &format!("show-{suffix}"), &owner).await;
    sqlx::query("UPDATE pubsub_nodes SET notify_sub=true WHERE id=$1")
        .bind(node.id)
        .execute(&pool)
        .await
        .unwrap();
    let node = get_node_by_id(&pool, node.id).await.unwrap().unwrap();
    let mut restricted = PubSubSubscriptionOptions::for_node_type("leaf");
    restricted.show_values = vec!["online".to_owned()];
    let application = format!("ps-show-{}", &suffix[..8]);
    let retry_pool = named_single_connection_pool(&url, &application).await;
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let renderer = Arc::new(RaceMutationRenderer {
        inner: crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test"),
        observations: observation_tx,
        gate: None,
    });
    let before_outbox: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node.node)
            .fetch_one(&pool)
            .await
            .unwrap();

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let task = tokio::spawn({
        let retry_pool = retry_pool.clone();
        let node = node.clone();
        let requester = requester.clone();
        let subscriber = subscriber.clone();
        let restricted = restricted.clone();
        let renderer = Arc::clone(&renderer);
        let subid = format!("rejected-{suffix}");
        async move {
            set_subscription_limited_with_options_and_renderer(
                &retry_pool,
                "example.test",
                node.id,
                &requester,
                &subscriber,
                "subscribed",
                &node.node_type,
                &node.access_model,
                100,
                Some(&restricted),
                &subid,
                &*renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    blocker.commit().await.unwrap();
    assert!(matches!(
        task.await.unwrap().unwrap(),
        SubscribeOutcome::InvalidOptions
    ));
    assert!(observation_rx.try_recv().is_err());
    let subscription_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2")
            .bind(node.id)
            .bind(&subscriber)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(subscription_count, 0);
    let outbox_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node.node)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(outbox_count, before_outbox);

    assert!(matches!(
        set_subscription_limited_with_options_and_renderer(
            &pool,
            "example.test",
            node.id,
            "another@remote.test",
            &subscriber,
            "subscribed",
            &node.node_type,
            &node.access_model,
            100,
            Some(&restricted),
            &format!("wrong-actor-{suffix}"),
            &*renderer,
        )
        .await
        .unwrap(),
        SubscribeOutcome::Forbidden
    ));
    assert!(matches!(
        set_subscription_limited_with_options_and_renderer(
            &pool,
            "example.test",
            node.id,
            &requester,
            &subscriber,
            "subscribed",
            "collection",
            &node.access_model,
            100,
            Some(&restricted),
            &format!("stale-{suffix}"),
            &*renderer,
        )
        .await
        .unwrap(),
        SubscribeOutcome::PreconditionFailed
    ));
    assert!(observation_rx.try_recv().is_err());

    let complete = PubSubSubscriptionOptions::for_node_type("leaf");
    assert!(matches!(
        set_subscription_limited_with_options_and_renderer(
            &pool,
            "example.test",
            node.id,
            &requester,
            &subscriber,
            "subscribed",
            &node.node_type,
            &node.access_model,
            100,
            Some(&complete),
            &format!("accepted-{suffix}"),
            &*renderer,
        )
        .await
        .unwrap(),
        SubscribeOutcome::Subscribed(_)
    ));
    let observation =
        await_mutation_observation(&mut observation_rx, "accepted subscription").await;
    assert_eq!(observation.kind, "subscription");
    assert_eq!(observation.recipients, vec![owner]);
    let after_outbox: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node.node)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(after_outbox > before_outbox);

    sqlx::query("UPDATE pubsub_subscriptions SET state='pending' WHERE node_id=$1 AND jid=$2")
        .bind(node.id)
        .bind(&subscriber)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        set_subscription_limited_with_options_and_renderer(
            &pool,
            "example.test",
            node.id,
            &requester,
            &subscriber,
            "subscribed",
            &node.node_type,
            &node.access_model,
            100,
            Some(&restricted),
            &format!("pending-{suffix}"),
            &*renderer,
        )
        .await
        .unwrap(),
        SubscribeOutcome::PreconditionFailed
    ));
    assert!(observation_rx.try_recv().is_err());

    retry_pool.close().await;
    pool.close().await;
}
