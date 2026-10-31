//! Node metadata, access model and affiliation checks under concurrent changes.

use super::*;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn node_metadata_keeps_affiliation_order_and_live_subscription_scope() {
    let (_, pool) = integration_pool(2).await;
    let node_name = format!("metadata-{}", Uuid::new_v4().simple());
    let node = create_default_test_node(&pool, &node_name, "alice@example.test").await;
    let initial = node_metadata(&pool, node.id).await.unwrap();
    assert_eq!(initial.owners, ["alice@example.test"]);
    assert!(initial.publishers.is_empty());
    assert_eq!(initial.active_subscribers, 0);

    for (jid, affiliation) in [
        ("zoe@example.test", "owner"),
        ("zack@example.test", "publisher"),
        ("amy@example.test", "publish-only"),
        ("member@example.test", "member"),
        ("outcast@example.test", "outcast"),
    ] {
        sqlx::query(
            "INSERT INTO pubsub_affiliations(node_id, jid, affiliation) VALUES ($1, $2, $3)",
        )
        .bind(node.id)
        .bind(jid)
        .bind(affiliation)
        .execute(&pool)
        .await
        .unwrap();
    }
    for (jid, state, expiry) in [
        ("bob@example.test", "subscribed", None),
        ("ghost@example.test/Phone", "subscribed", Some(3600)),
        ("expired@example.test", "subscribed", Some(-3600)),
        ("pending@example.test", "pending", None),
    ] {
        sqlx::query(
            "INSERT INTO pubsub_subscriptions(node_id, jid, state, subid, expire)
             VALUES ($1, $2, $3, $4, NOW() + $5::INT * INTERVAL '1 second')",
        )
        .bind(node.id)
        .bind(jid)
        .bind(state)
        .bind(Uuid::new_v4().to_string())
        .bind(expiry)
        .execute(&pool)
        .await
        .unwrap();
    }

    assert_eq!(
        node_metadata(&pool, node.id).await.unwrap(),
        PubSubNodeMetadata {
            owners: vec!["alice@example.test".into(), "zoe@example.test".into()],
            publishers: vec!["amy@example.test".into(), "zack@example.test".into()],
            active_subscribers: 2,
        }
    );
    let missing = node_metadata(&pool, Uuid::new_v4()).await.unwrap();
    assert!(missing.owners.is_empty());
    assert!(missing.publishers.is_empty());
    assert_eq!(missing.active_subscribers, 0);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn restricted_open_publish_is_denied_by_locked_publish_and_retract() {
    let (_, pool) = integration_pool(4).await;
    let owner = format!("restricted-owner-{}@example.test", Uuid::new_v4().simple());
    let outsider = format!(
        "restricted-outsider-{}@example.test",
        Uuid::new_v4().simple()
    );
    let node_name = format!("restricted-open-{}", Uuid::new_v4().simple());
    let mut config = PubSubNodeConfig {
        publish_model: "open".to_owned(),
        ..Default::default()
    };
    let node_id = match create_node(&pool, &node_name, &owner, &config, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected node create outcome: {other:?}"),
    };
    let open_node = get_node_by_id(&pool, node_id).await.unwrap().unwrap();
    let original_item = vec![("original".to_owned(), "<item id='original'/>".to_owned())];
    assert_eq!(
        publish_items(
            &pool,
            &open_node,
            &outsider,
            &original_item,
            false,
            1_000_000
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    set_subscription(&pool, node_id, "watcher@remote.test", "subscribed")
        .await
        .unwrap();

    config.access_model = "whitelist".to_owned();
    assert_eq!(
        update_node_config_and_graph(&pool, &open_node, &owner, &config)
            .await
            .unwrap(),
        PubSubConfigOutcome::Updated
    );
    let restricted_node = get_node_by_id(&pool, node_id).await.unwrap().unwrap();
    let renderer = crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test");
    let outbox_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node_name)
            .fetch_one(&pool)
            .await
            .unwrap();
    let forbidden_item = vec![("forbidden".to_owned(), "<item id='forbidden'/>".to_owned())];
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &restricted_node,
            &outsider,
            &forbidden_item,
            false,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Forbidden
    );
    assert_eq!(
        retract_items_with_renderer(
            &pool,
            node_id,
            &["original".to_owned()],
            &outsider,
            false,
            &renderer,
        )
        .await
        .unwrap(),
        RetractItemsOutcome::Forbidden
    );
    let outbox_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node_name)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(outbox_after, outbox_before);
    assert!(get_items(&pool, node_id, &["forbidden".to_owned()], 1)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        get_items(&pool, node_id, &["original".to_owned()], 1)
            .await
            .unwrap()
            .len(),
        1
    );

    assert!(matches!(
        set_affiliations(&pool, node_id, &[(outsider.clone(), "member".to_owned())])
            .await
            .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    let item_events_before_member_publish: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_event_outbox
          WHERE source_node=$1 AND payload_xml LIKE '%<items%'",
    )
    .bind(&node_name)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &restricted_node,
            &outsider,
            &forbidden_item,
            false,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let item_events_after_member_publish: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_event_outbox
          WHERE source_node=$1 AND payload_xml LIKE '%<items%'",
    )
    .bind(&node_name)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(item_events_after_member_publish > item_events_before_member_publish);
    assert_eq!(
        retract_items(&pool, node_id, &["original".to_owned()], &outsider, false)
            .await
            .unwrap(),
        RetractItemsOutcome::Retracted
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn publish_rechecks_access_model_after_concurrent_config_change() {
    let (url, pool) = integration_pool(10).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("race-owner-{suffix}@example.test");
    let outsider = format!("race-outsider-{suffix}@example.test");
    let config = PubSubNodeConfig {
        publish_model: "open".to_owned(),
        ..Default::default()
    };
    let node_id = match create_node(&pool, &format!("race-access-{suffix}"), &owner, &config, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected node create outcome: {other:?}"),
    };
    let open_node = get_node_by_id(&pool, node_id).await.unwrap().unwrap();
    set_subscription(&pool, node_id, "watcher@remote.test", "subscribed")
        .await
        .unwrap();
    assert!(tokio::time::timeout(
        Duration::from_secs(5),
        crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test")
            .can_publish(&open_node, &outsider)
    )
    .await
    .expect("open-publish precheck timed out")
    .unwrap());

    // Hold the same graph and node locks as a configuration mutation. The
    // publisher starts with a stale, open-access node and must recheck after
    // the committed policy change becomes visible.
    let mut config_tx = tokio::time::timeout(Duration::from_secs(5), pool.begin())
        .await
        .expect("configuration transaction timed out")
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
            .execute(&mut *config_tx),
    )
    .await
    .expect("configuration graph lock timed out")
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
            .bind(node_id)
            .fetch_one(&mut *config_tx),
    )
    .await
    .expect("configuration node lock timed out")
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("UPDATE pubsub_nodes SET access_model='whitelist' WHERE id=$1")
            .bind(node_id)
            .execute(&mut *config_tx),
    )
    .await
    .expect("configuration update timed out")
    .unwrap();

    let publish_application = format!("ps-access-publish-{}", &suffix[..10]);
    let publish_pool = tokio::time::timeout(
        Duration::from_secs(5),
        named_single_connection_pool(&url, &publish_application),
    )
    .await
    .expect("named publish pool connection timed out");
    let mut publish_task = tokio::spawn({
        let publish_pool = publish_pool.clone();
        let open_node = open_node.clone();
        let outsider = outsider.clone();
        async move {
            let renderer = crate::db::pubsub_repository::test_pubsub_service(
                publish_pool.clone(),
                "example.test",
            );
            publish_items_with_renderer(
                &publish_pool,
                &open_node,
                &outsider,
                &[("raced".to_owned(), "<item id='raced'/>".to_owned())],
                false,
                1_000_000,
                &renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &publish_application).await;
    tokio::time::timeout(Duration::from_secs(5), config_tx.commit())
        .await
        .expect("configuration commit timed out")
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), &mut publish_task)
            .await
            .expect("publisher did not finish after configuration commit")
            .unwrap()
            .unwrap(),
        PublishItemsOutcome::PreconditionFailed
    );
    assert!(tokio::time::timeout(
        Duration::from_secs(5),
        get_items(&pool, node_id, &["raced".to_owned()], 1)
    )
    .await
    .expect("item verification timed out")
    .unwrap()
    .is_empty());
    let item_events = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM pubsub_event_outbox
          WHERE source_node=$1 AND payload_xml LIKE '%<items%'",
    )
    .bind(&open_node.node)
    .fetch_one(&pool);
    let item_events = tokio::time::timeout(Duration::from_secs(5), item_events)
        .await
        .expect("outbox verification timed out")
        .unwrap();
    assert_eq!(item_events, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn concurrent_config_updates_use_a_locked_expected_snapshot() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let short = &suffix[..10];
    let owner = format!("config-owner-{suffix}@example.test");
    let subscriber = format!("config-subscriber-{suffix}@example.test/desktop");
    let node = create_default_test_node(&pool, &format!("config-conflict-{suffix}"), &owner).await;
    subscribe_for_race(&pool, &node, &subscriber, &format!("config-sub-{suffix}")).await;

    let expected = node.config();
    let mut first_config = expected.clone();
    first_config.title = Some("first-locked-title".to_owned());
    let mut second_config = expected.clone();
    second_config.description = Some("must-not-overwrite".to_owned());

    let gate = Arc::new(RenderGate::default());
    let (first_tx, mut first_rx) = tokio::sync::mpsc::unbounded_channel();
    let first_renderer = Arc::new(RaceMutationRenderer {
        inner: crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test"),
        observations: first_tx,
        gate: Some(Arc::clone(&gate)),
    });
    let first_application = format!("ps-config-first-{short}");
    let first_pool = named_single_connection_pool(&url, &first_application).await;
    let first_task = tokio::spawn({
        let first_pool = first_pool.clone();
        let first_renderer = Arc::clone(&first_renderer);
        let first_node = node.clone();
        let first_owner = owner.clone();
        let first_expected = expected.clone();
        async move {
            update_node_config_and_graph_with_outbox(
                &first_pool,
                &first_node,
                &first_owner,
                &first_expected,
                &first_config,
                &*first_renderer,
            )
            .await
        }
    });
    let first_observation = tokio::time::timeout(Duration::from_secs(3), first_rx.recv())
        .await
        .expect("first configuration never reached its locked renderer")
        .expect("first configuration observation channel closed");
    assert_eq!(first_observation.kind, "configuration");
    assert_eq!(first_observation.recipients, vec![subscriber.clone()]);

    let second_application = format!("ps-config-second-{short}");
    let second_pool = named_single_connection_pool(&url, &second_application).await;
    let second_task = tokio::spawn({
        let second_pool = second_pool.clone();
        let second_node = node.clone();
        let second_owner = owner.clone();
        let second_expected = expected.clone();
        async move {
            update_node_config_and_graph_with_outbox(
                &second_pool,
                &second_node,
                &second_owner,
                &second_expected,
                &second_config,
                &NoopMutationOutboxRenderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &second_application).await;
    gate.release();

    assert_eq!(
        first_task.await.unwrap().unwrap(),
        PubSubConfigOutcome::Updated
    );
    assert_eq!(
        second_task.await.unwrap().unwrap(),
        PubSubConfigOutcome::Conflict
    );
    let fresh = get_node_by_id(&pool, node.id).await.unwrap().unwrap();
    assert_eq!(fresh.title.as_deref(), Some("first-locked-title"));
    assert_eq!(fresh.description, None);
    let payload: String = sqlx::query_scalar(
        "SELECT payload_xml FROM pubsub_event_outbox
              WHERE event_id=$1 AND recipient_jid=$2",
    )
    .bind(first_observation.event_id)
    .bind(&subscriber)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(payload.contains("first-locked-title"));
    assert!(!payload.contains("must-not-overwrite"));

    first_pool.close().await;
    second_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn prohibited_affiliation_wins_atomically_over_owner_subscription_batch() {
    let (url, pool) = integration_pool(16).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("prohibited-owner-{suffix}@example.test");

    for (index, affiliation) in ["outcast", "publish-only"].into_iter().enumerate() {
        let bare = format!("prohibited-{index}-{suffix}@example.test");
        let full = format!("{bare}/phone");
        let node =
            create_default_test_node(&pool, &format!("prohibited-{affiliation}-{suffix}"), &owner)
                .await;
        let node_id = node.id;
        set_subscription(&pool, node_id, &bare, "subscribed")
            .await
            .unwrap();
        set_subscription(&pool, node_id, &full, "pending")
            .await
            .unwrap();
        sqlx::query(
                "INSERT INTO pubsub_digest_queue
                    (id,subscription_node_id,subscriber_jid,event_xml,deliver_after)
                 VALUES($1,$2,$3,'<event xmlns=''urn:test''/>',clock_timestamp()+INTERVAL '1 hour')",
            )
            .bind(Uuid::new_v4())
            .bind(node_id)
            .bind(&bare)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
                "INSERT INTO pubsub_digest_queue
                    (id,subscription_node_id,subscriber_jid,event_xml,deliver_after,source_delivery_id,show_values)
                 VALUES($1,$2,$3,'<event xmlns=''urn:test''/>',clock_timestamp()+INTERVAL '1 hour',$4,$5)",
            )
            .bind(Uuid::new_v4())
            .bind(node_id)
            .bind(&full)
            .bind(Uuid::new_v4())
            .bind(vec!["online".to_owned()])
            .execute(&pool)
            .await
            .unwrap();

        let gate = Arc::new(RenderGate::default());
        let (affiliation_tx, mut affiliation_rx) = tokio::sync::mpsc::unbounded_channel();
        let affiliation_renderer = Arc::new(RaceMutationRenderer {
            inner: crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test"),
            observations: affiliation_tx,
            gate: Some(Arc::clone(&gate)),
        });
        let affiliation_task = tokio::spawn({
            let affiliation_pool = pool.clone();
            let affiliation_renderer = Arc::clone(&affiliation_renderer);
            let affiliation_owner = owner.clone();
            let affiliation_bare = bare.clone();
            let affiliation_value = affiliation.to_owned();
            async move {
                set_affiliations_with_renderer(
                    &affiliation_pool,
                    node_id,
                    &affiliation_owner,
                    &[(affiliation_bare, affiliation_value)],
                    None,
                    None,
                    &*affiliation_renderer,
                )
                .await
            }
        });
        let first_observation = tokio::time::timeout(Duration::from_secs(3), affiliation_rx.recv())
            .await
            .expect("affiliation mutation never reached its in-transaction renderer")
            .expect("affiliation observation channel closed");
        assert_eq!(first_observation.kind, "affiliation");

        let batch_application = format!("ps-prohibited-{index}-{}", &suffix[..8]);
        let batch_pool = named_single_connection_pool(&url, &batch_application).await;
        let batch_task = tokio::spawn({
            let batch_pool = batch_pool.clone();
            let batch_owner = owner.clone();
            let batch_full = full.clone();
            async move {
                set_subscriptions_with_renderer(
                    &batch_pool,
                    node_id,
                    &batch_owner,
                    &[(batch_full, "subscribed".to_owned(), None)],
                    None,
                    &NoopMutationOutboxRenderer,
                )
                .await
            }
        });
        wait_for_named_session_lock(&pool, &batch_application).await;
        gate.release();

        assert!(matches!(
            affiliation_task.await.unwrap().unwrap(),
            SetAffiliationsOutcome::Updated {
                ref revoked_subscriptions,
                ..
            } if revoked_subscriptions.len() == 2
        ));
        assert_eq!(
            batch_task.await.unwrap().unwrap(),
            SetSubscriptionsOutcome::Forbidden
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_subscriptions
                      WHERE node_id=$1 AND split_part(jid,'/',1)=$2",
            )
            .bind(node_id)
            .bind(&bare)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_digest_queue
                      WHERE subscription_node_id=$1 AND split_part(subscriber_jid,'/',1)=$2",
            )
            .bind(node_id)
            .bind(&bare)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );

        // A defensive audience predicate must also suppress a prohibited
        // principal if maintenance SQL leaves a stale subscription row.
        set_subscription(&pool, node_id, &full, "subscribed")
            .await
            .unwrap();
        let (publish_tx, mut publish_rx) = tokio::sync::mpsc::unbounded_channel();
        let publish_renderer = RaceMutationRenderer {
            inner: crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test"),
            observations: publish_tx,
            gate: None,
        };
        assert_eq!(
            publish_items_with_renderer(
                &pool,
                &node,
                &owner,
                &[(format!("prohibited-{index}"), "<item/>".to_owned())],
                false,
                1_000_000,
                &publish_renderer,
            )
            .await
            .unwrap(),
            PublishItemsOutcome::Published
        );
        let publish_observation = tokio::time::timeout(Duration::from_secs(3), publish_rx.recv())
            .await
            .expect("defensive audience publication renderer was not called")
            .expect("defensive audience observation channel closed");
        assert!(publish_observation.recipients.is_empty());
        batch_pool.close().await;
    }
    pool.close().await;
}
