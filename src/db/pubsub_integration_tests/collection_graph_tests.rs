//! Collection graph creation, association and edge ownership.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn multi_parent_create_emits_one_recursive_audience_snapshot() {
    let (url, pool) = integration_pool(14).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("multi-owner-{suffix}@example.test");
    let subscriber = format!("multi-subscriber-{suffix}@example.test/desktop");
    let collection_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        deliver_payloads: false,
        ..PubSubNodeConfig::default()
    };
    let root_id = match create_node(
        &pool,
        &format!("multi-root-{suffix}"),
        &owner,
        &collection_config,
        20,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected root create outcome: {other:?}"),
    };
    let left_id = match create_node(
        &pool,
        &format!("multi-left-{suffix}"),
        &owner,
        &collection_config,
        20,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected left create outcome: {other:?}"),
    };
    let right_id = match create_node(
        &pool,
        &format!("multi-right-{suffix}"),
        &owner,
        &collection_config,
        20,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected right create outcome: {other:?}"),
    };
    let root = get_node_by_id(&pool, root_id).await.unwrap().unwrap();
    let left = get_node_by_id(&pool, left_id).await.unwrap().unwrap();
    let right = get_node_by_id(&pool, right_id).await.unwrap().unwrap();
    assert_eq!(
        associate_collection_child(&pool, &root, &left, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        associate_collection_child(&pool, &root, &right, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    let mut options = PubSubSubscriptionOptions::for_node_type("collection");
    options.subscription_depth = None;
    assert!(matches!(
        set_subscription_limited_with_options_and_renderer(
            &pool,
            "example.test",
            root.id,
            &northstar_xmpp_types::jid::canonical_bare_key(&subscriber).unwrap(),
            &subscriber,
            "subscribed",
            &root.node_type,
            &root.access_model,
            100,
            Some(&options),
            &format!("root-sub-{suffix}"),
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        SubscribeOutcome::Subscribed(_)
    ));

    let mut graph_blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *graph_blocker)
        .await
        .unwrap();
    let application = format!("ps-multi-create-{}", &suffix[..8]);
    let create_pool = named_single_connection_pool(&url, &application).await;
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let renderer = Arc::new(RaceMutationRenderer {
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
        observations: observation_tx,
        gate: None,
    });
    let leaf_name = format!("multi-leaf-{suffix}");
    let leaf_config = PubSubNodeConfig {
        collections: vec![left.node.clone(), right.node.clone()],
        ..PubSubNodeConfig::default()
    };
    let create_task = tokio::spawn({
        let create_pool = create_pool.clone();
        let renderer = Arc::clone(&renderer);
        let create_owner = owner.clone();
        let create_name = leaf_name.clone();
        async move {
            create_node_with_renderer(
                &create_pool,
                &create_name,
                &create_owner,
                &leaf_config,
                20,
                &*renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    graph_blocker.commit().await.unwrap();
    assert!(matches!(
        create_task.await.unwrap().unwrap(),
        CreateNodeOutcome::Created(_)
    ));
    let observation = tokio::time::timeout(Duration::from_secs(3), observation_rx.recv())
        .await
        .expect("multi-parent create renderer was not called")
        .expect("multi-parent create observation channel closed");
    assert_eq!(observation.kind, "create");
    assert_eq!(observation.recipients, vec![subscriber.clone()]);
    assert!(observation_rx.try_recv().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE event_id=$1 AND recipient_jid=$2 AND source_node=$3",
        )
        .bind(observation.event_id)
        .bind(&subscriber)
        .bind(&leaf_name)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    create_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn repeated_associate_is_idempotent_after_a_graph_lock_wait() {
    let (url, pool) = integration_pool(10).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("associate-owner-{suffix}@example.test");
    let collection_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        deliver_payloads: false,
        children_max: 1,
        ..PubSubNodeConfig::default()
    };
    let collection_id = match create_node(
        &pool,
        &format!("associate-parent-{suffix}"),
        &owner,
        &collection_config,
        10,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected collection create outcome: {other:?}"),
    };
    let child = create_default_test_node(&pool, &format!("associate-child-{suffix}"), &owner).await;
    let collection = get_node_by_id(&pool, collection_id).await.unwrap().unwrap();
    assert_eq!(
        associate_collection_child(&pool, &collection, &child, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    // At the quota boundary the first association must own exactly one
    // edge.  The graph guard must not count that same edge again when an
    // update names its immutable identities or only stamps metadata.
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query(
            "UPDATE pubsub_collection_members
                    SET collection_node_id=$1, child_node_id=$2
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    assert_eq!(
        sqlx::query(
            "UPDATE pubsub_collection_members
                    SET created_at=created_at + INTERVAL '1 microsecond'
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );

    // A move within a collection replaces its old edge rather than
    // consuming another slot.  Move it back before exercising the retry
    // path below so the second request is an actual idempotent repeat.
    let replacement =
        create_default_test_node(&pool, &format!("associate-replacement-{suffix}"), &owner).await;
    assert_eq!(
        sqlx::query(
            "UPDATE pubsub_collection_members SET child_node_id=$3
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .bind(replacement.id)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    assert_eq!(
        sqlx::query(
            "UPDATE pubsub_collection_members SET child_node_id=$3
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(replacement.id)
        .bind(child.id)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );

    // A move into a separately full collection and a second direct
    // insertion both remain database-enforced quota violations.
    let full_collection_id = match create_node(
        &pool,
        &format!("associate-full-parent-{suffix}"),
        &owner,
        &collection_config,
        10,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected full collection create outcome: {other:?}"),
    };
    let full_collection = get_node_by_id(&pool, full_collection_id)
        .await
        .unwrap()
        .unwrap();
    let full_child =
        create_default_test_node(&pool, &format!("associate-full-child-{suffix}"), &owner).await;
    assert_eq!(
        associate_collection_child(&pool, &full_collection, &full_child, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    let full_move = sqlx::query(
        "UPDATE pubsub_collection_members SET collection_node_id=$3
              WHERE collection_node_id=$1 AND child_node_id=$2",
    )
    .bind(collection.id)
    .bind(child.id)
    .bind(full_collection.id)
    .execute(&pool)
    .await
    .expect_err("moving an edge into a full collection must be rejected");
    assert_eq!(
        full_move
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514")
    );
    let overflow =
        create_default_test_node(&pool, &format!("associate-overflow-{suffix}"), &owner).await;
    assert_eq!(
        associate_collection_child(&pool, &collection, &overflow, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::LimitExceeded
    );
    let direct_overflow = sqlx::query(
        "INSERT INTO pubsub_collection_members(collection_node_id, child_node_id)
             VALUES($1, $2)",
    )
    .bind(collection.id)
    .bind(overflow.id)
    .execute(&pool)
    .await
    .expect_err("trigger must reject a second collection child at the limit");
    assert_eq!(
        direct_overflow
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514")
    );

    let mut graph_blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *graph_blocker)
        .await
        .unwrap();
    let application = format!("ps-repeat-assoc-{}", &suffix[..8]);
    let repeat_pool = named_single_connection_pool(&url, &application).await;
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let renderer = Arc::new(RaceMutationRenderer {
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
        observations: observation_tx,
        gate: None,
    });
    let repeat_task = tokio::spawn({
        let repeat_pool = repeat_pool.clone();
        let repeat_collection = collection.clone();
        let repeat_child = child.clone();
        let repeat_owner = owner.clone();
        let renderer = Arc::clone(&renderer);
        async move {
            associate_collection_child_with_renderer(
                &repeat_pool,
                &repeat_collection,
                &repeat_child,
                &repeat_owner,
                &*renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    graph_blocker.commit().await.unwrap();
    assert_eq!(
        repeat_task.await.unwrap().unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert!(observation_rx.try_recv().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    repeat_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn collection_edges_require_child_ownership_and_legacy_edges_do_not_disclose() {
    let (_, pool) = integration_pool(16).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let attacker = format!("collection-attacker-{suffix}@example.test");
    let victim = format!("collection-victim-{suffix}@example.test");
    let victim_leaf =
        create_default_test_node(&pool, &format!("collection-victim-leaf-{suffix}"), &victim).await;

    let malicious_create = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        children: vec![victim_leaf.node.clone()],
        ..PubSubNodeConfig::default()
    };
    let rejected_name = format!("collection-rejected-create-{suffix}");
    assert_eq!(
        create_node(&pool, &rejected_name, &attacker, &malicious_create, 100)
            .await
            .unwrap(),
        CreateNodeOutcome::Forbidden
    );
    assert!(get_node(&pool, &rejected_name).await.unwrap().is_none());

    let collection_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        ..PubSubNodeConfig::default()
    };
    let collection_id = match create_node(
        &pool,
        &format!("collection-existing-{suffix}"),
        &attacker,
        &collection_config,
        100,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected collection create outcome: {other:?}"),
    };
    let collection = get_node_by_id(&pool, collection_id).await.unwrap().unwrap();
    let mut malicious_update = collection.config();
    malicious_update.children = vec![victim_leaf.node.clone()];
    assert_eq!(
        update_node_config_and_graph(&pool, &collection, &attacker, &malicious_update)
            .await
            .unwrap(),
        PubSubConfigOutcome::Forbidden
    );
    assert_eq!(
        associate_collection_child(&pool, &collection, &victim_leaf, &attacker)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Forbidden
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(victim_leaf.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    let owned_leaf =
        create_default_test_node(&pool, &format!("collection-owned-leaf-{suffix}"), &attacker)
            .await;
    let mut legal_create = collection_config.clone();
    legal_create.children = vec![owned_leaf.node.clone()];
    let legal_collection_id = match create_node(
        &pool,
        &format!("collection-owned-parent-{suffix}"),
        &attacker,
        &legal_create,
        100,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("same-owner collection edge was rejected: {other:?}"),
    };
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(legal_collection_id)
        .bind(owned_leaf.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        publish_items(
            &pool,
            &owned_leaf,
            &attacker,
            &[(
                "owned-visible".to_owned(),
                "<item id='owned-visible'/>".to_owned(),
            )],
            false,
            1_000_000,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let legal_items =
        collection_visible_items(&pool, legal_collection_id, &attacker, 100, 4 * 1_048_576)
            .await
            .unwrap();
    assert_eq!(legal_items.len(), 1);
    assert!(legal_items[0].xml_payload.contains("owned-visible"));

    let restricted_config = PubSubNodeConfig {
        access_model: "whitelist".to_owned(),
        ..PubSubNodeConfig::default()
    };
    let restricted_id = match create_node(
        &pool,
        &format!("collection-restricted-leaf-{suffix}"),
        &victim,
        &restricted_config,
        100,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected restricted leaf create outcome: {other:?}"),
    };
    let restricted = get_node_by_id(&pool, restricted_id).await.unwrap().unwrap();
    assert_eq!(
        publish_items(
            &pool,
            &restricted,
            &victim,
            &[(
                "private-first".to_owned(),
                "<item id='private-first'/>".to_owned(),
            )],
            false,
            1_000_000,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let subscriber = format!("{attacker}/desktop");
    let mut options = PubSubSubscriptionOptions::for_node_type("collection");
    options.subscription_type = "items".to_owned();
    assert!(matches!(
        set_subscription_limited_with_options_and_renderer(
            &pool,
            "example.test",
            collection.id,
            &attacker,
            &subscriber,
            "subscribed",
            &collection.node_type,
            &collection.access_model,
            100,
            Some(&options),
            &format!("collection-legacy-sub-{suffix}"),
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        SubscribeOutcome::Subscribed(_)
    ));
    // Model an edge created by an older vulnerable server or a privileged
    // operator. Read and notification paths must remain fail-closed even
    // when the historical graph cannot be trusted.
    sqlx::query(
        "INSERT INTO pubsub_collection_members(collection_node_id,child_node_id)
             VALUES($1,$2)",
    )
    .bind(collection.id)
    .bind(restricted.id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        collection_visible_items(&pool, collection.id, &attacker, 100, 4 * 1_048_576)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        collection_visible_items(&pool, collection.id, &victim, 100, 4 * 1_048_576)
            .await
            .unwrap()
            .len(),
        1
    );

    sqlx::query("DELETE FROM pubsub_event_outbox WHERE source_node=$1")
        .bind(&restricted.node)
        .execute(&pool)
        .await
        .unwrap();
    let service = crate::services::pubsub::PubSubService::new(pool.clone(), "example.test");
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &restricted,
            &victim,
            &[(
                "private-second".to_owned(),
                "<item id='private-second'/>".to_owned(),
            )],
            false,
            1_000_000,
            &service,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE source_node=$1 AND recipient_jid=$2",
        )
        .bind(&restricted.node)
        .bind(&subscriber)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "ancestor subscriber crossed the restricted source-child ACL"
    );
    assert!(matches!(
        set_affiliations_with_renderer(
            &pool,
            restricted.id,
            &victim,
            &[(attacker.clone(), "member".to_owned())],
            None,
            None,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &restricted,
            &victim,
            &[(
                "private-authorized".to_owned(),
                "<item id='private-authorized'/>".to_owned(),
            )],
            false,
            1_000_000,
            &service,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE source_node=$1 AND recipient_jid=$2",
        )
        .bind(&restricted.node)
        .bind(&subscriber)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1,
        "authorized ancestor subscriber did not receive the child event"
    );
    assert_eq!(
        collection_visible_items(&pool, collection.id, &attacker, 100, 4 * 1_048_576)
            .await
            .unwrap()
            .len(),
        3
    );

    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn collection_edge_insert_linearizes_after_child_owner_revocation() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let attacker = format!("edge-race-attacker-{suffix}@example.test");
    let remaining_owner = format!("edge-race-owner-{suffix}@example.test");
    let child =
        create_default_test_node(&pool, &format!("edge-race-child-{suffix}"), &attacker).await;
    assert!(matches!(
        set_affiliations_with_renderer(
            &pool,
            child.id,
            &attacker,
            &[(remaining_owner.clone(), "owner".to_owned())],
            None,
            None,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    let collection_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        ..PubSubNodeConfig::default()
    };
    let collection_id = match create_node(
        &pool,
        &format!("edge-race-parent-{suffix}"),
        &attacker,
        &collection_config,
        100,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected race parent create outcome: {other:?}"),
    };
    let collection = get_node_by_id(&pool, collection_id).await.unwrap().unwrap();

    let mut revocation = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(child.id)
        .execute(&mut *revocation)
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM pubsub_affiliations
              WHERE node_id=$1 AND jid=$2 AND affiliation='owner'",
    )
    .bind(child.id)
    .bind(&attacker)
    .execute(&mut *revocation)
    .await
    .unwrap();

    let application = format!("ps-edge-owner-race-{}", &suffix[..8]);
    let contender_pool = named_single_connection_pool(&url, &application).await;
    let contender = tokio::spawn({
        let contender_pool = contender_pool.clone();
        let collection = collection.clone();
        let child = child.clone();
        let attacker = attacker.clone();
        async move {
            associate_collection_child_with_renderer(
                &contender_pool,
                &collection,
                &child,
                &attacker,
                &NoopMutationOutboxRenderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    revocation.commit().await.unwrap();
    assert_eq!(
        contender.await.unwrap().unwrap(),
        CollectionUpdateOutcome::Forbidden
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    contender_pool.close().await;
    pool.close().await;
}
