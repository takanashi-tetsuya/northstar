//! Linearizable publish, retract and subscription audiences.

use super::*;

struct FailingRetractRenderer;

impl PubSubMutationOutboxRenderer for FailingRetractRenderer {
    fn render_retract(
        &self,
        _: &PubSubNode,
        _: &[String],
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<db::PubSubOutboxInsert>> {
        anyhow::bail!("intentional renderer failure")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn publish_audience_is_linearizable_with_unsubscribe() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("publish-owner-{suffix}@example.test");
    let subscriber = format!("publish-sub-{suffix}@example.test/phone");
    let node = create_default_test_node(&pool, &format!("publish-audience-{suffix}"), &owner).await;
    let subscription =
        subscribe_for_race(&pool, &node, &subscriber, &format!("sub-{suffix}")).await;

    // Publication-first: the synchronous renderer is reached only after
    // the node/subscription authority is locked. Unsubscribe must wait,
    // and the old subscriber is durably part of this event snapshot.
    let gate = Arc::new(RenderGate::default());
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let renderer = Arc::new(RaceMutationRenderer {
        inner: PubSubEventRenderer::new("example.test"),
        observations: observation_tx,
        gate: Some(Arc::clone(&gate)),
    });
    let publish_pool = pool.clone();
    let publish_node = node.clone();
    let publish_owner = owner.clone();
    let publish_renderer = Arc::clone(&renderer);
    let publish = tokio::spawn(async move {
        publish_items_with_renderer(
            &publish_pool,
            &publish_node,
            &publish_owner,
            &[(
                "first".to_owned(),
                "<item id='first'><value xmlns='urn:test'>one</value></item>".to_owned(),
            )],
            false,
            1_000_000,
            &*publish_renderer,
        )
        .await
    });
    let first = tokio::time::timeout(Duration::from_secs(3), observation_rx.recv())
        .await
        .expect("publication never reached its audience snapshot")
        .expect("publication observer closed");
    assert_eq!(first.kind, "items");
    assert_eq!(first.recipients, vec![subscriber.clone()]);
    let unsubscribe_pool = pool.clone();
    let unsubscribe_subscriber = subscriber.clone();
    let unsubscribe_requester = northstar_xmpp_types::jid::canonical_bare_key(&subscriber).unwrap();
    let unsubscribe_subid = subscription.subid.clone();
    let unsubscribe_node_id = node.id;
    let mut unsubscribe = tokio::spawn(async move {
        unsubscribe_checked_with_outbox(
            &unsubscribe_pool,
            unsubscribe_node_id,
            &unsubscribe_requester,
            &unsubscribe_subscriber,
            &unsubscribe_subid,
            &[],
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut unsubscribe)
            .await
            .is_err(),
        "unsubscribe bypassed the publication audience lock"
    );
    gate.release();
    assert_eq!(
        publish.await.unwrap().unwrap(),
        PublishItemsOutcome::Published
    );
    assert_eq!(
        unsubscribe.await.unwrap().unwrap(),
        UnsubscribeOutcome::Unsubscribed
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE event_id=$1 AND recipient_jid=$2",
        )
        .bind(first.event_id)
        .bind(&subscriber)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    // Revocation-first: hold the node lock after deleting the row but
    // before commit. Publication must wait and then snapshot an empty
    // audience; it cannot revive the pre-delete principal.
    let resubscribed =
        subscribe_for_race(&pool, &node, &subscriber, &format!("sub2-{suffix}")).await;
    let mut revoke = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(node.id)
        .execute(&mut *revoke)
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM pubsub_subscriptions
              WHERE node_id=$1 AND jid=$2 AND subid=$3",
    )
    .bind(node.id)
    .bind(&subscriber)
    .bind(&resubscribed.subid)
    .execute(&mut *revoke)
    .await
    .unwrap();
    let application = format!("ps-publish-{}", &suffix[..10]);
    let waiting_pool = named_single_connection_pool(&url, &application).await;
    let (second_tx, mut second_rx) = tokio::sync::mpsc::unbounded_channel();
    let second_renderer = Arc::new(RaceMutationRenderer {
        inner: PubSubEventRenderer::new("example.test"),
        observations: second_tx,
        gate: None,
    });
    let second_node = node.clone();
    let second_owner = owner.clone();
    let second_renderer_task = Arc::clone(&second_renderer);
    let second = tokio::spawn({
        let waiting_pool = waiting_pool.clone();
        async move {
            publish_items_with_renderer(
                &waiting_pool,
                &second_node,
                &second_owner,
                &[("second".to_owned(), "<item id='second'/>".to_owned())],
                false,
                1_000_000,
                &*second_renderer_task,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    revoke.commit().await.unwrap();
    assert_eq!(
        second.await.unwrap().unwrap(),
        PublishItemsOutcome::Published
    );
    let second_observation = tokio::time::timeout(Duration::from_secs(3), second_rx.recv())
        .await
        .expect("second publication renderer was not called")
        .expect("second publication observer closed");
    assert!(second_observation.recipients.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1",)
            .bind(second_observation.event_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn retract_graph_outcast_and_last_item_snapshots_are_linearizable() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let short = &suffix[..10];
    let owner = format!("generic-owner-{suffix}@example.test");
    let subscriber = format!("generic-sub-{suffix}@example.test/phone");
    let collection_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        deliver_payloads: false,
        ..PubSubNodeConfig::default()
    };
    let collection_id = match create_node(
        &pool,
        &format!("generic-parent-{suffix}"),
        &owner,
        &collection_config,
        20,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected collection create outcome: {other:?}"),
    };
    let collection = get_node_by_id(&pool, collection_id).await.unwrap().unwrap();
    let leaf = create_default_test_node(&pool, &format!("generic-leaf-{suffix}"), &owner).await;
    // XEP-0248 defaults a collection subscription to `nodes`, which
    // receives association/configuration notifications only. This race
    // proves item retraction delivery through a direct collection edge,
    // therefore request the explicit `items` subscription type while
    // retaining the one-hop depth under test.
    let mut collection_options = PubSubSubscriptionOptions::for_node_type("collection");
    collection_options.subscription_type = "items".to_owned();
    assert!(matches!(
        set_subscription_limited_with_options_and_renderer(
            &pool,
            "example.test",
            collection.id,
            &northstar_xmpp_types::jid::canonical_bare_key(&subscriber).unwrap(),
            &subscriber,
            "subscribed",
            &collection.node_type,
            &collection.access_model,
            100,
            Some(&collection_options),
            &format!("parent-sub-{suffix}"),
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        SubscribeOutcome::Subscribed(_)
    ));
    let service = PubSubEventRenderer::new("example.test");
    assert_eq!(
        associate_collection_child_with_renderer(&pool, &collection, &leaf, &owner, &service,)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    sqlx::query("DELETE FROM pubsub_event_outbox WHERE source_node=ANY($1)")
        .bind(vec![collection.node.clone(), leaf.node.clone()])
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &leaf,
            &owner,
            &[(
                "graph-first".to_owned(),
                "<item id='graph-first'/>".to_owned()
            )],
            false,
            1_000_000,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );

    // Graph-change first: the retract waits for the graph authority lock,
    // then snapshots after dissociation and must not retain the former
    // ancestor subscription.
    let mut graph_change = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *graph_change)
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM pubsub_collection_members WHERE collection_node_id=$1 AND child_node_id=$2",
    )
    .bind(collection.id)
    .bind(leaf.id)
    .execute(&mut *graph_change)
    .await
    .unwrap();
    let graph_first_application = format!("ps-graph-first-{short}");
    let graph_first_pool = named_single_connection_pool(&url, &graph_first_application).await;
    let (graph_first_tx, mut graph_first_rx) = tokio::sync::mpsc::unbounded_channel();
    let graph_first_renderer = Arc::new(RaceMutationRenderer {
        inner: PubSubEventRenderer::new("example.test"),
        observations: graph_first_tx,
        gate: None,
    });
    let graph_first_task = tokio::spawn({
        let graph_first_pool = graph_first_pool.clone();
        let graph_first_renderer = Arc::clone(&graph_first_renderer);
        let owner = owner.clone();
        let leaf_id = leaf.id;
        async move {
            retract_items_with_renderer(
                &graph_first_pool,
                leaf_id,
                &["graph-first".to_owned()],
                &owner,
                true,
                &*graph_first_renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &graph_first_application).await;
    graph_change.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), graph_first_task)
            .await
            .expect("graph-first retraction did not return after graph release")
            .expect("graph-first retraction task panicked")
            .unwrap(),
        RetractItemsOutcome::Retracted
    );
    let graph_first_observation =
        await_mutation_observation(&mut graph_first_rx, "graph-first retraction").await;
    assert_eq!(graph_first_observation.kind, "retract");
    assert!(graph_first_observation.recipients.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1",)
            .bind(graph_first_observation.event_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    // Re-associate, then hold the retract renderer. The mutation owns the
    // graph and node authority, so concurrent dissociation must wait; the
    // old inherited subscriber appears exactly once in the committed event.
    assert_eq!(
        associate_collection_child_with_renderer(
            &pool,
            &collection,
            &leaf,
            &owner,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &leaf,
            &owner,
            &[(
                "mutation-first".to_owned(),
                "<item id='mutation-first'/>".to_owned()
            )],
            false,
            1_000_000,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let gate = Arc::new(RenderGate::default());
    let (mutation_tx, mut mutation_rx) = tokio::sync::mpsc::unbounded_channel();
    let mutation_renderer = Arc::new(RaceMutationRenderer {
        inner: PubSubEventRenderer::new("example.test"),
        observations: mutation_tx,
        gate: Some(Arc::clone(&gate)),
    });
    let mutation_task = tokio::spawn({
        let pool = pool.clone();
        let renderer = Arc::clone(&mutation_renderer);
        let owner = owner.clone();
        let leaf_id = leaf.id;
        async move {
            retract_items_with_renderer(
                &pool,
                leaf_id,
                &["mutation-first".to_owned()],
                &owner,
                true,
                &*renderer,
            )
            .await
        }
    });
    let mutation_observation =
        await_mutation_observation(&mut mutation_rx, "mutation-first retraction").await;
    assert_eq!(mutation_observation.recipients, vec![subscriber.clone()]);
    let graph_wait_application = format!("ps-graph-wait-{short}");
    let graph_wait_pool = named_single_connection_pool(&url, &graph_wait_application).await;
    let dissociate = tokio::spawn({
        let graph_wait_pool = graph_wait_pool.clone();
        let collection = collection.clone();
        let leaf = leaf.clone();
        let owner = owner.clone();
        async move {
            dissociate_collection_child_with_renderer(
                &graph_wait_pool,
                &collection,
                &leaf,
                &owner,
                &NoopMutationOutboxRenderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &graph_wait_application).await;
    gate.release();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), mutation_task)
            .await
            .expect("mutation-first retraction did not return after renderer release")
            .expect("mutation-first retraction task panicked")
            .unwrap(),
        RetractItemsOutcome::Retracted
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), dissociate)
            .await
            .expect("graph dissociation did not return after retraction commit")
            .expect("graph dissociation task panicked")
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1 AND recipient_jid=$2",
        )
        .bind(mutation_observation.event_id)
        .bind(&subscriber)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    // An outcast transition is authoritative before a later mutation.
    // Removing every addressed subscription in the affiliation transaction
    // prevents the next event from reviving a stale recipient.
    let outcast = set_affiliations_with_renderer(
        &pool,
        collection.id,
        &owner,
        &[(
            northstar_xmpp_types::jid::canonical_bare_key(&subscriber).unwrap(),
            "outcast".to_owned(),
        )],
        None,
        None,
        &NoopMutationOutboxRenderer,
    )
    .await
    .unwrap();
    assert!(matches!(
        outcast,
        SetAffiliationsOutcome::Updated {
            revoked_subscriptions,
            approved_subscriptions,
        } if revoked_subscriptions.len() == 1 && approved_subscriptions.is_empty()
    ));
    let (outcast_tx, mut outcast_rx) = tokio::sync::mpsc::unbounded_channel();
    let outcast_renderer = RaceMutationRenderer {
        inner: PubSubEventRenderer::new("example.test"),
        observations: outcast_tx,
        gate: None,
    };
    assert_eq!(
        associate_collection_child_with_renderer(
            &pool,
            &collection,
            &leaf,
            &owner,
            &outcast_renderer,
        )
        .await
        .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    let post_outcast =
        await_mutation_observation(&mut outcast_rx, "post-outcast association").await;
    assert_eq!(post_outcast.kind, "collection");
    assert!(post_outcast.recipients.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1",)
            .bind(post_outcast.event_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    // Renderer failure aborts both the mutation and its outbox projection.
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &leaf,
            &owner,
            &[("rollback".to_owned(), "<item id='rollback'/>".to_owned())],
            false,
            1_000_000,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    assert!(retract_items_with_renderer(
        &pool,
        leaf.id,
        &["rollback".to_owned()],
        &owner,
        true,
        &FailingRetractRenderer,
    )
    .await
    .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_items WHERE node_id=$1 AND item_id='rollback'",
        )
        .bind(leaf.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    // Owner batch subscription reads the retained item while holding the
    // same node lock and emits one transition plus one last-item row.
    let last_jid = format!("last-{suffix}@example.test/tablet");
    let (last_tx, mut last_rx) = tokio::sync::mpsc::unbounded_channel();
    let last_renderer = RaceMutationRenderer {
        inner: PubSubEventRenderer::new("example.test"),
        observations: last_tx,
        gate: None,
    };
    let batch = set_subscriptions_with_renderer(
        &pool,
        leaf.id,
        &owner,
        &[(last_jid.clone(), "subscribed".to_owned(), None)],
        None,
        &last_renderer,
    )
    .await
    .unwrap();
    assert!(matches!(batch, SetSubscriptionsOutcome::Updated(_)));
    let last_observation = await_mutation_observation(&mut last_rx, "last-item subscription").await;
    assert_eq!(last_observation.kind, "subscription");
    assert_eq!(last_observation.recipients, vec![last_jid.clone()]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1 AND recipient_jid=$2",
        )
        .bind(last_observation.event_id)
        .bind(&last_jid)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1 AND recipient_jid=$2 AND payload_xml LIKE '%<items%'",
            )
            .bind(&leaf.node)
            .bind(&last_jid)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
    let ordered_payloads = sqlx::query_scalar::<_, String>(
        "SELECT payload_xml FROM pubsub_event_outbox
              WHERE source_node=$1 AND recipient_jid=$2
              ORDER BY event_sequence,delivery_id",
    )
    .bind(&leaf.node)
    .bind(&last_jid)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(ordered_payloads.len(), 2);
    assert!(ordered_payloads[0].contains("<subscription"));
    assert!(ordered_payloads[1].contains("<items"));

    graph_first_pool.close().await;
    graph_wait_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mutation_audiences_are_serialized_with_subscribe_and_unsubscribe() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let short = &suffix[..10];
    let owner = format!("race-owner-{suffix}@example.test");
    let purge_node = create_default_test_node(&pool, &format!("race-purge-{suffix}"), &owner).await;
    let config_node =
        create_default_test_node(&pool, &format!("race-config-{suffix}"), &owner).await;
    let delete_node =
        create_default_test_node(&pool, &format!("race-delete-{suffix}"), &owner).await;

    // Subscribe-first ordering: the subscriber transaction owns the node
    // row while it is deliberately stalled on its actor lock. The purge
    // must queue behind that row and include both the old and newly
    // committed subscribers in one immutable outbox event.
    let old_purge_subscriber = format!("purge-old-{suffix}@example.test/desktop");
    let new_purge_subscriber = format!("purge-new-{suffix}@example.test/phone");
    subscribe_for_race(
        &pool,
        &purge_node,
        &old_purge_subscriber,
        &format!("old-{suffix}"),
    )
    .await;
    let mut subscriber_actor_blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 2))")
        .bind(&new_purge_subscriber)
        .execute(&mut *subscriber_actor_blocker)
        .await
        .unwrap();
    let subscribe_application = format!("ps-sub-{short}");
    let subscribe_pool = named_single_connection_pool(&url, &subscribe_application).await;
    let subscribe_node = purge_node.clone();
    let subscribe_jid = new_purge_subscriber.clone();
    let subscribe_requester =
        northstar_xmpp_types::jid::canonical_bare_key(&subscribe_jid).unwrap();
    let subscribe_task = tokio::spawn({
        let subscribe_pool = subscribe_pool.clone();
        let requested_subid = format!("new-{suffix}");
        async move {
            set_subscription_limited_with_options_and_outbox(
                &subscribe_pool,
                "example.test",
                subscribe_node.id,
                &subscribe_requester,
                &subscribe_jid,
                "subscribed",
                &subscribe_node.node_type,
                &subscribe_node.access_model,
                100,
                None,
                &requested_subid,
                &[],
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &subscribe_application).await;

    let purge_application = format!("ps-purge-{short}");
    let purge_pool = named_single_connection_pool(&url, &purge_application).await;
    let (purge_observation_tx, mut purge_observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let purge_renderer = Arc::new(RaceMutationRenderer {
        inner: PubSubEventRenderer::new("example.test"),
        observations: purge_observation_tx,
        gate: None,
    });
    let purge_task = tokio::spawn({
        let purge_pool = purge_pool.clone();
        let purge_renderer = Arc::clone(&purge_renderer);
        let purge_owner = owner.clone();
        async move {
            purge_node_as_owner_with_outbox(
                &purge_pool,
                purge_node.id,
                &purge_owner,
                &*purge_renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &purge_application).await;
    subscriber_actor_blocker.commit().await.unwrap();
    assert!(matches!(
        subscribe_task.await.unwrap().unwrap(),
        SubscribeOutcome::Subscribed(_)
    ));
    assert_eq!(
        purge_task.await.unwrap().unwrap(),
        OwnerMutationOutcome::Applied
    );
    let purge_observation =
        tokio::time::timeout(Duration::from_secs(3), purge_observation_rx.recv())
            .await
            .expect("purge renderer was not called")
            .expect("purge observation channel closed");
    assert_eq!(purge_observation.kind, "purge");
    let mut expected_purge_recipients =
        vec![new_purge_subscriber.clone(), old_purge_subscriber.clone()];
    expected_purge_recipients.sort();
    assert_eq!(purge_observation.recipients, expected_purge_recipients);
    let purge_rows = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT recipient_jid,event_id FROM pubsub_event_outbox
              WHERE source_node=$1 AND payload_xml LIKE '%<purge%'
              ORDER BY recipient_jid",
    )
    .bind(&purge_node.node)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        purge_rows
            .iter()
            .map(|(recipient, _)| recipient.clone())
            .collect::<Vec<_>>(),
        expected_purge_recipients
    );
    assert!(purge_rows
        .iter()
        .all(|(_, event_id)| *event_id == purge_observation.event_id));

    // Unsubscribe-first ordering: hold the outbox stream row after the
    // unsubscribe has locked the node and removed the subscription. The
    // configuration transaction must wait, then snapshot the committed
    // empty audience rather than the stale pre-unsubscribe row.
    let config_subscriber = format!("config-{suffix}@example.test/tablet");
    let config_subscription = subscribe_for_race(
        &pool,
        &config_node,
        &config_subscriber,
        &format!("config-{suffix}"),
    )
    .await;
    let unsubscribe_marker = db::PubSubOutboxInsert::new(
            Uuid::new_v4(),
            format!("test-unsubscribe:{}", config_node.id),
            db::PubSubOutboxSource::PubSub,
            db::PubSubOutboxDeliveryKind::PubSubDirect,
            config_subscriber.clone(),
            format!("<message xmlns='jabber:client' to='{config_subscriber}'><unsubscribe-fence xmlns='urn:test:pubsub-race'/></message>"),
            None,
            None,
            &config_node.node,
            None,
            Utc::now(),
        )
        .unwrap();
    let mut stream_blocker = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO pubsub_event_streams(ordering_key,next_sequence)
             VALUES($1,1) ON CONFLICT(ordering_key) DO NOTHING",
    )
    .bind(&unsubscribe_marker.ordering_key)
    .execute(&mut *stream_blocker)
    .await
    .unwrap();
    sqlx::query("SELECT ordering_key FROM pubsub_event_streams WHERE ordering_key=$1 FOR UPDATE")
        .bind(&unsubscribe_marker.ordering_key)
        .execute(&mut *stream_blocker)
        .await
        .unwrap();
    let unsubscribe_application = format!("ps-unsub-{short}");
    let unsubscribe_pool = named_single_connection_pool(&url, &unsubscribe_application).await;
    let unsubscribe_task = tokio::spawn({
        let unsubscribe_pool = unsubscribe_pool.clone();
        let config_subscriber = config_subscriber.clone();
        let config_subid = config_subscription.subid.clone();
        let config_requester =
            northstar_xmpp_types::jid::canonical_bare_key(&config_subscriber).unwrap();
        let unsubscribe_outbox = vec![unsubscribe_marker.clone()];
        async move {
            unsubscribe_checked_with_outbox(
                &unsubscribe_pool,
                config_node.id,
                &config_requester,
                &config_subscriber,
                &config_subid,
                &unsubscribe_outbox,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &unsubscribe_application).await;

    let config_application = format!("ps-config-{short}");
    let config_pool = named_single_connection_pool(&url, &config_application).await;
    let (config_observation_tx, mut config_observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let config_renderer = Arc::new(RaceMutationRenderer {
        inner: PubSubEventRenderer::new("example.test"),
        observations: config_observation_tx,
        gate: None,
    });
    let expected_config = config_node.config();
    let mut next_config = config_node.config();
    next_config.title = Some("committed-after-unsubscribe".to_owned());
    let config_task = tokio::spawn({
        let config_pool = config_pool.clone();
        let config_renderer = Arc::clone(&config_renderer);
        let config_owner = owner.clone();
        let config_node_for_update = config_node.clone();
        async move {
            update_node_config_and_graph_with_outbox(
                &config_pool,
                &config_node_for_update,
                &config_owner,
                &expected_config,
                &next_config,
                &*config_renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &config_application).await;
    stream_blocker.commit().await.unwrap();
    assert_eq!(
        unsubscribe_task.await.unwrap().unwrap(),
        UnsubscribeOutcome::Unsubscribed
    );
    assert_eq!(
        config_task.await.unwrap().unwrap(),
        PubSubConfigOutcome::Updated
    );
    let config_observation =
        tokio::time::timeout(Duration::from_secs(3), config_observation_rx.recv())
            .await
            .expect("configuration renderer was not called")
            .expect("configuration observation channel closed");
    assert_eq!(config_observation.kind, "configuration");
    assert!(config_observation.recipients.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1",)
            .bind(config_observation.event_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0,
        "a post-unsubscribe configuration snapshot must not create a stale delivery"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE delivery_id=$1 AND payload_xml LIKE '%unsubscribe-fence%'",
        )
        .bind(unsubscribe_marker.delivery_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1,
        "the unsubscribe state change and its own outbox projection must commit together"
    );

    // Mutation-first ordering: the delete renderer is a synchronous
    // in-transaction gate. Once it has observed the old subscription, a
    // concurrent unsubscribe must wait for deletion and then report that
    // the node no longer exists. The captured delete remains durable.
    let delete_subscriber = format!("delete-{suffix}@example.test/mobile");
    let delete_subscription = subscribe_for_race(
        &pool,
        &delete_node,
        &delete_subscriber,
        &format!("delete-{suffix}"),
    )
    .await;
    let delete_gate = Arc::new(RenderGate::default());
    let (delete_observation_tx, mut delete_observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let delete_renderer = Arc::new(RaceMutationRenderer {
        inner: PubSubEventRenderer::new("example.test"),
        observations: delete_observation_tx,
        gate: Some(Arc::clone(&delete_gate)),
    });
    let delete_application = format!("ps-delete-{short}");
    let delete_pool = named_single_connection_pool(&url, &delete_application).await;
    let delete_task = tokio::spawn({
        let delete_pool = delete_pool.clone();
        let delete_renderer = Arc::clone(&delete_renderer);
        let delete_owner = owner.clone();
        async move {
            delete_node_as_owner_with_redirect_and_outbox(
                &delete_pool,
                delete_node.id,
                &delete_owner,
                None,
                &*delete_renderer,
            )
            .await
        }
    });
    let delete_observation =
        tokio::time::timeout(Duration::from_secs(3), delete_observation_rx.recv())
            .await
            .expect("delete renderer was not called")
            .expect("delete observation channel closed");
    assert_eq!(delete_observation.kind, "delete");
    assert_eq!(
        delete_observation.recipients,
        vec![delete_subscriber.clone()]
    );

    let delete_unsubscribe_application = format!("ps-del-un-{short}");
    let delete_unsubscribe_pool =
        named_single_connection_pool(&url, &delete_unsubscribe_application).await;
    let delete_unsubscribe_task = tokio::spawn({
        let delete_unsubscribe_pool = delete_unsubscribe_pool.clone();
        let delete_subscriber = delete_subscriber.clone();
        let delete_subid = delete_subscription.subid.clone();
        let delete_requester =
            northstar_xmpp_types::jid::canonical_bare_key(&delete_subscriber).unwrap();
        async move {
            unsubscribe_checked_with_outbox(
                &delete_unsubscribe_pool,
                delete_node.id,
                &delete_requester,
                &delete_subscriber,
                &delete_subid,
                &[],
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &delete_unsubscribe_application).await;
    delete_gate.release();
    assert_eq!(
        delete_task.await.unwrap().unwrap(),
        OwnerMutationOutcome::Applied
    );
    assert_eq!(
        delete_unsubscribe_task.await.unwrap().unwrap(),
        UnsubscribeOutcome::NotFound
    );
    let delete_rows = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT recipient_jid,event_id FROM pubsub_event_outbox
              WHERE source_node=$1 AND payload_xml LIKE '%<delete%'
              ORDER BY recipient_jid",
    )
    .bind(&delete_node.node)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(delete_rows.len(), 1);
    assert_eq!(delete_rows[0].0, delete_subscriber);
    assert_eq!(delete_rows[0].1, delete_observation.event_id);

    subscribe_pool.close().await;
    purge_pool.close().await;
    unsubscribe_pool.close().await;
    config_pool.close().await;
    delete_pool.close().await;
    delete_unsubscribe_pool.close().await;
    pool.close().await;
}
