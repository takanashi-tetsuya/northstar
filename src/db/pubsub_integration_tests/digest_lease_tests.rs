//! Digest claims, leases and graph-lock atomicity.

use super::*;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn digest_idle_preflight_preserves_leases_and_authority_errors() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    // One connection owns this entire temporary namespace. Pin every
    // replacement connection too: losing the temporary table must fail
    // instead of falling back to a persistent application relation.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO pg_temp, pg_catalog")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TEMP TABLE pubsub_digest_queue (
            id UUID PRIMARY KEY, subscription_node_id UUID NOT NULL,
            subscriber_jid TEXT NOT NULL, event_xml TEXT NOT NULL,
            show_values TEXT[], deliver_after TIMESTAMPTZ NOT NULL,
            claimed_until TIMESTAMPTZ
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(claim_due_pubsub_digests(&pool, 10)
        .await
        .unwrap()
        .is_empty());

    let node = Uuid::new_v4();
    let future = Uuid::new_v4();
    let leased = Uuid::new_v4();
    let unclaimed = Uuid::new_v4();
    let expired = Uuid::new_v4();
    sqlx::query("INSERT INTO pubsub_digest_queue
            (id,subscription_node_id,subscriber_jid,event_xml,deliver_after,claimed_until)
            VALUES ($1,$3,'reader@example.test','<future/>',NOW()+INTERVAL '1 hour',NULL),
                   ($2,$3,'reader@example.test','<leased/>',NOW()-INTERVAL '1 hour',NOW()+INTERVAL '1 hour')")
            .bind(future).bind(leased).bind(node)
            .execute(&pool).await.unwrap();
    assert!(claim_due_pubsub_digests(&pool, 10)
        .await
        .unwrap()
        .is_empty());
    sqlx::query("INSERT INTO pubsub_digest_queue
            (id,subscription_node_id,subscriber_jid,event_xml,deliver_after,claimed_until)
            VALUES ($1,$3,'reader@example.test','<unclaimed/>',NOW()-INTERVAL '1 minute',NULL),
                   ($2,$3,'reader@example.test','<expired/>',NOW()-INTERVAL '1 minute',NOW()-INTERVAL '1 second')")
            .bind(unclaimed).bind(expired).bind(node)
            .execute(&pool).await.unwrap();
    let claimed = claim_due_pubsub_digests(&pool, 10).await.unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(
        claimed[0].ids.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([unclaimed, expired])
    );
    assert!(claim_due_pubsub_digests(&pool, 10)
        .await
        .unwrap()
        .is_empty());
    let protected: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_digest_queue WHERE id=ANY($1) AND claimed_until>NOW()",
    )
    .bind(vec![unclaimed, expired, leased])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(protected, 3);

    // A preceding empty result is not cached across worker ticks.
    sqlx::query(
        "UPDATE pubsub_digest_queue SET deliver_after=NOW()-INTERVAL '1 second' WHERE id=$1",
    )
    .bind(future)
    .execute(&pool)
    .await
    .unwrap();
    let newly_due = claim_due_pubsub_digests(&pool, 10).await.unwrap();
    assert_eq!(newly_due.len(), 1);
    assert_eq!(newly_due[0].ids, vec![future]);

    // Use a built-in read-only role on this temporary relation. Empty
    // queues must still reject lost UPDATE authority. RESET precedes
    // assertions so the connection never retains the borrowed role.
    sqlx::query("TRUNCATE pubsub_digest_queue")
        .execute(&pool)
        .await
        .unwrap();
    // Production uses a persistent table. This temporary-only fixture
    // checks the explicit mode guard, not PostgreSQL's separate allowance
    // for writes to temporary tables in read-only transactions.
    sqlx::query("SET default_transaction_read_only = on")
        .execute(&pool)
        .await
        .unwrap();
    let read_only = claim_due_pubsub_digests(&pool, 10).await;
    sqlx::query("SET default_transaction_read_only = off")
        .execute(&pool)
        .await
        .unwrap();
    assert!(read_only
        .unwrap_err()
        .to_string()
        .contains("writable transaction"));
    assert!(claim_due_pubsub_digests(&pool, 10)
        .await
        .unwrap()
        .is_empty());
    sqlx::query("GRANT SELECT ON pubsub_digest_queue TO pg_read_all_data")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("SET ROLE pg_read_all_data")
        .execute(&pool)
        .await
        .unwrap();
    let denied = claim_due_pubsub_digests(&pool, 10).await;
    sqlx::query("RESET ROLE").execute(&pool).await.unwrap();
    assert!(denied.unwrap_err().to_string().contains("UPDATE authority"));

    sqlx::query("DROP TABLE pubsub_digest_queue")
        .execute(&pool)
        .await
        .unwrap();
    assert!(claim_due_pubsub_digests(&pool, 10).await.is_err());
    let held = pool.acquire().await.unwrap();
    let busy = tokio::time::timeout(Duration::from_secs(4), claim_due_pubsub_digests(&pool, 10))
        .await
        .expect("the read-only preflight must bound its pool wait")
        .unwrap_err();
    assert!(busy.downcast_ref::<PubSubMutationBusy>().is_some());
    drop(held);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn graph_cycle_subscription_quota_and_digest_claim_are_atomic() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}@example.test");
    let subscriber = format!("subscriber-{suffix}@example.test");
    let first_name = format!("collection-{suffix}-a");
    let second_name = format!("collection-{suffix}-b");
    let collection = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        ..PubSubNodeConfig::default()
    };
    let first_id = match create_node(&pool, &first_name, &owner, &collection, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected create outcome: {other:?}"),
    };
    let second_id = match create_node(&pool, &second_name, &owner, &collection, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected create outcome: {other:?}"),
    };
    let first = get_node_by_id(&pool, first_id).await.unwrap().unwrap();
    let second = get_node_by_id(&pool, second_id).await.unwrap().unwrap();
    assert_eq!(
        associate_collection_child(&pool, &first, &second, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        associate_collection_child(&pool, &second, &first, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Cycle
    );

    let second_owner = format!("owner2-{suffix}@example.test");
    assert!(matches!(
        set_affiliations(
            &pool,
            first_id,
            &[(second_owner.clone(), "owner".to_owned())],
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    let remove_first = vec![(owner.clone(), "none".to_owned())];
    let remove_second = vec![(second_owner.clone(), "none".to_owned())];
    let (left, right) = tokio::join!(
        set_affiliations(&pool, first_id, &remove_first),
        set_affiliations(&pool, first_id, &remove_second),
    );
    assert_eq!(
        [left.unwrap(), right.unwrap()]
            .into_iter()
            .filter(|outcome| matches!(outcome, SetAffiliationsOutcome::Updated { .. }))
            .count(),
        1
    );
    let remaining_owner = node_metadata(&pool, first_id)
        .await
        .unwrap()
        .owners
        .remove(0);
    assert!(matches!(
        set_affiliations(
            &pool,
            second_id,
            &[(remaining_owner.clone(), "owner".to_owned())],
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    assert_eq!(
        dissociate_collection_child(&pool, &first, &second, &remaining_owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        dissociate_collection_child(&pool, &first, &second, &remaining_owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::NotAssociated
    );
    assert_eq!(
        associate_collection_child(&pool, &first, &second, &remaining_owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );

    let third_name = format!("collection-{suffix}-c");
    let leaf_path_name = format!("path-leaf-{suffix}");
    let third_id = match create_node(&pool, &third_name, &remaining_owner, &collection, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected third collection outcome: {other:?}"),
    };
    let path_leaf_id = match create_node(
        &pool,
        &leaf_path_name,
        &remaining_owner,
        &PubSubNodeConfig::default(),
        10,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected path leaf outcome: {other:?}"),
    };
    let third = get_node_by_id(&pool, third_id).await.unwrap().unwrap();
    let path_leaf = get_node_by_id(&pool, path_leaf_id).await.unwrap().unwrap();
    assert_eq!(
        associate_collection_child(&pool, &first, &third, &remaining_owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        associate_collection_child(&pool, &first, &path_leaf, &remaining_owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        associate_collection_child(&pool, &second, &path_leaf, &remaining_owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        associate_collection_child(&pool, &third, &path_leaf, &remaining_owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    let diamond_subscriber = format!("diamond-{suffix}@example.test");
    set_subscription(&pool, first_id, &diamond_subscriber, "subscribed")
        .await
        .unwrap();
    let resource_subscription = format!("{diamond_subscriber}/Phone");
    set_subscription(&pool, first_id, &resource_subscription, "subscribed")
        .await
        .unwrap();
    assert_eq!(
        get_subscription(&pool, first_id, &resource_subscription)
            .await
            .unwrap()
            .unwrap()
            .jid,
        resource_subscription
    );
    assert_eq!(
        subscriptions_for_jid(&pool, &diamond_subscriber, Some(&first_name))
            .await
            .unwrap()
            .len(),
        2,
        "entity-wide retrieval must include every full JID sharing the requester's bare JID"
    );
    assert_eq!(
            subscriptions_addressing_jid_page(
                &pool,
                &format!("{diamond_subscriber}/Other"),
                None,
                100,
            )
            .await
            .unwrap()
            .len(),
            1,
            "presence delivery must not select another resource's subscription"
        );

    // Presence-triggered last-item replay must cross the former 512
    // stanza self-channel boundary without truncation. Seed 513 distinct
    // nodes in two bounded bulk statements, then prove stable keyset
    // pagination reaches every subscription exactly once. The production
    // worker awaits one bounded page at a time on its independent sender.
    let replay_node_ids = (0..513).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let replay_node_names = (0..513)
        .map(|index| format!("presence-page-{suffix}-{index:03}"))
        .collect::<Vec<_>>();
    // Keep the pagination fixture independent from the graph owner's
    // production quota. These rows deliberately exercise the read path;
    // the graph section below must still prove create_node enforces its
    // explicit 100-node limit.
    let replay_owner = format!("replay-owner-{suffix}@example.test");
    sqlx::query(
        "INSERT INTO pubsub_nodes(id,node,creator_jid) \
             SELECT id,node,$3 FROM UNNEST($1::UUID[],$2::TEXT[]) AS seeded(id,node)",
    )
    .bind(&replay_node_ids)
    .bind(&replay_node_names)
    .bind(&replay_owner)
    .execute(&pool)
    .await
    .unwrap();
    let replay_subids = (0..513)
        .map(|_| Uuid::new_v4().to_string())
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO pubsub_subscriptions(node_id,jid,state,subid) \
             SELECT id,$3,'subscribed',subid \
               FROM UNNEST($1::UUID[],$2::TEXT[]) AS seeded(id,subid)",
    )
    .bind(&replay_node_ids)
    .bind(&replay_subids)
    .bind(&diamond_subscriber)
    .execute(&pool)
    .await
    .unwrap();
    let mut replay_cursor: Option<(String, String)> = None;
    let mut replay_seen = std::collections::BTreeSet::new();
    let mut replay_page_sizes = Vec::new();
    loop {
        let page = subscriptions_addressing_jid_page(
            &pool,
            &format!("{diamond_subscriber}/Other"),
            replay_cursor
                .as_ref()
                .map(|(node, jid)| (node.as_str(), jid.as_str())),
            100,
        )
        .await
        .unwrap();
        if page.is_empty() {
            break;
        }
        replay_page_sizes.push(page.len());
        for subscription in page {
            assert!(
                replay_seen.insert((subscription.node.clone(), subscription.jid.clone())),
                "keyset replay returned a subscription more than once"
            );
            replay_cursor = Some((subscription.node, subscription.jid));
        }
    }
    assert_eq!(replay_seen.len(), 514);
    assert_eq!(replay_page_sizes, vec![100, 100, 100, 100, 100, 14]);

    let root_total = usize::try_from(
        root_disco_page(&pool, &diamond_subscriber, None, false, 0)
            .await
            .unwrap()
            .total,
    )
    .unwrap();
    assert!(root_total > 512);
    let mut root_cursor = None;
    let mut root_seen = std::collections::BTreeSet::new();
    loop {
        let page = root_disco_page(
            &pool,
            &diamond_subscriber,
            root_cursor.as_deref(),
            false,
            100,
        )
        .await
        .unwrap();
        assert!(page.cursor_exists);
        assert_eq!(usize::try_from(page.total).unwrap(), root_total);
        if page.nodes.is_empty() {
            break;
        }
        for node in page.nodes {
            assert_eq!(usize::try_from(node.index).unwrap(), root_seen.len());
            assert!(
                root_seen.insert(node.node.clone()),
                "root disco keyset page returned a duplicate node"
            );
            root_cursor = Some(node.node);
        }
    }
    assert_eq!(root_seen.len(), root_total);
    assert!(root_seen.contains("serverinfo"));
    let serverinfo = root_disco_page(&pool, &diamond_subscriber, Some("serverinfo"), true, 1)
        .await
        .unwrap();
    assert!(serverinfo.cursor_exists);
    assert_eq!(usize::try_from(serverinfo.total).unwrap(), root_total);
    assert_eq!(
        usize::try_from(serverinfo.nodes[0].index).unwrap() + 1,
        root_seen
            .iter()
            .take_while(|node| node.as_str() < "serverinfo")
            .count()
    );
    assert!(
        !root_disco_page(&pool, &diamond_subscriber, Some("missing-root"), false, 0)
            .await
            .unwrap()
            .cursor_exists
    );
    let pending_jid = format!("pending-{suffix}@example.test/desktop");
    set_subscription(&pool, first_id, &pending_jid, "pending")
        .await
        .unwrap();
    let approved = set_affiliations(
        &pool,
        first_id,
        &[(
            northstar_xmpp_types::jid::canonical_bare_key(&pending_jid).unwrap(),
            "publisher".to_owned(),
        )],
    )
    .await
    .unwrap();
    assert!(matches!(
        approved,
        SetAffiliationsOutcome::Updated {
            ref approved_subscriptions,
            ..
        } if approved_subscriptions.iter().any(|(jid, _)| jid == &pending_jid)
    ));
    assert_eq!(
        get_subscription(&pool, first_id, &pending_jid)
            .await
            .unwrap()
            .unwrap()
            .state,
        "subscribed"
    );
    let revoked = set_affiliations(
        &pool,
        first_id,
        &[(diamond_subscriber.clone(), "outcast".to_owned())],
    )
    .await
    .unwrap();
    assert!(matches!(
        revoked,
        SetAffiliationsOutcome::Updated {
            ref revoked_subscriptions,
            ..
        } if revoked_subscriptions.len() == 2
            && revoked_subscriptions.iter().any(|(jid, _)| jid == &diamond_subscriber)
            && revoked_subscriptions.iter().any(|(jid, _)| jid == &resource_subscription)
    ));
    assert!(get_subscription(&pool, first_id, &diamond_subscriber)
        .await
        .unwrap()
        .is_none());
    assert!(get_subscription(&pool, first_id, &resource_subscription)
        .await
        .unwrap()
        .is_none());

    // Exactly 64 collection edges are accepted.  Two concurrent writers
    // trying to add a 65th edge are serialized by the graph advisory lock
    // and both receive a clean depth outcome; neither edge is persisted.
    let mut depth_nodes = Vec::new();
    for index in 0..=64 {
        let name = format!("depth-{suffix}-{index:02}");
        let id = match create_node(&pool, &name, &remaining_owner, &collection, 100)
            .await
            .unwrap()
        {
            CreateNodeOutcome::Created(id) => id,
            other => panic!("unexpected depth node outcome: {other:?}"),
        };
        depth_nodes.push(get_node_by_id(&pool, id).await.unwrap().unwrap());
    }
    for edge in depth_nodes.windows(2) {
        assert_eq!(
            associate_collection_child(&pool, &edge[0], &edge[1], &remaining_owner)
                .await
                .unwrap(),
            CollectionUpdateOutcome::Updated
        );
    }
    let mut extra_parents = Vec::new();
    for side in ["left", "right"] {
        let name = format!("depth-{suffix}-{side}");
        let id = match create_node(&pool, &name, &remaining_owner, &collection, 100)
            .await
            .unwrap()
        {
            CreateNodeOutcome::Created(id) => id,
            other => panic!("unexpected extra parent outcome: {other:?}"),
        };
        extra_parents.push(get_node_by_id(&pool, id).await.unwrap().unwrap());
    }
    let (left, right) = tokio::join!(
        associate_collection_child(&pool, &extra_parents[0], &depth_nodes[0], &remaining_owner,),
        associate_collection_child(&pool, &extra_parents[1], &depth_nodes[0], &remaining_owner,),
    );
    assert_eq!(left.unwrap(), CollectionUpdateOutcome::DepthExceeded);
    assert_eq!(right.unwrap(), CollectionUpdateOutcome::DepthExceeded);
    let rejected_edges: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pubsub_collection_members WHERE collection_node_id = ANY($1) AND child_node_id = $2",
        )
        .bind([extra_parents[0].id, extra_parents[1].id])
        .bind(depth_nodes[0].id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejected_edges, 0);
    let trigger_error = sqlx::query(
        "INSERT INTO pubsub_collection_members (collection_node_id, child_node_id) VALUES ($1, $2)",
    )
    .bind(extra_parents[0].id)
    .bind(depth_nodes[0].id)
    .execute(&pool)
    .await
    .expect_err("database trigger must independently reject a 65th edge");
    assert_eq!(
        trigger_error
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514")
    );

    // Config replacement removes the old graph inside its transaction.
    // A depth error on a later replacement edge must restore that old
    // graph and all node configuration when the transaction rolls back.
    let before = get_node_by_id(&pool, depth_nodes[0].id)
        .await
        .unwrap()
        .unwrap();
    let mut replacement = before.config();
    replacement.collections = vec![extra_parents[0].node.clone()];
    replacement.children = vec![depth_nodes[1].node.clone()];
    replacement.title = Some("must-roll-back".to_owned());
    assert_eq!(
        update_node_config_and_graph(&pool, &depth_nodes[0], &remaining_owner, &replacement,)
            .await
            .unwrap(),
        PubSubConfigOutcome::InvalidOptions
    );
    let after = get_node_by_id(&pool, depth_nodes[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.title, before.title);
    assert!(collection_children(&pool, depth_nodes[0].id)
        .await
        .unwrap()
        .iter()
        .any(|child| child.id == depth_nodes[1].id));
    assert!(!collection_parents(&pool, depth_nodes[0].id)
        .await
        .unwrap()
        .iter()
        .any(|parent| parent.id == extra_parents[0].id));

    let (left, right) = tokio::join!(
        set_subscription_limited(
            &pool,
            "example.test",
            first_id,
            &subscriber,
            "subscribed",
            1
        ),
        set_subscription_limited(
            &pool,
            "example.test",
            second_id,
            &subscriber,
            "subscribed",
            1
        ),
    );
    assert_eq!(
        [left.unwrap(), right.unwrap()]
            .into_iter()
            .filter(|v| *v)
            .count(),
        1
    );
    let subscribed_node: Uuid =
        sqlx::query_scalar("SELECT node_id FROM pubsub_subscriptions WHERE jid = $1")
            .bind(&subscriber)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut digest_options = PubSubSubscriptionOptions::for_node_type("collection");
    digest_options.digest = true;
    digest_options.digest_frequency = 1_000;
    digest_options.subscription_type = "all".to_owned();
    digest_options.subscription_depth = None;
    set_subscription_limited_with_options(
        &pool,
        "example.test",
        subscribed_node,
        &subscriber,
        "subscribed",
        1,
        Some(&digest_options),
    )
    .await
    .unwrap()
    .expect("the existing subscription must accept valid digest options");
    enqueue_pubsub_digest(&pool, subscribed_node, &subscriber, "<event/>", 1_000)
        .await
        .unwrap();
    sqlx::query("UPDATE pubsub_digest_queue SET deliver_after = NOW() - INTERVAL '1 second' WHERE subscriber_jid = $1")
            .bind(&subscriber)
            .execute(&pool)
            .await
            .unwrap();
    let (left, right) = tokio::join!(
        claim_due_pubsub_digests(&pool, 10),
        claim_due_pubsub_digests(&pool, 10),
    );
    assert_eq!(left.unwrap().len() + right.unwrap().len(), 1);

    // An expired lease must not permanently consume the subscriber-wide
    // quota.  Applying options is part of the same transaction: a
    // database-level option violation must roll the new row back rather
    // than leave a half-configured subscription behind.
    sqlx::query(
            "UPDATE pubsub_subscriptions SET expire = NOW() - INTERVAL '1 second' WHERE node_id = $1 AND jid = $2",
        )
        .bind(subscribed_node)
        .bind(&subscriber)
        .execute(&pool)
        .await
        .unwrap();
    let other_node = if subscribed_node == first_id {
        second_id
    } else {
        first_id
    };
    let mut invalid_options = PubSubSubscriptionOptions::for_node_type("collection");
    invalid_options.digest = true;
    invalid_options.digest_frequency = 1;
    assert!(set_subscription_limited_with_options(
        &pool,
        "example.test",
        other_node,
        &subscriber,
        "subscribed",
        1,
        Some(&invalid_options),
    )
    .await
    .is_err());
    assert!(get_subscription(&pool, other_node, &subscriber)
        .await
        .unwrap()
        .is_none());

    let mut valid_options = PubSubSubscriptionOptions::for_node_type("collection");
    valid_options.digest = true;
    valid_options.digest_frequency = 1_000;
    valid_options.subscription_type = "all".to_owned();
    valid_options.subscription_depth = None;
    let renewed = set_subscription_limited_with_options(
        &pool,
        "example.test",
        other_node,
        &subscriber,
        "subscribed",
        1,
        Some(&valid_options),
    )
    .await
    .unwrap()
    .expect("expired subscription must not consume quota");
    assert!(renewed.digest);
    assert_eq!(renewed.digest_frequency, 1_000);
    assert_eq!(renewed.subscription_type, "all");
    assert_eq!(renewed.subscription_depth, None);

    enqueue_pubsub_digest(&pool, other_node, &subscriber, "<event/>", 1_000)
        .await
        .unwrap();
    assert!(unsubscribe(&pool, other_node, &subscriber).await.unwrap());
    assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_digest_queue WHERE subscription_node_id=$1 AND subscriber_jid=$2",
            )
            .bind(other_node)
            .bind(&subscriber)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "unsubscribe must atomically remove queued digests"
        );
    assert!(
        enqueue_pubsub_digest(&pool, other_node, &subscriber, "<stale/>", 1_000)
            .await
            .unwrap()
    );
    assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_digest_queue WHERE subscription_node_id=$1 AND subscriber_jid=$2",
            )
            .bind(other_node)
            .bind(&subscriber)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "a stale notification snapshot must not requeue after unsubscribe"
        );

    let expired_jid = format!("expired-{suffix}@example.test");
    let mut expired_options = PubSubSubscriptionOptions::for_node_type("collection");
    expired_options.digest = true;
    expired_options.digest_frequency = 1_000;
    expired_options.expire = Some(Utc::now() + chrono::Duration::seconds(10));
    set_subscription_limited_with_options(
        &pool,
        "example.test",
        first_id,
        &expired_jid,
        "subscribed",
        10,
        Some(&expired_options),
    )
    .await
    .unwrap()
    .unwrap();
    enqueue_pubsub_digest(&pool, first_id, &expired_jid, "<lease/>", 1_000)
        .await
        .unwrap();
    sqlx::query(
            "UPDATE pubsub_subscriptions SET expire=NOW()-INTERVAL '1 second' WHERE node_id=$1 AND jid=$2",
        )
        .bind(first_id)
        .bind(&expired_jid)
        .execute(&pool)
        .await
        .unwrap();
    assert!(cleanup_expired_subscriptions(&pool, 10).await.unwrap() >= 1);
    assert!(get_subscription(&pool, first_id, &expired_jid)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_digest_queue WHERE subscription_node_id=$1 AND subscriber_jid=$2",
            )
            .bind(first_id)
            .bind(&expired_jid)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "lease cleanup must remove stale digest fragments atomically"
        );

    // An authorized publisher must be able to replace a colliding ItemID
    // even when another publisher created it. Storage quota rejection
    // still leaves no partial item, and successful history is pruned
    // deterministically.
    let leaf_name = format!("leaf-{suffix}");
    let leaf_config = PubSubNodeConfig {
        max_items: 2,
        ..PubSubNodeConfig::default()
    };
    let leaf_id = match create_node(&pool, &leaf_name, &owner, &leaf_config, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected leaf create outcome: {other:?}"),
    };
    let leaf = get_node_by_id(&pool, leaf_id).await.unwrap().unwrap();
    assert!(matches!(
        set_affiliations(
            &pool,
            leaf_id,
            &[("other@example.test".to_owned(), "publisher".to_owned())],
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    assert!(matches!(
        publish_items(
            &pool,
            &leaf,
            "other@example.test",
            &[("claimed".to_owned(), "<item id='claimed'/>".to_owned())],
            false,
            1_000_000,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    ));
    assert!(matches!(
        publish_items(
            &pool,
            &leaf,
            &owner,
            &[
                (
                    "must-rollback".to_owned(),
                    "<item id='must-rollback'/>".to_owned()
                ),
                ("claimed".to_owned(), "<item id='claimed'/>".to_owned()),
            ],
            false,
            1_000_000,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    ));
    assert!(!get_items(&pool, leaf_id, &["must-rollback".to_owned()], 1)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        get_items(&pool, leaf_id, &["claimed".to_owned()], 1)
            .await
            .unwrap()[0]
            .publisher_jid,
        northstar_xmpp_types::jid::canonical_bare_key(&owner).unwrap()
    );
    assert_eq!(
        retract_items(
            &pool,
            leaf_id,
            &["claimed".to_owned()],
            "intruder@example.test",
            false,
        )
        .await
        .unwrap(),
        RetractItemsOutcome::Forbidden
    );
    assert_eq!(
        retract_items(&pool, leaf_id, &["claimed".to_owned()], &owner, true,)
            .await
            .unwrap(),
        RetractItemsOutcome::Retracted
    );
    assert!(matches!(
        publish_items(
            &pool,
            &leaf,
            &owner,
            &[(
                "quota-rollback".to_owned(),
                "<item id='quota-rollback'/>".to_owned()
            )],
            false,
            0,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::QuotaExceeded
    ));
    assert!(get_items(&pool, leaf_id, &["quota-rollback".to_owned()], 1)
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        publish_items(
            &pool,
            &leaf,
            &owner,
            &[
                ("new-1".to_owned(), "<item id='new-1'/>".to_owned()),
                ("new-2".to_owned(), "<item id='new-2'/>".to_owned()),
                ("new-3".to_owned(), "<item id='new-3'/>".to_owned()),
            ],
            false,
            1_000_000,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    ));
    let retained = get_items(&pool, leaf_id, &[], 10).await.unwrap();
    assert_eq!(retained.len(), 2);
    assert!(retained.iter().all(|item| item.item_id != "claimed"));
    let discovered = leaf_disco_snapshot(&pool, &leaf.node, &owner)
        .await
        .unwrap()
        .unwrap()
        .item_ids;
    assert_eq!(discovered.len(), 2);
    assert_eq!(
        retained
            .iter()
            .map(|item| item.item_id.as_str())
            .collect::<Vec<_>>(),
        discovered.iter().map(String::as_str).collect::<Vec<_>>(),
        "disco#items must expose the exact retained item sequence"
    );
    assert_eq!(discovered, ["new-3", "new-2"]);
    assert!(!discovered.iter().any(|item| item == "new-1"));

    assert!(delete_node_with_redirect(
        &pool,
        &leaf,
        Some("xmpp:replacement.example.test?;node=leaf"),
    )
    .await
    .unwrap());
    assert!(get_node_by_id(&pool, leaf_id).await.unwrap().is_none());
    assert_eq!(
        node_redirect(&pool, &leaf_name).await.unwrap().as_deref(),
        Some("xmpp:replacement.example.test?;node=leaf")
    );

    sqlx::query("DELETE FROM pubsub_nodes WHERE id = ANY($1)")
        .bind(vec![first_id, second_id, third_id, path_leaf_id])
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn lease_expiry_is_evaluated_after_a_graph_lock_wait() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let short = &suffix[..10];
    let owner = format!("lease-owner-{suffix}@example.test");
    let stable = format!("lease-stable-{suffix}@example.test/desktop");
    let expiring = format!("lease-expiring-{suffix}@example.test/phone");
    let node = create_default_test_node(&pool, &format!("lease-{suffix}"), &owner).await;
    subscribe_for_race(&pool, &node, &stable, &format!("stable-{suffix}")).await;
    subscribe_for_race(&pool, &node, &expiring, &format!("expiring-{suffix}")).await;
    sqlx::query(
        "UPDATE pubsub_subscriptions
                SET expire=clock_timestamp()+INTERVAL '1 second'
              WHERE node_id=$1 AND jid=$2",
    )
    .bind(node.id)
    .bind(&expiring)
    .execute(&pool)
    .await
    .unwrap();

    let mut graph_blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *graph_blocker)
        .await
        .unwrap();
    let application = format!("ps-lease-{short}");
    let publish_pool = named_single_connection_pool(&url, &application).await;
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let renderer = Arc::new(RaceMutationRenderer {
        inner: crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test"),
        observations: observation_tx,
        gate: None,
    });
    let publish_task = tokio::spawn({
        let publish_pool = publish_pool.clone();
        let publish_node = node.clone();
        let publish_owner = owner.clone();
        let renderer = Arc::clone(&renderer);
        async move {
            publish_items_with_renderer(
                &publish_pool,
                &publish_node,
                &publish_owner,
                &[(
                    "after-wait".to_owned(),
                    "<item id='after-wait'/>".to_owned(),
                )],
                false,
                1_000_000,
                &*renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let expired: bool = sqlx::query_scalar(
                "SELECT clock_timestamp() >= expire
                       FROM pubsub_subscriptions
                      WHERE node_id=$1 AND jid=$2",
            )
            .bind(node.id)
            .bind(&expiring)
            .fetch_one(&pool)
            .await
            .unwrap();
            if expired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("subscription lease did not reach its deterministic expiry barrier");
    graph_blocker.commit().await.unwrap();

    assert_eq!(
        publish_task.await.unwrap().unwrap(),
        PublishItemsOutcome::Published
    );
    let observation = tokio::time::timeout(Duration::from_secs(3), observation_rx.recv())
        .await
        .expect("post-wait publication renderer was not called")
        .expect("post-wait publication observation channel closed");
    assert_eq!(observation.recipients, vec![stable.clone()]);
    let (item_time, outbox_time): (DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "SELECT i.created_at,o.created_at
               FROM pubsub_items i
               JOIN pubsub_event_outbox o ON o.event_id=$3 AND o.recipient_jid=$4
              WHERE i.node_id=$1 AND i.item_id=$2",
    )
    .bind(node.id)
    .bind("after-wait")
    .bind(observation.event_id)
    .bind(&stable)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(item_time, outbox_time);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE event_id=$1 AND recipient_jid=$2",
        )
        .bind(observation.event_id)
        .bind(&expiring)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    publish_pool.close().await;
    pool.close().await;
}
