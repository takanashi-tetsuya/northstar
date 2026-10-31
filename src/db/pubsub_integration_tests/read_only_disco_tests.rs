//! Read-only query ports and leaf and collection disco gates.

use super::*;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn query_ports_succeed_with_read_only_database_connections() {
    let (url, setup_pool) = integration_pool(2).await;
    let node_name = format!("readonly-{}", Uuid::new_v4().simple());
    let node = create_default_test_node(&setup_pool, &node_name, "alice@example.test").await;

    let read_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET default_transaction_read_only = on")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
        .fetch_one(&read_pool)
        .await
        .unwrap();
    assert_eq!(read_only, "on");

    let service = crate::db::pubsub_repository::test_pubsub_service(read_pool, "example.test");
    assert_eq!(
        service.get_node(&node_name).await.unwrap().unwrap().id,
        node.id
    );
    use northstar_pubsub_application::{PubSubOwnerRead, PubSubOwnerReadKind};
    match service
        .owner_read(
            &node_name,
            "alice@example.test",
            PubSubOwnerReadKind::Configure,
        )
        .await
        .unwrap()
    {
        PubSubOwnerRead::Configure(config) => {
            assert!(config.collections.is_empty());
            assert!(config.children.is_empty());
        }
        other => panic!("unexpected owner configuration: {other:?}"),
    }
    assert!(matches!(
        service
            .owner_read(
                &node_name,
                "bob@example.test",
                PubSubOwnerReadKind::Configure
            )
            .await
            .unwrap(),
        PubSubOwnerRead::Forbidden
    ));
    assert!(matches!(
        service
            .owner_read(
                "missing-node",
                "alice@example.test",
                PubSubOwnerReadKind::CheckOnly
            )
            .await
            .unwrap(),
        PubSubOwnerRead::Missing
    ));
    assert!(matches!(
        service
            .owner_read(
                &node_name,
                "alice@example.test",
                PubSubOwnerReadKind::CheckOnly
            )
            .await
            .unwrap(),
        PubSubOwnerRead::Authorized
    ));
    match service
        .owner_read(
            &node_name,
            "alice@example.test",
            PubSubOwnerReadKind::Affiliations,
        )
        .await
        .unwrap()
    {
        PubSubOwnerRead::Affiliations(entries) => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].jid, "alice@example.test");
            assert_eq!(entries[0].affiliation, "owner");
        }
        other => panic!("unexpected owner affiliations: {other:?}"),
    }
    assert_eq!(
        service.node_metadata(node.id).await.unwrap().owners,
        ["alice@example.test"]
    );
    assert!(
        service
            .discover_roots(northstar_pubsub_application::PubSubRootDiscoQuery {
                requester: "alice@example.test",
                cursor: None,
                backwards: false,
                max: Some(10),
                rsm_requested: false,
            },)
            .await
            .unwrap()
            .unwrap()
            .total
            >= 1
    );
    assert!(service
        .get_items(node.id, &[], 10)
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .get_subscription(node.id, "bob@example.test")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        service
            .get_node_affiliation(node.id, "alice@example.test")
            .await
            .unwrap()
            .as_deref(),
        Some("owner")
    );
    assert!(service
        .can_publish(&node, "alice@example.test/Phone")
        .await
        .unwrap());
    let mut subscriber_node = node.clone();
    subscriber_node.publish_model = "subscribers".to_owned();
    assert!(!service
        .can_publish(&subscriber_node, "bob@example.test/Phone")
        .await
        .unwrap());
    sqlx::query(
        "INSERT INTO pubsub_subscriptions(node_id, jid, state, subid) \
         VALUES ($1, $2, 'subscribed', $3)",
    )
    .bind(node.id)
    .bind("bob@example.test")
    .bind(Uuid::new_v4().to_string())
    .execute(&setup_pool)
    .await
    .unwrap();
    match service
        .owner_read(
            &node_name,
            "alice@example.test",
            PubSubOwnerReadKind::Subscriptions,
        )
        .await
        .unwrap()
    {
        PubSubOwnerRead::Subscriptions(entries) => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].jid, "bob@example.test");
        }
        other => panic!("unexpected owner subscriptions: {other:?}"),
    }
    assert!(service
        .can_publish(&subscriber_node, "bob@example.test/Phone")
        .await
        .unwrap());
    sqlx::query(
        "UPDATE pubsub_subscriptions SET expire = NOW() - INTERVAL '1 second' \
         WHERE node_id = $1 AND jid = $2",
    )
    .bind(node.id)
    .bind("bob@example.test")
    .execute(&setup_pool)
    .await
    .unwrap();
    assert!(matches!(
        service
            .owner_read(
                &node_name,
                "alice@example.test",
                PubSubOwnerReadKind::Subscriptions
            )
            .await
            .unwrap(),
        PubSubOwnerRead::Subscriptions(entries) if entries.is_empty()
    ));
    assert!(!service
        .can_publish(&subscriber_node, "bob@example.test/Phone")
        .await
        .unwrap());
    sqlx::query("UPDATE pubsub_subscriptions SET expire = NULL WHERE node_id = $1 AND jid = $2")
        .bind(node.id)
        .bind("bob@example.test")
        .execute(&setup_pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO pubsub_affiliations(node_id, jid, affiliation) \
         VALUES ($1, $2, 'outcast')",
    )
    .bind(node.id)
    .bind("bob@example.test")
    .execute(&setup_pool)
    .await
    .unwrap();
    assert!(!service
        .can_publish(&subscriber_node, "bob@example.test/Phone")
        .await
        .unwrap());
    assert!(service
        .pep_items(Uuid::new_v4(), "urn:xmpp:avatar:data", None, 10)
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .pep_subscribers(Uuid::new_v4(), "urn:xmpp:avatar:data")
        .await
        .unwrap()
        .is_empty());

    // Hold the authorization table after the node read. A committed owner
    // revocation or node deletion must veto the older projection before reply.
    for delete_node in [false, true] {
        let race_name = format!("owner-snapshot-{}", Uuid::new_v4().simple());
        let race_node =
            create_default_test_node(&setup_pool, &race_name, "alice@example.test").await;
        let mut blocker = setup_pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE pubsub_affiliations IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let reader = service.clone();
        let read_name = race_name.clone();
        let read = tokio::spawn(async move {
            reader
                .owner_read(
                    &read_name,
                    "alice@example.test",
                    PubSubOwnerReadKind::Configure,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE 'SELECT EXISTS(SELECT 1 FROM pubsub_affiliations WHERE node_id =%')",
                )
                .fetch_one(&setup_pool)
                .await
                .unwrap();
                if waiting {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("owner read did not reach the blocked authorization query");
        if delete_node {
            sqlx::query("DELETE FROM pubsub_nodes WHERE id = $1")
                .bind(race_node.id)
                .execute(&mut *blocker)
                .await
                .unwrap();
        } else {
            sqlx::query("UPDATE pubsub_affiliations SET affiliation = 'none' WHERE node_id = $1 AND jid = $2")
                .bind(race_node.id)
                .bind("alice@example.test")
                .execute(&mut *blocker)
                .await
                .unwrap();
        }
        blocker.commit().await.unwrap();
        assert!(matches!(
            (delete_node, read.await.unwrap().unwrap()),
            (true, PubSubOwnerRead::Missing) | (false, PubSubOwnerRead::Forbidden)
        ));
        let current = service
            .owner_read(
                &race_name,
                "alice@example.test",
                PubSubOwnerReadKind::Configure,
            )
            .await
            .unwrap();
        assert!(matches!(
            (delete_node, current),
            (true, PubSubOwnerRead::Missing) | (false, PubSubOwnerRead::Forbidden)
        ));
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn leaf_disco_uses_read_only_snapshot_and_live_subscription_scope() {
    let (url, setup_pool) = integration_pool(4).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let node_name = format!("leaf-disco-{suffix}");
    let owner = format!("owner-{suffix}@example.test");
    let subscriber = format!("reader-{suffix}@example.test");
    let config = PubSubNodeConfig {
        access_model: "whitelist".to_owned(),
        ..Default::default()
    };
    let node_id = match create_node(&setup_pool, &node_name, &owner, &config, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected node create outcome: {other:?}"),
    };
    for (item_id, age) in [("older", 2_i64), ("newer", 1_i64)] {
        sqlx::query(
            "INSERT INTO pubsub_items(id,node_id,item_id,publisher_jid,xml_payload,created_at)
             VALUES($1,$2,$3,$4,$5,NOW()-$6::BIGINT*INTERVAL '1 second')",
        )
        .bind(Uuid::new_v4())
        .bind(node_id)
        .bind(item_id)
        .bind(&owner)
        .bind(format!("<item id='{item_id}'/>"))
        .bind(age)
        .execute(&setup_pool)
        .await
        .unwrap();
    }

    let read_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET default_transaction_read_only = on")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let service = crate::db::pubsub_repository::test_pubsub_service(read_pool, "example.test");
    assert_eq!(
        service.leaf_disco_items(&node_name, &owner).await.unwrap(),
        LeafDiscoItems::Items(vec!["newer".to_owned(), "older".to_owned()])
    );
    assert_eq!(
        service
            .leaf_disco_items(&node_name, &subscriber)
            .await
            .unwrap(),
        LeafDiscoItems::Forbidden
    );

    let subscriber_resource = format!("{subscriber}/Phone");
    set_subscription(&setup_pool, node_id, &subscriber_resource, "subscribed")
        .await
        .unwrap();
    assert_eq!(
        service
            .leaf_disco_items(&node_name, &format!("{subscriber}/Tablet"))
            .await
            .unwrap(),
        LeafDiscoItems::Items(vec!["newer".to_owned(), "older".to_owned()])
    );
    sqlx::query(
        "UPDATE pubsub_subscriptions SET expire=NOW()-INTERVAL '1 second'
         WHERE node_id=$1 AND jid=$2",
    )
    .bind(node_id)
    .bind(&subscriber_resource)
    .execute(&setup_pool)
    .await
    .unwrap();
    assert_eq!(
        service
            .leaf_disco_items(&node_name, &subscriber)
            .await
            .unwrap(),
        LeafDiscoItems::Forbidden
    );
    sqlx::query("UPDATE pubsub_subscriptions SET expire=NULL WHERE node_id=$1 AND jid=$2")
        .bind(node_id)
        .bind(&subscriber_resource)
        .execute(&setup_pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO pubsub_affiliations(node_id,jid,affiliation)
         VALUES($1,$2,'outcast')",
    )
    .bind(node_id)
    .bind(&subscriber)
    .execute(&setup_pool)
    .await
    .unwrap();
    assert_eq!(
        service
            .leaf_disco_items(&node_name, &subscriber)
            .await
            .unwrap(),
        LeafDiscoItems::Forbidden
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn leaf_disco_sql_gate_matches_pure_retrieval_policy() {
    let (_, pool) = integration_pool(4).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let node_name = format!("leaf-disco-policy-{suffix}");
    let owner = format!("owner-{suffix}@example.test");
    let requester = format!("reader-{suffix}@example.test");
    let subscription_jid = format!("{requester}/Phone");
    let node = create_default_test_node(&pool, &node_name, &owner).await;
    sqlx::query(
        "INSERT INTO pubsub_items(id,node_id,item_id,publisher_jid,xml_payload)
         VALUES($1,$2,'sentinel',$3,'<item id=\"sentinel\"/>')",
    )
    .bind(Uuid::new_v4())
    .bind(node.id)
    .bind(&owner)
    .execute(&pool)
    .await
    .unwrap();
    let service = crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test");

    for access in ["open", "whitelist", "authorize"] {
        sqlx::query("UPDATE pubsub_nodes SET access_model=$2 WHERE id=$1")
            .bind(node.id)
            .bind(access)
            .execute(&pool)
            .await
            .unwrap();
        for affiliation in [
            None,
            Some("owner"),
            Some("publisher"),
            Some("member"),
            Some("publish-only"),
            Some("outcast"),
        ] {
            if let Some(affiliation) = affiliation {
                sqlx::query(
                    "INSERT INTO pubsub_affiliations(node_id,jid,affiliation)
                     VALUES($1,$2,$3)
                     ON CONFLICT(node_id,jid) DO UPDATE SET affiliation=EXCLUDED.affiliation",
                )
                .bind(node.id)
                .bind(&requester)
                .bind(affiliation)
                .execute(&pool)
                .await
                .unwrap();
            } else {
                sqlx::query("DELETE FROM pubsub_affiliations WHERE node_id=$1 AND jid=$2")
                    .bind(node.id)
                    .bind(&requester)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            for subscription in ["absent", "active", "expired"] {
                if subscription == "absent" {
                    sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2")
                        .bind(node.id)
                        .bind(&subscription_jid)
                        .execute(&pool)
                        .await
                        .unwrap();
                } else {
                    sqlx::query(
                        "INSERT INTO pubsub_subscriptions(node_id,jid,state,subid,expire)
                         VALUES($1,$2,'subscribed',$3,
                                CASE WHEN $4 THEN NOW()-INTERVAL '1 second' ELSE NULL END)
                         ON CONFLICT(node_id,jid) DO UPDATE SET
                             state='subscribed',expire=EXCLUDED.expire",
                    )
                    .bind(node.id)
                    .bind(&subscription_jid)
                    .bind(Uuid::new_v4().to_string())
                    .bind(subscription == "expired")
                    .execute(&pool)
                    .await
                    .unwrap();
                }
                let snapshot =
                    leaf_disco_snapshot(&pool, &node_name, &format!("{requester}/Tablet"))
                        .await
                        .unwrap()
                        .unwrap();
                let expected = northstar_xep_0060::can_retrieve_pure(
                    access.parse().unwrap(),
                    affiliation.map(|value| value.parse().unwrap()),
                    subscription == "active",
                );
                assert_eq!(
                    snapshot.affiliation.as_deref(),
                    affiliation,
                    "affiliation facts changed for {access}/{affiliation:?}/{subscription}"
                );
                assert_eq!(
                    snapshot.subscribed,
                    subscription == "active",
                    "subscription facts changed for {access}/{affiliation:?}/{subscription}"
                );
                assert_eq!(
                    snapshot.item_ids == vec!["sentinel".to_owned()],
                    expected,
                    "SQL item gate disagrees with pure policy for {access}/{affiliation:?}/{subscription}"
                );
                assert_eq!(
                    service
                        .leaf_disco_items(&node_name, &requester)
                        .await
                        .unwrap(),
                    if expected {
                        LeafDiscoItems::Items(vec!["sentinel".to_owned()])
                    } else {
                        LeafDiscoItems::Forbidden
                    },
                    "service policy disagrees for {access}/{affiliation:?}/{subscription}"
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn leaf_disco_rechecks_configuration_after_stale_node_lookup() {
    let (_, pool) = integration_pool(4).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let node_name = format!("leaf-config-race-{suffix}");
    let owner = format!("owner-{suffix}@example.test");
    let outsider = format!("outsider-{suffix}@example.test");
    let stale = create_default_test_node(&pool, &node_name, &owner).await;
    let service = crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test");
    assert_eq!(
        service
            .leaf_disco_items(&node_name, &outsider)
            .await
            .unwrap(),
        LeafDiscoItems::Items(Vec::new())
    );

    // The initial protocol lookup can precede a committed configuration
    // change. The leaf query must use its own current statement snapshot.
    let mut restricted = stale.config();
    restricted.access_model = "whitelist".to_owned();
    assert_eq!(
        update_node_config_and_graph_with_outbox(
            &pool,
            &stale,
            &owner,
            &stale.config(),
            &restricted,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        PubSubConfigOutcome::Updated
    );
    assert_eq!(stale.node_type, "leaf");
    assert_eq!(stale.access_model, "open");
    assert_eq!(
        service
            .leaf_disco_items(&node_name, &outsider)
            .await
            .unwrap(),
        LeafDiscoItems::Forbidden
    );

    let current = get_node_by_id(&pool, stale.id).await.unwrap().unwrap();
    let mut collection = current.config();
    collection.node_type = "collection".to_owned();
    assert_eq!(
        update_node_config_and_graph_with_outbox(
            &pool,
            &current,
            &owner,
            &current.config(),
            &collection,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        PubSubConfigOutcome::Updated
    );
    assert_eq!(
        service.leaf_disco_items(&node_name, &owner).await.unwrap(),
        LeafDiscoItems::NotLeaf
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn collection_disco_sql_gate_matches_parent_policy_on_read_only_pool() {
    let (url, pool) = integration_pool(6).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}@example.test");
    let requester = format!("reader-{suffix}@example.test");
    let subscription_jid = format!("{requester}/Phone");
    let parent_name = format!("collection-policy-{suffix}");
    let parent_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        ..Default::default()
    };
    let parent_id = match create_node(&pool, &parent_name, &owner, &parent_config, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected collection create outcome: {other:?}"),
    };
    let parent = get_node_by_id(&pool, parent_id).await.unwrap().unwrap();
    let first = create_default_test_node(&pool, &format!("a-{suffix}"), &owner).await;
    let restricted_config = PubSubNodeConfig {
        access_model: "whitelist".to_owned(),
        ..Default::default()
    };
    let restricted_name = format!("z-{suffix}");
    let restricted_id = match create_node(&pool, &restricted_name, &owner, &restricted_config, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected restricted child create outcome: {other:?}"),
    };
    let restricted = get_node_by_id(&pool, restricted_id).await.unwrap().unwrap();
    sqlx::query("UPDATE pubsub_nodes SET title='Private title' WHERE id=$1")
        .bind(restricted_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO pubsub_affiliations(node_id,jid,affiliation)
         VALUES($1,$2,'outcast')",
    )
    .bind(restricted_id)
    .bind(&requester)
    .execute(&pool)
    .await
    .unwrap();
    for child in [&restricted, &first] {
        assert_eq!(
            associate_collection_child(&pool, &parent, child, &owner)
                .await
                .unwrap(),
            CollectionUpdateOutcome::Updated
        );
    }

    let read_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET default_transaction_read_only = on")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let service =
        crate::db::pubsub_repository::test_pubsub_service(read_pool.clone(), "example.test");
    let expected_children = vec![
        PubSubCollectionDiscoChild {
            node: first.node.clone(),
            title: None,
        },
        PubSubCollectionDiscoChild {
            node: restricted.node.clone(),
            title: Some("Private title".to_owned()),
        },
    ];
    assert_eq!(
        service
            .collection_disco_items(&parent_name, &requester)
            .await
            .unwrap(),
        CollectionDiscoItems::Items(expected_children.clone()),
        "the parent's open policy must reveal both children in node-name order, even when a child denies access"
    );

    for access in ["open", "whitelist", "authorize"] {
        sqlx::query("UPDATE pubsub_nodes SET access_model=$2 WHERE id=$1")
            .bind(parent_id)
            .bind(access)
            .execute(&pool)
            .await
            .unwrap();
        for affiliation in [
            None,
            Some("owner"),
            Some("publisher"),
            Some("member"),
            Some("publish-only"),
            Some("outcast"),
        ] {
            if let Some(affiliation) = affiliation {
                sqlx::query(
                    "INSERT INTO pubsub_affiliations(node_id,jid,affiliation)
                     VALUES($1,$2,$3)
                     ON CONFLICT(node_id,jid) DO UPDATE SET affiliation=EXCLUDED.affiliation",
                )
                .bind(parent_id)
                .bind(&requester)
                .bind(affiliation)
                .execute(&pool)
                .await
                .unwrap();
            } else {
                sqlx::query("DELETE FROM pubsub_affiliations WHERE node_id=$1 AND jid=$2")
                    .bind(parent_id)
                    .bind(&requester)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            for subscription in ["absent", "active", "expired"] {
                if subscription == "absent" {
                    sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2")
                        .bind(parent_id)
                        .bind(&subscription_jid)
                        .execute(&pool)
                        .await
                        .unwrap();
                } else {
                    sqlx::query(
                        "INSERT INTO pubsub_subscriptions(node_id,jid,state,subid,expire)
                         VALUES($1,$2,'subscribed',$3,
                                CASE WHEN $4 THEN NOW()-INTERVAL '1 second' ELSE NULL END)
                         ON CONFLICT(node_id,jid) DO UPDATE SET
                             state='subscribed',expire=EXCLUDED.expire",
                    )
                    .bind(parent_id)
                    .bind(&subscription_jid)
                    .bind(Uuid::new_v4().to_string())
                    .bind(subscription == "expired")
                    .execute(&pool)
                    .await
                    .unwrap();
                }
                let snapshot = collection_disco_snapshot(
                    &read_pool,
                    &parent_name,
                    &format!("{requester}/Tablet"),
                )
                .await
                .unwrap()
                .unwrap();
                let expected = northstar_xep_0060::can_retrieve_pure(
                    access.parse().unwrap(),
                    affiliation.map(|value| value.parse().unwrap()),
                    subscription == "active",
                );
                assert_eq!(
                    snapshot.affiliation.as_deref(),
                    affiliation,
                    "affiliation facts changed for {access}/{affiliation:?}/{subscription}"
                );
                assert_eq!(
                    snapshot.subscribed,
                    subscription == "active",
                    "subscription facts changed for {access}/{affiliation:?}/{subscription}"
                );
                assert_eq!(
                    snapshot.children.len(),
                    if expected { 2 } else { 0 },
                    "SQL child gate disagrees with pure policy for {access}/{affiliation:?}/{subscription}"
                );
                assert_eq!(
                    service
                        .collection_disco_items(&parent_name, &requester)
                        .await
                        .unwrap(),
                    if expected {
                        CollectionDiscoItems::Items(expected_children.clone())
                    } else {
                        CollectionDiscoItems::Forbidden
                    },
                    "service policy disagrees for {access}/{affiliation:?}/{subscription}"
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn collection_disco_rechecks_parent_and_edges_after_stale_lookup() {
    let (_, pool) = integration_pool(6).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}@example.test");
    let outsider = format!("outsider-{suffix}@example.test");
    let parent_name = format!("collection-race-{suffix}");
    let config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        ..Default::default()
    };
    let parent_id = match create_node(&pool, &parent_name, &owner, &config, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected collection create outcome: {other:?}"),
    };
    let stale = get_node_by_id(&pool, parent_id).await.unwrap().unwrap();
    let first = create_default_test_node(&pool, &format!("first-{suffix}"), &owner).await;
    let second = create_default_test_node(&pool, &format!("second-{suffix}"), &owner).await;
    assert_eq!(
        associate_collection_child(&pool, &stale, &first, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    let service = crate::db::pubsub_repository::test_pubsub_service(pool.clone(), "example.test");
    assert_eq!(
        service
            .collection_disco_items(&parent_name, &outsider)
            .await
            .unwrap(),
        CollectionDiscoItems::Items(vec![PubSubCollectionDiscoChild {
            node: first.node.clone(),
            title: None,
        }])
    );

    // A configuration commit between the protocol's initial node lookup and
    // its collection query must override the stale access model.
    let mut expected = stale.config();
    expected.children = vec![first.node.clone()];
    let mut restricted = expected.clone();
    restricted.access_model = "whitelist".to_owned();
    assert_eq!(
        update_node_config_and_graph_with_outbox(
            &pool,
            &stale,
            &owner,
            &expected,
            &restricted,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        PubSubConfigOutcome::Updated
    );
    assert_eq!(stale.access_model, "open");
    assert_eq!(
        service
            .collection_disco_items(&parent_name, &outsider)
            .await
            .unwrap(),
        CollectionDiscoItems::Forbidden
    );

    let current = get_node_by_id(&pool, parent_id).await.unwrap().unwrap();
    assert_eq!(
        dissociate_collection_child(&pool, &current, &first, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        associate_collection_child(&pool, &current, &second, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        service
            .collection_disco_items(&parent_name, &owner)
            .await
            .unwrap(),
        CollectionDiscoItems::Items(vec![PubSubCollectionDiscoChild {
            node: second.node.clone(),
            title: None,
        }])
    );

    // Production refuses collection-to-leaf conversion. Model an externally
    // seeded type change after the stale lookup to exercise the read boundary.
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM pubsub_collection_members WHERE collection_node_id=$1")
        .bind(parent_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("UPDATE pubsub_nodes SET node_type='leaf' WHERE id=$1")
        .bind(parent_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(
        service
            .collection_disco_items(&parent_name, &owner)
            .await
            .unwrap(),
        CollectionDiscoItems::NotCollection
    );
    sqlx::query("DELETE FROM pubsub_nodes WHERE id=$1")
        .bind(parent_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        service
            .collection_disco_items(&parent_name, &owner)
            .await
            .unwrap(),
        CollectionDiscoItems::NotFound
    );
}
