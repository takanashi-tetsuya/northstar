//! Service discovery and node-scoped self lists across concurrent changes.

use super::*;
use northstar_pubsub_application::{
    PubSubNodeInfo, PubSubNodeInfoQuery, PubSubNodeItems, PubSubNodeItemsQuery, PubSubSelfList,
    PubSubSelfListQuery,
};
use northstar_workflows::pubsub_repository::test_pubsub_service;

async fn block_discovery_table(
    pool: &PgPool,
    statement: &'static str,
) -> Transaction<'static, sqlx::Postgres> {
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query(statement).execute(&mut *blocker).await.unwrap();
    blocker
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn node_items_selects_kind_and_entries_from_one_snapshot() {
    let (url, pool) = integration_pool(2).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let name = format!("disco-kind-{suffix}");
    let owner = format!("owner-{suffix}@example.test");
    let parent = create_default_test_node(&pool, &name, &owner).await;
    let child = create_default_test_node(&pool, &format!("child-{suffix}"), &owner).await;
    let reader = test_pubsub_service(
        named_single_connection_pool(&url, &name).await,
        "example.test",
    );
    let mut blocker =
        block_discovery_table(&pool, "LOCK TABLE pubsub_items IN ACCESS EXCLUSIVE MODE").await;

    let read = tokio::spawn({
        let reader = reader.clone();
        let name = name.clone();
        async move {
            reader
                .node_items(&PubSubNodeItemsQuery {
                    node: &name,
                    requester: "reader@example.test",
                })
                .await
        }
    });
    wait_for_named_session_lock(&pool, &name).await;
    sqlx::query("UPDATE pubsub_nodes SET node_type='collection', persist_items=FALSE WHERE id=$1")
        .bind(parent.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO pubsub_collection_members (collection_node_id, child_node_id) VALUES ($1,$2)",
    )
    .bind(parent.id)
    .bind(child.id)
    .execute(&mut *blocker)
    .await
    .unwrap();
    blocker.commit().await.unwrap();

    // The blocked leaf query must see the same version as the kind lookup.
    // Split reads would try leaf discovery on the new collection and deny it.
    let during = read.await.unwrap().unwrap();
    assert!(matches!(during, PubSubNodeItems::Leaf(leaf) if leaf.item_ids.is_empty()));
    let after = reader
        .node_items(&PubSubNodeItemsQuery {
            node: &name,
            requester: "reader@example.test",
        })
        .await
        .unwrap();
    assert!(matches!(after, PubSubNodeItems::Collection(collection)
        if collection.children.len() == 1 && collection.children[0].node == child.node));
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn node_info_keeps_metadata_when_node_is_deleted_mid_read() {
    let (url, pool) = integration_pool(2).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let name = format!("disco-info-{suffix}");
    let owner = format!("owner-{suffix}@example.test");
    let node = create_default_test_node(&pool, &name, &owner).await;
    let reader = test_pubsub_service(
        named_single_connection_pool(&url, &name).await,
        "example.test",
    );
    let mut blocker = block_discovery_table(
        &pool,
        "LOCK TABLE pubsub_affiliations IN ACCESS EXCLUSIVE MODE",
    )
    .await;

    let read = tokio::spawn({
        let reader = reader.clone();
        let name = name.clone();
        async move {
            reader
                .node_info(&PubSubNodeInfoQuery {
                    node: &name,
                    requester: "reader@example.test",
                })
                .await
        }
    });
    wait_for_named_session_lock(&pool, &name).await;
    sqlx::query("DELETE FROM pubsub_nodes WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();

    // With split reads the old open config passes ACL, then the owner array is empty.
    let during = read.await.unwrap().unwrap();
    assert!(
        matches!(during, PubSubNodeInfo::Info { node: snapshot, metadata }
        if snapshot.id == node.id && metadata.owners.as_slice() == [owner.as_str()])
    );
    assert!(matches!(
        reader
            .node_info(&PubSubNodeInfoQuery {
                node: &name,
                requester: "reader@example.test",
            })
            .await
            .unwrap(),
        PubSubNodeInfo::Missing { redirect: None }
    ));
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn filtered_self_lists_keep_rows_when_node_is_deleted_mid_read() {
    let (url, pool) = integration_pool(2).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let name = format!("self-list-{suffix}");
    let owner = format!("owner-{suffix}@example.test");
    let subscriber = format!("{owner}/Phone");
    let requester = format!("{owner}/Tablet");
    let node = create_default_test_node(&pool, &name, &owner).await;
    set_subscription(&pool, node.id, &subscriber, "subscribed")
        .await
        .unwrap();
    let subscriptions_session = format!("subscriptions-{suffix}");
    let affiliations_session = format!("affiliations-{suffix}");
    let subscriptions = test_pubsub_service(
        named_single_connection_pool(&url, &subscriptions_session).await,
        "example.test",
    );
    let affiliations = test_pubsub_service(
        named_single_connection_pool(&url, &affiliations_session).await,
        "example.test",
    );
    let mut blocker = block_discovery_table(
        &pool,
        "LOCK TABLE pubsub_subscriptions, pubsub_affiliations IN ACCESS EXCLUSIVE MODE",
    )
    .await;

    let read_subscriptions = tokio::spawn({
        let reader = subscriptions.clone();
        let name = name.clone();
        let requester = requester.clone();
        async move {
            reader
                .self_subscriptions(&PubSubSelfListQuery {
                    node: Some(&name),
                    requester: &requester,
                })
                .await
        }
    });
    let read_affiliations = tokio::spawn({
        let reader = affiliations.clone();
        let name = name.clone();
        let requester = requester.clone();
        async move {
            reader
                .self_affiliations(&PubSubSelfListQuery {
                    node: Some(&name),
                    requester: &requester,
                })
                .await
        }
    });
    wait_for_named_session_lock(&pool, &subscriptions_session).await;
    wait_for_named_session_lock(&pool, &affiliations_session).await;
    sqlx::query("DELETE FROM pubsub_nodes WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let uri = "xmpp:pubsub.example.test?;node=moved";
    sqlx::query("INSERT INTO pubsub_node_redirects (node, uri) VALUES ($1,$2)")
        .bind(&name)
        .bind(uri)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();

    // The old split reads return empty success after the delete cascades.
    assert!(
        matches!(read_subscriptions.await.unwrap().unwrap(), PubSubSelfList::List(rows)
        if rows.len() == 1 && rows[0].jid == subscriber)
    );
    assert!(
        matches!(read_affiliations.await.unwrap().unwrap(), PubSubSelfList::List(rows)
        if rows.len() == 1 && rows[0].jid == owner && rows[0].affiliation == "owner")
    );
    let query = PubSubSelfListQuery {
        node: Some(&name),
        requester: &requester,
    };
    assert!(
        matches!(subscriptions.self_subscriptions(&query).await.unwrap(),
        PubSubSelfList::Missing { redirect: Some(redirect) } if redirect == uri)
    );
    assert!(
        matches!(affiliations.self_affiliations(&query).await.unwrap(),
        PubSubSelfList::Missing { redirect: Some(redirect) } if redirect == uri)
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn node_miss_keeps_live_redirect_during_concurrent_create_and_expiry() {
    let (url, pool) = integration_pool(2).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let name = format!("disco-redirect-{suffix}");
    let owner = format!("owner-{suffix}@example.test");
    let uri = "xmpp:pubsub.example.test?;node=moved";
    sqlx::query("INSERT INTO pubsub_node_redirects (node, uri) VALUES ($1,$2)")
        .bind(&name)
        .bind(uri)
        .execute(&pool)
        .await
        .unwrap();
    let reader = test_pubsub_service(
        named_single_connection_pool(&url, &name).await,
        "example.test",
    );
    let mut blocker = block_discovery_table(
        &pool,
        "LOCK TABLE pubsub_node_redirects IN ACCESS EXCLUSIVE MODE",
    )
    .await;
    let read = tokio::spawn({
        let reader = reader.clone();
        let name = name.clone();
        async move {
            reader
                .node_info(&PubSubNodeInfoQuery {
                    node: &name,
                    requester: "reader@example.test",
                })
                .await
        }
    });
    wait_for_named_session_lock(&pool, &name).await;
    let created = create_default_test_node(&pool, &name, &owner).await;
    // Move the deadline after creation so the node and live redirect overlap.
    sqlx::query(
        "UPDATE pubsub_node_redirects SET expires_at=NOW()-INTERVAL '1 second' WHERE node=$1",
    )
    .bind(&name)
    .execute(&mut *blocker)
    .await
    .unwrap();
    blocker.commit().await.unwrap();

    let during = read.await.unwrap().unwrap();
    assert!(
        matches!(during, PubSubNodeInfo::Missing { redirect: Some(redirect) }
        if redirect == uri)
    );
    assert!(node_redirect(&pool, &name).await.unwrap().is_none());
    let after = reader
        .node_info(&PubSubNodeInfoQuery {
            node: &name,
            requester: "reader@example.test",
        })
        .await
        .unwrap();
    assert!(matches!(after, PubSubNodeInfo::Info { node, .. } if node.id == created.id));
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn discovery_snapshot_queries_work_on_read_only_connections() {
    let (url, pool) = integration_pool(2).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}@example.test");
    let subscriber = format!("subscriber-{suffix}@example.test");
    let name = format!("readonly-discovery-{suffix}");
    let node = create_default_test_node(&pool, &name, &owner).await;
    sqlx::query("UPDATE pubsub_nodes SET access_model='whitelist' WHERE id=$1")
        .bind(node.id)
        .execute(&pool)
        .await
        .unwrap();
    let subscription_jid = format!("{subscriber}/Phone");
    let requester = format!("{subscriber}/Tablet");
    set_subscription(&pool, node.id, &subscription_jid, "subscribed")
        .await
        .unwrap();
    let reader = test_pubsub_service(read_only_disco::read_only_pool(&url).await, "example.test");

    let info = reader
        .node_info(&PubSubNodeInfoQuery {
            node: &name,
            requester: &requester,
        })
        .await
        .unwrap();
    assert!(matches!(info, PubSubNodeInfo::Info { metadata, .. }
        if metadata.owners.as_slice() == [owner.as_str()] && metadata.active_subscribers == 1));
    let items = reader
        .node_items(&PubSubNodeItemsQuery {
            node: &name,
            requester: &requester,
        })
        .await
        .unwrap();
    assert!(matches!(items, PubSubNodeItems::Leaf(leaf) if leaf.item_ids.is_empty()));
    assert!(matches!(
        reader
            .node_info(&PubSubNodeInfoQuery {
                node: &name,
                requester: "outsider@example.test",
            })
            .await
            .unwrap(),
        PubSubNodeInfo::Forbidden
    ));
    for filter in [Some(name.as_str()), None] {
        let subscriptions = reader
            .self_subscriptions(&PubSubSelfListQuery {
                node: filter,
                requester: &requester,
            })
            .await
            .unwrap();
        assert!(matches!(subscriptions, PubSubSelfList::List(rows)
            if rows.len() == 1 && rows[0].jid == subscription_jid));
        let affiliations = reader
            .self_affiliations(&PubSubSelfListQuery {
                node: filter,
                requester: &owner,
            })
            .await
            .unwrap();
        assert!(matches!(affiliations, PubSubSelfList::List(rows)
            if rows.len() == 1 && rows[0].jid == owner));
    }
    assert!(matches!(
        reader
            .self_affiliations(&PubSubSelfListQuery {
                node: Some(&name),
                requester: &requester,
            })
            .await
            .unwrap(),
        PubSubSelfList::List(rows) if rows.is_empty()
    ));
}
