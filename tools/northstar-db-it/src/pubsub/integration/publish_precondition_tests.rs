//! Policy and identity races in the generic PubSub mutation paths.

use super::*;
use northstar_pubsub_core::{
    PubSubBareJid, PubSubConfigureNodeWrite, PubSubDeleteNodeWrite, PubSubNodeId, PubSubNodeName,
    PubSubPurgeNodeWrite, PubSubRetractOutcome, PubSubRetractWrite, PubSubSetAffiliationsWrite,
    PubSubSetSubscriptionsWrite, PublishPolicyRejection,
};
use northstar_workflows::pubsub_repository::test_pubsub_service;
use sqlx::Postgres;
use tokio::task::JoinHandle;

const DOMAIN: &str = "example.test";
const PUBLISHER: &str = "publisher@example.test";
const WATCHER: &str = "watcher@remote.test";
const ITEM_ID: &str = "raced";

async fn fixture(pool: &PgPool) -> PubSubNode {
    let suffix = Uuid::new_v4().simple().to_string();
    create_default_test_node(
        pool,
        &format!("precondition-{suffix}"),
        &format!("owner-{suffix}@{DOMAIN}"),
    )
    .await
}

fn publication() -> [(String, String); 1] {
    [(
        ITEM_ID.to_owned(),
        "<item id='raced'><value xmlns='urn:test'/></item>".to_owned(),
    )]
}

async fn lock_node(pool: &PgPool, node_id: Uuid) -> Transaction<'_, Postgres> {
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(node_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    blocker
}

async fn start_waiting_publish<'a>(
    pool: &'a PgPool,
    url: &str,
    node: &PubSubNode,
    publisher: &str,
    options: Option<PubSubNodeConfig>,
) -> (
    Transaction<'a, Postgres>,
    PgPool,
    JoinHandle<Result<PublishItemsOutcome>>,
) {
    let application = format!("ps-publish-policy-{}", Uuid::new_v4().simple());
    let writer_pool = named_single_connection_pool(url, &application).await;
    let blocker = lock_node(pool, node.id).await;
    let task = tokio::spawn({
        let writer_pool = writer_pool.clone();
        let node = node.clone();
        let publisher = publisher.to_owned();
        async move {
            publish_items_with_options_and_renderer(
                &writer_pool,
                &node,
                &publisher,
                &publication(),
                options.as_ref(),
                1_000_000,
                &PubSubEventRenderer::new(DOMAIN),
            )
            .await
        }
    });
    wait_for_named_session_lock(pool, &application).await;
    (blocker, writer_pool, task)
}

async fn item_event_count(pool: &PgPool, node: &PubSubNode) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pubsub_event_outbox WHERE source_node=$1 AND payload_xml LIKE '%<items%'",
    )
    .bind(&node.node)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn assert_no_publication(pool: &PgPool, node: &PubSubNode) {
    assert!(get_items(pool, node.id, &[], 1).await.unwrap().is_empty());
    assert_eq!(item_event_count(pool, node).await, 0);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn compatible_max_items_increase_does_not_fail_a_waiting_publish() {
    let (url, pool) = integration_pool(3).await;
    let node = fixture(&pool).await;
    set_subscription(&pool, node.id, WATCHER, "subscribed")
        .await
        .unwrap();
    let (mut blocker, writer_pool, publish) =
        start_waiting_publish(&pool, &url, &node, &node.creator_jid, None).await;
    sqlx::query("UPDATE pubsub_nodes SET max_items=max_items+1 WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(
        publish.await.unwrap().unwrap(),
        PublishItemsOutcome::Published
    );
    assert_eq!(
        get_items(&pool, node.id, &[], 1).await.unwrap()[0].item_id,
        ITEM_ID
    );
    assert_eq!(item_event_count(&pool, &node).await, 1);
    writer_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn explicit_options_are_compared_with_the_locked_config() {
    let (url, pool) = integration_pool(3).await;
    let node = fixture(&pool).await;
    set_subscription(&pool, node.id, WATCHER, "subscribed")
        .await
        .unwrap();
    let (mut blocker, writer_pool, publish) =
        start_waiting_publish(&pool, &url, &node, &node.creator_jid, Some(node.config())).await;
    sqlx::query("UPDATE pubsub_nodes SET title='new title' WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(
        publish.await.unwrap().unwrap(),
        PublishItemsOutcome::Rejected(PublishPolicyRejection::PreconditionNotMet)
    );
    assert_no_publication(&pool, &node).await;
    writer_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn payload_policy_is_decided_on_the_locked_config() {
    let (url, pool) = integration_pool(3).await;
    let node = fixture(&pool).await;
    set_subscription(&pool, node.id, WATCHER, "subscribed")
        .await
        .unwrap();
    let (mut blocker, writer_pool, publish) =
        start_waiting_publish(&pool, &url, &node, &node.creator_jid, None).await;
    sqlx::query("UPDATE pubsub_nodes SET max_payload_size=1 WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(
        publish.await.unwrap().unwrap(),
        PublishItemsOutcome::Rejected(PublishPolicyRejection::PayloadTooBig)
    );
    assert_no_publication(&pool, &node).await;
    writer_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn forbidden_still_precedes_policy_under_the_lock() {
    let (url, pool) = integration_pool(3).await;
    let node = fixture(&pool).await;
    set_subscription(&pool, node.id, WATCHER, "subscribed")
        .await
        .unwrap();
    assert!(matches!(
        set_affiliations(
            &pool,
            node.id,
            &[(PUBLISHER.to_owned(), "publisher".to_owned())]
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    let (mut blocker, writer_pool, publish) =
        start_waiting_publish(&pool, &url, &node, PUBLISHER, Some(node.config())).await;
    sqlx::query("UPDATE pubsub_affiliations SET affiliation='member' WHERE node_id=$1 AND jid=$2")
        .bind(node.id)
        .bind(PUBLISHER)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("UPDATE pubsub_nodes SET max_items=max_items+1 WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(
        publish.await.unwrap().unwrap(),
        PublishItemsOutcome::Forbidden
    );
    assert_no_publication(&pool, &node).await;
    writer_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn retract_after_persistence_disabled_is_not_persistent() {
    let (url, pool) = integration_pool(3).await;
    let node = fixture(&pool).await;
    set_subscription(&pool, node.id, WATCHER, "subscribed")
        .await
        .unwrap();
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &node,
            &node.creator_jid,
            &publication(),
            false,
            1_000_000,
            &PubSubEventRenderer::new(DOMAIN),
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let application = format!("ps-retract-policy-{}", Uuid::new_v4().simple());
    let writer_pool = named_single_connection_pool(&url, &application).await;
    let mut blocker = lock_node(&pool, node.id).await;
    let retract = tokio::spawn({
        let service = test_pubsub_service(writer_pool.clone(), DOMAIN);
        let node = node.clone();
        async move {
            service
                .execute_pubsub_retract(
                    PubSubRetractWrite {
                        requester: &node.creator_jid,
                        node: &node.node,
                        item_ids: &[ITEM_ID.to_owned()],
                        force_notification: true,
                    }
                    .into(),
                )
                .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    sqlx::query("UPDATE pubsub_nodes SET persist_items=false WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(
        retract.await.unwrap().unwrap().outcome,
        PubSubRetractOutcome::NotPersistent
    );
    assert_eq!(
        get_items(&pool, node.id, &[], 1).await.unwrap()[0].item_id,
        ITEM_ID
    );
    assert_eq!(item_event_count(&pool, &node).await, 1);
    writer_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn owner_write_after_same_name_replacement_fails_closed() {
    let (_, pool) = integration_pool(3).await;
    let node = fixture(&pool).await;
    let service = test_pubsub_service(pool.clone(), DOMAIN);
    let name = PubSubNodeName::parse(&node.node).unwrap();
    let requester = PubSubBareJid::parse(&node.creator_jid).unwrap();
    let preflight = service
        .owner_preflight(&name, &requester, true)
        .await
        .unwrap()
        .unwrap();
    assert!(preflight.is_owner);
    let node_id = PubSubNodeId::new(preflight.node.id);
    let owner = node.creator_jid.as_str();
    let node = node.node.as_str();
    assert_eq!(
        delete_node_as_owner_with_redirect_and_outbox(
            &pool,
            node_id.get(),
            owner,
            None,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        OwnerMutationOutcome::Applied
    );
    let replacement = create_default_test_node(&pool, node, owner).await;
    assert_ne!(node_id.get(), replacement.id);
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &replacement,
            owner,
            &publication(),
            false,
            1_000_000,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let subscription_changes = [(WATCHER.to_owned(), "subscribed".to_owned(), None)];
    let affiliation_changes = [(PUBLISHER.to_owned(), "publisher".to_owned())];
    let expected = preflight.node.config();
    let config = PubSubNodeConfig {
        title: Some("must stay untouched".to_owned()),
        ..expected.clone()
    };
    assert_eq!(
        service
            .execute_pubsub_delete_node(
                PubSubDeleteNodeWrite {
                    requester: owner,
                    node,
                    node_id,
                    redirect: Some("xmpp:other@example.test"),
                }
                .into(),
            )
            .await
            .unwrap()
            .outcome,
        northstar_pubsub_core::OwnerMutationOutcome::NotFound
    );
    assert_eq!(
        service
            .execute_pubsub_purge_node(
                PubSubPurgeNodeWrite {
                    requester: owner,
                    node,
                    node_id,
                    observed_node: &preflight.node,
                }
                .into(),
            )
            .await
            .unwrap()
            .outcome,
        northstar_pubsub_core::OwnerMutationOutcome::NotFound
    );
    assert_eq!(
        service
            .execute_pubsub_set_subscriptions(
                PubSubSetSubscriptionsWrite {
                    requester: owner,
                    node,
                    node_id,
                    changes: &subscription_changes,
                }
                .into(),
            )
            .await
            .unwrap()
            .outcome,
        northstar_pubsub_core::SetSubscriptionsOutcome::NotFound
    );
    assert_eq!(
        service
            .execute_pubsub_set_affiliations(
                PubSubSetAffiliationsWrite {
                    requester: owner,
                    node,
                    node_id,
                    changes: &affiliation_changes,
                }
                .into(),
            )
            .await
            .unwrap()
            .outcome,
        northstar_pubsub_core::SetAffiliationsOutcome::NotFound
    );
    assert_eq!(
        service
            .execute_pubsub_configure_node(
                PubSubConfigureNodeWrite {
                    requester: owner,
                    node: &preflight.node,
                    expected: &expected,
                    config: &config,
                }
                .into(),
            )
            .await
            .unwrap()
            .outcome,
        northstar_pubsub_core::PubSubConfigOutcome::NotFound
    );
    let current = get_node(&pool, node).await.unwrap().unwrap();
    assert_eq!(current.id, replacement.id);
    assert_eq!(current.config(), replacement.config());
    assert_eq!(
        get_items(&pool, current.id, &[], 1).await.unwrap()[0].item_id,
        ITEM_ID
    );
    assert!(get_subscription(&pool, current.id, WATCHER)
        .await
        .unwrap()
        .is_none());
    assert!(get_node_affiliation(&pool, current.id, PUBLISHER)
        .await
        .unwrap()
        .is_none());
    assert!(service.node_redirect(node).await.unwrap().is_none());
    let outbox_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(node)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(outbox_rows, 0);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn owner_preflight_reads_one_snapshot_on_a_read_only_connection() {
    let (url, pool) = integration_pool(3).await;
    let node = fixture(&pool).await;
    let parent = fixture(&pool).await;
    let child = fixture(&pool).await;
    // Seed an incoming and outgoing graph edge for the two preflight projections.
    sqlx::query("UPDATE pubsub_nodes SET node_type='collection' WHERE id IN ($1, $2)")
        .bind(parent.id)
        .bind(node.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO pubsub_collection_members(collection_node_id, child_node_id) VALUES ($1, $2), ($2, $3)",
    )
    .bind(parent.id)
    .bind(node.id)
    .bind(child.id)
    .execute(&pool)
    .await
    .unwrap();

    let application = format!("ps-owner-preflight-{}", Uuid::new_v4().simple());
    let reader_pool = named_single_connection_pool(&url, &application).await;
    sqlx::query("SET default_transaction_read_only = on")
        .execute(&reader_pool)
        .await
        .unwrap();
    let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
        .fetch_one(&reader_pool)
        .await
        .unwrap();
    assert_eq!(read_only, "on");
    let reader = test_pubsub_service(reader_pool.clone(), DOMAIN);
    let name = PubSubNodeName::parse(&node.node).unwrap();
    let requester = PubSubBareJid::parse(&node.creator_jid).unwrap();
    let without_graph = reader
        .owner_preflight(&name, &requester, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(without_graph.node.id, node.id);
    assert!(without_graph.is_owner);
    assert!(without_graph.parents.is_empty());
    assert!(without_graph.children.is_empty());

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE pubsub_collection_members IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let task = tokio::spawn({
        let reader = reader.clone();
        let name = name.clone();
        let requester = requester.clone();
        async move { reader.owner_preflight(&name, &requester, true).await }
    });
    wait_for_named_session_lock(&pool, &application).await;
    sqlx::query(
        "DELETE FROM pubsub_collection_members WHERE collection_node_id=$1 OR child_node_id=$1",
    )
    .bind(node.id)
    .execute(&mut *blocker)
    .await
    .unwrap();
    sqlx::query("UPDATE pubsub_affiliations SET affiliation='member' WHERE node_id=$1 AND jid=$2")
        .bind(node.id)
        .bind(&node.creator_jid)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("UPDATE pubsub_nodes SET title='new title' WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();

    let observed = task.await.unwrap().unwrap().unwrap();
    assert_eq!(observed.node.id, node.id);
    assert!(observed.is_owner);
    assert_eq!(observed.node.title, None);
    assert_eq!(observed.parents, [parent.node]);
    assert_eq!(observed.children, [child.node]);
    let current = reader
        .owner_preflight(&name, &requester, true)
        .await
        .unwrap()
        .unwrap();
    assert!(!current.is_owner);
    assert_eq!(current.node.title.as_deref(), Some("new title"));
    assert!(current.parents.is_empty());
    assert!(current.children.is_empty());
    reader_pool.close().await;
    pool.close().await;
}
