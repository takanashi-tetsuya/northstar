//! Races at the generic subscription command boundary.

use super::*;
use northstar_pubsub_application::{
    PubSubSubscribeCommand, PubSubUnsubscribeCommand, PubSubUpdateSubscriptionOptionsCommand,
};
use northstar_pubsub_core::{
    PubSubNodeId, PubSubSubscribeOutcome, PubSubSubscribeWrite, PubSubUnsubscribeOutcome,
    PubSubUnsubscribeWrite, RequestedSubId, SubscriptionOptionsOutcome, SubscriptionOptionsPatch,
};
use northstar_workflows::pubsub_repository::test_pubsub_service;

const DOMAIN: &str = "example.test";

async fn lock_node(transaction: &mut Transaction<'_, sqlx::Postgres>, node_id: Uuid) {
    sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(node_id)
        .fetch_one(&mut **transaction)
        .await
        .unwrap();
}

async fn lock_subscription(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    node_id: Uuid,
    jid: &str,
) {
    sqlx::query("SELECT subid FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2 FOR UPDATE")
        .bind(node_id)
        .bind(jid)
        .fetch_one(&mut **transaction)
        .await
        .unwrap();
}

async fn subscribe_request(
    pool: PgPool,
    node: String,
    jid: String,
) -> Result<PubSubSubscribeOutcome> {
    let service = test_pubsub_service(pool, DOMAIN);
    let requester = northstar_xmpp_types::jid::canonical_bare_key(&jid)?;
    Ok(service
        .execute_pubsub_subscribe(PubSubSubscribeCommand::from(PubSubSubscribeWrite {
            requester: &requester,
            subscriber_jid: &jid,
            node: &node,
            options: None,
            max_subscriptions: 100,
        }))
        .await?
        .outcome)
}

async fn patch_request(
    pool: PgPool,
    node_id: Uuid,
    jid: String,
    subid: String,
    patch: SubscriptionOptionsPatch,
) -> Result<SubscriptionOptionsOutcome> {
    let service = test_pubsub_service(pool, DOMAIN);
    let requester = northstar_xmpp_types::jid::canonical_bare_key(&jid)?;
    Ok(service
        .execute_pubsub_update_subscription_options(PubSubUpdateSubscriptionOptionsCommand {
            node_id: PubSubNodeId::new(node_id),
            requester: &requester,
            subscriber_jid: &jid,
            expected_subid: &subid,
            patch: &patch,
        })
        .await?
        .outcome)
}

async fn last_item_count(pool: &PgPool, node: &str, jid: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_event_outbox
          WHERE source_node=$1 AND recipient_jid=$2 AND payload_xml LIKE '%<items%'",
    )
    .bind(node)
    .bind(jid)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn disjoint_option_patches_both_survive_concurrent_updates() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("patch-owner-{suffix}@{DOMAIN}");
    let subscriber = format!("patch-reader-{suffix}@{DOMAIN}/desktop");
    let node = create_default_test_node(&pool, &format!("patch-{suffix}"), &owner).await;
    let original = subscribe_for_race(&pool, &node, &subscriber, &suffix).await;
    assert!(original.deliver);
    assert!(!original.digest);
    let first_session = format!("ps-patch-first-{suffix}");
    let second_session = format!("ps-patch-second-{suffix}");
    let first_pool = named_single_connection_pool(&url, &first_session).await;
    let second_pool = named_single_connection_pool(&url, &second_session).await;
    let mut blocker = pool.begin().await.unwrap();
    lock_subscription(&mut blocker, node.id, &subscriber).await;
    let first = tokio::spawn(patch_request(
        first_pool.clone(),
        node.id,
        subscriber.clone(),
        original.subid.clone(),
        SubscriptionOptionsPatch {
            deliver: Some(false),
            ..SubscriptionOptionsPatch::default()
        },
    ));
    let second = tokio::spawn(patch_request(
        second_pool.clone(),
        node.id,
        subscriber.clone(),
        original.subid.clone(),
        SubscriptionOptionsPatch {
            digest: Some(true),
            ..SubscriptionOptionsPatch::default()
        },
    ));
    wait_for_named_session_lock(&pool, &first_session).await;
    wait_for_named_session_lock(&pool, &second_session).await;
    blocker.commit().await.unwrap();

    assert_eq!(
        first.await.unwrap().unwrap(),
        SubscriptionOptionsOutcome::Updated
    );
    assert_eq!(
        second.await.unwrap().unwrap(),
        SubscriptionOptionsOutcome::Updated
    );
    let current = get_subscription(&pool, node.id, &subscriber)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.subid, original.subid);
    assert!(!current.deliver);
    assert!(current.digest);
    assert_eq!(current.digest_frequency, original.digest_frequency);

    let updated_at = || {
        sqlx::query_scalar::<_, DateTime<Utc>>(
            "SELECT updated_at FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2",
        )
        .bind(node.id)
        .bind(&subscriber)
        .fetch_one(&pool)
    };
    let before = updated_at().await.unwrap();
    assert_eq!(
        patch_request(
            first_pool.clone(),
            node.id,
            subscriber.clone(),
            original.subid,
            SubscriptionOptionsPatch::default(),
        )
        .await
        .unwrap(),
        SubscriptionOptionsOutcome::Updated
    );
    assert_eq!(updated_at().await.unwrap(), before);
    first_pool.close().await;
    second_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn subscribe_fast_paths_are_decided_under_the_lock() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("approve-owner-{suffix}@{DOMAIN}");
    let subscriber = format!("approve-reader-{suffix}@{DOMAIN}/desktop");
    let node = create_default_test_node(&pool, &format!("approve-{suffix}"), &owner).await;
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
    sqlx::query("UPDATE pubsub_nodes SET access_model='authorize' WHERE id=$1")
        .bind(node.id)
        .execute(&pool)
        .await
        .unwrap();
    let PubSubSubscribeOutcome::Subscribed(pending) =
        subscribe_request(pool.clone(), node.node.clone(), subscriber.clone())
            .await
            .unwrap()
    else {
        panic!("initial subscribe should create a pending row");
    };
    assert_eq!(pending.state, "pending");
    assert_eq!(last_item_count(&pool, &node.node, &subscriber).await, 0);

    let session = format!("ps-subscribe-approve-{suffix}");
    let retry_pool = named_single_connection_pool(&url, &session).await;
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let gate = Arc::new(RenderGate::default());
    let approval = tokio::spawn({
        let pool = pool.clone();
        let subscriber = subscriber.clone();
        let subid = pending.subid.clone();
        let renderer = RaceMutationRenderer {
            inner: PubSubEventRenderer::new(DOMAIN),
            observations: observation_tx,
            gate: Some(Arc::clone(&gate)),
        };
        let node_id = node.id;
        async move {
            resolve_pending_subscription_with_renderer(
                &pool,
                node_id,
                &owner,
                &subscriber,
                &subid,
                true,
                &renderer,
            )
            .await
        }
    });
    await_mutation_observation(&mut observation_rx, "subscription approval").await;
    let retry = tokio::spawn(subscribe_request(
        retry_pool.clone(),
        node.node.clone(),
        subscriber.clone(),
    ));
    wait_for_named_session_lock(&pool, &session).await;
    gate.release();
    assert_eq!(
        approval.await.unwrap().unwrap(),
        SubscriptionAuthorizationOutcome::Applied
    );
    assert!(matches!(
        retry.await.unwrap().unwrap(),
        PubSubSubscribeOutcome::ExistingActive(row) if row.subid == pending.subid
    ));
    assert_eq!(last_item_count(&pool, &node.node, &subscriber).await, 1);

    // The existing active row wins over whitelist access while live. After expiry,
    // the very same request must instead be evaluated against the closed policy.
    sqlx::query("UPDATE pubsub_nodes SET access_model='whitelist' WHERE id=$1")
        .bind(node.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        subscribe_request(pool.clone(), node.node.clone(), subscriber.clone())
            .await
            .unwrap(),
        PubSubSubscribeOutcome::ExistingActive(row) if row.subid == pending.subid
    ));
    let mut blocker = pool.begin().await.unwrap();
    lock_node(&mut blocker, node.id).await;
    let retry = tokio::spawn(subscribe_request(
        retry_pool.clone(),
        node.node.clone(),
        subscriber.clone(),
    ));
    wait_for_named_session_lock(&pool, &session).await;
    sqlx::query(
        "UPDATE pubsub_subscriptions SET expire=clock_timestamp() WHERE node_id=$1 AND jid=$2",
    )
    .bind(node.id)
    .bind(&subscriber)
    .execute(&mut *blocker)
    .await
    .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(
        retry.await.unwrap().unwrap(),
        PubSubSubscribeOutcome::ClosedNode
    );
    assert_eq!(last_item_count(&pool, &node.node, &subscriber).await, 1);
    retry_pool.close().await;
    pool.close().await;
}

async fn unsubscribe_across_replacement(
    echo: Option<&str>,
) -> (PubSubUnsubscribeOutcome, Option<String>, String) {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("replace-owner-{suffix}@{DOMAIN}");
    let subscriber = format!("replace-reader-{suffix}@{DOMAIN}/desktop");
    let requester = northstar_xmpp_types::jid::canonical_bare_key(&subscriber).unwrap();
    let node = create_default_test_node(&pool, &format!("replace-{suffix}"), &owner).await;
    let original_subid = format!("original-{suffix}");
    let replacement_subid = format!("replacement-{suffix}");
    let original = subscribe_for_race(&pool, &node, &subscriber, &original_subid).await;
    let session = format!("ps-unsubscribe-{suffix}");
    let retry_pool = named_single_connection_pool(&url, &session).await;
    let mut blocker = pool.begin().await.unwrap();
    lock_node(&mut blocker, node.id).await;
    let request = tokio::spawn({
        let service = test_pubsub_service(retry_pool.clone(), DOMAIN);
        let node = node.node.clone();
        let subscriber = subscriber.clone();
        let echo = echo.map(|echo| format!("{echo}-{suffix}"));
        async move {
            service
                .execute_pubsub_unsubscribe(PubSubUnsubscribeCommand::from(
                    PubSubUnsubscribeWrite {
                        requester: &requester,
                        subscriber_jid: &subscriber,
                        node: &node,
                        requested_subid: RequestedSubId(echo.as_deref()),
                    },
                ))
                .await
                .unwrap()
                .outcome
        }
    });
    wait_for_named_session_lock(&pool, &session).await;
    sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2 AND subid=$3")
        .bind(node.id)
        .bind(&subscriber)
        .bind(&original.subid)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO pubsub_subscriptions (node_id, jid, state, subid)
         VALUES ($1, $2, 'subscribed', $3)",
    )
    .bind(node.id)
    .bind(&subscriber)
    .bind(&replacement_subid)
    .execute(&mut *blocker)
    .await
    .unwrap();
    blocker.commit().await.unwrap();
    let outcome = request.await.unwrap();
    let remaining = get_subscription(&pool, node.id, &subscriber)
        .await
        .unwrap()
        .map(|row| row.subid);
    retry_pool.close().await;
    pool.close().await;
    (outcome, remaining, replacement_subid)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn unsubscribe_without_subid_removes_the_replacement_row() {
    let (outcome, remaining, replacement) = unsubscribe_across_replacement(None).await;
    assert_eq!(
        outcome,
        PubSubUnsubscribeOutcome::Unsubscribed {
            subid: Some(replacement)
        }
    );
    assert!(remaining.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn stale_echoed_subid_is_rejected_after_lock_wait() {
    // Exercise both an echo that loses its match while waiting and one that
    // would be rejected by the old application precheck without taking a lock.
    for echo in ["original", "older-than-original"] {
        let (outcome, remaining, replacement) = unsubscribe_across_replacement(Some(echo)).await;
        assert_eq!(outcome, PubSubUnsubscribeOutcome::InvalidSubid);
        assert_eq!(remaining, Some(replacement));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn lease_expiry_is_evaluated_after_subscribe_lock_wait() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("lease-owner-{suffix}@{DOMAIN}");
    let subscriber = format!("lease-reader-{suffix}@{DOMAIN}/desktop");
    let node = create_default_test_node(&pool, &format!("lease-subscribe-{suffix}"), &owner).await;
    let original = subscribe_for_race(&pool, &node, &subscriber, &suffix).await;
    let session = format!("ps-subscribe-lease-{suffix}");
    let retry_pool = named_single_connection_pool(&url, &session).await;
    let mut blocker = pool.begin().await.unwrap();
    lock_subscription(&mut blocker, node.id, &subscriber).await;
    let retry = tokio::spawn(subscribe_request(
        retry_pool.clone(),
        node.node.clone(),
        subscriber.clone(),
    ));
    wait_for_named_session_lock(&pool, &session).await;
    let expiry: DateTime<Utc> = sqlx::query_scalar(
        "UPDATE pubsub_subscriptions SET expire=clock_timestamp()
          WHERE node_id=$1 AND jid=$2 RETURNING expire",
    )
    .bind(node.id)
    .bind(&subscriber)
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(
        retry.await.unwrap().unwrap(),
        PubSubSubscribeOutcome::Subscribed(row) if row.subid == original.subid && row.expire.is_none()
    ));
    let created_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT created_at FROM pubsub_subscriptions WHERE node_id=$1 AND jid=$2",
    )
    .bind(node.id)
    .bind(&subscriber)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(created_at >= expiry);
    retry_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn subscribe_sees_affiliation_and_access_model_change_atomically() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("access-owner-{suffix}@{DOMAIN}");
    let subscriber = format!("access-reader-{suffix}@{DOMAIN}");
    let node = create_default_test_node(&pool, &format!("access-subscribe-{suffix}"), &owner).await;
    sqlx::query("UPDATE pubsub_nodes SET access_model='whitelist' WHERE id=$1")
        .bind(node.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO pubsub_affiliations (node_id, jid, affiliation) VALUES ($1, $2, 'member')",
    )
    .bind(node.id)
    .bind(&subscriber)
    .execute(&pool)
    .await
    .unwrap();
    let session = format!("ps-subscribe-access-{suffix}");
    let retry_pool = named_single_connection_pool(&url, &session).await;
    let mut blocker = pool.begin().await.unwrap();
    lock_node(&mut blocker, node.id).await;
    // The old split path could read whitelist, then wait on this table and
    // read the affiliation after it disappeared. The new path waits on the node.
    sqlx::query("LOCK TABLE pubsub_affiliations IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let retry = tokio::spawn(subscribe_request(
        retry_pool.clone(),
        node.node.clone(),
        subscriber.clone(),
    ));
    wait_for_named_session_lock(&pool, &session).await;
    sqlx::query("UPDATE pubsub_nodes SET access_model='open' WHERE id=$1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("DELETE FROM pubsub_affiliations WHERE node_id=$1 AND jid=$2")
        .bind(node.id)
        .bind(&subscriber)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert!(matches!(
        retry.await.unwrap().unwrap(),
        PubSubSubscribeOutcome::Subscribed(row) if row.state == "subscribed"
    ));
    retry_pool.close().await;
    pool.close().await;
}
