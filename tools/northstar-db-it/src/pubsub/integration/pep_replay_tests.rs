//! PEP replay authority, item selection and owner cursors on PostgreSQL.

use super::{
    integration_pool, named_single_connection_pool, read_only_disco::read_only_pool,
    wait_for_named_session_lock,
};
use northstar_pubsub_core::{
    PepReplayCursor, PepReplayMode, PepReplayOrigin, PepReplayPage, PepReplayQuery, PubSubAccount,
    PubSubAddress,
};
use northstar_time::{DateTime, Utc};
use northstar_workflows::pubsub_repository::test_pubsub_service;
use sqlx::{Executor, PgPool, Postgres};
use uuid::Uuid;

const DOMAIN: &str = "example.test";
const NODE: &str = "urn:test:pep:news";
const OTHER: &str = "urn:test:pep:weather";
const OLD: &str = "2025-01-01T00:00:00Z";
const NEW: &str = "2025-01-02T00:00:00Z";

async fn insert_account(pool: &PgPool) -> PubSubAccount {
    let id = Uuid::new_v4();
    let username = format!("pep-replay-{}", id.simple());
    let auth_generation = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test') RETURNING auth_generation",
    )
    .bind(id)
    .bind(&username)
    .fetch_one(pool)
    .await
    .unwrap();
    PubSubAccount {
        id,
        username,
        auth_generation,
    }
}

async fn delete_accounts(pool: &PgPool, ids: &[Uuid]) {
    sqlx::query("DELETE FROM users WHERE id=ANY($1)")
        .bind(ids)
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_node(pool: &PgPool, owner: Uuid, node: &str, model: &str) {
    sqlx::query(
        "INSERT INTO pep_nodes(owner_id,node,access_model,max_items,send_last_published_item)
         VALUES($1,$2,$3,10,'on_sub_and_presence')",
    )
    .bind(owner)
    .bind(node)
    .bind(model)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_item<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    owner: Uuid,
    node: &str,
    item: &str,
    at: &str,
) {
    sqlx::query(
        "INSERT INTO pep_items(owner_id,node,item_id,payload,updated_at) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(owner)
    .bind(node)
    .bind(item)
    .bind(format!("<item id='{item}'/>"))
    .bind(at.parse::<DateTime<Utc>>().unwrap())
    .execute(executor)
    .await
    .unwrap();
}

async fn insert_roster(pool: &PgPool, owner: Uuid, contact: &str, subscription: &str) {
    sqlx::query("INSERT INTO roster_items(owner_id,contact_jid,subscription) VALUES($1,$2,$3)")
        .bind(owner)
        .bind(contact)
        .bind(subscription)
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_subscription(pool: &PgPool, owner: Uuid, node: &str, subscriber: &str) {
    sqlx::query(
        "INSERT INTO pep_subscriptions(owner_id,node,subscriber_jid,subid) VALUES($1,$2,$3,$4)",
    )
    .bind(owner)
    .bind(node)
    .bind(subscriber)
    .bind(Uuid::new_v4().to_string())
    .execute(pool)
    .await
    .unwrap();
}

fn query(requester: &str, mode: PepReplayMode) -> PepReplayQuery {
    PepReplayQuery {
        requester: PubSubAddress::parse(requester).unwrap(),
        mode,
        local_domain: DOMAIN.to_owned(),
        after: None,
        limit: 1,
    }
}

fn federated_query(requester: &str, wanted: &[&str]) -> PepReplayQuery {
    query(
        requester,
        PepReplayMode::FederatedCaps {
            wanted: wanted.iter().map(|node| (*node).to_owned()).collect(),
        },
    )
}

fn selected_items(page: &PepReplayPage) -> Vec<(&str, &str, PepReplayOrigin)> {
    page.entries
        .iter()
        .map(|entry| (entry.node.as_str(), entry.item_id.as_str(), entry.origin))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pep_replay_page_reads_owner_facts_from_one_snapshot() {
    let (url, pool) = integration_pool(8).await;
    let owner = insert_account(&pool).await;
    let bare = format!("{}@remote.test", owner.username);
    let query = federated_query(&format!("{bare}/phone"), &[NODE]);
    insert_roster(&pool, owner.id, &bare, "from").await;
    insert_node(&pool, owner.id, NODE, "presence").await;
    insert_item(&pool, owner.id, NODE, "old", OLD).await;

    let application = format!("pep-replay-acl-{}", owner.id.simple());
    let read_pool = named_single_connection_pool(&url, &application).await;
    let reader = test_pubsub_service(read_pool.clone(), DOMAIN);
    let during = query.clone();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE pep_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let request = tokio::spawn(async move { reader.pep_replay_page(&during).await.unwrap() });
    wait_for_named_session_lock(&pool, &application).await;

    sqlx::query("UPDATE roster_items SET subscription='none' WHERE owner_id=$1 AND contact_jid=$2")
        .bind(owner.id)
        .bind(&bare)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
        .bind(owner.id)
        .bind(&bare)
        .execute(&mut *blocker)
        .await
        .unwrap();
    insert_item(&mut *blocker, owner.id, NODE, "new", NEW).await;
    blocker.commit().await.unwrap();

    // The split-read replay would use the old ACL and send the new item.
    let page = request.await.unwrap();
    assert_eq!((page.scanned, page.next.as_ref()), (1, None));
    assert_eq!(
        selected_items(&page),
        [(NODE, "old", PepReplayOrigin::Automatic)]
    );
    assert_eq!(page.entries[0].owner_id, owner.id);
    assert_eq!(page.entries[0].payload, "<item id='old'/>");
    assert_eq!(
        page.entries[0].updated_at.to_rfc3339(),
        "2025-01-01T00:00:00+00:00"
    );
    let service = test_pubsub_service(pool.clone(), DOMAIN);
    assert_eq!(
        service.pep_replay_page(&query).await.unwrap(),
        PepReplayPage::default()
    );
    read_pool.close().await;
    delete_accounts(&pool, &[owner.id]).await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pep_replay_dedups_explicit_and_automatic_in_one_snapshot() {
    let (url, pool) = integration_pool(8).await;
    let owner = insert_account(&pool).await;
    let bare = format!("{}@remote.test", owner.username);
    let full = format!("{bare}/phone");
    insert_roster(&pool, owner.id, &bare, "from").await;
    insert_node(&pool, owner.id, NODE, "presence").await;
    insert_node(&pool, owner.id, OTHER, "presence").await;
    insert_item(&pool, owner.id, NODE, "explicit", OLD).await;
    insert_item(&pool, owner.id, OTHER, "old", OLD).await;
    insert_subscription(&pool, owner.id, NODE, &bare).await;
    insert_subscription(&pool, owner.id, OTHER, &format!("{bare}/tablet")).await;

    let service = test_pubsub_service(pool.clone(), DOMAIN);
    let explicit = query(&full, PepReplayMode::Explicit);
    let page = service.pep_replay_page(&explicit).await.unwrap();
    assert_eq!(
        selected_items(&page),
        [(NODE, "explicit", PepReplayOrigin::Explicit)]
    );

    let query = federated_query(&full, &[NODE, OTHER]);
    let application = format!("pep-replay-dedup-{}", owner.id.simple());
    let read_pool = named_single_connection_pool(&url, &application).await;
    let reader = test_pubsub_service(read_pool.clone(), DOMAIN);
    let during = query.clone();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE pep_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let request = tokio::spawn(async move { reader.pep_replay_page(&during).await.unwrap() });
    wait_for_named_session_lock(&pool, &application).await;
    sqlx::query(
        "DELETE FROM pep_subscriptions WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3",
    )
    .bind(owner.id)
    .bind(NODE)
    .bind(&bare)
    .execute(&mut *blocker)
    .await
    .unwrap();
    insert_item(&mut *blocker, owner.id, OTHER, "new", NEW).await;
    blocker.commit().await.unwrap();

    // The other resource's explicit subscription never suppresses this replay.
    // Old dedup paired with the new publication would produce only OTHER/new.
    let page = request.await.unwrap();
    assert_eq!(
        selected_items(&page),
        [(OTHER, "old", PepReplayOrigin::Automatic)]
    );
    let page = service.pep_replay_page(&query).await.unwrap();
    assert_eq!(
        selected_items(&page),
        [
            (NODE, "explicit", PepReplayOrigin::Automatic),
            (OTHER, "new", PepReplayOrigin::Automatic),
        ],
    );
    assert!(service
        .pep_replay_page(&explicit)
        .await
        .unwrap()
        .entries
        .is_empty());
    read_pool.close().await;
    delete_accounts(&pool, &[owner.id]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pep_replay_page_succeeds_on_read_only_connections() {
    let (url, pool) = integration_pool(2).await;
    let owner = insert_account(&pool).await;
    let subscriber = insert_account(&pool).await;
    let local = format!("{}@{DOMAIN}", subscriber.username);
    let remote = format!("{}@remote.test", subscriber.username);
    insert_roster(
        &pool,
        subscriber.id,
        &format!("{}@{DOMAIN}", owner.username),
        "to",
    )
    .await;
    insert_roster(&pool, owner.id, &local, "from").await;
    insert_roster(&pool, owner.id, &remote, "from").await;
    insert_node(&pool, subscriber.id, NODE, "whitelist").await;
    insert_item(&pool, subscriber.id, NODE, "self", OLD).await;
    for (node, item) in [(NODE, "news"), (OTHER, "weather")] {
        insert_node(&pool, owner.id, node, "presence").await;
        insert_item(&pool, owner.id, node, item, OLD).await;
    }
    insert_subscription(&pool, owner.id, NODE, &remote).await;
    let full = format!("{remote}/phone");
    insert_subscription(&pool, subscriber.id, NODE, &full).await;

    let read_pool = read_only_pool(&url).await;
    let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
        .fetch_one(&read_pool)
        .await
        .unwrap();
    assert_eq!(read_only, "on");
    let service = test_pubsub_service(read_pool.clone(), DOMAIN);
    let mut local = query(
        &format!("{local}/desk"),
        PepReplayMode::LocalCaps {
            wanted: vec![OTHER.to_owned(), NODE.to_owned()],
        },
    );
    let page = service.pep_replay_page(&local).await.unwrap();
    assert_eq!(page.scanned, 1);
    assert_eq!(page.next, Some(PepReplayCursor::LocalSelf));
    assert_eq!(
        selected_items(&page),
        [(NODE, "self", PepReplayOrigin::Automatic)]
    );
    local.after = page.next;
    let page = service.pep_replay_page(&local).await.unwrap();
    assert_eq!((page.scanned, page.next.as_ref()), (1, None));
    assert_eq!(
        selected_items(&page),
        [
            (OTHER, "weather", PepReplayOrigin::Automatic),
            (NODE, "news", PepReplayOrigin::Automatic),
        ],
    );

    let mut explicit = query(&full, PepReplayMode::Explicit);
    let mut owner_order = [owner.id, subscriber.id];
    owner_order.sort_unstable();
    for (index, expected_owner) in owner_order.into_iter().enumerate() {
        let page = service.pep_replay_page(&explicit).await.unwrap();
        assert_eq!(page.scanned, 1);
        if expected_owner == owner.id {
            assert_eq!(
                selected_items(&page),
                [(NODE, "news", PepReplayOrigin::Explicit)]
            );
        } else {
            assert!(
                page.entries.is_empty(),
                "an explicit subscription still needs the node ACL"
            );
        }
        assert_eq!(
            page.next,
            (index == 0).then_some(PepReplayCursor::Explicit(expected_owner))
        );
        explicit.after = page.next;
    }
    let page = service
        .pep_replay_page(&federated_query(&full, &[NODE, OTHER]))
        .await
        .unwrap();
    assert_eq!(
        selected_items(&page),
        [(OTHER, "weather", PepReplayOrigin::Automatic)]
    );
    let direct = query(
        &remote,
        PepReplayMode::AfterSubscribe {
            owner: owner.clone(),
            node: NODE.to_owned(),
            on_presence: false,
        },
    );
    let page = service.pep_replay_page(&direct).await.unwrap();
    assert_eq!(
        selected_items(&page),
        [(NODE, "news", PepReplayOrigin::Explicit)]
    );
    let different_address = PepReplayQuery {
        requester: PubSubAddress::parse(&full).unwrap(),
        ..direct
    };
    assert!(service
        .pep_replay_page(&different_address)
        .await
        .unwrap()
        .entries
        .is_empty());

    read_pool.close().await;
    delete_accounts(&pool, &[owner.id, subscriber.id]).await;
    pool.close().await;
}
