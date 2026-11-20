//! PEP reads and explicit create under deterministic lock waits.

use super::{integration_pool, named_single_connection_pool, wait_for_named_session_lock};
use northstar_pubsub_application::{
    PepAccountItemsRead, PepAccountQuery, PepCreateNodeCommand, PepItemQuery, PepItemRead,
    PepItemSelection, PepNodeInfoRead, PepNodeItemsRead, PepNodeQuery, PepOwnerQuery,
    PepOwnerSubscriptionsRead, PepRequester,
};
use northstar_pubsub_core::{PepAccessDenial, PepCreateOutcome, PubSubAccount};
use northstar_workflows::pubsub_repository::test_pubsub_service;
use sqlx::{Executor, PgPool, Postgres};
use uuid::Uuid;

const DOMAIN: &str = "example.test";
const REQUESTER_BARE: &str = "reader@remote.test";
const REQUESTER_FULL: &str = "reader@remote.test/phone";
const NODE: &str = "urn:test:pep:snapshot";

async fn insert_owner(pool: &PgPool) -> PubSubAccount {
    let id = Uuid::new_v4();
    let username = format!("pep-snapshot-{}", id.simple());
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

async fn delete_owner(pool: &PgPool, owner_id: Uuid) {
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(owner_id)
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_node<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    node: &str,
    access_model: &str,
) {
    sqlx::query(
        "INSERT INTO pep_nodes(owner_id,node,access_model,max_items,roster_groups_allowed,access_whitelist)
         VALUES($1,$2,$3,100,ARRAY['Friends'],ARRAY[$4]::text[])",
    )
    .bind(owner_id)
    .bind(node)
    .bind(access_model)
    .bind(REQUESTER_BARE)
    .execute(executor)
    .await
    .unwrap();
}

async fn insert_item<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    item_id: &str,
) {
    sqlx::query("INSERT INTO pep_items(owner_id,node,item_id,payload) VALUES($1,$2,$3,$4)")
        .bind(owner_id)
        .bind(NODE)
        .bind(item_id)
        .bind(format!("<item id='{item_id}'/>"))
        .execute(executor)
        .await
        .unwrap();
}

fn item_query(owner_username: &str) -> PepItemQuery<'_> {
    PepItemQuery {
        owner_username,
        requester_jid: REQUESTER_FULL,
        node: NODE,
        selection: Some(PepItemSelection {
            item_ids: ["old-1", "old-2", "new"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            max_items: 3,
        }),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn item_read_never_combines_revoked_access_with_a_new_publication() {
    let (url, pool) = integration_pool(8).await;
    let service = test_pubsub_service(pool.clone(), DOMAIN);
    for (model, denial) in [
        ("open", PepAccessDenial::ClosedNode),
        ("presence", PepAccessDenial::PresenceSubscriptionRequired),
        ("roster", PepAccessDenial::NotInRosterGroup),
        ("whitelist", PepAccessDenial::ClosedNode),
    ] {
        let owner = insert_owner(&pool).await;
        let mut setup = pool.begin().await.unwrap();
        insert_node(&mut *setup, owner.id, NODE, model).await;
        insert_item(&mut *setup, owner.id, "old-1").await;
        insert_item(&mut *setup, owner.id, "old-2").await;
        sqlx::query(
            "INSERT INTO roster_items(owner_id,contact_jid,subscription,groups)
             VALUES($1,$2,'from','[\"Friends\"]')",
        )
        .bind(owner.id)
        .bind(REQUESTER_BARE)
        .execute(&mut *setup)
        .await
        .unwrap();
        setup.commit().await.unwrap();

        let application = format!("pep-items-{}", owner.id.simple());
        let reader_pool = named_single_connection_pool(&url, &application).await;
        let reader = test_pubsub_service(reader_pool.clone(), DOMAIN);
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE pep_items IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let username = owner.username.clone();
        let request =
            tokio::spawn(
                async move { reader.pep_items_read(&item_query(&username)).await.unwrap() },
            );
        wait_for_named_session_lock(&pool, &application).await;
        // The SQL under the table lock commits the revocation and new item
        // together. At no point is the new item visible to this reader.
        match model {
            "open" => sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
                .bind(owner.id)
                .bind(REQUESTER_BARE)
                .execute(&mut *blocker)
                .await
                .unwrap(),
            "presence" | "roster" => sqlx::query(
                "UPDATE roster_items SET subscription='none', groups='[]'
                 WHERE owner_id=$1 AND contact_jid=$2",
            )
            .bind(owner.id)
            .bind(REQUESTER_BARE)
            .execute(&mut *blocker)
            .await
            .unwrap(),
            "whitelist" => sqlx::query(
                "UPDATE pep_nodes SET access_whitelist='{}' WHERE owner_id=$1 AND node=$2",
            )
            .bind(owner.id)
            .bind(NODE)
            .execute(&mut *blocker)
            .await
            .unwrap(),
            _ => unreachable!("unexpected test case {model}"),
        };
        insert_item(&mut *blocker, owner.id, "new").await;
        blocker.commit().await.unwrap();

        let read = request.await.unwrap();
        let PepItemRead::Items { config, items } = read else {
            panic!("the established {model} snapshot should still allow access: {read:?}");
        };
        assert_eq!(config.access_model, model);
        assert_eq!(
            items,
            [
                ("old-2".to_owned(), "<item id='old-2'/>".to_owned()),
                ("old-1".to_owned(), "<item id='old-1'/>".to_owned()),
            ],
            "{model} read mixed old authority with a new payload",
        );
        assert!(matches!(
            service.pep_items_read(&item_query(&owner.username)).await.unwrap(),
            PepItemRead::Denied(reason) if reason == denial
        ));
        reader_pool.close().await;
        delete_owner(&pool, owner.id).await;
    }
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn node_discovery_cannot_pair_the_old_open_model_with_a_new_unblock() {
    let (url, pool) = integration_pool(8).await;
    check_node_discovery_snapshot(&url, &pool, true).await;
    check_node_discovery_snapshot(&url, &pool, false).await;
    pool.close().await;
}

async fn check_node_discovery_snapshot(url: &str, pool: &PgPool, initially_blocked: bool) {
    const BLOCK: &str = "INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)";
    const UNBLOCK: &str = "DELETE FROM blocked_jids WHERE owner_id=$1 AND blocked_jid=$2";
    let owner = insert_owner(pool).await;
    insert_node(pool, owner.id, NODE, "open").await;
    if initially_blocked {
        sqlx::query(BLOCK)
            .bind(owner.id)
            .bind(REQUESTER_BARE)
            .execute(pool)
            .await
            .unwrap();
    }

    let info_application = format!("pep-info-{}", owner.id.simple());
    let items_application = format!("pep-node-items-{}", owner.id.simple());
    let info_pool = named_single_connection_pool(url, &info_application).await;
    let items_pool = named_single_connection_pool(url, &items_application).await;
    let info_service = test_pubsub_service(info_pool.clone(), DOMAIN);
    let items_service = test_pubsub_service(items_pool.clone(), DOMAIN);

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE blocked_jids IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let username = owner.username.clone();
    let info = tokio::spawn(async move {
        info_service
            .pep_node_info(&PepNodeQuery {
                owner_username: &username,
                requester: PepRequester::Jid(REQUESTER_FULL),
                node: NODE,
            })
            .await
            .unwrap()
    });
    let username = owner.username.clone();
    let items = tokio::spawn(async move {
        items_service
            .pep_node_items(&PepNodeQuery {
                owner_username: &username,
                requester: PepRequester::Jid(REQUESTER_FULL),
                node: NODE,
            })
            .await
            .unwrap()
    });
    wait_for_named_session_lock(pool, &info_application).await;
    wait_for_named_session_lock(pool, &items_application).await;

    // An unblock during the model change must not authorize the old open node.
    // An added block must not change the reply from an earlier open snapshot.
    sqlx::query("UPDATE pep_nodes SET access_model='presence' WHERE owner_id=$1 AND node=$2")
        .bind(owner.id)
        .bind(NODE)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query(if initially_blocked { UNBLOCK } else { BLOCK })
        .bind(owner.id)
        .bind(REQUESTER_BARE)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    let info = info.await.unwrap();
    let items = items.await.unwrap();
    if initially_blocked {
        assert!(matches!(
            info,
            PepNodeInfoRead::Denied(PepAccessDenial::ClosedNode)
        ));
        assert_eq!(items, PepNodeItemsRead::Denied);
    } else {
        assert!(matches!(info, PepNodeInfoRead::Info { config } if config.access_model == "open"));
        assert_eq!(items, PepNodeItemsRead::Visible);
    }

    let service = test_pubsub_service(pool.clone(), DOMAIN);
    let query = PepNodeQuery {
        owner_username: &owner.username,
        requester: PepRequester::Jid(REQUESTER_FULL),
        node: NODE,
    };
    assert!(matches!(
        service.pep_node_info(&query).await.unwrap(),
        PepNodeInfoRead::Denied(PepAccessDenial::PresenceSubscriptionRequired)
    ));
    assert_eq!(
        service.pep_node_items(&query).await.unwrap(),
        PepNodeItemsRead::Denied
    );
    info_pool.close().await;
    items_pool.close().await;
    delete_owner(pool, owner.id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn owner_subscriptions_do_not_return_empty_for_a_concurrently_deleted_node() {
    let (url, pool) = integration_pool(8).await;
    let owner = insert_owner(&pool).await;
    insert_node(&pool, owner.id, NODE, "open").await;
    let subscription =
        northstar_pubsub_postgres::subscribe_pep_node(&pool, owner.id, NODE, REQUESTER_FULL, 10)
            .await
            .unwrap()
            .unwrap();
    let application = format!("pep-owner-subs-{}", owner.id.simple());
    let reader_pool = named_single_connection_pool(&url, &application).await;
    let reader = test_pubsub_service(reader_pool.clone(), DOMAIN);
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE pep_subscriptions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let requester = owner.clone();
    let request = tokio::spawn(async move {
        reader
            .pep_owner_subscriptions(&PepOwnerQuery {
                owner: &requester,
                node: NODE,
            })
            .await
            .unwrap()
    });
    wait_for_named_session_lock(&pool, &application).await;
    sqlx::query("DELETE FROM pep_nodes WHERE owner_id=$1 AND node=$2")
        .bind(owner.id)
        .bind(NODE)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    let read = request.await.unwrap();
    let PepOwnerSubscriptionsRead::Subscribers(rows) = read else {
        panic!("node existed in the established snapshot: {read:?}");
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].jid, subscription.jid);
    assert_eq!(rows[0].subid, subscription.subid);

    let service = test_pubsub_service(pool.clone(), DOMAIN);
    assert!(matches!(
        service
            .pep_owner_subscriptions(&PepOwnerQuery {
                owner: &owner,
                node: NODE
            })
            .await
            .unwrap(),
        PepOwnerSubscriptionsRead::NodeMissing
    ));
    reader_pool.close().await;
    delete_owner(&pool, owner.id).await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn account_discovery_keeps_candidates_and_visibility_in_one_snapshot() {
    const OLD: &str = "urn:test:pep:a-old";
    const NEW: &str = "urn:test:pep:m-new";
    const CHANGED: &str = "urn:test:pep:z-changed";
    let (url, pool) = integration_pool(8).await;
    let owner = insert_owner(&pool).await;
    insert_node(&pool, owner.id, OLD, "open").await;
    insert_node(&pool, owner.id, CHANGED, "presence").await;
    let application = format!("pep-account-{}", owner.id.simple());
    let reader_pool = named_single_connection_pool(&url, &application).await;
    let reader = test_pubsub_service(reader_pool.clone(), DOMAIN);
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE blocked_jids IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let username = owner.username.clone();
    let request = tokio::spawn(async move {
        reader
            .pep_account_items(&PepAccountQuery {
                owner_username: &username,
                requester: PepRequester::Jid(REQUESTER_FULL),
            })
            .await
            .unwrap()
    });
    wait_for_named_session_lock(&pool, &application).await;
    sqlx::query("DELETE FROM pep_nodes WHERE owner_id=$1 AND node=$2")
        .bind(owner.id)
        .bind(OLD)
        .execute(&mut *blocker)
        .await
        .unwrap();
    insert_node(&mut *blocker, owner.id, NEW, "open").await;
    sqlx::query("UPDATE pep_nodes SET access_model='open' WHERE owner_id=$1 AND node=$2")
        .bind(owner.id)
        .bind(CHANGED)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();

    let read = request.await.unwrap();
    let PepAccountItemsRead::Nodes { owner_jid, nodes } = read else {
        panic!("account should remain enabled: {read:?}");
    };
    assert_eq!(owner_jid, format!("{}@{DOMAIN}", owner.username));
    assert_eq!(nodes, [OLD]);

    let service = test_pubsub_service(pool.clone(), DOMAIN);
    assert!(matches!(
        service.pep_account_items(&PepAccountQuery {
            owner_username: &owner.username,
            requester: PepRequester::Jid(REQUESTER_FULL),
        }).await.unwrap(),
        PepAccountItemsRead::Nodes { nodes, .. } if nodes == [NEW, CHANGED]
    ));
    reader_pool.close().await;
    delete_owner(&pool, owner.id).await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn create_rechecks_owner_enablement_and_generation_after_the_advisory_wait() {
    let (url, pool) = integration_pool(8).await;
    for disable in [false, true] {
        let owner = insert_owner(&pool).await;
        let node = format!("urn:test:pep:stale-create:{}", owner.id.simple());
        let application = format!("pep-create-{}", owner.id.simple());
        let writer_pool = named_single_connection_pool(&url, &application).await;
        let writer = test_pubsub_service(writer_pool.clone(), DOMAIN);
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
            .bind(owner.id.to_string())
            .execute(&mut *blocker)
            .await
            .unwrap();
        let requester = owner.clone();
        let requested_node = node.clone();
        let request = tokio::spawn(async move {
            writer
                .execute_pep_create_node(PepCreateNodeCommand::new(&requester, &requested_node, 10))
                .await
                .unwrap()
                .outcome
        });
        wait_for_named_session_lock(&pool, &application).await;
        sqlx::query(
            "UPDATE users SET is_disabled=$2,auth_generation=auth_generation+$3 WHERE id=$1",
        )
        .bind(owner.id)
        .bind(disable)
        .bind(if disable { 0_i64 } else { 1_i64 })
        .execute(&mut *blocker)
        .await
        .unwrap();
        blocker.commit().await.unwrap();
        assert_eq!(request.await.unwrap(), PepCreateOutcome::StaleAuthority);
        let nodes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pep_nodes WHERE owner_id=$1")
            .bind(owner.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let intents: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
                .bind(&node)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((nodes, intents), (0, 0));
        writer_pool.close().await;
        delete_owner(&pool, owner.id).await;
    }
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pep_snapshot_queries_succeed_on_a_read_only_connection() {
    let (url, setup_pool) = integration_pool(2).await;
    let owner = insert_owner(&setup_pool).await;
    let requester = insert_owner(&setup_pool).await;
    let requester_jid = format!("{}@{DOMAIN}", requester.username);
    sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
        .bind(requester.id)
        .bind(format!("{}@{DOMAIN}", owner.username))
        .execute(&setup_pool)
        .await
        .unwrap();
    insert_node(&setup_pool, owner.id, NODE, "open").await;
    let restricted = "urn:test:pep:restricted";
    insert_node(&setup_pool, owner.id, restricted, "roster").await;
    insert_item(&setup_pool, owner.id, "visible").await;
    northstar_pubsub_postgres::subscribe_pep_node(&setup_pool, owner.id, NODE, REQUESTER_FULL, 10)
        .await
        .unwrap()
        .unwrap();

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
    let service = test_pubsub_service(read_pool.clone(), DOMAIN);
    let mut items = item_query(&owner.username);
    items.requester_jid = &requester_jid;
    items.selection = Some(PepItemSelection {
        item_ids: Vec::new(),
        max_items: 1,
    });
    assert!(matches!(
        service.pep_items_read(&items).await.unwrap(),
        PepItemRead::Items { items, .. } if items.len() == 1 && items[0].0 == "visible"
    ));
    let query = PepNodeQuery {
        owner_username: &owner.username,
        requester: PepRequester::LocalAnonymous,
        node: NODE,
    };
    assert!(matches!(
        service.pep_node_info(&query).await.unwrap(),
        PepNodeInfoRead::Info { config } if config.access_model == "open" && config.persist_items
    ));
    assert_eq!(
        service.pep_node_items(&query).await.unwrap(),
        PepNodeItemsRead::Visible
    );
    assert_eq!(
        service
            .pep_node_items(&PepNodeQuery {
                node: restricted,
                ..query
            })
            .await
            .unwrap(),
        PepNodeItemsRead::Denied
    );
    assert!(matches!(
        service.pep_account_items(&PepAccountQuery {
            owner_username: &owner.username,
            requester: PepRequester::LocalAnonymous,
        }).await.unwrap(),
        PepAccountItemsRead::Nodes { nodes, .. } if nodes == [NODE]
    ));
    assert!(matches!(
        service.pep_owner_subscriptions(&PepOwnerQuery { owner: &owner, node: NODE }).await.unwrap(),
        PepOwnerSubscriptionsRead::Subscribers(rows) if rows.len() == 1 && rows[0].jid == REQUESTER_FULL
    ));
    read_pool.close().await;
    delete_owner(&setup_pool, requester.id).await;
    delete_owner(&setup_pool, owner.id).await;
    setup_pool.close().await;
}
