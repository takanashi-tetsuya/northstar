//! Service IQ queries exercised through the PostgreSQL snapshot ports.

use super::*;
use northstar_pubsub_application::{
    PubSubCollectionItemSelection, PubSubItemQuery, PubSubItemRead, PubSubService,
};
use northstar_pubsub_xmpp::pubsub::{
    handle_request, PubSubError, PubSubHost, PubSubOwnerLimits, PubSubReply,
};
use northstar_workflows::pubsub_repository::{test_pubsub_service, PostgresPubSubRepository};
use northstar_xep_0060::{MAX_ITEM_XML_BYTES, MAX_PUBLISH_XML_BYTES, NS_DATA, NS_PUBSUB, NS_RSM};
use roxmltree::Document;

const OWNER: &str = "snapshot-owner@example.test";
const READER: &str = "snapshot-reader@example.test/requesting";
const READER_BARE: &str = "snapshot-reader@example.test";
const SUBSCRIBER: &str = "snapshot-reader@example.test/subscribed";
const ATOM: &str = "http://www.w3.org/2005/Atom";

struct SnapshotHost(PubSubService<PostgresPubSubRepository>);

impl PubSubHost for SnapshotHost {
    fn pubsub_local_domain(&self) -> &str {
        "example.test"
    }

    fn pubsub_server_name(&self) -> &str {
        "PubSub snapshot tests"
    }

    fn pubsub_node_owner_limits(&self) -> PubSubOwnerLimits {
        PubSubOwnerLimits {
            max_nodes: 1000,
            max_storage_bytes: 16 * 1_048_576,
        }
    }

    fn pubsub_application_service(
        &self,
    ) -> &PubSubService<impl northstar_pubsub_xmpp::PubSubRepositories> {
        &self.0
    }
}

impl SnapshotHost {
    fn new(pool: &PgPool) -> Self {
        Self(test_pubsub_service(pool.clone(), "example.test"))
    }

    async fn request(&self, kind: &str, operation: &str) -> PubSubReply {
        let xml = format!("<pubsub xmlns='{NS_PUBSUB}'>{operation}</pubsub>");
        let document = Document::parse(&xml).unwrap();
        handle_request(self, READER, kind, document.root_element())
            .await
            .unwrap()
    }
}

async fn create_snapshot_node(pool: &PgPool, label: &str, config: PubSubNodeConfig) -> PubSubNode {
    let name = format!("item-snapshot-{label}-{}", Uuid::new_v4().simple());
    let id = match create_node(pool, &name, OWNER, &config, 1000)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected node creation outcome: {other:?}"),
    };
    get_node_by_id(pool, id).await.unwrap().unwrap()
}

async fn insert_subscription(pool: &PgPool, node_id: Uuid, jid: &str) -> String {
    let subid = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO pubsub_subscriptions(node_id, jid, state, subid)
         VALUES ($1, $2, 'subscribed', $3)",
    )
    .bind(node_id)
    .bind(jid)
    .bind(&subid)
    .execute(pool)
    .await
    .unwrap();
    subid
}

async fn insert_item<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Postgres>,
    node_id: Uuid,
    item_id: &str,
    age_seconds: i32,
) {
    sqlx::query(
        "INSERT INTO pubsub_items(id, node_id, item_id, publisher_jid, xml_payload, created_at)
         VALUES ($1, $2, $3, $4, $5, NOW() - $6::INTEGER * INTERVAL '1 second')",
    )
    .bind(Uuid::new_v4())
    .bind(node_id)
    .bind(item_id)
    .bind(OWNER)
    .bind(format!("<item id='{item_id}'/>"))
    .bind(age_seconds)
    .execute(executor)
    .await
    .unwrap();
}

async fn start_blocked_get(
    url: &str,
    setup_pool: &PgPool,
    operation: String,
) -> (PgPool, tokio::task::JoinHandle<PubSubReply>) {
    let application = format!("snapshot-reader-{}", Uuid::new_v4().simple());
    let reader_pool = named_single_connection_pool(url, &application).await;
    let host = SnapshotHost::new(&reader_pool);
    let task = tokio::spawn(async move { host.request("get", &operation).await });
    wait_for_named_session_lock(setup_pool, &application).await;
    (reader_pool, task)
}

fn result_xml(reply: PubSubReply) -> String {
    match reply {
        PubSubReply::Result(xml) => xml,
        other => panic!("expected PubSub result: {other:?}"),
    }
}

fn replied_item_ids(reply: PubSubReply) -> Vec<String> {
    let xml = result_xml(reply);
    let document = Document::parse(&xml).unwrap();
    document
        .descendants()
        .filter(|item| item.has_tag_name((NS_PUBSUB, "item")))
        .map(|item| item.attribute("id").unwrap().to_owned())
        .collect()
}

fn assert_error(reply: PubSubReply, expected: PubSubError) {
    let PubSubReply::ExtendedError(error) = reply else {
        panic!("expected {expected:?}, got {reply:?}");
    };
    assert_eq!(error, expected);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn leaf_items_keep_snapshot_after_subscription_or_affiliation_revocation() {
    let (url, pool) = integration_pool(2).await;
    let host = SnapshotHost::new(&pool);
    for make_outcast in [false, true] {
        let node = create_snapshot_node(
            &pool,
            "leaf-revocation",
            PubSubNodeConfig {
                access_model: "authorize".to_owned(),
                ..Default::default()
            },
        )
        .await;
        insert_subscription(&pool, node.id, SUBSCRIBER).await;
        insert_item(&pool, node.id, "old", 1).await;
        let operation = format!("<items node='{}'/>", node.node);

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE pubsub_items IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let (reader_pool, read) = start_blocked_get(&url, &pool, operation.clone()).await;
        if make_outcast {
            sqlx::query(
                "INSERT INTO pubsub_affiliations(node_id, jid, affiliation) VALUES ($1, $2, 'outcast')",
            )
            .bind(node.id)
            .bind(READER_BARE)
            .execute(&mut *blocker)
            .await
            .unwrap();
        } else {
            sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id = $1 AND jid = $2")
                .bind(node.id)
                .bind(SUBSCRIBER)
                .execute(&mut *blocker)
                .await
                .unwrap();
        }
        insert_item(&mut *blocker, node.id, "new", 0).await;
        blocker.commit().await.unwrap();

        // The wait comes after the node and ACL reads. A separate item
        // statement at READ COMMITTED would return the newly inserted item.
        assert_eq!(replied_item_ids(read.await.unwrap()), ["old"]);
        let denied = if make_outcast {
            PubSubError::forbidden()
        } else {
            PubSubError::new("not-authorized", "not-subscribed")
        };
        assert_error(host.request("get", &operation).await, denied.clone());
        let malformed_selection =
            format!("<items node='{}' max_items='0'><item/></items>", node.node);
        assert_error(host.request("get", &malformed_selection).await, denied);
        reader_pool.close().await;
    }
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn collection_items_keep_the_selected_subid_snapshot() {
    let (url, pool) = integration_pool(2).await;
    let parent = create_snapshot_node(
        &pool,
        "collection-subid",
        PubSubNodeConfig {
            node_type: "collection".to_owned(),
            access_model: "authorize".to_owned(),
            persist_items: false,
            ..Default::default()
        },
    )
    .await;
    let leaf = create_snapshot_node(&pool, "subid-leaf", PubSubNodeConfig::default()).await;
    assert_eq!(
        associate_collection_child(&pool, &parent, &leaf, OWNER)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );

    let selected = insert_subscription(&pool, parent.id, SUBSCRIBER).await;
    let survivor = insert_subscription(&pool, parent.id, READER_BARE).await;
    insert_item(&pool, leaf.id, "old", 1).await;
    let operation = format!("<items node='{}' subid='{selected}'/>", parent.node);
    let host = SnapshotHost::new(&pool);
    assert_eq!(
        replied_item_ids(host.request("get", &operation).await),
        ["old"]
    );

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE pubsub_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let (reader_pool, read) = start_blocked_get(&url, &pool, operation.clone()).await;
    sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id = $1 AND subid = $2")
        .bind(parent.id)
        .bind(selected)
        .execute(&mut *blocker)
        .await
        .unwrap();
    insert_item(&mut *blocker, leaf.id, "new", 0).await;
    blocker.commit().await.unwrap();

    assert_eq!(replied_item_ids(read.await.unwrap()), ["old"]);
    assert_error(
        host.request("get", &operation).await,
        PubSubError::new("not-acceptable", "invalid-subid"),
    );
    let survivor_request = format!("<items node='{}' subid='{survivor}'/>", parent.node);
    assert_eq!(
        replied_item_ids(host.request("get", &survivor_request).await),
        ["new", "old"]
    );
    reader_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn leaf_items_resolve_one_node_incarnation() {
    let (url, pool) = integration_pool(2).await;
    let node = create_snapshot_node(&pool, "leaf-recreate", PubSubNodeConfig::default()).await;
    insert_item(&pool, node.id, "old-node", 0).await;
    let operation = format!("<items node='{}'/>", node.node);

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE pubsub_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let (reader_pool, read) = start_blocked_get(&url, &pool, operation.clone()).await;
    sqlx::query("DELETE FROM pubsub_nodes WHERE id = $1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let replacement = Uuid::new_v4();
    sqlx::query("INSERT INTO pubsub_nodes(id, node, creator_jid) VALUES ($1, $2, $3)")
        .bind(replacement)
        .bind(&node.node)
        .bind(OWNER)
        .execute(&mut *blocker)
        .await
        .unwrap();
    insert_item(&mut *blocker, replacement, "new-node", 0).await;
    blocker.commit().await.unwrap();

    // The two serial replies both contain an item. A read using the removed
    // UUID against the new state returned an empty result.
    assert_eq!(replied_item_ids(read.await.unwrap()), ["old-node"]);
    let host = SnapshotHost::new(&pool);
    assert_eq!(
        replied_item_ids(host.request("get", &operation).await),
        ["new-node"]
    );
    reader_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn collection_caps_and_leaf_rsm_preserve_item_order() {
    let (_, pool) = integration_pool(2).await;
    let parent = create_snapshot_node(
        &pool,
        "collection-caps",
        PubSubNodeConfig {
            node_type: "collection".to_owned(),
            persist_items: false,
            ..Default::default()
        },
    )
    .await;
    let leaf = create_snapshot_node(
        &pool,
        "caps-leaf",
        PubSubNodeConfig {
            max_items: 105,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        associate_collection_child(&pool, &parent, &leaf, OWNER)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    sqlx::query(
        "INSERT INTO pubsub_items(id, node_id, item_id, publisher_jid, xml_payload, created_at)
         SELECT pg_catalog.gen_random_uuid(), $1, 'small-' || lpad(n::TEXT, 3, '0'), $2,
                '<item id=''small-' || lpad(n::TEXT, 3, '0') || '''/>',
                NOW() - (100 + n) * INTERVAL '1 second'
           FROM generate_series(0, 109) AS entries(n)",
    )
    .bind(leaf.id)
    .bind(OWNER)
    .execute(&pool)
    .await
    .unwrap();

    let host = SnapshotHost::new(&pool);
    let collection_request = format!("<items node='{}' max_items='1000'/>", parent.node);
    let collection_query = PubSubItemQuery {
        node: &parent.node,
        requester: READER_BARE,
        echoed_subid: None,
        leaf: None,
        collection: PubSubCollectionItemSelection::Items {
            max_items: 1000,
            max_xml_bytes: MAX_PUBLISH_XML_BYTES as i64,
        },
    };
    let read = host.0.read_items(&collection_query).await.unwrap();
    assert!(matches!(read, PubSubItemRead::Collection { items } if items.len() == 100));
    let expected = (0..100)
        .map(|n| format!("small-{n:03}"))
        .collect::<Vec<_>>();
    assert_eq!(
        replied_item_ids(host.request("get", &collection_request).await),
        expected
    );
    let limited_request = format!("<items node='{}' max_items='3'/>", parent.node);
    assert_eq!(
        replied_item_ids(host.request("get", &limited_request).await).as_slice(),
        &expected[..3]
    );
    let unsupported_rsm = format!(
        "<items node='{}' max_items='0'><item/></items><set xmlns='{NS_RSM}'/>",
        parent.node
    );
    assert_error(
        host.request("get", &unsupported_rsm).await,
        PubSubError::unsupported("rsm"),
    );

    let leaf_page = format!(
        "<items node='{}'/><set xmlns='{NS_RSM}'><max>2</max><after>small-002</after></set>",
        leaf.node
    );
    assert_eq!(
        result_xml(host.request("get", &leaf_page).await),
        format!(
            "<pubsub xmlns='{NS_PUBSUB}'><items node='{}'>\
             <item id='small-003'/><item id='small-004'/></items>\
             <set xmlns='{NS_RSM}'><first index='3'>small-003</first>\
             <last>small-004</last><count>105</count></set></pubsub>",
            leaf.node,
        )
    );
    let bad_cursor = leaf_page.replace("small-002", "small-105");
    assert!(matches!(
        host.request("get", &bad_cursor).await,
        PubSubReply::Error("item-not-found")
    ));
    let requested_ids = format!(
        "<items node='{}'><item id='small-004'/><item id='small-003'/></items>",
        leaf.node,
    );
    assert_eq!(
        replied_item_ids(host.request("get", &requested_ids).await),
        ["small-003", "small-004"]
    );
    let limited_ids = requested_ids.replacen("<items ", "<items max_items='1' ", 1);
    assert!(matches!(
        host.request("get", &limited_ids).await,
        PubSubReply::Error("item-not-found")
    ));

    let mut large_items = pool.begin().await.unwrap();
    for ordinal in 0..5 {
        let id = format!("large-{ordinal}");
        let start = format!("<item id='{id}'>");
        let end = "</item>";
        let text = "é".repeat((MAX_ITEM_XML_BYTES - start.len() - end.len()) / 'é'.len_utf8());
        let payload = format!("{start}{text}{end}");
        assert_eq!(payload.len(), MAX_ITEM_XML_BYTES);
        sqlx::query(
            "INSERT INTO pubsub_items (id, node_id, item_id, publisher_jid, xml_payload, created_at)
             VALUES (pg_catalog.gen_random_uuid(), $1, $2, $3, $4,
                     NOW() - $5::INTEGER * INTERVAL '1 second')",
        )
        .bind(leaf.id)
        .bind(id)
        .bind(OWNER)
        .bind(payload)
        .bind(ordinal)
        .execute(&mut *large_items)
        .await
        .unwrap();
    }
    large_items.commit().await.unwrap();
    let read = host.0.read_items(&collection_query).await.unwrap();
    let PubSubItemRead::Collection { items } = read else {
        panic!("expected collection: {read:?}");
    };
    assert_eq!(items.len(), 4);
    assert_eq!(
        items
            .iter()
            .map(|item| item.xml_payload.len())
            .sum::<usize>(),
        MAX_PUBLISH_XML_BYTES
    );
    assert_eq!(
        replied_item_ids(host.request("get", &collection_request).await),
        ["large-0", "large-1", "large-2", "large-3"]
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn options_get_keeps_form_and_subscription_from_one_snapshot() {
    let (url, pool) = integration_pool(2).await;
    let node = create_snapshot_node(
        &pool,
        "options-reconfigure",
        PubSubNodeConfig {
            payload_type: Some(ATOM.to_owned()),
            ..Default::default()
        },
    )
    .await;
    let subid = insert_subscription(&pool, node.id, SUBSCRIBER).await;
    let operation = format!(
        "<options node='{}' jid='{SUBSCRIBER}' subid='{subid}'/>",
        node.node
    );
    let host = SnapshotHost::new(&pool);
    let before = result_xml(host.request("get", &operation).await);
    assert!(before.contains("var='pubsub#include_body'"));
    assert!(before.contains("var='pubsub#deliver' type='boolean'><value>true</value>"));

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE pubsub_subscriptions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let (reader_pool, read) = start_blocked_get(&url, &pool, operation.clone()).await;
    sqlx::query("UPDATE pubsub_nodes SET payload_type = 'urn:test:new-payload' WHERE id = $1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("UPDATE pubsub_subscriptions SET deliver = FALSE WHERE node_id = $1 AND jid = $2")
        .bind(node.id)
        .bind(SUBSCRIBER)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();

    assert_eq!(result_xml(read.await.unwrap()), before);
    let after = result_xml(host.request("get", &operation).await);
    assert!(!after.contains("var='pubsub#include_body'"));
    assert!(after.contains("var='pubsub#deliver' type='boolean'><value>false</value>"));
    reader_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn options_get_and_cancel_resolve_a_live_redirect() {
    let (url, pool) = integration_pool(2).await;
    let node = create_snapshot_node(&pool, "options-delete", PubSubNodeConfig::default()).await;
    let subid = insert_subscription(&pool, node.id, SUBSCRIBER).await;
    let get = format!(
        "<options node='{}' jid='{SUBSCRIBER}' subid='{subid}'/>",
        node.node
    );
    let cancel = format!(
        "<options node='{}' jid='{SUBSCRIBER}' subid='{subid}'>\
         <x xmlns='{NS_DATA}' type='cancel'/></options>",
        node.node,
    );
    let host = SnapshotHost::new(&pool);
    let before = result_xml(host.request("get", &get).await);
    assert!(result_xml(host.request("set", &cancel).await).is_empty());

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE pubsub_subscriptions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let (reader_pool, read) = start_blocked_get(&url, &pool, get.clone()).await;
    sqlx::query("DELETE FROM pubsub_nodes WHERE id = $1")
        .bind(node.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let uri = "xmpp:pubsub.example.test?;node=replacement";
    sqlx::query("INSERT INTO pubsub_node_redirects(node, uri) VALUES ($1, $2)")
        .bind(&node.node)
        .bind(uri)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();

    assert_eq!(result_xml(read.await.unwrap()), before);
    assert_error(host.request("get", &get).await, PubSubError::moved(uri));
    assert_error(host.request("set", &cancel).await, PubSubError::moved(uri));
    let items = format!("<items node='{}' max_items='0'/>", node.node);
    assert_error(host.request("get", &items).await, PubSubError::moved(uri));
    sqlx::query(
        "UPDATE pubsub_node_redirects SET expires_at = NOW() - INTERVAL '1 second' WHERE node = $1",
    )
    .bind(&node.node)
    .execute(&pool)
    .await
    .unwrap();
    for operation in [&get, &items] {
        assert!(matches!(
            host.request("get", operation).await,
            PubSubReply::Error("item-not-found")
        ));
    }
    reader_pool.close().await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn item_and_options_snapshots_succeed_on_read_only_connections() {
    let (url, pool) = integration_pool(2).await;
    let node = create_snapshot_node(
        &pool,
        "read-only",
        PubSubNodeConfig {
            access_model: "authorize".to_owned(),
            ..Default::default()
        },
    )
    .await;
    let collection = create_snapshot_node(
        &pool,
        "read-only-collection",
        PubSubNodeConfig {
            node_type: "collection".to_owned(),
            persist_items: false,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        associate_collection_child(&pool, &collection, &node, OWNER)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    let subid = insert_subscription(&pool, node.id, SUBSCRIBER).await;
    insert_item(&pool, node.id, "retained", 0).await;
    let read_pool = read_only_disco::read_only_pool(&url).await;
    let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
        .fetch_one(&read_pool)
        .await
        .unwrap();
    assert_eq!(read_only, "on");
    let host = SnapshotHost::new(&read_pool);
    let items = format!("<items node='{}' subid='{subid}'/>", node.node);
    assert_eq!(
        replied_item_ids(host.request("get", &items).await),
        ["retained"]
    );
    let collection_items = format!("<items node='{}'/>", collection.node);
    assert_eq!(
        replied_item_ids(host.request("get", &collection_items).await),
        ["retained"]
    );
    let options = format!(
        "<options node='{}' jid='{SUBSCRIBER}' subid='{subid}'/>",
        node.node
    );
    let xml = result_xml(host.request("get", &options).await);
    let document = Document::parse(&xml).unwrap();
    let form = document.root_element().first_element_child().unwrap();
    assert_eq!(form.attribute("jid"), Some(SUBSCRIBER));
    assert_eq!(form.attribute("subid"), Some(subid.as_str()));

    let wrong_subid = options.replace(&subid, "wrong");
    assert_error(
        host.request("get", &wrong_subid).await,
        PubSubError::new("not-acceptable", "invalid-subid"),
    );
    for jid in [READER, READER_BARE] {
        let wrong_jid = options.replace(SUBSCRIBER, jid);
        assert_error(
            host.request("get", &wrong_jid).await,
            PubSubError::new("unexpected-request", "not-subscribed"),
        );
    }
    let other_account = options.replace(SUBSCRIBER, OWNER);
    assert!(matches!(
        host.request("get", &other_account).await,
        PubSubReply::Error("forbidden")
    ));
    sqlx::query("UPDATE pubsub_subscriptions SET expire = NOW() - INTERVAL '1 second' WHERE node_id = $1 AND jid = $2")
        .bind(node.id)
        .bind(SUBSCRIBER)
        .execute(&pool)
        .await
        .unwrap();
    assert_error(
        host.request("get", &wrong_subid).await,
        PubSubError::new("unexpected-request", "not-subscribed"),
    );
    assert_error(
        host.request("get", &items).await,
        PubSubError::new("not-acceptable", "invalid-subid"),
    );
    assert!(replied_item_ids(host.request("get", &collection_items).await).is_empty());
    read_pool.close().await;
    pool.close().await;
}
