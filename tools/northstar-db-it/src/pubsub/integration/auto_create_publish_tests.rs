//! Transaction boundaries for service-node auto-create and first publish.

use super::*;

// A fresh node has no direct subscribers. Supply one direct recipient per
// event so the transaction's outbox writes are observable in the fixture.
struct AutoCreateRenderer {
    inner: PubSubEventRenderer,
    // Outbox streams are per recipient; `None` sends the create event to the creator.
    create_recipient: Option<String>,
    item_recipient: String,
}

impl PubSubMutationOutboxRenderer for AutoCreateRenderer {
    fn new_event_id(&self) -> Uuid {
        self.inner.new_event_id()
    }

    fn render_create(
        &self,
        node: &PubSubNode,
        _: &[PubSubNotificationDelivery],
        event_id: Uuid,
        event_time: DateTime<Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        self.inner.render_transactional_node_event(
            node,
            &[],
            std::slice::from_ref(self.create_recipient.as_ref().unwrap_or(&node.creator_jid)),
            &format!("<create node='{}'/>", node.node),
            event_id,
            event_time,
        )
    }

    fn render_items(
        &self,
        node: &PubSubNode,
        items: &[(String, String)],
        _: &[PubSubNotificationDelivery],
        event_id: Uuid,
        event_time: DateTime<Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let payload: String = items.iter().map(|(_, xml)| xml.as_str()).collect();
        self.inner.render_transactional_node_event(
            node,
            &[],
            std::slice::from_ref(&self.item_recipient),
            &format!("<items node='{}'>{payload}</items>", node.node),
            event_id,
            event_time,
        )
    }
}

struct AutoCreateFixture {
    node: String,
    publisher: String,
    item_domain: String,
    items: [(String, String); 2],
    renderer: AutoCreateRenderer,
}

impl AutoCreateFixture {
    fn new() -> Self {
        let suffix = Uuid::new_v4().simple().to_string();
        let item_domain = format!("auto-create-{suffix}.example.test");
        Self {
            node: format!("auto-create-{suffix}"),
            publisher: format!("auto-create-{suffix}@example.test"),
            items: [
                (
                    "first".to_owned(),
                    "<item id='first'><value xmlns='urn:test'>one</value></item>".to_owned(),
                ),
                (
                    "second".to_owned(),
                    "<item id='second'><value xmlns='urn:test'>two</value></item>".to_owned(),
                ),
            ],
            renderer: AutoCreateRenderer {
                inner: PubSubEventRenderer::new("example.test"),
                create_recipient: None,
                item_recipient: format!("reader@{item_domain}"),
            },
            item_domain,
        }
    }

    async fn publish(&self, pool: &PgPool, storage_limit: i64) -> Result<AutoCreatePublishOutcome> {
        create_node_and_publish_items_with_renderer(
            pool,
            &self.node,
            &self.publisher,
            &PubSubNodeConfig::default(),
            20,
            &self.items,
            storage_limit,
            &self.renderer,
        )
        .await
    }

    async fn assert_rolled_back(&self, pool: &PgPool) {
        let rows: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM pubsub_nodes WHERE node=$1),
                    (SELECT COUNT(*) FROM pubsub_affiliations WHERE jid=$2),
                    (SELECT COUNT(*) FROM pubsub_items WHERE publisher_jid=$2),
                    (SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1)",
        )
        .bind(&self.node)
        .bind(&self.publisher)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(rows, (0, 0, 0, 0));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn auto_create_publish_storage_quota_rolls_back_creation() {
    let (_, pool) = integration_pool(12).await;
    let fixture = AutoCreateFixture::new();
    assert_eq!(
        fixture.publish(&pool, 1).await.unwrap(),
        AutoCreatePublishOutcome::Publish(
            northstar_pubsub_core::PublishItemsOutcome::QuotaExceeded
        )
    );
    fixture.assert_rolled_back(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn auto_create_publish_commits_node_items_and_ordered_events_together() {
    let (_, pool) = integration_pool(12).await;
    let mut fixture = AutoCreateFixture::new();
    // Both events go to one recipient so they share an outbox stream and its sequence.
    fixture.renderer.create_recipient = Some(fixture.renderer.item_recipient.clone());
    assert_eq!(
        fixture.publish(&pool, 1_000_000).await.unwrap(),
        AutoCreatePublishOutcome::Published
    );

    // A split create/publish would leave different inserting transaction IDs.
    let (node_id, node_xid, owner_xid): (Uuid, String, String) = sqlx::query_as(
        "SELECT n.id, n.xmin::text, a.xmin::text
           FROM pubsub_nodes n JOIN pubsub_affiliations a ON a.node_id=n.id
          WHERE n.node=$1 AND n.creator_jid=$2 AND a.jid=$2 AND a.affiliation='owner'",
    )
    .bind(&fixture.node)
    .bind(&fixture.publisher)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner_xid, node_xid);
    let items: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT item_id, xml_payload, publisher_jid, xmin::text FROM pubsub_items
          WHERE node_id=$1 ORDER BY created_at",
    )
    .bind(node_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(items.len(), fixture.items.len());
    for ((item_id, xml, publisher, xid), (expected_id, expected_xml)) in
        items.iter().zip(&fixture.items)
    {
        assert_eq!((item_id, xml), (expected_id, expected_xml));
        assert_eq!(publisher, &fixture.publisher);
        assert_eq!(xid, &node_xid);
    }

    let events: Vec<(i64, Uuid, String, String)> = sqlx::query_as(
        "SELECT event_sequence, event_id, payload_xml, xmin::text FROM pubsub_event_outbox
          WHERE source_node=$1 ORDER BY event_sequence",
    )
    .bind(&fixture.node)
    .fetch_all(&pool)
    .await
    .unwrap();
    let [create, publish] = events.as_slice() else {
        panic!("expected two events, got {events:?}");
    };
    let (create_sequence, create_id, create_xml, create_xid) = create;
    let (publish_sequence, publish_id, publish_xml, publish_xid) = publish;
    assert_eq!((*create_sequence, *publish_sequence), (1, 2));
    assert_ne!(create_id, publish_id);
    assert!(create_xml.contains("<create "));
    assert!(publish_xml.contains("<items "));
    assert_eq!(create_xid, &node_xid);
    assert_eq!(publish_xid, &node_xid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn auto_create_publish_yields_to_explicit_create_during_owner_lock_wait() {
    let (url, pool) = integration_pool(12).await;
    let fixture = AutoCreateFixture::new();
    let node = fixture.node.clone();
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&fixture.publisher)
        .execute(&mut *holder)
        .await
        .unwrap();

    let application = format!("ps-{node}");
    let waiting_pool = named_single_connection_pool(&url, &application).await;
    let publish = tokio::spawn(async move { fixture.publish(&waiting_pool, 1_000_000).await });
    wait_for_named_session_lock(&pool, &application).await;
    let creator = format!("explicit-{node}@example.test");
    let created = create_default_test_node(&pool, &node, &creator).await;
    holder.commit().await.unwrap();
    assert_eq!(
        publish.await.unwrap().unwrap(),
        AutoCreatePublishOutcome::NodeExists
    );

    let stored = get_node(&pool, &node).await.unwrap().unwrap();
    assert_eq!(stored.id, created.id);
    assert_eq!(stored.creator_jid, creator);
    let affiliations: Vec<(String, String)> =
        sqlx::query_as("SELECT jid, affiliation FROM pubsub_affiliations WHERE node_id=$1")
            .bind(stored.id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(affiliations, [(creator, "owner".to_owned())]);
    assert!(get_items(&pool, stored.id, &[], 10)
        .await
        .unwrap()
        .is_empty());
    let outbox_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(outbox_count, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn auto_create_publish_outbox_capacity_rolls_back_creation() {
    let (_, pool) = integration_pool(12).await;
    let fixture = AutoCreateFixture::new();
    // Fill the publish recipient's domain ledger, leaving the create
    // recipient's domain available. All shards cover the random event ID.
    sqlx::query(
        "INSERT INTO pubsub_event_outbox_domain_capacity(target_domain, capacity_shard, queued_rows)
         SELECT $1, shard, 781 FROM generate_series(0, 63) AS shards(shard)",
    )
    .bind(&fixture.item_domain)
    .execute(&pool)
    .await
    .unwrap();
    let outcome = fixture.publish(&pool, 1_000_000).await;
    sqlx::query("DELETE FROM pubsub_event_outbox_domain_capacity WHERE target_domain=$1")
        .bind(&fixture.item_domain)
        .execute(&pool)
        .await
        .unwrap();
    let error = outcome.unwrap_err();
    let database_error = error
        .downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .unwrap();
    assert_eq!(database_error.code().as_deref(), Some("23514"));
    assert!(database_error
        .constraint()
        .is_some_and(|name| name.starts_with("pubsub_event_outbox_domain_capacity")));
    fixture.assert_rolled_back(&pool).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn auto_create_publish_preserves_collection_options_precondition() {
    let (_, pool) = integration_pool(12).await;
    let fixture = AutoCreateFixture::new();
    let parent = format!("parent-{}", fixture.node);
    let parent_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        deliver_payloads: false,
        children_association_policy: "all".to_owned(),
        ..PubSubNodeConfig::default()
    };
    let parent_owner = format!("{parent}@example.test");
    assert!(matches!(
        create_node(&pool, &parent, &parent_owner, &parent_config, 20)
            .await
            .unwrap(),
        CreateNodeOutcome::Created(_)
    ));
    let config = PubSubNodeConfig {
        collections: vec![parent],
        ..PubSubNodeConfig::default()
    };
    assert_eq!(
        create_node_and_publish_items_with_renderer(
            &pool,
            &fixture.node,
            &fixture.publisher,
            &config,
            20,
            &fixture.items,
            1_000_000,
            &fixture.renderer,
        )
        .await
        .unwrap(),
        AutoCreatePublishOutcome::Publish(
            northstar_pubsub_core::PublishItemsOutcome::PreconditionFailed
        )
    );
    fixture.assert_rolled_back(&pool).await;
}
