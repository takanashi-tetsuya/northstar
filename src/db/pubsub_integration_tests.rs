use super::*;
use crate::db;
use crate::services::pubsub::{
    CollectionDiscoItems, LeafDiscoItems, PubSubCollectionDiscoChild, PubSubService,
};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Clone, Debug)]
struct MutationObservation {
    kind: &'static str,
    recipients: Vec<String>,
    event_id: Uuid,
}

#[derive(Default)]
struct RenderGate {
    released: Mutex<bool>,
    wake: Condvar,
}

impl RenderGate {
    fn wait(&self) -> Result<()> {
        let released = self.released.lock().expect("render gate poisoned");
        let (released, _) = self
            .wake
            .wait_timeout_while(released, Duration::from_secs(30), |released| !*released)
            .expect("render gate poisoned");
        anyhow::ensure!(*released, "PubSub test renderer gate timed out");
        Ok(())
    }

    fn release(&self) {
        *self.released.lock().expect("render gate poisoned") = true;
        self.wake.notify_all();
    }
}

struct RaceMutationRenderer {
    inner: crate::services::pubsub::PubSubService<
        crate::db::pubsub_repository::PostgresPubSubRepository,
    >,
    observations: tokio::sync::mpsc::UnboundedSender<MutationObservation>,
    gate: Option<Arc<RenderGate>>,
}

impl RaceMutationRenderer {
    fn observe(
        &self,
        kind: &'static str,
        audience: &[PubSubNotificationDelivery],
        direct_recipients: &[String],
        event_id: Uuid,
    ) -> Result<()> {
        let mut recipients = audience
            .iter()
            .map(|delivery| delivery.subscription.jid.clone())
            .chain(direct_recipients.iter().cloned())
            .collect::<Vec<_>>();
        recipients.sort();
        recipients.dedup();
        self.observations
            .send(MutationObservation {
                kind,
                recipients,
                event_id,
            })
            .map_err(|_| anyhow::anyhow!("mutation observation receiver closed"))?;
        if let Some(gate) = &self.gate {
            gate.wait()?;
        }
        Ok(())
    }
}

impl PubSubMutationOutboxRenderer for RaceMutationRenderer {
    fn render_create(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        self.observe("create", audience, &[], event_id)?;
        PubSubMutationOutboxRenderer::render_create(
            &self.inner,
            node,
            audience,
            event_id,
            created_at,
        )
    }

    fn render_items(
        &self,
        node: &PubSubNode,
        items: &[(String, String)],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        self.observe("items", audience, &[], event_id)?;
        PubSubMutationOutboxRenderer::render_items(
            &self.inner,
            node,
            items,
            audience,
            event_id,
            created_at,
        )
    }

    fn render_purge(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        self.observe("purge", audience, &[], event_id)?;
        PubSubMutationOutboxRenderer::render_purge(
            &self.inner,
            node,
            audience,
            event_id,
            created_at,
        )
    }

    fn render_retract(
        &self,
        node: &PubSubNode,
        item_ids: &[String],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        self.observe("retract", audience, &[], event_id)?;
        PubSubMutationOutboxRenderer::render_retract(
            &self.inner,
            node,
            item_ids,
            audience,
            event_id,
            created_at,
        )
    }

    fn render_delete(
        &self,
        node: &PubSubNode,
        redirect: Option<&str>,
        audience: &[PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        self.observe("delete", audience, nonactive_recipients, event_id)?;
        PubSubMutationOutboxRenderer::render_delete(
            &self.inner,
            node,
            redirect,
            audience,
            nonactive_recipients,
            event_id,
            created_at,
        )
    }

    fn render_configuration(
        &self,
        node: &PubSubNode,
        config: &PubSubNodeConfig,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        self.observe("configuration", audience, &[], event_id)?;
        PubSubMutationOutboxRenderer::render_configuration(
            &self.inner,
            node,
            config,
            audience,
            event_id,
            created_at,
        )
    }

    fn render_collection_edge(
        &self,
        source: &PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        self.observe("collection", audience, &[], event_id)?;
        PubSubMutationOutboxRenderer::render_collection_edge(
            &self.inner,
            source,
            action,
            target_node,
            audience,
            event_id,
            created_at,
        )
    }

    fn render_subscription_transition(
        &self,
        node: &PubSubNode,
        subscription: &PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&PubSubItem>,
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        let mut recipients = notify_recipients.to_vec();
        recipients.extend_from_slice(authorization_recipients);
        if last_item.is_some() {
            recipients.push(subscription.jid.clone());
        }
        self.observe("subscription", &[], &recipients, event_id)?;
        PubSubMutationOutboxRenderer::render_subscription_transition(
            &self.inner,
            node,
            subscription,
            notify_recipients,
            authorization_recipients,
            last_item,
            event_id,
            created_at,
        )
    }

    fn render_affiliation_transition(
        &self,
        node: &PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        self.observe("affiliation", &[], &[jid.to_owned()], event_id)?;
        PubSubMutationOutboxRenderer::render_affiliation_transition(
            &self.inner,
            node,
            jid,
            affiliation,
            event_id,
            created_at,
        )
    }
}

struct FailingRetractRenderer;

impl PubSubMutationOutboxRenderer for FailingRetractRenderer {
    fn render_retract(
        &self,
        _: &PubSubNode,
        _: &[String],
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
        anyhow::bail!("intentional renderer failure")
    }
}

async fn named_single_connection_pool(url: &str, application_name: &str) -> PgPool {
    let application_name = Arc::new(application_name.to_owned());
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let application_name = Arc::clone(&application_name);
            Box::pin(async move {
                sqlx::query("SELECT set_config('application_name', $1, false)")
                    .bind(application_name.as_str())
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap()
}

async fn wait_for_named_session_lock(pool: &PgPool, application_name: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                         SELECT 1 FROM pg_stat_activity
                          WHERE datname=current_database()
                            AND application_name=$1
                            AND wait_event_type='Lock'
                     )",
            )
            .bind(application_name)
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("session {application_name} never reached its lock wait"));
}

async fn await_mutation_observation(
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<MutationObservation>,
    phase: &str,
) -> MutationObservation {
    tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .unwrap_or_else(|_| panic!("{phase} did not emit its mutation observation"))
        .unwrap_or_else(|| panic!("{phase} mutation observation channel closed"))
}

async fn integration_pool(max_connections: u32) -> (String, PgPool) {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    (url, pool)
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn timed_out_mutation_begin_rolls_back_before_releasing_connection() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let observer = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let (released_tx, mut released_rx) = tokio::sync::mpsc::unbounded_channel();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let released_tx = released_tx.clone();
            Box::pin(async move {
                let _ = released_tx.send(());
                Ok(true)
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    while released_rx.try_recv().is_ok() {}

    // Force BEGIN to complete after the admission deadline without changing
    // PostgreSQL settings or relying on a timing-sensitive server stall.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    let delayed_begin = async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Transaction::begin(connection, None).await
    };
    let error = match finish_bounded_pubsub_begin(deadline, delayed_begin).await {
        Ok(_) => panic!("a late BEGIN unexpectedly passed admission"),
        Err(error) => error,
    };
    assert!(error.downcast_ref::<PubSubMutationBusy>().is_some());

    tokio::time::timeout(Duration::from_secs(5), released_rx.recv())
        .await
        .expect("timed-out BEGIN did not release its connection")
        .expect("pool release observer closed");
    let state: String = sqlx::query_scalar("SELECT state FROM pg_stat_activity WHERE pid = $1")
        .bind(backend_pid)
        .fetch_one(&observer)
        .await
        .unwrap();
    assert_eq!(state, "idle");
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn timed_out_mutation_acquire_leaves_no_detached_waiter() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let (released_tx, mut released_rx) = tokio::sync::mpsc::unbounded_channel();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let released_tx = released_tx.clone();
            Box::pin(async move {
                let _ = released_tx.send(());
                Ok(true)
            })
        })
        .connect(&url)
        .await
        .unwrap();
    // Exhausting the pool must time out at acquisition, without leaving a
    // detached task to begin a transaction when the connection is released.
    let held = pool.acquire().await.unwrap();
    while released_rx.try_recv().is_ok() {}
    let error =
        match begin_bounded_pubsub_mutation_with_timeout(&pool, Duration::from_millis(20)).await {
            Ok(_) => panic!("a blocked mutation unexpectedly acquired the pool"),
            Err(error) => error,
        };
    assert!(error.downcast_ref::<PubSubMutationBusy>().is_some());
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), released_rx.recv())
        .await
        .expect("holder did not release its connection")
        .expect("pool release observer closed");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), released_rx.recv())
            .await
            .is_err(),
        "timed-out acquisition left a detached pool waiter"
    );
}

async fn create_default_test_node(pool: &PgPool, node: &str, owner: &str) -> PubSubNode {
    let node_id = match create_node(pool, node, owner, &PubSubNodeConfig::default(), 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected create outcome for {node}: {other:?}"),
    };
    get_node_by_id(pool, node_id).await.unwrap().unwrap()
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn node_metadata_keeps_affiliation_order_and_live_subscription_scope() {
    let (_, pool) = integration_pool(2).await;
    let node_name = format!("metadata-{}", Uuid::new_v4().simple());
    let node = create_default_test_node(&pool, &node_name, "alice@example.test").await;
    let initial = node_metadata(&pool, node.id).await.unwrap();
    assert_eq!(initial.owners, ["alice@example.test"]);
    assert!(initial.publishers.is_empty());
    assert_eq!(initial.active_subscribers, 0);

    for (jid, affiliation) in [
        ("zoe@example.test", "owner"),
        ("zack@example.test", "publisher"),
        ("amy@example.test", "publish-only"),
        ("member@example.test", "member"),
        ("outcast@example.test", "outcast"),
    ] {
        sqlx::query(
            "INSERT INTO pubsub_affiliations(node_id, jid, affiliation) VALUES ($1, $2, $3)",
        )
        .bind(node.id)
        .bind(jid)
        .bind(affiliation)
        .execute(&pool)
        .await
        .unwrap();
    }
    for (jid, state, expiry) in [
        ("bob@example.test", "subscribed", None),
        ("ghost@example.test/Phone", "subscribed", Some(3600)),
        ("expired@example.test", "subscribed", Some(-3600)),
        ("pending@example.test", "pending", None),
    ] {
        sqlx::query(
            "INSERT INTO pubsub_subscriptions(node_id, jid, state, subid, expire)
             VALUES ($1, $2, $3, $4, NOW() + $5::INT * INTERVAL '1 second')",
        )
        .bind(node.id)
        .bind(jid)
        .bind(state)
        .bind(Uuid::new_v4().to_string())
        .bind(expiry)
        .execute(&pool)
        .await
        .unwrap();
    }

    assert_eq!(
        node_metadata(&pool, node.id).await.unwrap(),
        PubSubNodeMetadata {
            owners: vec!["alice@example.test".into(), "zoe@example.test".into()],
            publishers: vec!["amy@example.test".into(), "zack@example.test".into()],
            active_subscribers: 2,
        }
    );
    let missing = node_metadata(&pool, Uuid::new_v4()).await.unwrap();
    assert!(missing.owners.is_empty());
    assert!(missing.publishers.is_empty());
    assert_eq!(missing.active_subscribers, 0);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn restricted_open_publish_is_denied_by_locked_publish_and_retract() {
    let (_, pool) = integration_pool(4).await;
    let owner = format!("restricted-owner-{}@example.test", Uuid::new_v4().simple());
    let outsider = format!(
        "restricted-outsider-{}@example.test",
        Uuid::new_v4().simple()
    );
    let node_name = format!("restricted-open-{}", Uuid::new_v4().simple());
    let mut config = PubSubNodeConfig {
        publish_model: "open".to_owned(),
        ..Default::default()
    };
    let node_id = match create_node(&pool, &node_name, &owner, &config, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected node create outcome: {other:?}"),
    };
    let open_node = get_node_by_id(&pool, node_id).await.unwrap().unwrap();
    let original_item = vec![("original".to_owned(), "<item id='original'/>".to_owned())];
    assert_eq!(
        publish_items(
            &pool,
            &open_node,
            &outsider,
            &original_item,
            false,
            1_000_000
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    set_subscription(&pool, node_id, "watcher@remote.test", "subscribed")
        .await
        .unwrap();

    config.access_model = "whitelist".to_owned();
    assert_eq!(
        update_node_config_and_graph(&pool, &open_node, &owner, &config)
            .await
            .unwrap(),
        PubSubConfigOutcome::Updated
    );
    let restricted_node = get_node_by_id(&pool, node_id).await.unwrap().unwrap();
    let renderer = crate::services::pubsub::PubSubService::new(pool.clone(), "example.test");
    let outbox_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node_name)
            .fetch_one(&pool)
            .await
            .unwrap();
    let forbidden_item = vec![("forbidden".to_owned(), "<item id='forbidden'/>".to_owned())];
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &restricted_node,
            &outsider,
            &forbidden_item,
            false,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Forbidden
    );
    assert_eq!(
        retract_items_with_renderer(
            &pool,
            node_id,
            &["original".to_owned()],
            &outsider,
            false,
            &renderer,
        )
        .await
        .unwrap(),
        RetractItemsOutcome::Forbidden
    );
    let outbox_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_event_outbox WHERE source_node=$1")
            .bind(&node_name)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(outbox_after, outbox_before);
    assert!(get_items(&pool, node_id, &["forbidden".to_owned()], 1)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        get_items(&pool, node_id, &["original".to_owned()], 1)
            .await
            .unwrap()
            .len(),
        1
    );

    assert!(matches!(
        set_affiliations(&pool, node_id, &[(outsider.clone(), "member".to_owned())])
            .await
            .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    let item_events_before_member_publish: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_event_outbox
          WHERE source_node=$1 AND payload_xml LIKE '%<items%'",
    )
    .bind(&node_name)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &restricted_node,
            &outsider,
            &forbidden_item,
            false,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let item_events_after_member_publish: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_event_outbox
          WHERE source_node=$1 AND payload_xml LIKE '%<items%'",
    )
    .bind(&node_name)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(item_events_after_member_publish > item_events_before_member_publish);
    assert_eq!(
        retract_items(&pool, node_id, &["original".to_owned()], &outsider, false)
            .await
            .unwrap(),
        RetractItemsOutcome::Retracted
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn publish_rechecks_access_model_after_concurrent_config_change() {
    let (url, pool) = integration_pool(10).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("race-owner-{suffix}@example.test");
    let outsider = format!("race-outsider-{suffix}@example.test");
    let config = PubSubNodeConfig {
        publish_model: "open".to_owned(),
        ..Default::default()
    };
    let node_id = match create_node(&pool, &format!("race-access-{suffix}"), &owner, &config, 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected node create outcome: {other:?}"),
    };
    let open_node = get_node_by_id(&pool, node_id).await.unwrap().unwrap();
    set_subscription(&pool, node_id, "watcher@remote.test", "subscribed")
        .await
        .unwrap();
    assert!(tokio::time::timeout(
        Duration::from_secs(5),
        crate::services::pubsub::PubSubService::new(pool.clone(), "example.test")
            .can_publish(&open_node, &outsider)
    )
    .await
    .expect("open-publish precheck timed out")
    .unwrap());

    // Hold the same graph and node locks as a configuration mutation. The
    // publisher starts with a stale, open-access node and must recheck after
    // the committed policy change becomes visible.
    let mut config_tx = tokio::time::timeout(Duration::from_secs(5), pool.begin())
        .await
        .expect("configuration transaction timed out")
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
            .execute(&mut *config_tx),
    )
    .await
    .expect("configuration graph lock timed out")
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
            .bind(node_id)
            .fetch_one(&mut *config_tx),
    )
    .await
    .expect("configuration node lock timed out")
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("UPDATE pubsub_nodes SET access_model='whitelist' WHERE id=$1")
            .bind(node_id)
            .execute(&mut *config_tx),
    )
    .await
    .expect("configuration update timed out")
    .unwrap();

    let publish_application = format!("ps-access-publish-{}", &suffix[..10]);
    let publish_pool = tokio::time::timeout(
        Duration::from_secs(5),
        named_single_connection_pool(&url, &publish_application),
    )
    .await
    .expect("named publish pool connection timed out");
    let mut publish_task = tokio::spawn({
        let publish_pool = publish_pool.clone();
        let open_node = open_node.clone();
        let outsider = outsider.clone();
        async move {
            let renderer =
                crate::services::pubsub::PubSubService::new(publish_pool.clone(), "example.test");
            publish_items_with_renderer(
                &publish_pool,
                &open_node,
                &outsider,
                &[("raced".to_owned(), "<item id='raced'/>".to_owned())],
                false,
                1_000_000,
                &renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &publish_application).await;
    tokio::time::timeout(Duration::from_secs(5), config_tx.commit())
        .await
        .expect("configuration commit timed out")
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), &mut publish_task)
            .await
            .expect("publisher did not finish after configuration commit")
            .unwrap()
            .unwrap(),
        PublishItemsOutcome::PreconditionFailed
    );
    assert!(tokio::time::timeout(
        Duration::from_secs(5),
        get_items(&pool, node_id, &["raced".to_owned()], 1)
    )
    .await
    .expect("item verification timed out")
    .unwrap()
    .is_empty());
    let item_events = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM pubsub_event_outbox
          WHERE source_node=$1 AND payload_xml LIKE '%<items%'",
    )
    .bind(&open_node.node)
    .fetch_one(&pool);
    let item_events = tokio::time::timeout(Duration::from_secs(5), item_events)
        .await
        .expect("outbox verification timed out")
        .unwrap();
    assert_eq!(item_events, 0);
}

async fn subscribe_for_race(
    pool: &PgPool,
    node: &PubSubNode,
    subscriber: &str,
    subid: &str,
) -> PubSubSubscription {
    let requester = crate::jid::canonical_bare_key(subscriber).unwrap();
    match set_subscription_limited_with_options_and_outbox(
        pool,
        node.id,
        &requester,
        subscriber,
        "subscribed",
        &node.node_type,
        &node.access_model,
        100,
        None,
        subid,
        &[],
    )
    .await
    .unwrap()
    {
        SubscribeOutcome::Subscribed(subscription) => subscription,
        other => panic!("unexpected subscribe outcome: {other:?}"),
    }
}

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

    let service = crate::services::pubsub::PubSubService::new(read_pool, "example.test");
    assert_eq!(
        service.get_node(&node_name).await.unwrap().unwrap().id,
        node.id
    );
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
    let service = PubSubService::new(read_pool, "example.test");
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
    let service = PubSubService::new(pool.clone(), "example.test");

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
    let service = PubSubService::new(pool.clone(), "example.test");
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
    let service = PubSubService::new(read_pool.clone(), "example.test");
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
    let service = PubSubService::new(pool.clone(), "example.test");
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

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mutation_authority_and_stale_preconditions_are_checked_in_transaction() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let renderer = crate::services::pubsub::PubSubService::new(pool.clone(), "example.test");

    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}@example.test");
    let publisher = format!("publisher-{suffix}@example.test");
    let intruder = format!("intruder-{suffix}@example.test");
    let subscriber = format!("subscriber-{suffix}@example.test/desktop");
    let node_name = format!("authority-{suffix}");
    let node_id = match create_node(&pool, &node_name, &owner, &PubSubNodeConfig::default(), 10)
        .await
        .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected create outcome: {other:?}"),
    };
    let stale_node = get_node_by_id(&pool, node_id).await.unwrap().unwrap();

    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &stale_node,
            &intruder,
            &[("forbidden".to_owned(), "<item id='forbidden'/>".to_owned())],
            true,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Forbidden,
        "a protocol-supplied owner boolean must never authorize publication"
    );
    assert!(matches!(
        set_affiliations_with_outbox(
            &pool,
            node_id,
            &owner,
            &[(publisher.clone(), "publisher".to_owned())],
            None,
            None,
            &[],
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &stale_node,
            &publisher,
            &[("allowed".to_owned(), "<item id='allowed'/>".to_owned())],
            false,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );

    let mut changed_config = stale_node.config();
    // Change a publication-semantic field, not display-only metadata.
    // A stale handler must not retain an obsolete persistence decision.
    changed_config.persist_items = false;
    assert_eq!(
        update_node_config_and_graph(&pool, &stale_node, &owner, &changed_config,)
            .await
            .unwrap(),
        PubSubConfigOutcome::Updated
    );
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &stale_node,
            &publisher,
            &[("stale".to_owned(), "<item id='stale'/>".to_owned())],
            false,
            1_000_000,
            &renderer,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::PreconditionFailed,
        "validation against an old node configuration must not authorize a write"
    );

    assert_eq!(
        set_subscriptions_with_outbox(
            &pool,
            node_id,
            &intruder,
            &[(subscriber.clone(), "subscribed".to_owned(), None)],
            None,
            &[],
        )
        .await
        .unwrap(),
        SetSubscriptionsOutcome::Forbidden
    );
    assert_eq!(
        set_affiliations_with_outbox(
            &pool,
            node_id,
            &intruder,
            &[(intruder.clone(), "owner".to_owned())],
            None,
            None,
            &[],
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Forbidden
    );
    assert_eq!(
        purge_node_as_owner_with_outbox(&pool, node_id, &intruder, &renderer)
            .await
            .unwrap(),
        OwnerMutationOutcome::Forbidden
    );

    set_subscription(&pool, node_id, &subscriber, "pending")
        .await
        .unwrap();
    let pending = get_subscription(&pool, node_id, &subscriber)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resolve_pending_subscription_with_outbox(
            &pool,
            node_id,
            &intruder,
            &subscriber,
            &pending.subid,
            true,
            &[],
        )
        .await
        .unwrap(),
        SubscriptionAuthorizationOutcome::Forbidden
    );
    assert_eq!(
        resolve_pending_subscription_with_outbox(
            &pool,
            node_id,
            &owner,
            &subscriber,
            "stale-subid",
            true,
            &[],
        )
        .await
        .unwrap(),
        SubscriptionAuthorizationOutcome::Stale
    );
    assert_eq!(
        resolve_pending_subscription_with_outbox(
            &pool,
            node_id,
            &owner,
            &subscriber,
            &pending.subid,
            true,
            &[],
        )
        .await
        .unwrap(),
        SubscriptionAuthorizationOutcome::Applied
    );

    let current = get_node_by_id(&pool, node_id).await.unwrap().unwrap();
    assert_eq!(
        delete_node_as_owner_with_redirect_and_outbox(
            &pool, current.id, &intruder, None, &renderer,
        )
        .await
        .unwrap(),
        OwnerMutationOutcome::Forbidden
    );
    assert_eq!(
        delete_node_as_owner_with_redirect_and_outbox(&pool, current.id, &owner, None, &renderer,)
            .await
            .unwrap(),
        OwnerMutationOutcome::Applied
    );
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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
    let unsubscribe_requester = crate::jid::canonical_bare_key(&subscriber).unwrap();
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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
            collection.id,
            &crate::jid::canonical_bare_key(&subscriber).unwrap(),
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
    let service = crate::services::pubsub::PubSubService::new(pool.clone(), "example.test");
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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
            crate::jid::canonical_bare_key(&subscriber).unwrap(),
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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
    let subscribe_requester = crate::jid::canonical_bare_key(&subscribe_jid).unwrap();
    let subscribe_task = tokio::spawn({
        let subscribe_pool = subscribe_pool.clone();
        let requested_subid = format!("new-{suffix}");
        async move {
            set_subscription_limited_with_options_and_outbox(
                &subscribe_pool,
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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
    let unsubscribe_marker = super::super::PubSubOutboxInsert::new(
            Uuid::new_v4(),
            format!("test-unsubscribe:{}", config_node.id),
            super::super::PubSubOutboxSource::PubSub,
            super::super::PubSubOutboxDeliveryKind::PubSubDirect,
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
        let config_requester = crate::jid::canonical_bare_key(&config_subscriber).unwrap();
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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
        let delete_requester = crate::jid::canonical_bare_key(&delete_subscriber).unwrap();
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
            crate::jid::canonical_bare_key(&pending_jid).unwrap(),
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
        set_subscription_limited(&pool, first_id, &subscriber, "subscribed", 1),
        set_subscription_limited(&pool, second_id, &subscriber, "subscribed", 1),
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
        crate::jid::canonical_bare_key(&owner).unwrap()
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
async fn concurrent_config_updates_use_a_locked_expected_snapshot() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let short = &suffix[..10];
    let owner = format!("config-owner-{suffix}@example.test");
    let subscriber = format!("config-subscriber-{suffix}@example.test/desktop");
    let node = create_default_test_node(&pool, &format!("config-conflict-{suffix}"), &owner).await;
    subscribe_for_race(&pool, &node, &subscriber, &format!("config-sub-{suffix}")).await;

    let expected = node.config();
    let mut first_config = expected.clone();
    first_config.title = Some("first-locked-title".to_owned());
    let mut second_config = expected.clone();
    second_config.description = Some("must-not-overwrite".to_owned());

    let gate = Arc::new(RenderGate::default());
    let (first_tx, mut first_rx) = tokio::sync::mpsc::unbounded_channel();
    let first_renderer = Arc::new(RaceMutationRenderer {
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
        observations: first_tx,
        gate: Some(Arc::clone(&gate)),
    });
    let first_application = format!("ps-config-first-{short}");
    let first_pool = named_single_connection_pool(&url, &first_application).await;
    let first_task = tokio::spawn({
        let first_pool = first_pool.clone();
        let first_renderer = Arc::clone(&first_renderer);
        let first_node = node.clone();
        let first_owner = owner.clone();
        let first_expected = expected.clone();
        async move {
            update_node_config_and_graph_with_outbox(
                &first_pool,
                &first_node,
                &first_owner,
                &first_expected,
                &first_config,
                &*first_renderer,
            )
            .await
        }
    });
    let first_observation = tokio::time::timeout(Duration::from_secs(3), first_rx.recv())
        .await
        .expect("first configuration never reached its locked renderer")
        .expect("first configuration observation channel closed");
    assert_eq!(first_observation.kind, "configuration");
    assert_eq!(first_observation.recipients, vec![subscriber.clone()]);

    let second_application = format!("ps-config-second-{short}");
    let second_pool = named_single_connection_pool(&url, &second_application).await;
    let second_task = tokio::spawn({
        let second_pool = second_pool.clone();
        let second_node = node.clone();
        let second_owner = owner.clone();
        let second_expected = expected.clone();
        async move {
            update_node_config_and_graph_with_outbox(
                &second_pool,
                &second_node,
                &second_owner,
                &second_expected,
                &second_config,
                &NoopMutationOutboxRenderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &second_application).await;
    gate.release();

    assert_eq!(
        first_task.await.unwrap().unwrap(),
        PubSubConfigOutcome::Updated
    );
    assert_eq!(
        second_task.await.unwrap().unwrap(),
        PubSubConfigOutcome::Conflict
    );
    let fresh = get_node_by_id(&pool, node.id).await.unwrap().unwrap();
    assert_eq!(fresh.title.as_deref(), Some("first-locked-title"));
    assert_eq!(fresh.description, None);
    let payload: String = sqlx::query_scalar(
        "SELECT payload_xml FROM pubsub_event_outbox
              WHERE event_id=$1 AND recipient_jid=$2",
    )
    .bind(first_observation.event_id)
    .bind(&subscriber)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(payload.contains("first-locked-title"));
    assert!(!payload.contains("must-not-overwrite"));

    first_pool.close().await;
    second_pool.close().await;
    pool.close().await;
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
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn prohibited_affiliation_wins_atomically_over_owner_subscription_batch() {
    let (url, pool) = integration_pool(16).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("prohibited-owner-{suffix}@example.test");

    for (index, affiliation) in ["outcast", "publish-only"].into_iter().enumerate() {
        let bare = format!("prohibited-{index}-{suffix}@example.test");
        let full = format!("{bare}/phone");
        let node =
            create_default_test_node(&pool, &format!("prohibited-{affiliation}-{suffix}"), &owner)
                .await;
        let node_id = node.id;
        set_subscription(&pool, node_id, &bare, "subscribed")
            .await
            .unwrap();
        set_subscription(&pool, node_id, &full, "pending")
            .await
            .unwrap();
        sqlx::query(
                "INSERT INTO pubsub_digest_queue
                    (id,subscription_node_id,subscriber_jid,event_xml,deliver_after)
                 VALUES($1,$2,$3,'<event xmlns=''urn:test''/>',clock_timestamp()+INTERVAL '1 hour')",
            )
            .bind(Uuid::new_v4())
            .bind(node_id)
            .bind(&bare)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
                "INSERT INTO pubsub_digest_queue
                    (id,subscription_node_id,subscriber_jid,event_xml,deliver_after,source_delivery_id,show_values)
                 VALUES($1,$2,$3,'<event xmlns=''urn:test''/>',clock_timestamp()+INTERVAL '1 hour',$4,$5)",
            )
            .bind(Uuid::new_v4())
            .bind(node_id)
            .bind(&full)
            .bind(Uuid::new_v4())
            .bind(vec!["online".to_owned()])
            .execute(&pool)
            .await
            .unwrap();

        let gate = Arc::new(RenderGate::default());
        let (affiliation_tx, mut affiliation_rx) = tokio::sync::mpsc::unbounded_channel();
        let affiliation_renderer = Arc::new(RaceMutationRenderer {
            inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
            observations: affiliation_tx,
            gate: Some(Arc::clone(&gate)),
        });
        let affiliation_task = tokio::spawn({
            let affiliation_pool = pool.clone();
            let affiliation_renderer = Arc::clone(&affiliation_renderer);
            let affiliation_owner = owner.clone();
            let affiliation_bare = bare.clone();
            let affiliation_value = affiliation.to_owned();
            async move {
                set_affiliations_with_renderer(
                    &affiliation_pool,
                    node_id,
                    &affiliation_owner,
                    &[(affiliation_bare, affiliation_value)],
                    None,
                    None,
                    &*affiliation_renderer,
                )
                .await
            }
        });
        let first_observation = tokio::time::timeout(Duration::from_secs(3), affiliation_rx.recv())
            .await
            .expect("affiliation mutation never reached its in-transaction renderer")
            .expect("affiliation observation channel closed");
        assert_eq!(first_observation.kind, "affiliation");

        let batch_application = format!("ps-prohibited-{index}-{}", &suffix[..8]);
        let batch_pool = named_single_connection_pool(&url, &batch_application).await;
        let batch_task = tokio::spawn({
            let batch_pool = batch_pool.clone();
            let batch_owner = owner.clone();
            let batch_full = full.clone();
            async move {
                set_subscriptions_with_renderer(
                    &batch_pool,
                    node_id,
                    &batch_owner,
                    &[(batch_full, "subscribed".to_owned(), None)],
                    None,
                    &NoopMutationOutboxRenderer,
                )
                .await
            }
        });
        wait_for_named_session_lock(&pool, &batch_application).await;
        gate.release();

        assert!(matches!(
            affiliation_task.await.unwrap().unwrap(),
            SetAffiliationsOutcome::Updated {
                ref revoked_subscriptions,
                ..
            } if revoked_subscriptions.len() == 2
        ));
        assert_eq!(
            batch_task.await.unwrap().unwrap(),
            SetSubscriptionsOutcome::Forbidden
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_subscriptions
                      WHERE node_id=$1 AND split_part(jid,'/',1)=$2",
            )
            .bind(node_id)
            .bind(&bare)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_digest_queue
                      WHERE subscription_node_id=$1 AND split_part(subscriber_jid,'/',1)=$2",
            )
            .bind(node_id)
            .bind(&bare)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );

        // A defensive audience predicate must also suppress a prohibited
        // principal if maintenance SQL leaves a stale subscription row.
        set_subscription(&pool, node_id, &full, "subscribed")
            .await
            .unwrap();
        let (publish_tx, mut publish_rx) = tokio::sync::mpsc::unbounded_channel();
        let publish_renderer = RaceMutationRenderer {
            inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
            observations: publish_tx,
            gate: None,
        };
        assert_eq!(
            publish_items_with_renderer(
                &pool,
                &node,
                &owner,
                &[(format!("prohibited-{index}"), "<item/>".to_owned())],
                false,
                1_000_000,
                &publish_renderer,
            )
            .await
            .unwrap(),
            PublishItemsOutcome::Published
        );
        let publish_observation = tokio::time::timeout(Duration::from_secs(3), publish_rx.recv())
            .await
            .expect("defensive audience publication renderer was not called")
            .expect("defensive audience observation channel closed");
        assert!(publish_observation.recipients.is_empty());
        batch_pool.close().await;
    }
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn multi_parent_create_emits_one_recursive_audience_snapshot() {
    let (url, pool) = integration_pool(14).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("multi-owner-{suffix}@example.test");
    let subscriber = format!("multi-subscriber-{suffix}@example.test/desktop");
    let collection_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        deliver_payloads: false,
        ..PubSubNodeConfig::default()
    };
    let root_id = match create_node(
        &pool,
        &format!("multi-root-{suffix}"),
        &owner,
        &collection_config,
        20,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected root create outcome: {other:?}"),
    };
    let left_id = match create_node(
        &pool,
        &format!("multi-left-{suffix}"),
        &owner,
        &collection_config,
        20,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected left create outcome: {other:?}"),
    };
    let right_id = match create_node(
        &pool,
        &format!("multi-right-{suffix}"),
        &owner,
        &collection_config,
        20,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected right create outcome: {other:?}"),
    };
    let root = get_node_by_id(&pool, root_id).await.unwrap().unwrap();
    let left = get_node_by_id(&pool, left_id).await.unwrap().unwrap();
    let right = get_node_by_id(&pool, right_id).await.unwrap().unwrap();
    assert_eq!(
        associate_collection_child(&pool, &root, &left, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert_eq!(
        associate_collection_child(&pool, &root, &right, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    let mut options = PubSubSubscriptionOptions::for_node_type("collection");
    options.subscription_depth = None;
    assert!(matches!(
        set_subscription_limited_with_options_and_renderer(
            &pool,
            root.id,
            &crate::jid::canonical_bare_key(&subscriber).unwrap(),
            &subscriber,
            "subscribed",
            &root.node_type,
            &root.access_model,
            100,
            Some(&options),
            &format!("root-sub-{suffix}"),
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        SubscribeOutcome::Subscribed(_)
    ));

    let mut graph_blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *graph_blocker)
        .await
        .unwrap();
    let application = format!("ps-multi-create-{}", &suffix[..8]);
    let create_pool = named_single_connection_pool(&url, &application).await;
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let renderer = Arc::new(RaceMutationRenderer {
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
        observations: observation_tx,
        gate: None,
    });
    let leaf_name = format!("multi-leaf-{suffix}");
    let leaf_config = PubSubNodeConfig {
        collections: vec![left.node.clone(), right.node.clone()],
        ..PubSubNodeConfig::default()
    };
    let create_task = tokio::spawn({
        let create_pool = create_pool.clone();
        let renderer = Arc::clone(&renderer);
        let create_owner = owner.clone();
        let create_name = leaf_name.clone();
        async move {
            create_node_with_renderer(
                &create_pool,
                &create_name,
                &create_owner,
                &leaf_config,
                20,
                &*renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    graph_blocker.commit().await.unwrap();
    assert!(matches!(
        create_task.await.unwrap().unwrap(),
        CreateNodeOutcome::Created(_)
    ));
    let observation = tokio::time::timeout(Duration::from_secs(3), observation_rx.recv())
        .await
        .expect("multi-parent create renderer was not called")
        .expect("multi-parent create observation channel closed");
    assert_eq!(observation.kind, "create");
    assert_eq!(observation.recipients, vec![subscriber.clone()]);
    assert!(observation_rx.try_recv().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE event_id=$1 AND recipient_jid=$2 AND source_node=$3",
        )
        .bind(observation.event_id)
        .bind(&subscriber)
        .bind(&leaf_name)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    create_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn repeated_associate_is_idempotent_after_a_graph_lock_wait() {
    let (url, pool) = integration_pool(10).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("associate-owner-{suffix}@example.test");
    let collection_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        deliver_payloads: false,
        children_max: 1,
        ..PubSubNodeConfig::default()
    };
    let collection_id = match create_node(
        &pool,
        &format!("associate-parent-{suffix}"),
        &owner,
        &collection_config,
        10,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected collection create outcome: {other:?}"),
    };
    let child = create_default_test_node(&pool, &format!("associate-child-{suffix}"), &owner).await;
    let collection = get_node_by_id(&pool, collection_id).await.unwrap().unwrap();
    assert_eq!(
        associate_collection_child(&pool, &collection, &child, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    // At the quota boundary the first association must own exactly one
    // edge.  The graph guard must not count that same edge again when an
    // update names its immutable identities or only stamps metadata.
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query(
            "UPDATE pubsub_collection_members
                    SET collection_node_id=$1, child_node_id=$2
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    assert_eq!(
        sqlx::query(
            "UPDATE pubsub_collection_members
                    SET created_at=created_at + INTERVAL '1 microsecond'
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );

    // A move within a collection replaces its old edge rather than
    // consuming another slot.  Move it back before exercising the retry
    // path below so the second request is an actual idempotent repeat.
    let replacement =
        create_default_test_node(&pool, &format!("associate-replacement-{suffix}"), &owner).await;
    assert_eq!(
        sqlx::query(
            "UPDATE pubsub_collection_members SET child_node_id=$3
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .bind(replacement.id)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    assert_eq!(
        sqlx::query(
            "UPDATE pubsub_collection_members SET child_node_id=$3
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(replacement.id)
        .bind(child.id)
        .execute(&pool)
        .await
        .unwrap()
        .rows_affected(),
        1
    );

    // A move into a separately full collection and a second direct
    // insertion both remain database-enforced quota violations.
    let full_collection_id = match create_node(
        &pool,
        &format!("associate-full-parent-{suffix}"),
        &owner,
        &collection_config,
        10,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected full collection create outcome: {other:?}"),
    };
    let full_collection = get_node_by_id(&pool, full_collection_id)
        .await
        .unwrap()
        .unwrap();
    let full_child =
        create_default_test_node(&pool, &format!("associate-full-child-{suffix}"), &owner).await;
    assert_eq!(
        associate_collection_child(&pool, &full_collection, &full_child, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Updated
    );
    let full_move = sqlx::query(
        "UPDATE pubsub_collection_members SET collection_node_id=$3
              WHERE collection_node_id=$1 AND child_node_id=$2",
    )
    .bind(collection.id)
    .bind(child.id)
    .bind(full_collection.id)
    .execute(&pool)
    .await
    .expect_err("moving an edge into a full collection must be rejected");
    assert_eq!(
        full_move
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514")
    );
    let overflow =
        create_default_test_node(&pool, &format!("associate-overflow-{suffix}"), &owner).await;
    assert_eq!(
        associate_collection_child(&pool, &collection, &overflow, &owner)
            .await
            .unwrap(),
        CollectionUpdateOutcome::LimitExceeded
    );
    let direct_overflow = sqlx::query(
        "INSERT INTO pubsub_collection_members(collection_node_id, child_node_id)
             VALUES($1, $2)",
    )
    .bind(collection.id)
    .bind(overflow.id)
    .execute(&pool)
    .await
    .expect_err("trigger must reject a second collection child at the limit");
    assert_eq!(
        direct_overflow
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514")
    );

    let mut graph_blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *graph_blocker)
        .await
        .unwrap();
    let application = format!("ps-repeat-assoc-{}", &suffix[..8]);
    let repeat_pool = named_single_connection_pool(&url, &application).await;
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let renderer = Arc::new(RaceMutationRenderer {
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
        observations: observation_tx,
        gate: None,
    });
    let repeat_task = tokio::spawn({
        let repeat_pool = repeat_pool.clone();
        let repeat_collection = collection.clone();
        let repeat_child = child.clone();
        let repeat_owner = owner.clone();
        let renderer = Arc::clone(&renderer);
        async move {
            associate_collection_child_with_renderer(
                &repeat_pool,
                &repeat_collection,
                &repeat_child,
                &repeat_owner,
                &*renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    graph_blocker.commit().await.unwrap();
    assert_eq!(
        repeat_task.await.unwrap().unwrap(),
        CollectionUpdateOutcome::Updated
    );
    assert!(observation_rx.try_recv().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    repeat_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn subscription_and_option_retries_do_not_emit_transitions_after_lock_wait() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("retry-owner-{suffix}@example.test");
    let subscriber = format!("retry-subscriber-{suffix}@example.test/desktop");
    let requester = crate::jid::canonical_bare_key(&subscriber).unwrap();
    let node = create_default_test_node(&pool, &format!("retry-{suffix}"), &owner).await;
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
    let mut options = PubSubSubscriptionOptions::for_node_type("leaf");
    options.include_body = false;
    let original = match set_subscription_limited_with_options_and_renderer(
        &pool,
        node.id,
        &requester,
        &subscriber,
        "subscribed",
        &node.node_type,
        &node.access_model,
        100,
        Some(&options),
        &format!("original-{suffix}"),
        &NoopMutationOutboxRenderer,
    )
    .await
    .unwrap()
    {
        SubscribeOutcome::Subscribed(subscription) => subscription,
        other => panic!("unexpected initial subscription outcome: {other:?}"),
    };

    let mut node_blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(node.id)
        .execute(&mut *node_blocker)
        .await
        .unwrap();
    let application = format!("ps-options-retry-{}", &suffix[..8]);
    let retry_pool = named_single_connection_pool(&url, &application).await;
    let (observation_tx, mut observation_rx) = tokio::sync::mpsc::unbounded_channel();
    let renderer = Arc::new(RaceMutationRenderer {
        inner: crate::services::pubsub::PubSubService::new(pool.clone(), "example.test"),
        observations: observation_tx,
        gate: None,
    });
    let retry_task = tokio::spawn({
        let retry_pool = retry_pool.clone();
        let retry_node = node.clone();
        let retry_requester = requester.clone();
        let retry_subscriber = subscriber.clone();
        let retry_options = options.clone();
        let renderer = Arc::clone(&renderer);
        async move {
            set_subscription_limited_with_options_and_renderer(
                &retry_pool,
                retry_node.id,
                &retry_requester,
                &retry_subscriber,
                "subscribed",
                &retry_node.node_type,
                &retry_node.access_model,
                100,
                Some(&retry_options),
                &format!("retry-{suffix}"),
                &*renderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    node_blocker.commit().await.unwrap();
    let retried = match retry_task.await.unwrap().unwrap() {
        SubscribeOutcome::Subscribed(subscription) => subscription,
        other => panic!("unexpected retry subscription outcome: {other:?}"),
    };
    assert_eq!(retried.subid, original.subid);
    assert!(observation_rx.try_recv().is_err());

    assert_eq!(
        set_subscriptions_with_renderer(
            &pool,
            node.id,
            &owner,
            &[(subscriber.clone(), "subscribed".to_owned(), None)],
            None,
            &*renderer,
        )
        .await
        .unwrap(),
        SetSubscriptionsOutcome::Updated(Vec::new())
    );
    assert!(matches!(
        set_affiliations_with_renderer(
            &pool,
            node.id,
            &owner,
            &[(owner.clone(), "owner".to_owned())],
            None,
            None,
            &*renderer,
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated {
            ref revoked_subscriptions,
            ref approved_subscriptions,
        } if revoked_subscriptions.is_empty() && approved_subscriptions.is_empty()
    ));
    assert_eq!(
        update_subscription_options_checked(
            &pool,
            node.id,
            &requester,
            &subscriber,
            Some(&original.subid),
            &options,
        )
        .await
        .unwrap(),
        SubscriptionOptionsOutcome::Updated
    );
    assert_eq!(
        update_subscription_options_checked(
            &pool,
            node.id,
            &requester,
            &subscriber,
            Some(&original.subid),
            &options,
        )
        .await
        .unwrap(),
        SubscriptionOptionsOutcome::Updated
    );
    assert!(observation_rx.try_recv().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE source_node=$1 AND recipient_jid=$2",
        )
        .bind(&node.node)
        .bind(&subscriber)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    retry_pool.close().await;
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn collection_edges_require_child_ownership_and_legacy_edges_do_not_disclose() {
    let (_, pool) = integration_pool(16).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let attacker = format!("collection-attacker-{suffix}@example.test");
    let victim = format!("collection-victim-{suffix}@example.test");
    let victim_leaf =
        create_default_test_node(&pool, &format!("collection-victim-leaf-{suffix}"), &victim).await;

    let malicious_create = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        children: vec![victim_leaf.node.clone()],
        ..PubSubNodeConfig::default()
    };
    let rejected_name = format!("collection-rejected-create-{suffix}");
    assert_eq!(
        create_node(&pool, &rejected_name, &attacker, &malicious_create, 100)
            .await
            .unwrap(),
        CreateNodeOutcome::Forbidden
    );
    assert!(get_node(&pool, &rejected_name).await.unwrap().is_none());

    let collection_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        ..PubSubNodeConfig::default()
    };
    let collection_id = match create_node(
        &pool,
        &format!("collection-existing-{suffix}"),
        &attacker,
        &collection_config,
        100,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected collection create outcome: {other:?}"),
    };
    let collection = get_node_by_id(&pool, collection_id).await.unwrap().unwrap();
    let mut malicious_update = collection.config();
    malicious_update.children = vec![victim_leaf.node.clone()];
    assert_eq!(
        update_node_config_and_graph(&pool, &collection, &attacker, &malicious_update)
            .await
            .unwrap(),
        PubSubConfigOutcome::Forbidden
    );
    assert_eq!(
        associate_collection_child(&pool, &collection, &victim_leaf, &attacker)
            .await
            .unwrap(),
        CollectionUpdateOutcome::Forbidden
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(victim_leaf.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    let owned_leaf =
        create_default_test_node(&pool, &format!("collection-owned-leaf-{suffix}"), &attacker)
            .await;
    let mut legal_create = collection_config.clone();
    legal_create.children = vec![owned_leaf.node.clone()];
    let legal_collection_id = match create_node(
        &pool,
        &format!("collection-owned-parent-{suffix}"),
        &attacker,
        &legal_create,
        100,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("same-owner collection edge was rejected: {other:?}"),
    };
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(legal_collection_id)
        .bind(owned_leaf.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        publish_items(
            &pool,
            &owned_leaf,
            &attacker,
            &[(
                "owned-visible".to_owned(),
                "<item id='owned-visible'/>".to_owned(),
            )],
            false,
            1_000_000,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let legal_items =
        collection_visible_items(&pool, legal_collection_id, &attacker, 100, 4 * 1_048_576)
            .await
            .unwrap();
    assert_eq!(legal_items.len(), 1);
    assert!(legal_items[0].xml_payload.contains("owned-visible"));

    let restricted_config = PubSubNodeConfig {
        access_model: "whitelist".to_owned(),
        ..PubSubNodeConfig::default()
    };
    let restricted_id = match create_node(
        &pool,
        &format!("collection-restricted-leaf-{suffix}"),
        &victim,
        &restricted_config,
        100,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected restricted leaf create outcome: {other:?}"),
    };
    let restricted = get_node_by_id(&pool, restricted_id).await.unwrap().unwrap();
    assert_eq!(
        publish_items(
            &pool,
            &restricted,
            &victim,
            &[(
                "private-first".to_owned(),
                "<item id='private-first'/>".to_owned(),
            )],
            false,
            1_000_000,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    let subscriber = format!("{attacker}/desktop");
    let mut options = PubSubSubscriptionOptions::for_node_type("collection");
    options.subscription_type = "items".to_owned();
    assert!(matches!(
        set_subscription_limited_with_options_and_renderer(
            &pool,
            collection.id,
            &attacker,
            &subscriber,
            "subscribed",
            &collection.node_type,
            &collection.access_model,
            100,
            Some(&options),
            &format!("collection-legacy-sub-{suffix}"),
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        SubscribeOutcome::Subscribed(_)
    ));
    // Model an edge created by an older vulnerable server or a privileged
    // operator. Read and notification paths must remain fail-closed even
    // when the historical graph cannot be trusted.
    sqlx::query(
        "INSERT INTO pubsub_collection_members(collection_node_id,child_node_id)
             VALUES($1,$2)",
    )
    .bind(collection.id)
    .bind(restricted.id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        collection_visible_items(&pool, collection.id, &attacker, 100, 4 * 1_048_576)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        collection_visible_items(&pool, collection.id, &victim, 100, 4 * 1_048_576)
            .await
            .unwrap()
            .len(),
        1
    );

    sqlx::query("DELETE FROM pubsub_event_outbox WHERE source_node=$1")
        .bind(&restricted.node)
        .execute(&pool)
        .await
        .unwrap();
    let service = crate::services::pubsub::PubSubService::new(pool.clone(), "example.test");
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &restricted,
            &victim,
            &[(
                "private-second".to_owned(),
                "<item id='private-second'/>".to_owned(),
            )],
            false,
            1_000_000,
            &service,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE source_node=$1 AND recipient_jid=$2",
        )
        .bind(&restricted.node)
        .bind(&subscriber)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "ancestor subscriber crossed the restricted source-child ACL"
    );
    assert!(matches!(
        set_affiliations_with_renderer(
            &pool,
            restricted.id,
            &victim,
            &[(attacker.clone(), "member".to_owned())],
            None,
            None,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    assert_eq!(
        publish_items_with_renderer(
            &pool,
            &restricted,
            &victim,
            &[(
                "private-authorized".to_owned(),
                "<item id='private-authorized'/>".to_owned(),
            )],
            false,
            1_000_000,
            &service,
        )
        .await
        .unwrap(),
        PublishItemsOutcome::Published
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_event_outbox
                  WHERE source_node=$1 AND recipient_jid=$2",
        )
        .bind(&restricted.node)
        .bind(&subscriber)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1,
        "authorized ancestor subscriber did not receive the child event"
    );
    assert_eq!(
        collection_visible_items(&pool, collection.id, &attacker, 100, 4 * 1_048_576)
            .await
            .unwrap()
            .len(),
        3
    );

    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn collection_edge_insert_linearizes_after_child_owner_revocation() {
    let (url, pool) = integration_pool(12).await;
    let suffix = Uuid::new_v4().simple().to_string();
    let attacker = format!("edge-race-attacker-{suffix}@example.test");
    let remaining_owner = format!("edge-race-owner-{suffix}@example.test");
    let child =
        create_default_test_node(&pool, &format!("edge-race-child-{suffix}"), &attacker).await;
    assert!(matches!(
        set_affiliations_with_renderer(
            &pool,
            child.id,
            &attacker,
            &[(remaining_owner.clone(), "owner".to_owned())],
            None,
            None,
            &NoopMutationOutboxRenderer,
        )
        .await
        .unwrap(),
        SetAffiliationsOutcome::Updated { .. }
    ));
    let collection_config = PubSubNodeConfig {
        node_type: "collection".to_owned(),
        persist_items: false,
        ..PubSubNodeConfig::default()
    };
    let collection_id = match create_node(
        &pool,
        &format!("edge-race-parent-{suffix}"),
        &attacker,
        &collection_config,
        100,
    )
    .await
    .unwrap()
    {
        CreateNodeOutcome::Created(id) => id,
        other => panic!("unexpected race parent create outcome: {other:?}"),
    };
    let collection = get_node_by_id(&pool, collection_id).await.unwrap().unwrap();

    let mut revocation = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(child.id)
        .execute(&mut *revocation)
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM pubsub_affiliations
              WHERE node_id=$1 AND jid=$2 AND affiliation='owner'",
    )
    .bind(child.id)
    .bind(&attacker)
    .execute(&mut *revocation)
    .await
    .unwrap();

    let application = format!("ps-edge-owner-race-{}", &suffix[..8]);
    let contender_pool = named_single_connection_pool(&url, &application).await;
    let contender = tokio::spawn({
        let contender_pool = contender_pool.clone();
        let collection = collection.clone();
        let child = child.clone();
        let attacker = attacker.clone();
        async move {
            associate_collection_child_with_renderer(
                &contender_pool,
                &collection,
                &child,
                &attacker,
                &NoopMutationOutboxRenderer,
            )
            .await
        }
    });
    wait_for_named_session_lock(&pool, &application).await;
    revocation.commit().await.unwrap();
    assert_eq!(
        contender.await.unwrap().unwrap(),
        CollectionUpdateOutcome::Forbidden
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pubsub_collection_members
                  WHERE collection_node_id=$1 AND child_node_id=$2",
        )
        .bind(collection.id)
        .bind(child.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    contender_pool.close().await;
    pool.close().await;
}
