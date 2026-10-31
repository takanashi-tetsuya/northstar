use super::*;
use crate::db;
use northstar_pubsub_application::{
    service::{CollectionDiscoItems, LeafDiscoItems},
    PubSubCollectionDiscoChild,
};
use northstar_pubsub_core::{PepAudienceSnapshot, PepOutboxFactory};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[path = "pubsub_integration_tests/access_policy_tests.rs"]
mod access_policy;
#[path = "pubsub_integration_tests/audience_tests.rs"]
mod audience;
#[path = "pubsub_integration_tests/bookmark_tests.rs"]
mod bookmarks;
#[path = "pubsub_integration_tests/collection_graph_tests.rs"]
mod collection_graph;
#[path = "pubsub_integration_tests/digest_lease_tests.rs"]
mod digest_lease;
#[path = "pubsub_integration_tests/mutation_transaction_tests.rs"]
mod mutation_transaction;
#[path = "pubsub_integration_tests/read_only_disco_tests.rs"]
mod read_only_disco;
#[path = "pubsub_integration_tests/subscription_lock_wait_tests.rs"]
mod subscription_lock_wait;

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
    inner: northstar_pubsub_application::PubSubService<
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

async fn subscribe_for_race(
    pool: &PgPool,
    node: &PubSubNode,
    subscriber: &str,
    subid: &str,
) -> PubSubSubscription {
    let requester = northstar_xmpp_types::jid::canonical_bare_key(subscriber).unwrap();
    match set_subscription_limited_with_options_and_outbox(
        pool,
        "example.test",
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
