use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_pubsub_core::{pubsub_subscribe_policy, PubSubSubscribePolicy};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;
use uuid::Uuid;

const PUBSUB_POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);
const COLLECTION_ITEMS_XML_BYTES_MAX: i64 = 4 * 1_048_576;

/// A PubSub/PEP mutation could not enter its bounded database execution
/// window.  Protocol callers deliberately map this retryable condition to
/// XMPP `resource-constraint` instead of keeping a connection actor blocked
/// behind PostgreSQL row/advisory locks.
#[derive(Debug, thiserror::Error)]
#[error("PubSub mutation capacity is temporarily exhausted")]
pub(crate) struct PubSubMutationBusy;

/// Start a network-facing PubSub/PEP mutation with bounded pool and database
/// lock waits.  The process-local admission gate in `PubSubService` runs
/// before this helper; these limits are the cross-process/foreign-transaction
/// safety net and therefore remain transaction-local.
pub(crate) async fn begin_bounded_pubsub_mutation(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>> {
    begin_bounded_pubsub_mutation_with_timeout(pool, PUBSUB_POOL_ACQUIRE_TIMEOUT).await
}

async fn begin_bounded_pubsub_mutation_with_timeout(
    pool: &PgPool,
    admission_timeout: Duration,
) -> Result<Transaction<'static, Postgres>> {
    // Pool acquisition can be cancelled before BEGIN is sent. Once a
    // connection is owned, let BEGIN finish in a separate task so a caller
    // timeout cannot interrupt the wire exchange.
    let deadline = tokio::time::Instant::now() + admission_timeout;
    let connection = tokio::time::timeout_at(deadline, pool.acquire())
        .await
        .map_err(|_| PubSubMutationBusy)??;
    let mut transaction =
        finish_bounded_pubsub_begin(deadline, Transaction::begin(connection, None)).await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

async fn finish_bounded_pubsub_begin(
    deadline: tokio::time::Instant,
    begin: impl std::future::Future<
            Output = std::result::Result<Transaction<'static, Postgres>, sqlx::Error>,
        > + Send
        + 'static,
) -> Result<Transaction<'static, Postgres>> {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (transaction_tx, transaction_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        match begin.await {
            Ok(transaction) => {
                // Keep ownership until the caller confirms that its deadline
                // has not elapsed. A late BEGIN is always explicitly rolled
                // back, including the race at the deadline.
                if ready_tx.send(Ok(())).is_err() || accepted_rx.await.is_err() {
                    let _ = transaction.rollback().await;
                } else if let Err(transaction) = transaction_tx.send(transaction) {
                    let _ = transaction.rollback().await;
                }
            }
            Err(error) => {
                let _ = ready_tx.send(Err(error));
            }
        }
    });
    tokio::time::timeout_at(deadline, ready_rx)
        .await
        .map_err(|_| PubSubMutationBusy)?
        .map_err(|_| PubSubMutationBusy)??;
    // A completed oneshot can win a poll even after the timer deadline when
    // this task was not scheduled promptly. Do not admit that late BEGIN.
    if tokio::time::Instant::now() >= deadline {
        return Err(PubSubMutationBusy.into());
    }
    accepted_tx.send(()).map_err(|_| PubSubMutationBusy)?;
    Ok(transaction_rx.await.map_err(|_| PubSubMutationBusy)?)
}

const EDGE_EXCEEDS_MAX_DEPTH_SQL: &str = "WITH RECURSIVE
    ancestors(id, depth) AS (
        SELECT $1::UUID, 0
        UNION
        SELECT e.collection_node_id, a.depth + 1
          FROM ancestors a
          JOIN pubsub_collection_members e ON e.child_node_id = a.id
         WHERE a.depth < 64
    ),
    descendants(id, depth) AS (
        SELECT $2::UUID, 0
        UNION
        SELECT e.child_node_id, d.depth + 1
          FROM descendants d
          JOIN pubsub_collection_members e ON e.collection_node_id = d.id
         WHERE d.depth < 64
    )
    SELECT COALESCE((SELECT MAX(depth) FROM ancestors), 0)
         + 1
         + COALESCE((SELECT MAX(depth) FROM descendants), 0) > 64";

pub use northstar_pubsub_core::{
    PubSubNode, PubSubNodeConfig, PubSubNodeMetadata, PubSubRootDiscoNode, PubSubRootDiscoPage,
};

#[derive(Debug, Serialize, Clone)]
pub struct PubSubItem {
    pub item_id: String,
    pub publisher_jid: String,
    pub xml_payload: String,
    pub created_at: DateTime<Utc>,
}

/// One item from an ACL-filtered descendant leaf of a collection. The
/// database returns these in `(node ASC, item recency DESC)` order from one
/// statement snapshot so callers cannot accidentally split graph traversal,
/// authorization and payload extraction into a TOCTOU sequence.
#[derive(Debug, Serialize)]
pub struct CollectionVisibleItem {
    pub node: String,
    pub xml_payload: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PubSubSubscription {
    pub node: String,
    pub jid: String,
    pub state: String,
    pub subid: String,
    pub deliver: bool,
    pub digest: bool,
    pub digest_frequency: i32,
    pub expire: Option<DateTime<Utc>>,
    pub include_body: bool,
    pub show_values: Vec<String>,
    pub subscription_type: String,
    pub subscription_depth: Option<i32>,
}

#[derive(Clone, Debug)]
pub struct PubSubSubscriptionOptions {
    pub deliver: bool,
    pub digest: bool,
    pub digest_frequency: i32,
    pub expire: Option<DateTime<Utc>>,
    pub include_body: bool,
    pub show_values: Vec<String>,
    pub subscription_type: String,
    /// `None` is the XEP-0248 value `all`.
    pub subscription_depth: Option<i32>,
}

impl PubSubSubscriptionOptions {
    #[cfg(test)]
    pub fn for_node_type(node_type: &str) -> Self {
        Self {
            deliver: true,
            digest: false,
            digest_frequency: 86_400_000,
            expire: None,
            include_body: false,
            show_values: vec![
                "away".to_owned(),
                "chat".to_owned(),
                "dnd".to_owned(),
                "online".to_owned(),
                "xa".to_owned(),
            ],
            subscription_type: if node_type == "collection" {
                "nodes".to_owned()
            } else {
                "items".to_owned()
            },
            subscription_depth: Some(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionUpdateOutcome {
    Updated,
    NotFound,
    NotAssociated,
    NotCollection,
    Forbidden,
    LimitExceeded,
    DepthExceeded,
    Cycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubConfigOutcome {
    Updated,
    Conflict,
    NotFound,
    InvalidOptions,
    Forbidden,
    LimitExceeded,
    Cycle,
}

#[derive(Clone, Debug)]
pub(crate) struct PubSubNotificationDelivery {
    pub(crate) subscription_node_id: Uuid,
    pub(crate) subscription: PubSubSubscription,
    pub(crate) collection: Option<String>,
}

/// Application-layer XML renderer invoked only after the repository has
/// locked the source node, every ancestor collection and their subscription
/// authority. The returned rows are inserted before the mutation commits.
pub(crate) trait PubSubMutationOutboxRenderer: Sync {
    fn render_create(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        let _ = (node, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_items(
        &self,
        node: &PubSubNode,
        items: &[(String, String)],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        let _ = (node, items, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_purge(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        let _ = (node, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_retract(
        &self,
        node: &PubSubNode,
        item_ids: &[String],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        let _ = (node, item_ids, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_delete(
        &self,
        node: &PubSubNode,
        redirect: Option<&str>,
        audience: &[PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        let _ = (
            node,
            redirect,
            audience,
            nonactive_recipients,
            event_id,
            created_at,
        );
        Ok(Vec::new())
    }

    fn render_configuration(
        &self,
        node: &PubSubNode,
        config: &PubSubNodeConfig,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        let _ = (node, config, audience, event_id, created_at);
        Ok(Vec::new())
    }

    fn render_collection_edge(
        &self,
        source: &PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        let _ = (source, action, target_node, audience, event_id, created_at);
        Ok(Vec::new())
    }

    /// Render one authoritative subscription transition. `notify_recipients`
    /// and `authorization_recipients` are derived under the node lock; the
    /// protocol layer never supplies either list. `last_item` is read in the
    /// same transaction after the new subscription state is visible.
    #[allow(clippy::too_many_arguments)]
    fn render_subscription_transition(
        &self,
        node: &PubSubNode,
        subscription: &PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&PubSubItem>,
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        let _ = (
            node,
            subscription,
            notify_recipients,
            authorization_recipients,
            last_item,
            event_id,
            created_at,
        );
        Ok(Vec::new())
    }

    fn render_affiliation_transition(
        &self,
        node: &PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        let _ = (node, jid, affiliation, event_id, created_at);
        Ok(Vec::new())
    }
}

#[cfg(test)]
struct NoopMutationOutboxRenderer;

#[cfg(test)]
impl PubSubMutationOutboxRenderer for NoopMutationOutboxRenderer {}

#[cfg(test)]
struct FixedMutationOutboxRenderer<'a>(&'a [super::PubSubOutboxInsert]);

#[cfg(test)]
impl PubSubMutationOutboxRenderer for FixedMutationOutboxRenderer<'_> {
    fn render_create(
        &self,
        _: &PubSubNode,
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_items(
        &self,
        _: &PubSubNode,
        _: &[(String, String)],
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_purge(
        &self,
        _: &PubSubNode,
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_retract(
        &self,
        _: &PubSubNode,
        _: &[String],
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_delete(
        &self,
        _: &PubSubNode,
        _: Option<&str>,
        _: &[PubSubNotificationDelivery],
        _: &[String],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_configuration(
        &self,
        _: &PubSubNode,
        _: &PubSubNodeConfig,
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_collection_edge(
        &self,
        _: &PubSubNode,
        _: &str,
        _: &str,
        _: &[PubSubNotificationDelivery],
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_subscription_transition(
        &self,
        _: &PubSubNode,
        _: &PubSubSubscription,
        _: &[String],
        _: &[String],
        _: Option<&PubSubItem>,
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }

    fn render_affiliation_transition(
        &self,
        _: &PubSubNode,
        _: &str,
        _: &str,
        _: Uuid,
        _: DateTime<Utc>,
    ) -> Result<Vec<super::PubSubOutboxInsert>> {
        Ok(self.0.to_vec())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PubSubAffiliation {
    pub node: String,
    pub jid: String,
    pub affiliation: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateNodeOutcome {
    Created(Uuid),
    Conflict,
    QuotaExceeded,
    InvalidOptions,
    Forbidden,
    CollectionLimitExceeded,
    Cycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishItemsOutcome {
    Published,
    Conflict,
    QuotaExceeded,
    Forbidden,
    PreconditionFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetractItemsOutcome {
    Retracted,
    NotFound,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetAffiliationsOutcome {
    Updated {
        /// Active or pending subscriptions cancelled by an `outcast`
        /// affiliation change. The SubID is retained for the mandatory
        /// post-commit state-change notification.
        revoked_subscriptions: Vec<(String, String)>,
        /// Pending subscriptions automatically approved when their bare JID
        /// becomes an owner or publisher (XEP-0060 section 8.7.4).
        approved_subscriptions: Vec<(String, String)>,
    },
    LastOwner,
    NotFound,
    Forbidden,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetSubscriptionsOutcome {
    /// Canonical JID, new state and stable SubID for each actual transition.
    Updated(Vec<(String, String, String)>),
    LimitExceeded,
    InvalidSubid,
    NotFound,
    Forbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerMutationOutcome {
    Applied,
    NotFound,
    Forbidden,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionAuthorizationOutcome {
    Applied,
    NotFound,
    Forbidden,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsubscribeOutcome {
    Unsubscribed,
    NotFound,
    InvalidSubid,
    Forbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionOptionsOutcome {
    Updated,
    NotFound,
    InvalidSubid,
    Forbidden,
}

#[derive(Clone, Debug)]
pub enum SubscribeOutcome {
    Subscribed(PubSubSubscription),
    LimitExceeded,
    NotFound,
    Forbidden,
    ClosedNode,
    PreconditionFailed,
}

fn canonical_bare_jids(values: &[String]) -> Result<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut canonical = Vec::with_capacity(values.len());
    for value in values {
        let jid = crate::jid::canonical_bare_key(value)?;
        if !seen.insert(jid.clone()) {
            anyhow::bail!("PubSub JID list contains canonically equivalent duplicate {jid}");
        }
        canonical.push(jid);
    }
    Ok(canonical)
}

async fn requester_is_owner(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node_id: Uuid,
    requester: &str,
) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM pubsub_affiliations
              WHERE node_id = $1 AND jid = $2 AND affiliation = 'owner'
         )",
    )
    .bind(node_id)
    .bind(requester)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

/// Authorize the child side of a collection edge while holding the child
/// node's authority lock. Every production graph-insertion path calls this
/// helper in the same transaction that inserts the edge. Affiliation changes
/// also lock the node row, so ownership revocation and edge insertion have a
/// single, linearizable order.
async fn requester_owns_locked_collection_child(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    child_node_id: Uuid,
    requester: &str,
) -> Result<Option<bool>> {
    if sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(child_node_id)
        .fetch_optional(&mut **transaction)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    Ok(Some(
        requester_is_owner(transaction, child_node_id, requester).await?,
    ))
}

async fn get_node_by_id_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node_id: Uuid,
) -> Result<Option<PubSubNode>> {
    let row = sqlx::query("SELECT id, node, creator_jid, access_model, publish_model, max_items, title, description, deliver_payloads, notify_delete, notify_retract, persist_items, send_last_published_item, node_type, deliver_notifications, notify_config, notify_sub, language, payload_type, max_payload_size, children_max, children_association_policy, children_association_whitelist, created_at FROM pubsub_nodes WHERE id=$1")
        .bind(node_id)
        .fetch_optional(&mut **transaction)
        .await?;
    Ok(row.as_ref().map(row_to_node))
}

/// Lock source nodes and all ancestor collections in UUID order. Subscription
/// mutations lock their own node row, so this turns the audience query into a
/// linearizable snapshot without introducing a multi-node lock inversion.
async fn lock_notification_authority(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source_node_ids: &[Uuid],
) -> Result<Vec<Uuid>> {
    let ids = sqlx::query_scalar::<_, Uuid>(
        "WITH RECURSIVE authority(id) AS (
             SELECT unnest($1::UUID[])
             UNION
             SELECT e.collection_node_id
               FROM authority a
               JOIN pubsub_collection_members e ON e.child_node_id=a.id
         )
         SELECT DISTINCT id FROM authority ORDER BY id",
    )
    .bind(source_node_ids)
    .fetch_all(&mut **transaction)
    .await?;
    for id in &ids {
        sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
            .bind(id)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(ids)
}

/// Capture one wall-clock instant only after the mutation's authority locks
/// have been obtained. PostgreSQL `NOW()` is the transaction start time and
/// can otherwise be combined with post-wait state into a snapshot that never
/// existed.
async fn locked_event_time(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<DateTime<Utc>> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await?)
}

/// Insert mutation deliveries with the same locked event instant used by the
/// authorization, lease and audience snapshot. The generic outbox repository
/// intentionally defaults `created_at` to insertion time; PubSub mutations
/// need the stronger invariant that state and durable projection share one
/// timestamp even after a lock wait.
async fn enqueue_locked_mutation_outbox(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deliveries: &[super::PubSubOutboxInsert],
    event_time: DateTime<Utc>,
) -> Result<()> {
    if deliveries.is_empty() {
        return Ok(());
    }
    let mut sequences = HashMap::<(String, Uuid), i64>::new();
    for delivery in deliveries {
        let key = (delivery.ordering_key.clone(), delivery.event_id);
        if !sequences.contains_key(&key) {
            let sequence: i64 = sqlx::query_scalar(
                "INSERT INTO pubsub_event_streams(ordering_key,next_sequence) VALUES($1,2)
                 ON CONFLICT(ordering_key) DO UPDATE
                    SET next_sequence=pubsub_event_streams.next_sequence+1,
                        updated_at=clock_timestamp()
                 RETURNING next_sequence-1",
            )
            .bind(&delivery.ordering_key)
            .fetch_one(&mut **transaction)
            .await?;
            sequences.insert(key.clone(), sequence);
        }
        let source = match delivery.source {
            super::PubSubOutboxSource::PubSub => "pubsub",
            super::PubSubOutboxSource::Pep => "pep",
        };
        let delivery_kind = match delivery.delivery_kind {
            super::PubSubOutboxDeliveryKind::PubSubChildren => "pubsub-children",
            super::PubSubOutboxDeliveryKind::PubSubDigest => "pubsub-digest",
            super::PubSubOutboxDeliveryKind::PubSubDirect => "pubsub-direct",
            super::PubSubOutboxDeliveryKind::PepStanza => "pep-stanza",
        };
        let capacity_shard = i16::from(delivery.delivery_id.as_bytes()[0] & 63);
        sqlx::query(
            "INSERT INTO pubsub_event_outbox(
                 delivery_id,event_id,ordering_key,event_sequence,source_kind,source_node,delivery_kind,
                 recipient_jid,target_domain,payload_xml,payload_digest,show_values,
                 subscription_node_id,digest_frequency_ms,
                 security_sensitive,coalesce_key,capacity_shard,created_at,expires_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
        )
        .bind(delivery.delivery_id)
        .bind(delivery.event_id)
        .bind(&delivery.ordering_key)
        .bind(sequences[&key])
        .bind(source)
        .bind(&delivery.source_node)
        .bind(delivery_kind)
        .bind(&delivery.recipient_jid)
        .bind(&delivery.target_domain)
        .bind(&delivery.payload_xml)
        .bind(delivery.payload_digest.as_slice())
        .bind(&delivery.show_values)
        .bind(delivery.subscription_node_id)
        .bind(delivery.digest_frequency_ms)
        .bind(delivery.security_sensitive)
        .bind(&delivery.coalesce_key)
        .bind(capacity_shard)
        .bind(event_time)
        .bind(delivery.expires_at)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn notification_audience_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node: &PubSubNode,
    event_type: &str,
    event_time: DateTime<Utc>,
) -> Result<Vec<PubSubNotificationDelivery>> {
    if !node.deliver_notifications {
        return Ok(Vec::new());
    }
    let direct = sqlx::query("SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id=s.node_id WHERE s.node_id=$1 AND s.state='subscribed' AND (s.expire IS NULL OR s.expire>$2) AND NOT EXISTS (SELECT 1 FROM pubsub_affiliations denied WHERE denied.node_id=s.node_id AND denied.jid=split_part(s.jid, '/', 1) AND denied.affiliation IN ('outcast','publish-only')) ORDER BY s.jid")
        .bind(node.id)
        .bind(event_time)
        .fetch_all(&mut **transaction)
        .await?;
    let mut audience = direct
        .iter()
        .map(row_to_subscription)
        .filter(|subscription| {
            subscription.deliver
                && (node.node_type == "leaf"
                    || event_type == "items"
                    || matches!(subscription.subscription_type.as_str(), "nodes" | "all"))
        })
        .map(|subscription| PubSubNotificationDelivery {
            subscription_node_id: node.id,
            subscription,
            collection: None,
        })
        .collect::<Vec<_>>();
    let ancestors = sqlx::query(
        "WITH RECURSIVE paths(id,node,depth) AS (
             SELECT parent.id,parent.node,1
               FROM pubsub_collection_members e
               JOIN pubsub_nodes parent ON parent.id=e.collection_node_id
              WHERE e.child_node_id=$1
             UNION
             SELECT parent.id,parent.node,a.depth+1
               FROM paths a
               JOIN pubsub_collection_members e ON e.child_node_id=a.id
               JOIN pubsub_nodes parent ON parent.id=e.collection_node_id
              WHERE a.depth<64
         ), ancestors AS (
             SELECT id,node,MIN(depth)::INTEGER AS depth FROM paths GROUP BY id,node
         )
         SELECT a.id AS collection_id,a.node AS collection,a.depth,a.node,
                s.jid,s.state,s.subid,s.deliver,s.digest,s.digest_frequency,
                s.expire,s.include_body,s.show_values,s.subscription_type,
                s.subscription_depth
           FROM ancestors a
           JOIN pubsub_subscriptions s ON s.node_id=a.id
           JOIN pubsub_nodes source ON source.id=$1
          WHERE s.state='subscribed'
            AND (s.expire IS NULL OR s.expire>$2)
            AND NOT EXISTS (
                SELECT 1 FROM pubsub_affiliations denied
                 WHERE denied.node_id=s.node_id
                   AND denied.jid=split_part(s.jid, '/', 1)
                   AND denied.affiliation IN ('outcast','publish-only')
            )
            AND NOT EXISTS (
                SELECT 1 FROM pubsub_affiliations source_denied
                 WHERE source_denied.node_id=source.id
                   AND source_denied.jid=split_part(s.jid, '/', 1)
                   AND source_denied.affiliation='outcast'
            )
            AND (
                source.access_model='open'
                OR EXISTS (
                    SELECT 1 FROM pubsub_affiliations source_allowed
                     WHERE source_allowed.node_id=source.id
                       AND source_allowed.jid=split_part(s.jid, '/', 1)
                       AND source_allowed.affiliation IN ('owner','publisher','member')
                )
                OR EXISTS (
                    SELECT 1 FROM pubsub_subscriptions source_subscription
                     WHERE source_subscription.node_id=source.id
                       AND split_part(source_subscription.jid, '/', 1)=split_part(s.jid, '/', 1)
                       AND source_subscription.state='subscribed'
                       AND (source_subscription.expire IS NULL OR source_subscription.expire>$2)
                )
            )
            AND (s.subscription_depth IS NULL OR s.subscription_depth>=a.depth)
          ORDER BY a.depth,s.jid",
    )
    .bind(node.id)
    .bind(event_time)
    .fetch_all(&mut **transaction)
    .await?;
    audience.extend(ancestors.iter().filter_map(|row| {
        let subscription = row_to_subscription(row);
        let accepts = if event_type == "nodes" {
            matches!(subscription.subscription_type.as_str(), "nodes" | "all")
        } else {
            matches!(subscription.subscription_type.as_str(), "items" | "all")
        };
        (subscription.deliver && accepts).then(|| PubSubNotificationDelivery {
            subscription_node_id: row.get("collection_id"),
            subscription,
            collection: Some(row.get("collection")),
        })
    }));
    Ok(audience)
}

async fn owner_jids_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node_id: Uuid,
) -> Result<Vec<String>> {
    sqlx::query_scalar(
        "SELECT jid FROM pubsub_affiliations
          WHERE node_id=$1 AND affiliation='owner'
          ORDER BY jid",
    )
    .bind(node_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn latest_item_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node_id: Uuid,
) -> Result<Option<PubSubItem>> {
    let row = sqlx::query(
        "SELECT item_id,publisher_jid,xml_payload,created_at
           FROM pubsub_items
          WHERE node_id=$1
          ORDER BY created_at DESC,id DESC
          LIMIT 1",
    )
    .bind(node_id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(|row| PubSubItem {
        item_id: row.get("item_id"),
        publisher_jid: row.get("publisher_jid"),
        xml_payload: row.get("xml_payload"),
        created_at: row.get("created_at"),
    }))
}

fn publish_preconditions_match(expected: &PubSubNode, actual: &PubSubNode) -> bool {
    expected.id == actual.id
        && expected.node == actual.node
        && expected.creator_jid == actual.creator_jid
        && expected.access_model == actual.access_model
        && expected.publish_model == actual.publish_model
        && expected.max_items == actual.max_items
        && expected.deliver_payloads == actual.deliver_payloads
        && expected.persist_items == actual.persist_items
        && expected.node_type == actual.node_type
        && expected.payload_type == actual.payload_type
        && expected.max_payload_size == actual.max_payload_size
}

/// Recheck publication authority after the node and notification authority
/// locks are held. The service precheck only controls error ordering; it does
/// not authorize a mutation against a later node or subscription state.
async fn locked_publish_authorization(
    transaction: &mut Transaction<'_, Postgres>,
    node: &PubSubNode,
    publisher_bare_jid: &str,
    event_time: DateTime<Utc>,
) -> Result<(bool, bool)> {
    let row = sqlx::query(
        "SELECT (SELECT affiliation FROM pubsub_affiliations
                  WHERE node_id=$1 AND jid=$2) AS affiliation,
                EXISTS(SELECT 1 FROM pubsub_subscriptions
                        WHERE node_id=$1
                          AND (jid=$2 OR split_part(jid, '/', 1)=$2)
                          AND state='subscribed'
                          AND (expire IS NULL OR expire>$3)) AS subscribed",
    )
    .bind(node.id)
    .bind(publisher_bare_jid)
    .bind(event_time)
    .fetch_one(&mut **transaction)
    .await?;
    let affiliation = row.try_get::<Option<String>, _>("affiliation")?;
    let affiliation = affiliation
        .as_deref()
        .map(str::parse::<northstar_xep_0060::Affiliation>)
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid stored PubSub affiliation: {error}"))?;
    let publish_model = node
        .publish_model
        .parse::<northstar_xep_0060::PublishModel>()
        .map_err(|error| anyhow::anyhow!("invalid stored PubSub publish model: {error}"))?;
    let access_model = node
        .access_model
        .parse::<northstar_xep_0060::AccessModel>()
        .map_err(|error| anyhow::anyhow!("invalid stored PubSub access model: {error}"))?;
    Ok((
        northstar_xep_0060::can_publish_pure(
            publish_model,
            access_model,
            affiliation,
            row.try_get("subscribed")?,
        ),
        affiliation == Some(northstar_xep_0060::Affiliation::Owner),
    ))
}

async fn edge_exceeds_max_depth(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    parent_id: Uuid,
    child_id: Uuid,
) -> Result<bool> {
    sqlx::query_scalar(EDGE_EXCEEDS_MAX_DEPTH_SQL)
        .bind(parent_id)
        .bind(child_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
pub async fn create_node(
    pool: &PgPool,
    node: &str,
    creator_jid: &str,
    config: &PubSubNodeConfig,
    max_nodes_per_owner: i64,
) -> Result<CreateNodeOutcome> {
    create_node_with_renderer(
        pool,
        node,
        creator_jid,
        config,
        max_nodes_per_owner,
        &NoopMutationOutboxRenderer,
    )
    .await
}

pub async fn create_node_with_renderer(
    pool: &PgPool,
    node: &str,
    creator_jid: &str,
    config: &PubSubNodeConfig,
    max_nodes_per_owner: i64,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<CreateNodeOutcome> {
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let creator_jid = crate::jid::canonical_bare_key(creator_jid)?;
    let association_whitelist = canonical_bare_jids(&config.children_association_whitelist)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&creator_jid)
        .execute(&mut *transaction)
        .await?;
    let node_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pubsub_nodes WHERE node = $1)")
            .bind(node)
            .fetch_one(&mut *transaction)
            .await?;
    if node_exists {
        transaction.rollback().await?;
        return Ok(CreateNodeOutcome::Conflict);
    }
    let node_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_nodes WHERE creator_jid = $1")
            .bind(&creator_jid)
            .fetch_one(&mut *transaction)
            .await?;
    if node_count >= max_nodes_per_owner {
        transaction.rollback().await?;
        return Ok(CreateNodeOutcome::QuotaExceeded);
    }
    if config.node_type == "leaf" && !config.children.is_empty()
        || config.children.len() > config.children_max as usize
        || config
            .collections
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.collections.len()
        || config
            .children
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.children.len()
    {
        transaction.rollback().await?;
        return Ok(CreateNodeOutcome::InvalidOptions);
    }
    let mut parent_ids = Vec::with_capacity(config.collections.len());
    let mut child_ids = Vec::with_capacity(config.children.len());
    if !config.collections.is_empty() || !config.children.is_empty() {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
            .execute(&mut *transaction)
            .await?;
        for parent_name in &config.collections {
            let Some(parent) = sqlx::query("SELECT id, node_type, children_max, children_association_policy, children_association_whitelist FROM pubsub_nodes WHERE node = $1 FOR UPDATE")
                .bind(parent_name)
                .fetch_optional(&mut *transaction)
                .await?
            else {
                transaction.rollback().await?;
                return Ok(CreateNodeOutcome::InvalidOptions);
            };
            if parent.get::<String, _>("node_type") != "collection" {
                transaction.rollback().await?;
                return Ok(CreateNodeOutcome::InvalidOptions);
            }
            let parent_id: Uuid = parent.get("id");
            let owner: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2 AND affiliation = 'owner')")
                .bind(parent_id)
                .bind(&creator_jid)
                .fetch_one(&mut *transaction)
                .await?;
            let policy: String = parent.get("children_association_policy");
            let whitelist: Vec<String> = parent.get("children_association_whitelist");
            if !(owner
                || policy == "all"
                || policy == "whitelist" && whitelist.iter().any(|jid| jid == &creator_jid))
            {
                transaction.rollback().await?;
                return Ok(CreateNodeOutcome::Forbidden);
            }
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pubsub_collection_members WHERE collection_node_id = $1",
            )
            .bind(parent_id)
            .fetch_one(&mut *transaction)
            .await?;
            if count >= parent.get::<i32, _>("children_max") as i64 {
                transaction.rollback().await?;
                return Ok(CreateNodeOutcome::CollectionLimitExceeded);
            }
            parent_ids.push(parent_id);
        }
        for child_name in &config.children {
            let Some(child_id) = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM pubsub_nodes WHERE node = $1 FOR UPDATE",
            )
            .bind(child_name)
            .fetch_optional(&mut *transaction)
            .await?
            else {
                transaction.rollback().await?;
                return Ok(CreateNodeOutcome::InvalidOptions);
            };
            match requester_owns_locked_collection_child(&mut transaction, child_id, &creator_jid)
                .await?
            {
                Some(true) => {}
                Some(false) => {
                    transaction.rollback().await?;
                    return Ok(CreateNodeOutcome::Forbidden);
                }
                None => {
                    transaction.rollback().await?;
                    return Ok(CreateNodeOutcome::InvalidOptions);
                }
            }
            child_ids.push(child_id);
        }
        for parent_id in &parent_ids {
            for child_id in &child_ids {
                let would_cycle: bool = sqlx::query_scalar("WITH RECURSIVE descendants(id) AS (
                        SELECT child_node_id FROM pubsub_collection_members WHERE collection_node_id = $1
                        UNION SELECT e.child_node_id FROM pubsub_collection_members e JOIN descendants d ON e.collection_node_id = d.id
                    ) SELECT $2 = $1 OR EXISTS(SELECT 1 FROM descendants WHERE id = $2)")
                    .bind(child_id)
                    .bind(parent_id)
                    .fetch_one(&mut *transaction)
                    .await?;
                if would_cycle {
                    transaction.rollback().await?;
                    return Ok(CreateNodeOutcome::Cycle);
                }
            }
        }
    }
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO pubsub_nodes (id, node, creator_jid, access_model, publish_model, max_items, title, description, deliver_payloads, notify_delete, notify_retract, persist_items, send_last_published_item, node_type, deliver_notifications, notify_config, notify_sub, language, payload_type, max_payload_size, children_max, children_association_policy, children_association_whitelist) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23) ON CONFLICT (node) DO NOTHING",
    )
    .bind(id)
    .bind(node)
    .bind(&creator_jid)
    .bind(&config.access_model)
    .bind(&config.publish_model)
    .bind(config.max_items)
    .bind(&config.title)
    .bind(&config.description)
    .bind(config.deliver_payloads)
    .bind(config.notify_delete)
    .bind(config.notify_retract)
    .bind(config.persist_items)
    .bind(&config.send_last_published_item)
    .bind(&config.node_type)
    .bind(config.deliver_notifications)
    .bind(config.notify_config)
    .bind(config.notify_sub)
    .bind(&config.language)
    .bind(&config.payload_type)
    .bind(config.max_payload_size)
    .bind(config.children_max)
    .bind(&config.children_association_policy)
    .bind(&association_whitelist)
    .execute(&mut *transaction)
    .await?;
    if inserted.rows_affected() == 0 {
        transaction.rollback().await?;
        return Ok(CreateNodeOutcome::Conflict);
    }

    sqlx::query(
        "INSERT INTO pubsub_affiliations (node_id, jid, affiliation) VALUES ($1, $2, 'owner')",
    )
    .bind(id)
    .bind(&creator_jid)
    .execute(&mut *transaction)
    .await?;
    // The new node is the child for every `collections` edge. Keep this
    // apparently redundant check at the common edge-authorization boundary:
    // it prevents future create-path changes from bypassing child ownership.
    if !parent_ids.is_empty() {
        match requester_owns_locked_collection_child(&mut transaction, id, &creator_jid).await? {
            Some(true) => {}
            Some(false) => {
                transaction.rollback().await?;
                return Ok(CreateNodeOutcome::Forbidden);
            }
            None => {
                transaction.rollback().await?;
                return Ok(CreateNodeOutcome::InvalidOptions);
            }
        }
    }
    for parent_id in &parent_ids {
        if edge_exceeds_max_depth(&mut transaction, *parent_id, id).await? {
            transaction.rollback().await?;
            return Ok(CreateNodeOutcome::InvalidOptions);
        }
        sqlx::query("INSERT INTO pubsub_collection_members (collection_node_id, child_node_id) VALUES ($1, $2)")
            .bind(parent_id)
            .bind(id)
            .execute(&mut *transaction)
            .await?;
    }
    for child_id in &child_ids {
        if edge_exceeds_max_depth(&mut transaction, id, *child_id).await? {
            transaction.rollback().await?;
            return Ok(CreateNodeOutcome::InvalidOptions);
        }
        sqlx::query("INSERT INTO pubsub_collection_members (collection_node_id, child_node_id) VALUES ($1, $2)")
            .bind(id)
            .bind(child_id)
            .execute(&mut *transaction)
            .await?;
    }
    // Snapshot from the newly-created node once. A common ancestor reached
    // through multiple direct parents must receive one create event for its
    // one subscription, not one event per graph path.
    lock_notification_authority(&mut transaction, &[id]).await?;
    let event_time = locked_event_time(&mut transaction).await?;
    sqlx::query("UPDATE pubsub_nodes SET created_at=$2, updated_at=$2 WHERE id=$1")
        .bind(id)
        .bind(event_time)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE pubsub_collection_members SET created_at=$2
          WHERE child_node_id=$1 OR collection_node_id=$1",
    )
    .bind(id)
    .bind(event_time)
    .execute(&mut *transaction)
    .await?;
    let created = get_node_by_id_in_transaction(&mut transaction, id)
        .await?
        .expect("newly created PubSub node disappeared inside its transaction");
    let audience =
        notification_audience_in_transaction(&mut transaction, &created, "nodes", event_time)
            .await?;
    let outbox = renderer.render_create(&created, &audience, Uuid::new_v4(), event_time)?;
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(CreateNodeOutcome::Created(id))
}

pub async fn get_node(pool: &PgPool, node: &str) -> Result<Option<PubSubNode>> {
    let row = sqlx::query("SELECT id, node, creator_jid, access_model, publish_model, max_items, title, description, deliver_payloads, notify_delete, notify_retract, persist_items, send_last_published_item, node_type, deliver_notifications, notify_config, notify_sub, language, payload_type, max_payload_size, children_max, children_association_policy, children_association_whitelist, created_at FROM pubsub_nodes WHERE node = $1")
        .bind(node)
        .fetch_optional(pool)
        .await?;

    Ok(row.map(|row| PubSubNode {
        id: row.get("id"),
        node: row.get("node"),
        creator_jid: row.get("creator_jid"),
        access_model: row.get("access_model"),
        publish_model: row.get("publish_model"),
        max_items: row.get("max_items"),
        title: row.get("title"),
        description: row.get("description"),
        deliver_payloads: row.get("deliver_payloads"),
        notify_delete: row.get("notify_delete"),
        notify_retract: row.get("notify_retract"),
        persist_items: row.get("persist_items"),
        send_last_published_item: row.get("send_last_published_item"),
        node_type: row.get("node_type"),
        deliver_notifications: row.get("deliver_notifications"),
        notify_config: row.get("notify_config"),
        notify_sub: row.get("notify_sub"),
        language: row.get("language"),
        payload_type: row.get("payload_type"),
        max_payload_size: row.get("max_payload_size"),
        children_max: row.get("children_max"),
        children_association_policy: row.get("children_association_policy"),
        children_association_whitelist: row.get("children_association_whitelist"),
        created_at: row.get("created_at"),
    }))
}

#[cfg(test)]
pub async fn get_node_by_id(pool: &PgPool, node_id: Uuid) -> Result<Option<PubSubNode>> {
    let row = sqlx::query("SELECT id, node, creator_jid, access_model, publish_model, max_items, title, description, deliver_payloads, notify_delete, notify_retract, persist_items, send_last_published_item, node_type, deliver_notifications, notify_config, notify_sub, language, payload_type, max_payload_size, children_max, children_association_policy, children_association_whitelist, created_at FROM pubsub_nodes WHERE id = $1")
        .bind(node_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(row_to_node))
}

#[cfg(test)]
pub async fn update_node_config_and_graph(
    pool: &PgPool,
    node: &PubSubNode,
    requester: &str,
    config: &PubSubNodeConfig,
) -> Result<PubSubConfigOutcome> {
    let renderer = crate::services::pubsub::PubSubService::new(pool.clone(), "example.test");
    let mut expected = node.config();
    expected.collections = collection_parents(pool, node.id)
        .await?
        .into_iter()
        .map(|parent| parent.node)
        .collect();
    expected.children = collection_children(pool, node.id)
        .await?
        .into_iter()
        .map(|child| child.node)
        .collect();
    update_node_config_and_graph_with_outbox(pool, node, requester, &expected, config, &renderer)
        .await
}

pub async fn update_node_config_and_graph_with_outbox(
    pool: &PgPool,
    node: &PubSubNode,
    requester: &str,
    expected: &PubSubNodeConfig,
    config: &PubSubNodeConfig,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<PubSubConfigOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let association_whitelist = canonical_bare_jids(&config.children_association_whitelist)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *transaction)
        .await?;
    let current = sqlx::query("SELECT id, node, creator_jid, access_model, publish_model, max_items, title, description, deliver_payloads, notify_delete, notify_retract, persist_items, send_last_published_item, node_type, deliver_notifications, notify_config, notify_sub, language, payload_type, max_payload_size, children_max, children_association_policy, children_association_whitelist, created_at FROM pubsub_nodes WHERE id = $1 FOR UPDATE")
        .bind(node.id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(current) = current else {
        transaction.rollback().await?;
        return Ok(PubSubConfigOutcome::NotFound);
    };
    let current = row_to_node(&current);
    let current_type = current.node_type.clone();
    let requester_is_owner: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2 AND affiliation = 'owner')")
        .bind(node.id)
        .bind(&requester)
        .fetch_one(&mut *transaction)
        .await?;
    if !requester_is_owner {
        transaction.rollback().await?;
        return Ok(PubSubConfigOutcome::Forbidden);
    }
    // This node is the child for every requested `collections` edge. Route
    // that insertion through the same locked child-owner authority used by
    // create and explicit associate operations.
    if !config.collections.is_empty() {
        match requester_owns_locked_collection_child(&mut transaction, node.id, &requester).await? {
            Some(true) => {}
            Some(false) => {
                transaction.rollback().await?;
                return Ok(PubSubConfigOutcome::Forbidden);
            }
            None => {
                transaction.rollback().await?;
                return Ok(PubSubConfigOutcome::NotFound);
            }
        }
    }
    let previous_parents = sqlx::query_scalar::<_, String>(
        "SELECT parent.node
           FROM pubsub_collection_members e
           JOIN pubsub_nodes parent ON parent.id=e.collection_node_id
          WHERE e.child_node_id=$1 ORDER BY parent.node",
    )
    .bind(node.id)
    .fetch_all(&mut *transaction)
    .await?;
    let previous_children = sqlx::query_scalar::<_, String>(
        "SELECT child.node
           FROM pubsub_collection_members e
           JOIN pubsub_nodes child ON child.id=e.child_node_id
          WHERE e.collection_node_id=$1 ORDER BY child.node",
    )
    .bind(node.id)
    .fetch_all(&mut *transaction)
    .await?;
    let mut locked_config = current.config();
    locked_config.collections = previous_parents.clone();
    locked_config.children = previous_children.clone();
    if &locked_config != expected {
        transaction.rollback().await?;
        return Ok(PubSubConfigOutcome::Conflict);
    }
    if current_type == "collection" && config.node_type != "collection"
        || config.node_type == "leaf" && !config.children.is_empty()
    {
        transaction.rollback().await?;
        return Ok(PubSubConfigOutcome::InvalidOptions);
    }
    if config.children.len() > config.children_max as usize {
        transaction.rollback().await?;
        return Ok(PubSubConfigOutcome::LimitExceeded);
    }
    let unique_parents = config
        .collections
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    let unique_children = config
        .children
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    if unique_parents.len() != config.collections.len()
        || unique_children.len() != config.children.len()
    {
        transaction.rollback().await?;
        return Ok(PubSubConfigOutcome::InvalidOptions);
    }
    let previous_parent_set = previous_parents.iter().cloned().collect::<BTreeSet<_>>();
    let next_parent_set = config.collections.iter().cloned().collect::<BTreeSet<_>>();
    let previous_child_set = previous_children.iter().cloned().collect::<BTreeSet<_>>();
    let next_child_set = config.children.iter().cloned().collect::<BTreeSet<_>>();
    let parent_deltas = previous_parent_set
        .symmetric_difference(&next_parent_set)
        .map(|parent| {
            (
                parent.clone(),
                if next_parent_set.contains(parent) {
                    "associate"
                } else {
                    "dissociate"
                },
            )
        })
        .collect::<Vec<_>>();
    let child_deltas = previous_child_set
        .symmetric_difference(&next_child_set)
        .map(|child| {
            (
                child.clone(),
                if next_child_set.contains(child) {
                    "associate"
                } else {
                    "dissociate"
                },
            )
        })
        .collect::<Vec<_>>();

    // Removed edges are notification sources too. Lock both the old and new
    // graph endpoints while the graph advisory lock is held; later audience
    // snapshots therefore cannot race a subscription mutation on either side.
    let graph_node_names = previous_parent_set
        .iter()
        .chain(next_parent_set.iter())
        .chain(previous_child_set.iter())
        .chain(next_child_set.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    for graph_node_name in graph_node_names {
        sqlx::query("SELECT id FROM pubsub_nodes WHERE node=$1 FOR UPDATE")
            .bind(graph_node_name)
            .execute(&mut *transaction)
            .await?;
    }

    let mut parent_ids = Vec::with_capacity(config.collections.len());
    for parent_name in &config.collections {
        let parent = sqlx::query("SELECT id, node_type, children_max, children_association_policy, children_association_whitelist FROM pubsub_nodes WHERE node = $1 FOR UPDATE")
            .bind(parent_name)
            .fetch_optional(&mut *transaction)
            .await?;
        let Some(parent) = parent else {
            transaction.rollback().await?;
            return Ok(PubSubConfigOutcome::NotFound);
        };
        if parent.get::<String, _>("node_type") != "collection" {
            transaction.rollback().await?;
            return Ok(PubSubConfigOutcome::InvalidOptions);
        }
        let parent_id: Uuid = parent.get("id");
        let policy: String = parent.get("children_association_policy");
        let whitelist: Vec<String> = parent.get("children_association_whitelist");
        let parent_owner: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2 AND affiliation = 'owner')")
            .bind(parent_id)
            .bind(&requester)
            .fetch_one(&mut *transaction)
            .await?;
        let edge_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pubsub_collection_members WHERE collection_node_id = $1 AND child_node_id = $2)")
            .bind(parent_id)
            .bind(node.id)
            .fetch_one(&mut *transaction)
            .await?;
        let permitted = edge_exists
            || policy == "all"
            || parent_owner
            || policy == "whitelist" && whitelist.iter().any(|jid| jid == &requester);
        if !permitted {
            transaction.rollback().await?;
            return Ok(PubSubConfigOutcome::Forbidden);
        }
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_collection_members WHERE collection_node_id = $1 AND child_node_id <> $2")
            .bind(parent_id)
            .bind(node.id)
            .fetch_one(&mut *transaction)
            .await?;
        if existing >= parent.get::<i32, _>("children_max") as i64 {
            transaction.rollback().await?;
            return Ok(PubSubConfigOutcome::LimitExceeded);
        }
        parent_ids.push(parent_id);
    }

    let mut child_ids = Vec::with_capacity(config.children.len());
    for child_name in &config.children {
        let Some(child_id) =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE node = $1 FOR UPDATE")
                .bind(child_name)
                .fetch_optional(&mut *transaction)
                .await?
        else {
            transaction.rollback().await?;
            return Ok(PubSubConfigOutcome::NotFound);
        };
        match requester_owns_locked_collection_child(&mut transaction, child_id, &requester).await?
        {
            Some(true) => {}
            Some(false) => {
                transaction.rollback().await?;
                return Ok(PubSubConfigOutcome::Forbidden);
            }
            None => {
                transaction.rollback().await?;
                return Ok(PubSubConfigOutcome::NotFound);
            }
        }
        child_ids.push(child_id);
    }

    let mut notification_sources = vec![node.id];
    for (parent_name, _) in &parent_deltas {
        if let Some(parent_id) =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE node=$1")
                .bind(parent_name)
                .fetch_optional(&mut *transaction)
                .await?
        {
            notification_sources.push(parent_id);
        }
    }
    notification_sources.sort_unstable();
    notification_sources.dedup();
    lock_notification_authority(&mut transaction, &notification_sources).await?;
    let event_time = locked_event_time(&mut transaction).await?;

    sqlx::query(
        "DELETE FROM pubsub_collection_members WHERE child_node_id = $1 OR collection_node_id = $1",
    )
    .bind(node.id)
    .execute(&mut *transaction)
    .await?;
    if current_type == "leaf" && config.node_type == "collection" {
        sqlx::query("DELETE FROM pubsub_items WHERE node_id = $1")
            .bind(node.id)
            .execute(&mut *transaction)
            .await?;
    }
    // Update the node kind before edges are inserted so the database trigger
    // can enforce the parent invariant as a final line of defence.
    sqlx::query("UPDATE pubsub_nodes SET access_model = $2, publish_model = $3, max_items = $4, title = $5, description = $6, deliver_payloads = $7, notify_delete = $8, notify_retract = $9, persist_items = $10, send_last_published_item = $11, node_type = $12, deliver_notifications = $13, notify_config = $14, notify_sub = $15, language = $16, payload_type = $17, max_payload_size = $18, children_max = $19, children_association_policy = $20, children_association_whitelist = $21, updated_at = $22 WHERE id = $1")
        .bind(node.id)
        .bind(&config.access_model)
        .bind(&config.publish_model)
        .bind(config.max_items)
        .bind(&config.title)
        .bind(&config.description)
        .bind(config.deliver_payloads)
        .bind(config.notify_delete)
        .bind(config.notify_retract)
        .bind(config.persist_items)
        .bind(&config.send_last_published_item)
        .bind(&config.node_type)
        .bind(config.deliver_notifications)
        .bind(config.notify_config)
        .bind(config.notify_sub)
        .bind(&config.language)
        .bind(&config.payload_type)
        .bind(config.max_payload_size)
        .bind(config.children_max)
        .bind(&config.children_association_policy)
        .bind(&association_whitelist)
        .bind(event_time)
        .execute(&mut *transaction)
        .await?;
    for parent_id in parent_ids {
        let cycle: bool = sqlx::query_scalar("WITH RECURSIVE descendants(id) AS (
                SELECT child_node_id FROM pubsub_collection_members WHERE collection_node_id = $1
                UNION SELECT e.child_node_id FROM pubsub_collection_members e JOIN descendants d ON e.collection_node_id = d.id
            ) SELECT $2 = $1 OR EXISTS(SELECT 1 FROM descendants WHERE id = $2)")
            .bind(node.id)
            .bind(parent_id)
            .fetch_one(&mut *transaction)
            .await?;
        if cycle {
            transaction.rollback().await?;
            return Ok(PubSubConfigOutcome::Cycle);
        }
        if edge_exceeds_max_depth(&mut transaction, parent_id, node.id).await? {
            transaction.rollback().await?;
            return Ok(PubSubConfigOutcome::InvalidOptions);
        }
        sqlx::query("INSERT INTO pubsub_collection_members (collection_node_id, child_node_id, created_at) VALUES ($1, $2, $3)")
            .bind(parent_id)
            .bind(node.id)
            .bind(event_time)
            .execute(&mut *transaction)
            .await?;
    }
    for child_id in child_ids {
        let cycle: bool = sqlx::query_scalar("WITH RECURSIVE descendants(id) AS (
                SELECT child_node_id FROM pubsub_collection_members WHERE collection_node_id = $1
                UNION SELECT e.child_node_id FROM pubsub_collection_members e JOIN descendants d ON e.collection_node_id = d.id
            ) SELECT $2 = $1 OR EXISTS(SELECT 1 FROM descendants WHERE id = $2)")
            .bind(child_id)
            .bind(node.id)
            .fetch_one(&mut *transaction)
            .await?;
        if cycle {
            transaction.rollback().await?;
            return Ok(PubSubConfigOutcome::Cycle);
        }
        if edge_exceeds_max_depth(&mut transaction, node.id, child_id).await? {
            transaction.rollback().await?;
            return Ok(PubSubConfigOutcome::InvalidOptions);
        }
        sqlx::query("INSERT INTO pubsub_collection_members (collection_node_id, child_node_id, created_at) VALUES ($1, $2, $3)")
            .bind(node.id)
            .bind(child_id)
            .bind(event_time)
            .execute(&mut *transaction)
            .await?;
    }
    if config.persist_items {
        sqlx::query("DELETE FROM pubsub_items WHERE node_id = $1 AND id NOT IN (SELECT id FROM pubsub_items WHERE node_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2)")
            .bind(node.id)
            .bind(config.max_items)
            .execute(&mut *transaction)
            .await?;
    } else {
        sqlx::query("DELETE FROM pubsub_items WHERE node_id = $1")
            .bind(node.id)
            .execute(&mut *transaction)
            .await?;
    }
    let updated = get_node_by_id_in_transaction(&mut transaction, node.id)
        .await?
        .expect("updated PubSub node disappeared inside its locked transaction");
    let mut updated_config = updated.config();
    updated_config.collections = sqlx::query_scalar::<_, String>(
        "SELECT parent.node
           FROM pubsub_collection_members e
           JOIN pubsub_nodes parent ON parent.id=e.collection_node_id
          WHERE e.child_node_id=$1 ORDER BY parent.node",
    )
    .bind(updated.id)
    .fetch_all(&mut *transaction)
    .await?;
    updated_config.children = sqlx::query_scalar::<_, String>(
        "SELECT child.node
           FROM pubsub_collection_members e
           JOIN pubsub_nodes child ON child.id=e.child_node_id
          WHERE e.collection_node_id=$1 ORDER BY child.node",
    )
    .bind(updated.id)
    .fetch_all(&mut *transaction)
    .await?;
    let mut outbox = Vec::new();
    if updated.notify_config {
        let audience =
            notification_audience_in_transaction(&mut transaction, &updated, "nodes", event_time)
                .await?;
        outbox.extend(renderer.render_configuration(
            &updated,
            &updated_config,
            &audience,
            Uuid::new_v4(),
            event_time,
        )?);
    }
    for (parent_name, action) in parent_deltas {
        let Some(parent_id) =
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE node=$1")
                .bind(&parent_name)
                .fetch_optional(&mut *transaction)
                .await?
        else {
            continue;
        };
        let Some(parent) = get_node_by_id_in_transaction(&mut transaction, parent_id).await? else {
            continue;
        };
        let audience =
            notification_audience_in_transaction(&mut transaction, &parent, "nodes", event_time)
                .await?;
        outbox.extend(renderer.render_collection_edge(
            &parent,
            action,
            &updated.node,
            &audience,
            Uuid::new_v4(),
            event_time,
        )?);
    }
    for (child_name, action) in child_deltas {
        let audience =
            notification_audience_in_transaction(&mut transaction, &updated, "nodes", event_time)
                .await?;
        outbox.extend(renderer.render_collection_edge(
            &updated,
            action,
            &child_name,
            &audience,
            Uuid::new_v4(),
            event_time,
        )?);
    }
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(PubSubConfigOutcome::Updated)
}

pub async fn get_node_affiliation(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
) -> Result<Option<String>> {
    let jid = crate::jid::canonical_bare_key(jid)?;
    let row =
        sqlx::query("SELECT affiliation FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2")
            .bind(node_id)
            .bind(jid)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|row| row.get("affiliation")))
}

pub async fn affiliations_for_jid(
    pool: &PgPool,
    jid: &str,
    node: Option<&str>,
) -> Result<Vec<PubSubAffiliation>> {
    let jid = crate::jid::canonical_bare_key(jid)?;
    let rows = sqlx::query("SELECT n.node, a.jid, a.affiliation FROM pubsub_affiliations a JOIN pubsub_nodes n ON n.id = a.node_id WHERE a.jid = $1 AND a.affiliation <> 'none' AND ($2::TEXT IS NULL OR n.node = $2) ORDER BY n.node")
        .bind(jid)
        .bind(node)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .map(|row| PubSubAffiliation {
            node: row.get("node"),
            jid: row.get("jid"),
            affiliation: row.get("affiliation"),
        })
        .collect())
}

pub async fn node_affiliations(pool: &PgPool, node_id: Uuid) -> Result<Vec<PubSubAffiliation>> {
    let rows = sqlx::query("SELECT n.node, a.jid, a.affiliation FROM pubsub_affiliations a JOIN pubsub_nodes n ON n.id = a.node_id WHERE a.node_id = $1 AND a.affiliation <> 'none' ORDER BY a.jid")
        .bind(node_id)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .map(|row| PubSubAffiliation {
            node: row.get("node"),
            jid: row.get("jid"),
            affiliation: row.get("affiliation"),
        })
        .collect())
}

#[cfg(test)]
pub async fn set_affiliations(
    pool: &PgPool,
    node_id: Uuid,
    changes: &[(String, String)],
) -> Result<SetAffiliationsOutcome> {
    let requester: String = sqlx::query_scalar(
        "SELECT jid FROM pubsub_affiliations WHERE node_id = $1 AND affiliation = 'owner' ORDER BY jid LIMIT 1",
    )
    .bind(node_id)
    .fetch_one(pool)
    .await?;
    set_affiliations_with_outbox(pool, node_id, &requester, changes, None, None, &[]).await
}

pub async fn set_affiliations_with_renderer(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    changes: &[(String, String)],
    expected_revoked: Option<&[(String, String)]>,
    expected_approved: Option<&[(String, String)]>,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<SetAffiliationsOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let mut seen = std::collections::BTreeSet::new();
    let changes = changes
        .iter()
        .map(|(jid, affiliation)| {
            let jid = crate::jid::canonical_bare_key(jid)?;
            if !seen.insert(jid.clone()) {
                anyhow::bail!(
                    "PubSub affiliation batch contains canonically equivalent duplicate {jid}"
                );
            }
            Ok((jid, affiliation.as_str()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let node_exists =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id = $1 FOR UPDATE")
            .bind(node_id)
            .fetch_optional(&mut *transaction)
            .await?;
    if node_exists.is_none() {
        transaction.rollback().await?;
        return Ok(SetAffiliationsOutcome::NotFound);
    }
    if !requester_is_owner(&mut transaction, node_id, &requester).await? {
        transaction.rollback().await?;
        return Ok(SetAffiliationsOutcome::Forbidden);
    }
    let node = get_node_by_id_in_transaction(&mut transaction, node_id)
        .await?
        .expect("locked PubSub node disappeared during affiliation update");
    let event_time = locked_event_time(&mut transaction).await?;
    let mut revoked_subscriptions = Vec::new();
    let mut approved_subscriptions = Vec::new();
    let mut revoked_details = Vec::new();
    let mut approved_details = Vec::new();
    let mut affiliation_transitions = Vec::new();
    for (jid, affiliation) in &changes {
        let previous: Option<String> = sqlx::query_scalar(
            "SELECT affiliation FROM pubsub_affiliations WHERE node_id=$1 AND jid=$2",
        )
        .bind(node_id)
        .bind(jid)
        .fetch_optional(&mut *transaction)
        .await?;
        let affected = sqlx::query("SELECT n.node,s.jid,s.state,s.subid,s.deliver,s.digest,s.digest_frequency,s.expire,s.include_body,s.show_values,s.subscription_type,s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id=s.node_id WHERE s.node_id=$1 AND split_part(s.jid, '/', 1)=$2 ORDER BY s.jid FOR UPDATE")
            .bind(node_id)
            .bind(jid)
            .fetch_all(&mut *transaction)
            .await?;
        let affiliation_changed = if *affiliation == "none" {
            previous.as_deref().is_some_and(|value| value != "none")
        } else {
            previous.as_deref() != Some(*affiliation)
        };
        if affiliation_changed {
            if *affiliation == "none" {
                sqlx::query("DELETE FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2")
                    .bind(node_id)
                    .bind(jid)
                    .execute(&mut *transaction)
                    .await?;
            } else {
                sqlx::query("INSERT INTO pubsub_affiliations (node_id, jid, affiliation) VALUES ($1, $2, $3) ON CONFLICT (node_id, jid) DO UPDATE SET affiliation = EXCLUDED.affiliation")
                    .bind(node_id)
                    .bind(jid)
                    .bind(affiliation)
                    .execute(&mut *transaction)
                    .await?;
            }
            affiliation_transitions.push((jid.clone(), (*affiliation).to_owned()));
        }
        if matches!(*affiliation, "outcast" | "publish-only") {
            for subscription in &affected {
                let mut subscription = row_to_subscription(subscription);
                revoked_subscriptions.push((subscription.jid.clone(), subscription.subid.clone()));
                subscription.state = "none".to_owned();
                revoked_details.push(subscription);
            }
            sqlx::query("DELETE FROM pubsub_digest_queue WHERE subscription_node_id = $1 AND split_part(subscriber_jid, '/', 1) = $2")
                .bind(node_id)
                .bind(jid)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id = $1 AND split_part(jid, '/', 1) = $2")
                .bind(node_id)
                .bind(jid)
                .execute(&mut *transaction)
                .await?;
        } else if matches!(*affiliation, "owner" | "publisher") {
            let subscriptions = sqlx::query(
                "UPDATE pubsub_subscriptions
                    SET state='subscribed', updated_at=$3
                  WHERE node_id=$1 AND split_part(jid, '/', 1)=$2 AND state='pending'
                    AND (expire IS NULL OR expire>$3)
                  RETURNING jid, subid",
            )
            .bind(node_id)
            .bind(jid)
            .bind(event_time)
            .fetch_all(&mut *transaction)
            .await?;
            approved_subscriptions.extend(
                subscriptions
                    .iter()
                    .map(|row| (row.get("jid"), row.get("subid"))),
            );
            approved_details.extend(affected.iter().filter_map(|row| {
                let mut subscription = row_to_subscription(row);
                if subscription.state != "pending"
                    || subscription
                        .expire
                        .is_some_and(|expire| expire <= event_time)
                {
                    return None;
                }
                subscription.state = "subscribed".to_owned();
                Some(subscription)
            }));
        }
    }
    let owner_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_affiliations WHERE node_id = $1 AND affiliation = 'owner'",
    )
    .bind(node_id)
    .fetch_one(&mut *transaction)
    .await?;
    if owner_count == 0 {
        transaction.rollback().await?;
        return Ok(SetAffiliationsOutcome::LastOwner);
    }
    if expected_revoked.is_some_and(|expected| expected != revoked_subscriptions)
        || expected_approved.is_some_and(|expected| expected != approved_subscriptions)
    {
        transaction.rollback().await?;
        anyhow::bail!("PubSub affiliation notification snapshot changed concurrently");
    }
    let last_item = if !approved_details.is_empty() && node.send_last_published_item != "never" {
        latest_item_in_transaction(&mut transaction, node.id).await?
    } else {
        None
    };
    let mut outbox = Vec::new();
    for (jid, affiliation) in &affiliation_transitions {
        outbox.extend(renderer.render_affiliation_transition(
            &node,
            jid,
            affiliation,
            Uuid::new_v4(),
            event_time,
        )?);
    }
    for subscription in &revoked_details {
        outbox.extend(renderer.render_subscription_transition(
            &node,
            subscription,
            std::slice::from_ref(&subscription.jid),
            &[],
            None,
            Uuid::new_v4(),
            event_time,
        )?);
    }
    for subscription in &approved_details {
        outbox.extend(renderer.render_subscription_transition(
            &node,
            subscription,
            std::slice::from_ref(&subscription.jid),
            &[],
            last_item.as_ref(),
            Uuid::new_v4(),
            event_time,
        )?);
    }
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(SetAffiliationsOutcome::Updated {
        revoked_subscriptions,
        approved_subscriptions,
    })
}

pub async fn is_subscribed(pool: &PgPool, node_id: Uuid, jid: &str) -> Result<bool> {
    let jid = crate::jid::canonicalize(jid)?;
    let bare = crate::jid::canonical_bare_key(&jid)?;
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pubsub_subscriptions WHERE node_id = $1 AND (jid = $2 OR split_part(jid, '/', 1) = $3) AND state = 'subscribed' AND (expire IS NULL OR expire > NOW()))",
    )
    .bind(node_id)
    .bind(jid)
    .bind(bare)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Read the two mutable inputs to a publish precheck from one statement
/// snapshot. The publication transaction still makes the authoritative
/// decision under its existing locks.
pub(crate) async fn publish_authorization_facts(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
) -> Result<(Option<String>, bool)> {
    let full = crate::jid::canonicalize(requester)?;
    let bare = crate::jid::canonical_bare_key(&full)?;
    let row = sqlx::query(
        "SELECT (SELECT affiliation FROM pubsub_affiliations \
                 WHERE node_id = $1 AND jid = $2) AS affiliation, \
                EXISTS(SELECT 1 FROM pubsub_subscriptions \
                       WHERE node_id = $1 \
                         AND (jid = $3 OR split_part(jid, '/', 1) = $2) \
                         AND state = 'subscribed' \
                         AND (expire IS NULL OR expire > NOW())) AS subscribed",
    )
    .bind(node_id)
    .bind(bare)
    .bind(full)
    .fetch_one(pool)
    .await?;
    Ok((row.try_get("affiliation")?, row.try_get("subscribed")?))
}

pub async fn subscriptions_for_jid(
    pool: &PgPool,
    jid: &str,
    node: Option<&str>,
) -> Result<Vec<PubSubSubscription>> {
    let jid = crate::jid::canonicalize(jid)?;
    let bare = crate::jid::canonical_bare_key(&jid)?;
    let rows = sqlx::query("SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id = s.node_id WHERE split_part(s.jid, '/', 1) = $1 AND ($2::TEXT IS NULL OR n.node = $2) AND (s.expire IS NULL OR s.expire > NOW()) ORDER BY n.node, s.jid")
        .bind(bare)
        .bind(node)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_subscription).collect())
}

/// Stable bounded page for presence-triggered last-item replay. A bare
/// subscription and the exact full-resource subscription are both addressed
/// by that resource; subscriptions to sibling resources are not.
pub async fn subscriptions_addressing_jid_page(
    pool: &PgPool,
    jid: &str,
    after: Option<(&str, &str)>,
    limit: i64,
) -> Result<Vec<PubSubSubscription>> {
    let jid = crate::jid::canonicalize(jid)?;
    let bare = crate::jid::canonical_bare_key(&jid)?;
    let (after_node, after_jid) = after.unzip();
    let rows = sqlx::query("SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id = s.node_id WHERE (s.jid = $1 OR s.jid = $2) AND (s.expire IS NULL OR s.expire > NOW()) AND ($3::TEXT IS NULL OR (n.node, s.jid) > ($3, $4)) ORDER BY n.node, s.jid LIMIT $5")
        .bind(jid)
        .bind(bare)
        .bind(after_node)
        .bind(after_jid)
        .bind(limit.clamp(1, 100))
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_subscription).collect())
}

pub async fn node_subscriptions(pool: &PgPool, node_id: Uuid) -> Result<Vec<PubSubSubscription>> {
    let rows = sqlx::query("SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id = s.node_id WHERE s.node_id = $1 AND (s.expire IS NULL OR s.expire > NOW()) ORDER BY s.jid")
        .bind(node_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_subscription).collect())
}

#[cfg(test)]
pub async fn set_subscription(pool: &PgPool, node_id: Uuid, jid: &str, state: &str) -> Result<()> {
    set_subscription_with_outbox(pool, node_id, jid, state, &[]).await
}

#[cfg(test)]
pub async fn set_subscription_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
    state: &str,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<()> {
    let jid = crate::jid::canonicalize(jid)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("INSERT INTO pubsub_subscriptions (node_id, jid, state, subid) VALUES ($1, $2, $3, $4) ON CONFLICT (node_id, jid) DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()")
        .bind(node_id)
        .bind(jid)
        .bind(state)
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *transaction)
        .await?;
    super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    transaction.commit().await?;
    Ok(())
}

/// Resolve an XEP-0060 `authorize` subscription request.  Owner authority,
/// pending state and SubID are all checked under the same node lock as the
/// state change and durable notification projection.  A stale or replayed
/// form therefore cannot mutate a renewed subscription.
pub async fn resolve_pending_subscription_with_renderer(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    subscriber_jid: &str,
    expected_subid: &str,
    allow: bool,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<SubscriptionAuthorizationOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let subscriber_jid = crate::jid::canonicalize(subscriber_jid)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    if sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id = $1 FOR UPDATE")
        .bind(node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_none()
    {
        transaction.rollback().await?;
        return Ok(SubscriptionAuthorizationOutcome::NotFound);
    }
    if !requester_is_owner(&mut transaction, node_id, &requester).await? {
        transaction.rollback().await?;
        return Ok(SubscriptionAuthorizationOutcome::Forbidden);
    }
    let event_time = locked_event_time(&mut transaction).await?;
    let current = sqlx::query(
        "SELECT n.node,s.jid,s.state,s.subid,s.deliver,s.digest,s.digest_frequency,
                s.expire,s.include_body,s.show_values,s.subscription_type,s.subscription_depth
           FROM pubsub_subscriptions s
           JOIN pubsub_nodes n ON n.id=s.node_id
          WHERE s.node_id = $1 AND s.jid = $2
            AND (s.expire IS NULL OR s.expire > $3)
          FOR UPDATE",
    )
    .bind(node_id)
    .bind(&subscriber_jid)
    .bind(event_time)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(current) = current else {
        transaction.rollback().await?;
        return Ok(SubscriptionAuthorizationOutcome::NotFound);
    };
    let mut subscription = row_to_subscription(&current);
    if subscription.state != "pending" || subscription.subid != expected_subid {
        transaction.rollback().await?;
        return Ok(SubscriptionAuthorizationOutcome::Stale);
    }
    if allow {
        let subscriber_bare = crate::jid::canonical_bare_key(&subscriber_jid)?;
        let prohibited = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM pubsub_affiliations
                 WHERE node_id = $1 AND jid = $2
                   AND affiliation IN ('outcast', 'publish-only')
             )",
        )
        .bind(node_id)
        .bind(subscriber_bare)
        .fetch_one(&mut *transaction)
        .await?;
        if prohibited {
            transaction.rollback().await?;
            return Ok(SubscriptionAuthorizationOutcome::Forbidden);
        }
        sqlx::query(
            "UPDATE pubsub_subscriptions
                SET state = 'subscribed', updated_at = $4
              WHERE node_id = $1 AND jid = $2 AND state = 'pending' AND subid = $3",
        )
        .bind(node_id)
        .bind(&subscriber_jid)
        .bind(expected_subid)
        .bind(event_time)
        .execute(&mut *transaction)
        .await?;
        subscription.state = "subscribed".to_owned();
    } else {
        sqlx::query(
            "DELETE FROM pubsub_digest_queue
              WHERE subscription_node_id = $1
                AND subscriber_jid = $2
                AND source_delivery_id IS NULL",
        )
        .bind(node_id)
        .bind(&subscriber_jid)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM pubsub_subscriptions
              WHERE node_id = $1 AND jid = $2 AND state = 'pending' AND subid = $3",
        )
        .bind(node_id)
        .bind(&subscriber_jid)
        .bind(expected_subid)
        .execute(&mut *transaction)
        .await?;
        subscription.state = "none".to_owned();
    }
    let node = get_node_by_id_in_transaction(&mut transaction, node_id)
        .await?
        .expect("locked PubSub node disappeared during subscription authorization");
    let last_item = if allow && node.send_last_published_item != "never" {
        latest_item_in_transaction(&mut transaction, node.id).await?
    } else {
        None
    };
    let outbox = renderer.render_subscription_transition(
        &node,
        &subscription,
        std::slice::from_ref(&subscriber_jid),
        &[],
        last_item.as_ref(),
        Uuid::new_v4(),
        event_time,
    )?;
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(SubscriptionAuthorizationOutcome::Applied)
}

pub async fn set_subscriptions_with_renderer(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    changes: &[(String, String, Option<String>)],
    expected_transitions: Option<&[(String, String, String)]>,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<SetSubscriptionsOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let mut seen = std::collections::BTreeSet::new();
    let changes = changes
        .iter()
        .map(|(jid, state, expected_subid)| {
            let jid = crate::jid::canonicalize(jid)?;
            if !seen.insert(jid.clone()) {
                anyhow::bail!(
                    "PubSub subscription batch contains canonically equivalent duplicate {jid}"
                );
            }
            Ok((jid, state.as_str(), expected_subid.as_deref()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let node_exists =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id = $1 FOR UPDATE")
            .bind(node_id)
            .fetch_optional(&mut *transaction)
            .await?;
    if node_exists.is_none() {
        transaction.rollback().await?;
        return Ok(SetSubscriptionsOutcome::NotFound);
    }
    if !requester_is_owner(&mut transaction, node_id, &requester).await? {
        transaction.rollback().await?;
        return Ok(SetSubscriptionsOutcome::Forbidden);
    }
    let node = get_node_by_id_in_transaction(&mut transaction, node_id)
        .await?
        .expect("locked PubSub node disappeared during owner subscription update");
    let event_time = locked_event_time(&mut transaction).await?;
    sqlx::query(
        "DELETE FROM pubsub_digest_queue q USING pubsub_subscriptions s WHERE s.node_id = $1 AND s.expire <= $2 AND q.subscription_node_id = s.node_id AND q.subscriber_jid = s.jid AND q.source_delivery_id IS NULL",
    )
    .bind(node_id)
    .bind(event_time)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id = $1 AND expire <= $2")
        .bind(node_id)
        .bind(event_time)
        .execute(&mut *transaction)
        .await?;
    for (jid, state, _) in &changes {
        if *state == "none" {
            continue;
        }
        let bare = crate::jid::canonical_bare_key(jid)?;
        let prohibited: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM pubsub_affiliations
                  WHERE node_id=$1 AND jid=$2
                    AND affiliation IN ('outcast','publish-only')
             )",
        )
        .bind(node_id)
        .bind(bare)
        .fetch_one(&mut *transaction)
        .await?;
        if prohibited {
            transaction.rollback().await?;
            return Ok(SetSubscriptionsOutcome::Forbidden);
        }
    }
    let current_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_subscriptions WHERE node_id = $1")
            .bind(node_id)
            .fetch_one(&mut *transaction)
            .await?;
    let additions = changes
        .iter()
        .filter(|(_, state, _)| *state != "none")
        .count() as i64;
    let changed_jids = changes
        .iter()
        .map(|(jid, _, _)| jid.clone())
        .collect::<Vec<_>>();
    let existing_changed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_subscriptions WHERE node_id = $1 AND jid = ANY($2)",
    )
    .bind(node_id)
    .bind(&changed_jids)
    .fetch_one(&mut *transaction)
    .await?;
    if current_count + additions - existing_changed > 10_000 {
        transaction.rollback().await?;
        return Ok(SetSubscriptionsOutcome::LimitExceeded);
    }
    for (jid, _, expected_subid) in &changes {
        if let Some(expected_subid) = expected_subid {
            let actual: Option<String> = sqlx::query_scalar(
                "SELECT subid FROM pubsub_subscriptions WHERE node_id = $1 AND jid = $2",
            )
            .bind(node_id)
            .bind(jid)
            .fetch_optional(&mut *transaction)
            .await?;
            if actual.as_deref() != Some(*expected_subid) {
                transaction.rollback().await?;
                return Ok(SetSubscriptionsOutcome::InvalidSubid);
            }
        }
    }
    let mut transitions = Vec::with_capacity(changes.len());
    let mut rendered_transitions = Vec::with_capacity(changes.len());
    for (jid, state, _) in &changes {
        if *state == "none" {
            let previous = sqlx::query("SELECT n.node,s.jid,s.state,s.subid,s.deliver,s.digest,s.digest_frequency,s.expire,s.include_body,s.show_values,s.subscription_type,s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id=s.node_id WHERE s.node_id=$1 AND s.jid=$2 FOR UPDATE")
                .bind(node_id)
                .bind(jid)
                .fetch_optional(&mut *transaction)
                .await?;
            let removed: Option<String> = sqlx::query_scalar(
                "DELETE FROM pubsub_subscriptions WHERE node_id = $1 AND jid = $2 RETURNING subid",
            )
            .bind(node_id)
            .bind(jid)
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some(subid) = removed {
                sqlx::query("DELETE FROM pubsub_digest_queue WHERE subscription_node_id = $1 AND subscriber_jid = $2 AND source_delivery_id IS NULL")
                    .bind(node_id)
                    .bind(jid)
                    .execute(&mut *transaction)
                    .await?;
                transitions.push((jid.clone(), (*state).to_owned(), subid));
                if let Some(previous) = previous {
                    let mut subscription = row_to_subscription(&previous);
                    subscription.state = "none".to_owned();
                    rendered_transitions.push(subscription);
                }
            }
        } else {
            let previous = sqlx::query("SELECT n.node,s.jid,s.state,s.subid,s.deliver,s.digest,s.digest_frequency,s.expire,s.include_body,s.show_values,s.subscription_type,s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id=s.node_id WHERE s.node_id=$1 AND s.jid=$2 FOR UPDATE")
                .bind(node_id)
                .bind(jid)
                .fetch_optional(&mut *transaction)
                .await?;
            if previous
                .as_ref()
                .is_some_and(|row| row.get::<String, _>("state") == *state)
            {
                continue;
            }
            let planned_subid = expected_transitions
                .and_then(|expected| expected.iter().find(|(candidate, _, _)| candidate == jid))
                .map(|(_, _, subid)| subid.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            let subid: String = sqlx::query_scalar("INSERT INTO pubsub_subscriptions (node_id, jid, state, subid, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT (node_id, jid) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at RETURNING subid")
                .bind(node_id)
                .bind(jid)
                .bind(state)
                .bind(planned_subid)
                .bind(event_time)
                .fetch_one(&mut *transaction)
                .await?;
            transitions.push((jid.clone(), (*state).to_owned(), subid));
            let row = sqlx::query("SELECT n.node,s.jid,s.state,s.subid,s.deliver,s.digest,s.digest_frequency,s.expire,s.include_body,s.show_values,s.subscription_type,s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id=s.node_id WHERE s.node_id=$1 AND s.jid=$2")
                .bind(node_id)
                .bind(jid)
                .fetch_one(&mut *transaction)
                .await?;
            rendered_transitions.push(row_to_subscription(&row));
        }
    }
    if expected_transitions.is_some_and(|expected| expected != transitions) {
        transaction.rollback().await?;
        return Ok(SetSubscriptionsOutcome::InvalidSubid);
    }
    let needs_last_item = rendered_transitions.iter().any(|subscription| {
        subscription.state == "subscribed" && node.send_last_published_item != "never"
    });
    let last_item = if needs_last_item {
        latest_item_in_transaction(&mut transaction, node.id).await?
    } else {
        None
    };
    let mut outbox = Vec::new();
    for subscription in &rendered_transitions {
        outbox.extend(
            renderer.render_subscription_transition(
                &node,
                subscription,
                std::slice::from_ref(&subscription.jid),
                &[],
                (subscription.state == "subscribed")
                    .then_some(last_item.as_ref())
                    .flatten(),
                Uuid::new_v4(),
                event_time,
            )?,
        );
    }
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(SetSubscriptionsOutcome::Updated(transitions))
}

#[cfg(test)]
pub async fn unsubscribe(pool: &PgPool, node_id: Uuid, jid: &str) -> Result<bool> {
    unsubscribe_with_outbox(pool, node_id, jid, &[]).await
}

#[cfg(test)]
pub async fn unsubscribe_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<bool> {
    let jid = crate::jid::canonicalize(jid)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let deleted = sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id = $1 AND jid = $2")
        .bind(node_id)
        .bind(&jid)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "DELETE FROM pubsub_digest_queue WHERE subscription_node_id = $1 AND subscriber_jid = $2 AND source_delivery_id IS NULL",
    )
    .bind(node_id)
    .bind(&jid)
    .execute(&mut *transaction)
    .await?;
    if deleted.rows_affected() > 0 {
        super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    }
    transaction.commit().await?;
    Ok(deleted.rows_affected() > 0)
}

/// Remove the requester's own subscription with an optimistic SubID fence.
/// The identity check and deletion share the node lock, preventing an old
/// unsubscribe stanza from deleting a concurrently renewed subscription.
pub async fn unsubscribe_checked_with_renderer(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    subscriber_jid: &str,
    expected_subid: &str,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<UnsubscribeOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let subscriber_jid = crate::jid::canonicalize(subscriber_jid)?;
    if crate::jid::canonical_bare_key(&subscriber_jid)? != requester {
        return Ok(UnsubscribeOutcome::Forbidden);
    }
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    if sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id = $1 FOR UPDATE")
        .bind(node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_none()
    {
        transaction.rollback().await?;
        return Ok(UnsubscribeOutcome::NotFound);
    }
    let event_time = locked_event_time(&mut transaction).await?;
    let current = sqlx::query(
        "SELECT n.node,s.jid,s.state,s.subid,s.deliver,s.digest,s.digest_frequency,
                s.expire,s.include_body,s.show_values,s.subscription_type,s.subscription_depth
           FROM pubsub_subscriptions s
           JOIN pubsub_nodes n ON n.id=s.node_id
          WHERE s.node_id = $1 AND s.jid = $2
            AND (s.expire IS NULL OR s.expire > $3)
          FOR UPDATE",
    )
    .bind(node_id)
    .bind(&subscriber_jid)
    .bind(event_time)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(current) = current else {
        transaction.rollback().await?;
        return Ok(UnsubscribeOutcome::NotFound);
    };
    let mut subscription = row_to_subscription(&current);
    if subscription.subid != expected_subid {
        transaction.rollback().await?;
        return Ok(UnsubscribeOutcome::InvalidSubid);
    }
    sqlx::query(
        "DELETE FROM pubsub_digest_queue
          WHERE subscription_node_id = $1
            AND subscriber_jid = $2
            AND source_delivery_id IS NULL",
    )
    .bind(node_id)
    .bind(&subscriber_jid)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "DELETE FROM pubsub_subscriptions
          WHERE node_id = $1 AND jid = $2 AND subid = $3",
    )
    .bind(node_id)
    .bind(&subscriber_jid)
    .bind(expected_subid)
    .execute(&mut *transaction)
    .await?;
    let node = get_node_by_id_in_transaction(&mut transaction, node_id)
        .await?
        .expect("locked PubSub node disappeared during unsubscribe");
    subscription.state = "none".to_owned();
    let owners = if node.notify_sub {
        owner_jids_in_transaction(&mut transaction, node.id).await?
    } else {
        Vec::new()
    };
    let outbox = renderer.render_subscription_transition(
        &node,
        &subscription,
        &owners,
        &[],
        None,
        Uuid::new_v4(),
        event_time,
    )?;
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(UnsubscribeOutcome::Unsubscribed)
}

pub async fn get_subscription(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
) -> Result<Option<PubSubSubscription>> {
    let jid = crate::jid::canonicalize(jid)?;
    let row = sqlx::query("SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id = s.node_id WHERE s.node_id = $1 AND s.jid = $2")
        .bind(node_id)
        .bind(jid)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(row_to_subscription))
}

#[cfg(test)]
pub async fn set_subscription_limited(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
    state: &str,
    max_subscriptions: i64,
) -> Result<bool> {
    Ok(
        set_subscription_limited_with_options(pool, node_id, jid, state, max_subscriptions, None)
            .await?
            .is_some(),
    )
}

/// Creates/renews a subscription and applies its options in one transaction.
/// Invalid options are parsed by the protocol layer before entering here, so a
/// failed subscribe-and-configure request can never leave a default-configured
/// subscription behind.
#[cfg(test)]
pub async fn set_subscription_limited_with_options(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
    state: &str,
    max_subscriptions: i64,
    options: Option<&PubSubSubscriptionOptions>,
) -> Result<Option<PubSubSubscription>> {
    let node = get_node_by_id(pool, node_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("PubSub test node does not exist"))?;
    let requester = crate::jid::canonical_bare_key(jid)?;
    Ok(
        match set_subscription_limited_with_options_and_outbox(
            pool,
            node_id,
            &requester,
            jid,
            state,
            &node.node_type,
            &node.access_model,
            max_subscriptions,
            options,
            &Uuid::new_v4().to_string(),
            &[],
        )
        .await?
        {
            SubscribeOutcome::Subscribed(subscription) => Some(subscription),
            SubscribeOutcome::LimitExceeded => None,
            other => anyhow::bail!("unexpected PubSub test subscription outcome: {other:?}"),
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn set_subscription_limited_with_options_and_renderer(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    jid: &str,
    state: &str,
    expected_node_type: &str,
    expected_access_model: &str,
    max_subscriptions: i64,
    options: Option<&PubSubSubscriptionOptions>,
    requested_subid: &str,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<SubscribeOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let jid = crate::jid::canonicalize(jid)?;
    let bare = crate::jid::canonical_bare_key(&jid)?;
    if bare != requester {
        return Ok(SubscribeOutcome::Forbidden);
    }
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let current_node = sqlx::query("SELECT id FROM pubsub_nodes WHERE id=$1 FOR UPDATE")
        .bind(node_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(_) = current_node else {
        transaction.rollback().await?;
        return Ok(SubscribeOutcome::NotFound);
    };
    let Some(node) = get_node_by_id_in_transaction(&mut transaction, node_id).await? else {
        transaction.rollback().await?;
        return Ok(SubscribeOutcome::NotFound);
    };
    if node.node_type != expected_node_type || node.access_model != expected_access_model {
        transaction.rollback().await?;
        return Ok(SubscribeOutcome::PreconditionFailed);
    }
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2",
    )
    .bind(node_id)
    .bind(&requester)
    .fetch_optional(&mut *transaction)
    .await?;
    let authorized_state = match pubsub_subscribe_policy(&node.access_model, affiliation.as_deref())
    {
        PubSubSubscribePolicy::Subscribed => "subscribed",
        PubSubSubscribePolicy::Pending => "pending",
        PubSubSubscribePolicy::ClosedNode => {
            transaction.rollback().await?;
            return Ok(SubscribeOutcome::ClosedNode);
        }
        PubSubSubscribePolicy::Forbidden => {
            transaction.rollback().await?;
            return Ok(SubscribeOutcome::Forbidden);
        }
    };
    if state != authorized_state {
        transaction.rollback().await?;
        return Ok(SubscribeOutcome::PreconditionFailed);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 2))")
        .bind(&jid)
        .execute(&mut *transaction)
        .await?;
    let event_time = locked_event_time(&mut transaction).await?;
    let existing = sqlx::query(
        "SELECT state, expire FROM pubsub_subscriptions WHERE node_id = $1 AND jid = $2 FOR UPDATE",
    )
    .bind(node_id)
    .bind(&jid)
    .fetch_optional(&mut *transaction)
    .await?;
    let expired = existing.as_ref().is_some_and(|row| {
        row.get::<Option<DateTime<Utc>>, _>("expire")
            .is_some_and(|expiry| expiry <= event_time)
    });
    if existing
        .as_ref()
        .is_some_and(|row| row.get::<String, _>("state") == "pending")
        && !expired
    {
        transaction.rollback().await?;
        return Ok(SubscribeOutcome::PreconditionFailed);
    }
    if expired {
        sqlx::query("DELETE FROM pubsub_digest_queue WHERE subscription_node_id = $1 AND subscriber_jid = $2 AND source_delivery_id IS NULL")
            .bind(node_id)
            .bind(&jid)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM pubsub_subscriptions WHERE node_id = $1 AND jid = $2")
            .bind(node_id)
            .bind(&jid)
            .execute(&mut *transaction)
            .await?;
    }
    let exists = existing.is_some() && !expired;
    let state_changed = !exists
        || existing
            .as_ref()
            .is_none_or(|row| row.get::<String, _>("state") != state);
    if !exists {
        // Expired leases do not consume the per-subscriber quota.  Leaving
        // their rows in place is useful for diagnostics, but must not prevent
        // the entity from subscribing to new nodes forever.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pubsub_subscriptions WHERE split_part(jid, '/', 1) = $1 AND (expire IS NULL OR expire > $2)",
        )
        .bind(&bare)
        .bind(event_time)
        .fetch_one(&mut *transaction)
        .await?;
        if count >= max_subscriptions {
            transaction.rollback().await?;
            return Ok(SubscribeOutcome::LimitExceeded);
        }
    }
    sqlx::query("INSERT INTO pubsub_subscriptions (node_id, jid, state, subid, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT (node_id, jid) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at")
        .bind(node_id)
        .bind(&jid)
        .bind(state)
        .bind(requested_subid)
        .bind(event_time)
        .execute(&mut *transaction)
        .await?;
    if let Some(options) = options {
        sqlx::query("UPDATE pubsub_subscriptions SET deliver = $3, digest = $4, digest_frequency = $5, expire = $6, include_body = $7, show_values = $8, subscription_type = $9, subscription_depth = $10, updated_at = $11 WHERE node_id = $1 AND jid = $2")
            .bind(node_id)
            .bind(&jid)
            .bind(options.deliver)
            .bind(options.digest)
            .bind(options.digest_frequency)
            .bind(options.expire)
            .bind(options.include_body)
            .bind(&options.show_values)
            .bind(&options.subscription_type)
            .bind(options.subscription_depth)
            .bind(event_time)
            .execute(&mut *transaction)
            .await?;
    }
    let row = sqlx::query("SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id = s.node_id WHERE s.node_id = $1 AND s.jid = $2")
        .bind(node_id)
        .bind(&jid)
        .fetch_one(&mut *transaction)
        .await?;
    let subscription = row_to_subscription(&row);
    if subscription.subid != requested_subid && !exists {
        transaction.rollback().await?;
        anyhow::bail!("PubSub subscription identity changed during atomic notification projection");
    }
    if !state_changed {
        transaction.commit().await?;
        return Ok(SubscribeOutcome::Subscribed(subscription));
    }
    let owners = if node.notify_sub || subscription.state == "pending" {
        owner_jids_in_transaction(&mut transaction, node.id).await?
    } else {
        Vec::new()
    };
    let notify_recipients = if node.notify_sub {
        owners.as_slice()
    } else {
        &[]
    };
    let authorization_recipients = if subscription.state == "pending" {
        owners.as_slice()
    } else {
        &[]
    };
    let last_item =
        if subscription.state == "subscribed" && node.send_last_published_item != "never" {
            latest_item_in_transaction(&mut transaction, node.id).await?
        } else {
            None
        };
    let outbox = renderer.render_subscription_transition(
        &node,
        &subscription,
        notify_recipients,
        authorization_recipients,
        last_item.as_ref(),
        Uuid::new_v4(),
        event_time,
    )?;
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(SubscribeOutcome::Subscribed(subscription))
}

pub async fn update_subscription_options_checked(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    subscriber_jid: &str,
    expected_subid: Option<&str>,
    options: &PubSubSubscriptionOptions,
) -> Result<SubscriptionOptionsOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let subscriber_jid = crate::jid::canonicalize(subscriber_jid)?;
    if crate::jid::canonical_bare_key(&subscriber_jid)? != requester {
        return Ok(SubscriptionOptionsOutcome::Forbidden);
    }
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    if sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id = $1 FOR UPDATE")
        .bind(node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_none()
    {
        transaction.rollback().await?;
        return Ok(SubscriptionOptionsOutcome::NotFound);
    }
    let event_time = locked_event_time(&mut transaction).await?;
    let actual_subid: Option<String> = sqlx::query_scalar(
        "SELECT subid
           FROM pubsub_subscriptions
          WHERE node_id = $1 AND jid = $2
            AND (expire IS NULL OR expire > $3)
          FOR UPDATE",
    )
    .bind(node_id)
    .bind(&subscriber_jid)
    .bind(event_time)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(actual_subid) = actual_subid else {
        transaction.rollback().await?;
        return Ok(SubscriptionOptionsOutcome::NotFound);
    };
    if expected_subid.is_some_and(|expected| expected != actual_subid) {
        transaction.rollback().await?;
        return Ok(SubscriptionOptionsOutcome::InvalidSubid);
    }
    let result = sqlx::query("UPDATE pubsub_subscriptions SET deliver = $3, digest = $4, digest_frequency = $5, expire = $6, include_body = $7, show_values = $8, subscription_type = $9, subscription_depth = $10, updated_at = $12 WHERE node_id = $1 AND jid = $2 AND ($11::TEXT IS NULL OR subid = $11)")
        .bind(node_id)
        .bind(&subscriber_jid)
        .bind(options.deliver)
        .bind(options.digest)
        .bind(options.digest_frequency)
        .bind(options.expire)
        .bind(options.include_body)
        .bind(&options.show_values)
        .bind(&options.subscription_type)
        .bind(options.subscription_depth)
        .bind(expected_subid)
        .bind(event_time)
        .execute(&mut *transaction)
        .await?;
    if result.rows_affected() != 1 {
        transaction.rollback().await?;
        return Ok(SubscriptionOptionsOutcome::InvalidSubid);
    }
    transaction.commit().await?;
    Ok(SubscriptionOptionsOutcome::Updated)
}

fn row_to_subscription(row: &sqlx::postgres::PgRow) -> PubSubSubscription {
    PubSubSubscription {
        node: row.get("node"),
        jid: row.get("jid"),
        state: row.get("state"),
        subid: row.get("subid"),
        deliver: row.get("deliver"),
        digest: row.get("digest"),
        digest_frequency: row.get("digest_frequency"),
        expire: row.get("expire"),
        include_body: row.get("include_body"),
        show_values: row.get("show_values"),
        subscription_type: row.get("subscription_type"),
        subscription_depth: row.get("subscription_depth"),
    }
}

/// One read-only statement keeps the metadata fields on the same snapshot.
/// The caller must already have authorized discovery of this node.
pub async fn node_metadata(pool: &PgPool, node_id: Uuid) -> Result<PubSubNodeMetadata> {
    let row = sqlx::query(
        "SELECT ARRAY(
             SELECT jid FROM pubsub_affiliations
              WHERE node_id=$1 AND affiliation='owner' ORDER BY jid
         ) AS owners,
         ARRAY(
             SELECT jid FROM pubsub_affiliations
              WHERE node_id=$1 AND affiliation IN ('publisher','publish-only') ORDER BY jid
         ) AS publishers,
         (SELECT COUNT(*) FROM pubsub_subscriptions
           WHERE node_id=$1 AND state='subscribed'
             AND (expire IS NULL OR expire>NOW())) AS active_subscribers",
    )
    .bind(node_id)
    .fetch_one(pool)
    .await?;
    Ok(PubSubNodeMetadata {
        owners: row.get("owners"),
        publishers: row.get("publishers"),
        active_subscribers: row.get("active_subscribers"),
    })
}

#[cfg(test)]
pub async fn publish_items(
    pool: &PgPool,
    node: &PubSubNode,
    publisher_jid: &str,
    items: &[(String, String)],
    _can_replace_other_publishers: bool,
    max_storage_bytes_per_owner: i64,
) -> Result<PublishItemsOutcome> {
    struct EmptyRenderer;
    impl PubSubMutationOutboxRenderer for EmptyRenderer {
        fn render_items(
            &self,
            _node: &PubSubNode,
            _items: &[(String, String)],
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_purge(
            &self,
            _node: &PubSubNode,
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_delete(
            &self,
            _node: &PubSubNode,
            _redirect: Option<&str>,
            _audience: &[PubSubNotificationDelivery],
            _nonactive_recipients: &[String],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_configuration(
            &self,
            _node: &PubSubNode,
            _config: &PubSubNodeConfig,
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_collection_edge(
            &self,
            _source: &PubSubNode,
            _action: &str,
            _target_node: &str,
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }
    }
    publish_items_with_renderer(
        pool,
        node,
        publisher_jid,
        items,
        _can_replace_other_publishers,
        max_storage_bytes_per_owner,
        &EmptyRenderer,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn publish_items_with_renderer(
    pool: &PgPool,
    node: &PubSubNode,
    publisher_jid: &str,
    items: &[(String, String)],
    _can_replace_other_publishers: bool,
    max_storage_bytes_per_owner: i64,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<PublishItemsOutcome> {
    let publisher_jid = crate::jid::canonical_bare_key(publisher_jid)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1))")
        .bind(&node.creator_jid)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *transaction)
        .await?;
    // Subscription, collection and configuration mutations all lock their
    // affected node row before changing authorization. Locking the source and
    // every ancestor first makes the audience and item mutation one
    // linearizable event-time snapshot.
    lock_notification_authority(&mut transaction, &[node.id]).await?;
    let event_time = locked_event_time(&mut transaction).await?;
    let Some(fresh) = get_node_by_id_in_transaction(&mut transaction, node.id).await? else {
        transaction.rollback().await?;
        return Ok(PublishItemsOutcome::Conflict);
    };
    if !publish_preconditions_match(node, &fresh) {
        transaction.rollback().await?;
        return Ok(PublishItemsOutcome::PreconditionFailed);
    }
    let (authorized, _) =
        locked_publish_authorization(&mut transaction, &fresh, &publisher_jid, event_time).await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(PublishItemsOutcome::Forbidden);
    }
    let audience =
        notification_audience_in_transaction(&mut transaction, &fresh, "items", event_time).await?;
    let outbox = renderer.render_items(&fresh, items, &audience, Uuid::new_v4(), event_time)?;
    if !fresh.persist_items {
        enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
        transaction.commit().await?;
        return Ok(PublishItemsOutcome::Published);
    }
    // `clock_timestamp()` is shared by the whole locked mutation so that the
    // outbox and authorization snapshot have one event instant. Item history
    // additionally needs a stable per-node order when one publish contains
    // several items. Advance from the newest retained timestamp while the
    // node lock is held; UUID tie-breakers alone would make retention and
    // disco#items order arbitrary for same-batch publications.
    let first_item_time: DateTime<Utc> = sqlx::query_scalar(
        "SELECT GREATEST($2, COALESCE(MAX(created_at) + INTERVAL '1 microsecond', $2))
           FROM pubsub_items WHERE node_id=$1",
    )
    .bind(fresh.id)
    .bind(event_time)
    .fetch_one(&mut *transaction)
    .await?;
    for (ordinal, (item_id, xml_payload)) in items.iter().enumerate() {
        let item_time = first_item_time + chrono::Duration::microseconds(ordinal as i64);
        // XEP-0060 section 12.9 requires an authorized publisher to overwrite
        // an existing NodeID+ItemID rather than rejecting the publication.
        // Node-level authorization has already happened at the protocol
        // boundary; item authorship only constrains retraction.
        let result = sqlx::query("INSERT INTO pubsub_items (id, node_id, item_id, publisher_jid, xml_payload, created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (node_id, item_id) DO UPDATE SET publisher_jid = EXCLUDED.publisher_jid, xml_payload = EXCLUDED.xml_payload, created_at = EXCLUDED.created_at")
            .bind(Uuid::new_v4())
            .bind(fresh.id)
            .bind(item_id)
            .bind(&publisher_jid)
            .bind(xml_payload)
            .bind(item_time)
            .execute(&mut *transaction)
            .await?;
        if result.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(PublishItemsOutcome::Conflict);
        }
    }
    sqlx::query(
        "DELETE FROM pubsub_items WHERE node_id = $1 AND id NOT IN (SELECT id FROM pubsub_items WHERE node_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2)",
    )
    .bind(fresh.id)
    .bind(fresh.max_items)
    .execute(&mut *transaction)
    .await?;
    let stored_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(i.xml_payload)), 0)::BIGINT FROM pubsub_items i JOIN pubsub_nodes n ON n.id = i.node_id WHERE n.creator_jid = $1",
    )
    .bind(&fresh.creator_jid)
    .fetch_one(&mut *transaction)
    .await?;
    if stored_bytes > max_storage_bytes_per_owner {
        transaction.rollback().await?;
        return Ok(PublishItemsOutcome::QuotaExceeded);
    }
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(PublishItemsOutcome::Published)
}

pub async fn get_items(
    pool: &PgPool,
    node_id: Uuid,
    item_ids: &[String],
    limit: i64,
) -> Result<Vec<PubSubItem>> {
    let rows = if item_ids.is_empty() {
        sqlx::query("SELECT item_id, publisher_jid, xml_payload, created_at FROM pubsub_items WHERE node_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2")
            .bind(node_id)
            .bind(limit.clamp(1, 1_000))
            .fetch_all(pool)
            .await?
    } else {
        sqlx::query("SELECT item_id, publisher_jid, xml_payload, created_at FROM pubsub_items WHERE node_id = $1 AND item_id = ANY($2) ORDER BY created_at DESC, id DESC LIMIT $3")
            .bind(node_id)
            .bind(item_ids)
            .bind(limit.clamp(1, 1_000))
            .fetch_all(pool)
            .await?
    };

    Ok(rows
        .iter()
        .map(|row| PubSubItem {
            item_id: row.get("item_id"),
            publisher_jid: row.get("publisher_jid"),
            xml_payload: row.get("xml_payload"),
            created_at: row.get("created_at"),
        })
        .collect())
}

/// Return the complete retained item identity sequence for disco#items.
/// Node configuration caps persistent history at 1,000 items, so this does
/// not need a hidden server-side truncation. Payloads are deliberately absent
/// from the projection to keep discovery from becoming a data disclosure
/// path.
pub async fn item_ids_for_disco(pool: &PgPool, node_id: Uuid) -> Result<Vec<String>> {
    sqlx::query_scalar(
        "SELECT item_id FROM pubsub_items
         WHERE node_id = $1
         ORDER BY created_at DESC, id DESC",
    )
    .bind(node_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

#[cfg(test)]
pub async fn retract_items(
    pool: &PgPool,
    node_id: Uuid,
    item_ids: &[String],
    publisher_jid: &str,
    _can_retract_other_publishers: bool,
) -> Result<RetractItemsOutcome> {
    retract_items_with_renderer(
        pool,
        node_id,
        item_ids,
        publisher_jid,
        false,
        &NoopMutationOutboxRenderer,
    )
    .await
}

pub async fn retract_items_with_renderer(
    pool: &PgPool,
    node_id: Uuid,
    item_ids: &[String],
    publisher_jid: &str,
    force_notification: bool,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<RetractItemsOutcome> {
    let publisher_jid = crate::jid::canonical_bare_key(publisher_jid)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *transaction)
        .await?;
    lock_notification_authority(&mut transaction, &[node_id]).await?;
    let event_time = locked_event_time(&mut transaction).await?;
    let Some(node) = get_node_by_id_in_transaction(&mut transaction, node_id).await? else {
        transaction.rollback().await?;
        return Ok(RetractItemsOutcome::NotFound);
    };
    let (can_publish, can_retract_other_publishers) =
        locked_publish_authorization(&mut transaction, &node, &publisher_jid, event_time).await?;
    if !can_publish {
        transaction.rollback().await?;
        return Ok(RetractItemsOutcome::Forbidden);
    }
    let (existing, authorized): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE publisher_jid = $3 OR $4) FROM pubsub_items WHERE node_id = $1 AND item_id = ANY($2)",
    )
    .bind(node_id)
    .bind(item_ids)
    .bind(publisher_jid)
    .bind(can_retract_other_publishers)
    .fetch_one(&mut *transaction)
    .await?;
    if existing != item_ids.len() as i64 {
        transaction.rollback().await?;
        return Ok(RetractItemsOutcome::NotFound);
    }
    if authorized != item_ids.len() as i64 {
        transaction.rollback().await?;
        return Ok(RetractItemsOutcome::Forbidden);
    }
    let outbox = if node.notify_retract || force_notification {
        let audience =
            notification_audience_in_transaction(&mut transaction, &node, "items", event_time)
                .await?;
        renderer.render_retract(&node, item_ids, &audience, Uuid::new_v4(), event_time)?
    } else {
        Vec::new()
    };
    sqlx::query("DELETE FROM pubsub_items WHERE node_id = $1 AND item_id = ANY($2)")
        .bind(node_id)
        .bind(item_ids)
        .execute(&mut *transaction)
        .await?;
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(RetractItemsOutcome::Retracted)
}

pub async fn purge_node_as_owner_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<OwnerMutationOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *transaction)
        .await?;
    if sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id=$1")
        .bind(node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_none()
    {
        transaction.rollback().await?;
        return Ok(OwnerMutationOutcome::NotFound);
    }
    lock_notification_authority(&mut transaction, &[node_id]).await?;
    let event_time = locked_event_time(&mut transaction).await?;
    let Some(node) = get_node_by_id_in_transaction(&mut transaction, node_id).await? else {
        transaction.rollback().await?;
        return Ok(OwnerMutationOutcome::NotFound);
    };
    if !requester_is_owner(&mut transaction, node_id, &requester).await? {
        transaction.rollback().await?;
        return Ok(OwnerMutationOutcome::Forbidden);
    }
    if node.node_type != "leaf" || !node.persist_items {
        transaction.rollback().await?;
        return Ok(OwnerMutationOutcome::Invalid);
    }
    let audience =
        notification_audience_in_transaction(&mut transaction, &node, "items", event_time).await?;
    let outbox = renderer.render_purge(&node, &audience, Uuid::new_v4(), event_time)?;
    sqlx::query("DELETE FROM pubsub_items WHERE node_id = $1")
        .bind(node_id)
        .execute(&mut *transaction)
        .await?;
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(OwnerMutationOutcome::Applied)
}

#[cfg(test)]
pub async fn delete_node_with_redirect(
    pool: &PgPool,
    node: &PubSubNode,
    redirect: Option<&str>,
) -> Result<bool> {
    struct EmptyRenderer;
    impl PubSubMutationOutboxRenderer for EmptyRenderer {
        fn render_items(
            &self,
            _node: &PubSubNode,
            _items: &[(String, String)],
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_purge(
            &self,
            _node: &PubSubNode,
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_delete(
            &self,
            _node: &PubSubNode,
            _redirect: Option<&str>,
            _audience: &[PubSubNotificationDelivery],
            _nonactive_recipients: &[String],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_configuration(
            &self,
            _node: &PubSubNode,
            _config: &PubSubNodeConfig,
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_collection_edge(
            &self,
            _source: &PubSubNode,
            _action: &str,
            _target_node: &str,
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }
    }
    Ok(matches!(
        delete_node_as_owner_with_redirect_and_outbox(
            pool,
            node.id,
            &node.creator_jid,
            redirect,
            &EmptyRenderer,
        )
        .await?,
        OwnerMutationOutcome::Applied
    ))
}

pub async fn delete_node_as_owner_with_redirect_and_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    redirect: Option<&str>,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<OwnerMutationOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *transaction)
        .await?;
    if sqlx::query_scalar::<_, Uuid>("SELECT id FROM pubsub_nodes WHERE id=$1")
        .bind(node_id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_none()
    {
        transaction.rollback().await?;
        return Ok(OwnerMutationOutcome::NotFound);
    }
    lock_notification_authority(&mut transaction, &[node_id]).await?;
    let event_time = locked_event_time(&mut transaction).await?;
    let Some(node) = get_node_by_id_in_transaction(&mut transaction, node_id).await? else {
        transaction.rollback().await?;
        return Ok(OwnerMutationOutcome::NotFound);
    };
    if !requester_is_owner(&mut transaction, node.id, &requester).await? {
        transaction.rollback().await?;
        return Ok(OwnerMutationOutcome::Forbidden);
    }
    let audience = if node.notify_delete {
        notification_audience_in_transaction(&mut transaction, &node, "nodes", event_time).await?
    } else {
        Vec::new()
    };
    let nonactive_recipients = if node.notify_delete {
        sqlx::query_scalar::<_, String>(
            "SELECT jid FROM pubsub_subscriptions
              WHERE node_id=$1 AND state<>'subscribed'
                AND (expire IS NULL OR expire>$2)
                AND NOT EXISTS (
                    SELECT 1 FROM pubsub_affiliations denied
                     WHERE denied.node_id=pubsub_subscriptions.node_id
                       AND denied.jid=split_part(pubsub_subscriptions.jid, '/', 1)
                       AND denied.affiliation IN ('outcast','publish-only')
                )
              ORDER BY jid",
        )
        .bind(node.id)
        .bind(event_time)
        .fetch_all(&mut *transaction)
        .await?
    } else {
        Vec::new()
    };
    let outbox = renderer.render_delete(
        &node,
        redirect,
        &audience,
        &nonactive_recipients,
        Uuid::new_v4(),
        event_time,
    )?;
    sqlx::query("DELETE FROM pubsub_nodes WHERE id = $1")
        .bind(node.id)
        .execute(&mut *transaction)
        .await?;
    if let Some(uri) = redirect {
        sqlx::query("INSERT INTO pubsub_node_redirects (node, uri, created_at, expires_at) VALUES ($1, $2, $3, $3 + INTERVAL '30 days') ON CONFLICT (node) DO UPDATE SET uri = EXCLUDED.uri, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at")
            .bind(&node.node)
            .bind(uri)
            .bind(event_time)
            .execute(&mut *transaction)
            .await?;
    } else {
        sqlx::query("DELETE FROM pubsub_node_redirects WHERE node = $1")
            .bind(&node.node)
            .execute(&mut *transaction)
            .await?;
    }
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(OwnerMutationOutcome::Applied)
}

pub async fn node_redirect(pool: &PgPool, node: &str) -> Result<Option<String>> {
    sqlx::query_scalar(
        "SELECT uri FROM pubsub_node_redirects WHERE node = $1 AND expires_at > NOW()",
    )
    .bind(node)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

pub async fn collection_parents(pool: &PgPool, child_id: Uuid) -> Result<Vec<PubSubNode>> {
    let rows = sqlx::query("SELECT n.id, n.node, n.creator_jid, n.access_model, n.publish_model, n.max_items, n.title, n.description, n.deliver_payloads, n.notify_delete, n.notify_retract, n.persist_items, n.send_last_published_item, n.node_type, n.deliver_notifications, n.notify_config, n.notify_sub, n.language, n.payload_type, n.max_payload_size, n.children_max, n.children_association_policy, n.children_association_whitelist, n.created_at FROM pubsub_collection_members e JOIN pubsub_nodes n ON n.id = e.collection_node_id WHERE e.child_node_id = $1 ORDER BY n.node")
        .bind(child_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_node).collect())
}

pub async fn collection_children(pool: &PgPool, collection_id: Uuid) -> Result<Vec<PubSubNode>> {
    let rows = sqlx::query("SELECT n.id, n.node, n.creator_jid, n.access_model, n.publish_model, n.max_items, n.title, n.description, n.deliver_payloads, n.notify_delete, n.notify_retract, n.persist_items, n.send_last_published_item, n.node_type, n.deliver_notifications, n.notify_config, n.notify_sub, n.language, n.payload_type, n.max_payload_size, n.children_max, n.children_association_policy, n.children_association_whitelist, n.created_at FROM pubsub_collection_members e JOIN pubsub_nodes n ON n.id = e.child_node_id WHERE e.collection_node_id = $1 ORDER BY n.node LIMIT 1000")
        .bind(collection_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_node).collect())
}

/// Read a collection's retained descendant items with leaf ACLs applied in
/// the same PostgreSQL statement as graph traversal and item extraction.
/// Legacy or externally-seeded illegal edges therefore cannot expose a
/// restricted child through an otherwise-open parent collection.
pub async fn collection_visible_items(
    pool: &PgPool,
    collection_id: Uuid,
    requester: &str,
    global_item_limit: i64,
    xml_byte_limit: i64,
) -> Result<Vec<CollectionVisibleItem>> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let rows = sqlx::query(
        "WITH RECURSIVE authorized_root(id) AS (
             SELECT root.id
               FROM pubsub_nodes root
              WHERE root.id=$1
                AND root.node_type='collection'
                AND NOT EXISTS (
                    SELECT 1 FROM pubsub_affiliations denied
                     WHERE denied.node_id=root.id
                       AND denied.jid=$2
                       AND denied.affiliation='outcast'
                )
                AND (
                    root.access_model='open'
                    OR EXISTS (
                        SELECT 1 FROM pubsub_affiliations allowed
                         WHERE allowed.node_id=root.id
                           AND allowed.jid=$2
                           AND allowed.affiliation IN ('owner','publisher','member')
                    )
                    OR EXISTS (
                        SELECT 1 FROM pubsub_subscriptions subscription
                         WHERE subscription.node_id=root.id
                           AND split_part(subscription.jid, '/', 1)=$2
                           AND subscription.state='subscribed'
                           AND (subscription.expire IS NULL OR subscription.expire>statement_timestamp())
                    )
                )
         ), descendant_paths(id, depth) AS (
             SELECT edge.child_node_id, 1
               FROM authorized_root root
               JOIN pubsub_collection_members edge ON edge.collection_node_id=root.id
             UNION
             SELECT edge.child_node_id, path.depth+1
               FROM descendant_paths path
               JOIN pubsub_collection_members edge ON edge.collection_node_id=path.id
              WHERE path.depth<64
         ), descendant_ids AS (
             SELECT id, MIN(depth) AS depth
               FROM descendant_paths
              GROUP BY id
         ), visible_leaves AS (
             SELECT node.id,node.node,node.max_items
               FROM descendant_ids descendant
               JOIN pubsub_nodes node ON node.id=descendant.id
              WHERE node.node_type='leaf'
                AND NOT EXISTS (
                    SELECT 1 FROM pubsub_affiliations denied
                     WHERE denied.node_id=node.id
                       AND denied.jid=$2
                       AND denied.affiliation='outcast'
                )
                AND (
                    node.access_model='open'
                    OR EXISTS (
                        SELECT 1 FROM pubsub_affiliations allowed
                         WHERE allowed.node_id=node.id
                           AND allowed.jid=$2
                           AND allowed.affiliation IN ('owner','publisher','member')
                    )
                    OR EXISTS (
                        SELECT 1 FROM pubsub_subscriptions subscription
                         WHERE subscription.node_id=node.id
                           AND split_part(subscription.jid, '/', 1)=$2
                           AND subscription.state='subscribed'
                           AND (subscription.expire IS NULL OR subscription.expire>statement_timestamp())
                    )
                )
              ORDER BY node.node
              LIMIT 100
         ), ranked_per_leaf AS (
             SELECT leaf.id AS node_id,leaf.node,leaf.max_items,
                    item.id AS storage_id,item.item_id,item.xml_payload,item.created_at,
                    ROW_NUMBER() OVER (
                        PARTITION BY leaf.id
                        ORDER BY item.created_at DESC,item.id DESC
                    ) AS leaf_rank
               FROM visible_leaves leaf
               JOIN pubsub_items item ON item.node_id=leaf.id
         ), eligible AS (
             SELECT * FROM ranked_per_leaf
              WHERE leaf_rank<=GREATEST(max_items, 0)
         ), globally_bounded AS (
             SELECT node,item_id,xml_payload,created_at,storage_id,
                    ROW_NUMBER() OVER (
                        ORDER BY node,created_at DESC,storage_id DESC
                    ) AS global_rank,
                    SUM(octet_length(xml_payload)::BIGINT) OVER (
                        ORDER BY node,created_at DESC,storage_id DESC
                        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                    ) AS cumulative_xml_bytes
               FROM eligible
         )
         SELECT node,xml_payload
           FROM globally_bounded
          WHERE global_rank<=$3 AND cumulative_xml_bytes<=$4
          ORDER BY node,created_at DESC,storage_id DESC",
    )
    .bind(collection_id)
    .bind(requester)
    .bind(global_item_limit.clamp(1, 100))
    .bind(xml_byte_limit.clamp(1, COLLECTION_ITEMS_XML_BYTES_MAX))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|row| CollectionVisibleItem {
            node: row.get("node"),
            xml_payload: row.get("xml_payload"),
        })
        .collect())
}

/// Count, cursor admission, page and index share one authorized statement
/// snapshot. A concurrent node or ACL change cannot split their results.
pub async fn root_disco_page(
    pool: &PgPool,
    requester: &str,
    cursor: Option<&str>,
    backwards: bool,
    limit: i64,
) -> Result<PubSubRootDiscoPage> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let order = if backwards { "DESC" } else { "ASC" };
    let comparison = if backwards { "<" } else { ">" };
    let sql = format!(
        "WITH visible AS MATERIALIZED (
             SELECT n.node,n.title
               FROM pubsub_nodes n
              WHERE NOT EXISTS (SELECT 1 FROM pubsub_collection_members e WHERE e.child_node_id=n.id)
                AND NOT EXISTS (SELECT 1 FROM pubsub_affiliations denied WHERE denied.node_id=n.id AND denied.jid=$1 AND denied.affiliation='outcast')
                AND (n.access_model='open'
                     OR EXISTS (SELECT 1 FROM pubsub_affiliations allowed WHERE allowed.node_id=n.id AND allowed.jid=$1 AND allowed.affiliation IN ('owner','publisher','member'))
                     OR EXISTS (SELECT 1 FROM pubsub_subscriptions s WHERE s.node_id=n.id AND split_part(s.jid,'/',1)=$1 AND s.state='subscribed' AND (s.expire IS NULL OR s.expire>NOW())))
             UNION ALL SELECT 'serverinfo',NULL::TEXT
         ), ranked AS MATERIALIZED (
             SELECT node,title,ROW_NUMBER() OVER (ORDER BY node)-1 AS ordinal
               FROM visible
         ), summary AS (
             SELECT COUNT(*) AS total,
                    ($2::TEXT IS NULL OR EXISTS(SELECT 1 FROM ranked WHERE node=$2)) AS cursor_exists
               FROM ranked
         )
         SELECT summary.total,summary.cursor_exists,page.node,page.title,page.ordinal
           FROM summary
           LEFT JOIN LATERAL (
               SELECT node,title,ordinal FROM ranked
                WHERE ($2::TEXT IS NULL OR node {comparison} $2)
                ORDER BY node {order} LIMIT $3
           ) page ON TRUE"
    );
    let rows = sqlx::query(&sql)
        .bind(requester)
        .bind(cursor)
        .bind(limit.clamp(0, 1_000))
        .fetch_all(pool)
        .await?;
    let summary = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("root disco query returned no summary"))?;
    let nodes = rows
        .iter()
        .filter_map(|row| {
            row.get::<Option<String>, _>("node")
                .map(|node| PubSubRootDiscoNode {
                    node,
                    title: row.get("title"),
                    index: row.get("ordinal"),
                })
        })
        .collect();
    Ok(PubSubRootDiscoPage {
        total: summary.get("total"),
        cursor_exists: summary.get("cursor_exists"),
        nodes,
    })
}

#[cfg(test)]
pub async fn associate_collection_child(
    pool: &PgPool,
    collection: &PubSubNode,
    child: &PubSubNode,
    requester: &str,
) -> Result<CollectionUpdateOutcome> {
    associate_collection_child_with_renderer(
        pool,
        collection,
        child,
        requester,
        &NoopMutationOutboxRenderer,
    )
    .await
}

pub async fn associate_collection_child_with_renderer(
    pool: &PgPool,
    collection: &PubSubNode,
    child: &PubSubNode,
    requester: &str,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<CollectionUpdateOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    // Serialize all graph changes so two valid-looking concurrent inserts
    // cannot jointly violate the child quota or create a cycle.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *transaction)
        .await?;
    let Some(fresh) = sqlx::query("SELECT node_type, children_max, children_association_policy, children_association_whitelist FROM pubsub_nodes WHERE id = $1 FOR UPDATE")
        .bind(collection.id)
        .fetch_optional(&mut *transaction)
        .await?
    else {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::NotFound);
    };
    // XEP-0248 association is performed by an owner of the child node. The
    // collection's policy decides whether that child owner may attach to this
    // parent; it must never let an arbitrary third party attach someone
    // else's node merely because the parent uses policy `all`.
    match requester_owns_locked_collection_child(&mut transaction, child.id, &requester).await? {
        Some(true) => {}
        Some(false) => {
            transaction.rollback().await?;
            return Ok(CollectionUpdateOutcome::Forbidden);
        }
        None => {
            transaction.rollback().await?;
            return Ok(CollectionUpdateOutcome::NotFound);
        }
    }
    if fresh.get::<String, _>("node_type") != "collection" {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::NotCollection);
    }
    let edge_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM pubsub_collection_members
              WHERE collection_node_id=$1 AND child_node_id=$2
         )",
    )
    .bind(collection.id)
    .bind(child.id)
    .fetch_one(&mut *transaction)
    .await?;
    if edge_exists {
        transaction.commit().await?;
        return Ok(CollectionUpdateOutcome::Updated);
    }
    let policy: String = fresh.get("children_association_policy");
    let whitelist: Vec<String> = fresh.get("children_association_whitelist");
    let allowed = match policy.as_str() {
        "all" => true,
        "whitelist" => whitelist.iter().any(|jid| jid == &requester),
        _ => false,
    } || sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2 AND affiliation = 'owner')")
            .bind(collection.id)
            .bind(requester)
            .fetch_one(&mut *transaction)
            .await?;
    if !allowed {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::Forbidden);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pubsub_collection_members WHERE collection_node_id = $1",
    )
    .bind(collection.id)
    .fetch_one(&mut *transaction)
    .await?;
    if count >= fresh.get::<i32, _>("children_max") as i64 {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::LimitExceeded);
    }
    let cycle: bool = sqlx::query_scalar(
        "WITH RECURSIVE descendants(id) AS (
             SELECT child_node_id FROM pubsub_collection_members WHERE collection_node_id = $1
             UNION
             SELECT e.child_node_id FROM pubsub_collection_members e JOIN descendants d ON e.collection_node_id = d.id
         ) SELECT $2 = $1 OR EXISTS(SELECT 1 FROM descendants WHERE id = $2)",
    )
    .bind(child.id)
    .bind(collection.id)
    .fetch_one(&mut *transaction)
    .await?;
    if cycle {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::Cycle);
    }
    if edge_exceeds_max_depth(&mut transaction, collection.id, child.id).await? {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::DepthExceeded);
    }
    sqlx::query("INSERT INTO pubsub_collection_members (collection_node_id, child_node_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(collection.id)
        .bind(child.id)
        .execute(&mut *transaction)
        .await?;
    lock_notification_authority(&mut transaction, &[collection.id]).await?;
    let event_time = locked_event_time(&mut transaction).await?;
    sqlx::query(
        "UPDATE pubsub_collection_members SET created_at=$3
          WHERE collection_node_id=$1 AND child_node_id=$2",
    )
    .bind(collection.id)
    .bind(child.id)
    .bind(event_time)
    .execute(&mut *transaction)
    .await?;
    let Some(fresh_collection) =
        get_node_by_id_in_transaction(&mut transaction, collection.id).await?
    else {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::NotFound);
    };
    let Some(fresh_child) = get_node_by_id_in_transaction(&mut transaction, child.id).await? else {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::NotFound);
    };
    let audience = notification_audience_in_transaction(
        &mut transaction,
        &fresh_collection,
        "nodes",
        event_time,
    )
    .await?;
    let outbox = renderer.render_collection_edge(
        &fresh_collection,
        "associate",
        &fresh_child.node,
        &audience,
        Uuid::new_v4(),
        event_time,
    )?;
    enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
    transaction.commit().await?;
    Ok(CollectionUpdateOutcome::Updated)
}

#[cfg(test)]
pub async fn dissociate_collection_child(
    pool: &PgPool,
    collection: &PubSubNode,
    child: &PubSubNode,
    requester: &str,
) -> Result<CollectionUpdateOutcome> {
    dissociate_collection_child_with_renderer(
        pool,
        collection,
        child,
        requester,
        &NoopMutationOutboxRenderer,
    )
    .await
}

pub async fn dissociate_collection_child_with_renderer(
    pool: &PgPool,
    collection: &PubSubNode,
    child: &PubSubNode,
    requester: &str,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<CollectionUpdateOutcome> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('pubsub-collection-graph', 0))")
        .execute(&mut *transaction)
        .await?;
    let nodes = vec![collection.id, child.id];
    let existing = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM pubsub_nodes WHERE id = ANY($1) ORDER BY id FOR UPDATE",
    )
    .bind(&nodes)
    .fetch_all(&mut *transaction)
    .await?;
    if existing.len() != 2 {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::NotFound);
    }
    let owner: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pubsub_affiliations WHERE node_id = ANY($1) AND jid = $2 AND affiliation = 'owner')")
        .bind(&nodes)
        .bind(requester)
        .fetch_one(&mut *transaction)
        .await?;
    if !owner {
        transaction.rollback().await?;
        return Ok(CollectionUpdateOutcome::Forbidden);
    }
    let deleted = sqlx::query("DELETE FROM pubsub_collection_members WHERE collection_node_id = $1 AND child_node_id = $2")
        .bind(collection.id)
        .bind(child.id)
        .execute(&mut *transaction)
        .await?;
    let outcome = if deleted.rows_affected() == 1 {
        lock_notification_authority(&mut transaction, &[collection.id]).await?;
        let event_time = locked_event_time(&mut transaction).await?;
        let Some(fresh_collection) =
            get_node_by_id_in_transaction(&mut transaction, collection.id).await?
        else {
            transaction.rollback().await?;
            return Ok(CollectionUpdateOutcome::NotFound);
        };
        let Some(fresh_child) = get_node_by_id_in_transaction(&mut transaction, child.id).await?
        else {
            transaction.rollback().await?;
            return Ok(CollectionUpdateOutcome::NotFound);
        };
        let audience = notification_audience_in_transaction(
            &mut transaction,
            &fresh_collection,
            "nodes",
            event_time,
        )
        .await?;
        let outbox = renderer.render_collection_edge(
            &fresh_collection,
            "dissociate",
            &fresh_child.node,
            &audience,
            Uuid::new_v4(),
            event_time,
        )?;
        enqueue_locked_mutation_outbox(&mut transaction, &outbox, event_time).await?;
        CollectionUpdateOutcome::Updated
    } else {
        CollectionUpdateOutcome::NotAssociated
    };
    transaction.commit().await?;
    Ok(outcome)
}

fn row_to_node(row: &sqlx::postgres::PgRow) -> PubSubNode {
    PubSubNode {
        id: row.get("id"),
        node: row.get("node"),
        creator_jid: row.get("creator_jid"),
        access_model: row.get("access_model"),
        publish_model: row.get("publish_model"),
        max_items: row.get("max_items"),
        title: row.get("title"),
        description: row.get("description"),
        deliver_payloads: row.get("deliver_payloads"),
        notify_delete: row.get("notify_delete"),
        notify_retract: row.get("notify_retract"),
        persist_items: row.get("persist_items"),
        send_last_published_item: row.get("send_last_published_item"),
        node_type: row.get("node_type"),
        deliver_notifications: row.get("deliver_notifications"),
        notify_config: row.get("notify_config"),
        notify_sub: row.get("notify_sub"),
        language: row.get("language"),
        payload_type: row.get("payload_type"),
        max_payload_size: row.get("max_payload_size"),
        children_max: row.get("children_max"),
        children_association_policy: row.get("children_association_policy"),
        children_association_whitelist: row.get("children_association_whitelist"),
        created_at: row.get("created_at"),
    }
}

#[derive(Debug)]
pub struct DuePubSubDigest {
    pub ids: Vec<Uuid>,
    pub subscription_node_id: Uuid,
    pub subscriber_jid: String,
    pub event_xml: Vec<String>,
    /// `Some` is an immutable event-time subscription snapshot produced by
    /// the notification outbox. `None` denotes a legacy queue row which still
    /// requires the compatibility live-subscription lookup.
    pub show_values: Option<Vec<String>>,
}

pub async fn enqueue_pubsub_digest_snapshot(
    pool: &PgPool,
    source_delivery_id: Uuid,
    node_id: Uuid,
    subscriber_jid: &str,
    event_xml: &str,
    frequency_ms: i32,
    show_values: &[String],
) -> Result<()> {
    if event_xml.is_empty() || event_xml.len() > 4_000_000 {
        anyhow::bail!("PubSub digest event violates the durable queue size bound");
    }
    if show_values.is_empty() || show_values.len() > 8 {
        anyhow::bail!("PubSub digest event has an invalid show-value snapshot");
    }
    let subscriber_jid = crate::jid::canonicalize(subscriber_jid)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 3))")
        .bind(&subscriber_jid)
        .execute(&mut *transaction)
        .await?;
    // The outbox worker may retry after the digest projection committed but
    // before its source row was acknowledged.  Resolve that exact replay
    // before applying capacity limits so a full queue cannot turn a durable,
    // already accepted delivery into an endless retry/dead-letter cycle.
    let already_projected: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pubsub_digest_queue WHERE source_delivery_id=$1)",
    )
    .bind(source_delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    if already_projected {
        transaction.commit().await?;
        return Ok(());
    }
    let (subscriber_count, subscriber_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*),COALESCE(SUM(octet_length(event_xml)),0)::BIGINT
           FROM pubsub_digest_queue WHERE subscriber_jid=$1",
    )
    .bind(&subscriber_jid)
    .fetch_one(&mut *transaction)
    .await?;
    if subscriber_count >= 10_000
        || subscriber_bytes.saturating_add(event_xml.len() as i64) > 64 * 1_048_576
    {
        anyhow::bail!("PubSub digest subscriber queue limit exceeded");
    }
    let (node_count, node_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*),COALESCE(SUM(octet_length(event_xml)),0)::BIGINT
           FROM pubsub_digest_queue
          WHERE subscription_node_id=$1 AND subscriber_jid=$2",
    )
    .bind(node_id)
    .bind(&subscriber_jid)
    .fetch_one(&mut *transaction)
    .await?;
    if node_count >= 1_000 || node_bytes.saturating_add(event_xml.len() as i64) > 16 * 1_048_576 {
        anyhow::bail!("PubSub digest node queue limit exceeded");
    }
    sqlx::query(
        "INSERT INTO pubsub_digest_queue(
             id,subscription_node_id,subscriber_jid,event_xml,deliver_after,
             source_delivery_id,show_values)
         VALUES($1,$2,$3,$4,
                COALESCE((SELECT MIN(deliver_after) FROM pubsub_digest_queue
                           WHERE subscription_node_id=$2 AND subscriber_jid=$3),
                         NOW()+($5::TEXT || ' milliseconds')::INTERVAL),
                $6,$7)
         ON CONFLICT(source_delivery_id) WHERE source_delivery_id IS NOT NULL DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(node_id)
    .bind(&subscriber_jid)
    .bind(event_xml)
    .bind(frequency_ms.clamp(1_000, 86_400_000))
    .bind(source_delivery_id)
    .bind(show_values)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn enqueue_pubsub_digest(
    pool: &PgPool,
    node_id: Uuid,
    subscriber_jid: &str,
    event_xml: &str,
    frequency_ms: i32,
) -> Result<bool> {
    if event_xml.is_empty() || event_xml.len() > 4_000_000 {
        anyhow::bail!("PubSub digest event violates the durable queue size bound");
    }
    let subscriber_jid = crate::jid::canonicalize(subscriber_jid)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    // One subscriber can have many digest-enabled nodes.  Serialize and cap
    // the aggregate as well as each node so an attacker cannot multiply the
    // per-node queue allowance into unbounded database growth.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 3))")
        .bind(&subscriber_jid)
        .execute(&mut *transaction)
        .await?;
    // The notification plan is captured before the publication commits. A
    // concurrent unsubscribe may win afterwards; lock and re-check the live
    // subscription so that race cannot enqueue or immediately deliver a
    // notification after cancellation.
    let eligible: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pubsub_subscriptions WHERE node_id = $1 AND jid = $2 AND state = 'subscribed' AND deliver AND digest AND (expire IS NULL OR expire > NOW()) FOR SHARE)",
    )
    .bind(node_id)
    .bind(&subscriber_jid)
    .fetch_one(&mut *transaction)
    .await?;
    if !eligible {
        transaction.commit().await?;
        // Treat a cancelled/stale plan as consumed. Falling through to direct
        // delivery would violate both cancellation and digest timing.
        return Ok(true);
    }
    let (subscriber_count, subscriber_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(octet_length(event_xml)), 0)::BIGINT FROM pubsub_digest_queue WHERE subscriber_jid = $1",
    )
    .bind(&subscriber_jid)
    .fetch_one(&mut *transaction)
    .await?;
    if subscriber_count >= 10_000
        || subscriber_bytes.saturating_add(event_xml.len() as i64) > 64 * 1_048_576
    {
        transaction.rollback().await?;
        anyhow::bail!("PubSub digest subscriber queue limit exceeded");
    }
    let (count, bytes): (i64, i64) = sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(octet_length(event_xml)), 0)::BIGINT FROM pubsub_digest_queue WHERE subscription_node_id = $1 AND subscriber_jid = $2")
        .bind(node_id)
        .bind(&subscriber_jid)
        .fetch_one(&mut *transaction)
        .await?;
    if count >= 1_000 || bytes.saturating_add(event_xml.len() as i64) > 16 * 1_048_576 {
        transaction.rollback().await?;
        anyhow::bail!("PubSub digest node queue limit exceeded");
    }
    sqlx::query("INSERT INTO pubsub_digest_queue (id, subscription_node_id, subscriber_jid, event_xml, deliver_after) VALUES ($1, $2, $3, $4, COALESCE((SELECT MIN(deliver_after) FROM pubsub_digest_queue WHERE subscription_node_id = $2 AND subscriber_jid = $3), NOW() + ($5::TEXT || ' milliseconds')::INTERVAL))")
        .bind(Uuid::new_v4())
        .bind(node_id)
        .bind(&subscriber_jid)
        .bind(event_xml)
        .bind(frequency_ms.clamp(1_000, 86_400_000))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn claim_due_pubsub_digests(pool: &PgPool, limit: i64) -> Result<Vec<DuePubSubDigest>> {
    // Empty queues do not need a mutation transaction on every one-second
    // worker tick. This is only a scheduling hint: a positive result still
    // enters the original bounded transaction and claims with SKIP LOCKED.
    // Do not cache a negative result; newly due rows are seen next tick.
    // Keep UPDATE revocation and read-only mode visible even without work.
    let (may_update, writable, has_due): (bool, bool, bool) = tokio::time::timeout(
        PUBSUB_POOL_ACQUIRE_TIMEOUT,
        sqlx::query_as(
            "SELECT has_table_privilege('pubsub_digest_queue', 'UPDATE'),
                    current_setting('transaction_read_only') = 'off',
                    EXISTS(SELECT 1 FROM pubsub_digest_queue
                            WHERE deliver_after <= NOW()
                              AND (claimed_until IS NULL OR claimed_until <= NOW()))",
        )
        .fetch_one(pool),
    )
    .await
    .map_err(|_| PubSubMutationBusy)??;
    anyhow::ensure!(
        may_update,
        "PubSub digest queue UPDATE authority is unavailable"
    );
    anyhow::ensure!(
        writable,
        "PubSub digest queue requires a writable transaction"
    );
    if !has_due {
        return Ok(Vec::new());
    }
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let rows = sqlx::query(
        "WITH due AS (
            SELECT id FROM pubsub_digest_queue
             WHERE deliver_after <= NOW()
               AND (claimed_until IS NULL OR claimed_until <= NOW())
             ORDER BY deliver_after, id LIMIT $1 FOR UPDATE SKIP LOCKED
        )
        UPDATE pubsub_digest_queue q
           SET claimed_until = NOW() + INTERVAL '1 minute'
          FROM due WHERE q.id = due.id
        RETURNING q.id,q.subscription_node_id,q.subscriber_jid,q.event_xml,q.show_values",
    )
    .bind(limit.clamp(1, 1000))
    .fetch_all(&mut *transaction)
    .await?;
    let mut grouped = std::collections::BTreeMap::<
        (Uuid, String, Option<Vec<String>>),
        (Vec<Uuid>, Vec<String>),
    >::new();
    for row in &rows {
        let entry = grouped
            .entry((
                row.get("subscription_node_id"),
                row.get("subscriber_jid"),
                row.get("show_values"),
            ))
            .or_default();
        entry.0.push(row.get("id"));
        entry.1.push(row.get("event_xml"));
    }
    transaction.commit().await?;
    Ok(grouped
        .into_iter()
        .map(
            |((subscription_node_id, subscriber_jid, show_values), (ids, event_xml))| {
                DuePubSubDigest {
                    ids,
                    subscription_node_id,
                    subscriber_jid,
                    event_xml,
                    show_values,
                }
            },
        )
        .collect())
}

pub async fn release_pubsub_digests(pool: &PgPool, ids: &[Uuid]) -> Result<()> {
    if !ids.is_empty() {
        sqlx::query("UPDATE pubsub_digest_queue SET claimed_until = NULL WHERE id = ANY($1)")
            .bind(ids)
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub async fn acknowledge_pubsub_digests(pool: &PgPool, ids: &[Uuid]) -> Result<()> {
    if !ids.is_empty() {
        sqlx::query("DELETE FROM pubsub_digest_queue WHERE id = ANY($1)")
            .bind(ids)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Bounded lease garbage collection. Expired subscriptions are already
/// excluded from authorization and delivery; this removes their durable rows
/// (and any stale digest fragments) so one-shot leased subscriptions cannot
/// grow the database forever across restarts.
pub async fn cleanup_expired_subscriptions(pool: &PgPool, limit: i64) -> Result<u64> {
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let limit = limit.clamp(1, 10_000);
    sqlx::query(
        "WITH expired AS (
             SELECT node_id, jid FROM pubsub_subscriptions
              WHERE expire <= NOW()
              ORDER BY expire, node_id, jid
              LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM pubsub_digest_queue q USING expired e
          WHERE q.subscription_node_id = e.node_id AND q.subscriber_jid = e.jid
            AND q.source_delivery_id IS NULL",
    )
    .bind(limit)
    .execute(&mut *transaction)
    .await?;
    let deleted = sqlx::query(
        "WITH expired AS (
             SELECT node_id, jid FROM pubsub_subscriptions
              WHERE expire <= NOW()
              ORDER BY expire, node_id, jid
              LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM pubsub_subscriptions s USING expired e
          WHERE s.node_id = e.node_id AND s.jid = e.jid",
    )
    .bind(limit)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    transaction.commit().await?;
    Ok(deleted)
}

// Compatibility shims for legacy repository-level tests. Production callers
// cannot provide pre-authorized recipients; they must use the renderer APIs.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn set_subscription_limited_with_options_and_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    jid: &str,
    state: &str,
    expected_node_type: &str,
    expected_access_model: &str,
    max_subscriptions: i64,
    options: Option<&PubSubSubscriptionOptions>,
    requested_subid: &str,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<SubscribeOutcome> {
    set_subscription_limited_with_options_and_renderer(
        pool,
        node_id,
        requester,
        jid,
        state,
        expected_node_type,
        expected_access_model,
        max_subscriptions,
        options,
        requested_subid,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}

#[cfg(test)]
async fn unsubscribe_checked_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    subscriber_jid: &str,
    expected_subid: &str,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<UnsubscribeOutcome> {
    unsubscribe_checked_with_renderer(
        pool,
        node_id,
        requester,
        subscriber_jid,
        expected_subid,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}

#[cfg(test)]
async fn resolve_pending_subscription_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    subscriber_jid: &str,
    expected_subid: &str,
    allow: bool,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<SubscriptionAuthorizationOutcome> {
    resolve_pending_subscription_with_renderer(
        pool,
        node_id,
        requester,
        subscriber_jid,
        expected_subid,
        allow,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}

#[cfg(test)]
async fn set_subscriptions_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    changes: &[(String, String, Option<String>)],
    expected_transitions: Option<&[(String, String, String)]>,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<SetSubscriptionsOutcome> {
    set_subscriptions_with_renderer(
        pool,
        node_id,
        requester,
        changes,
        expected_transitions,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}

#[cfg(test)]
async fn set_affiliations_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    changes: &[(String, String)],
    expected_revoked: Option<&[(String, String)]>,
    expected_approved: Option<&[(String, String)]>,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<SetAffiliationsOutcome> {
    set_affiliations_with_renderer(
        pool,
        node_id,
        requester,
        changes,
        expected_revoked,
        expected_approved,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}

#[cfg(test)]
#[path = "pubsub_integration_tests.rs"]
mod integration_tests;
