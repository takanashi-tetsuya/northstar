use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_pubsub_application::{PubSubOwnerRead, PubSubOwnerReadKind};
use northstar_pubsub_core::{pubsub_subscribe_policy, PubSubSubscribePolicy};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;
use uuid::Uuid;

mod affiliation;
mod collection;
mod digest;
mod disco;
mod item;
mod node;
mod subscription;

pub use self::affiliation::*;
pub use self::collection::*;
pub use self::digest::*;
pub use self::disco::*;
pub use self::item::*;
pub use self::node::*;
pub use self::subscription::*;

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

fn row_to_affiliation(row: &sqlx::postgres::PgRow) -> PubSubAffiliation {
    PubSubAffiliation {
        node: row.get("node"),
        jid: row.get("jid"),
        affiliation: row.get("affiliation"),
    }
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
    InvalidOptions,
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
    InvalidOptions,
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

// Compatibility shims for legacy repository-level tests. Production callers
// cannot provide pre-authorized recipients; they must use the renderer APIs.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn set_subscription_limited_with_options_and_outbox(
    pool: &PgPool,
    local_domain: &str,
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
        local_domain,
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
