use anyhow::Result;
use chrono::{DateTime, Utc};
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
    let mut transaction = tokio::time::timeout(PUBSUB_POOL_ACQUIRE_TIMEOUT, pool.begin())
        .await
        .map_err(|_| PubSubMutationBusy)??;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
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

#[derive(Clone, Debug, Serialize)]
pub struct PubSubNode {
    pub id: Uuid,
    pub node: String,
    pub creator_jid: String,
    pub access_model: String,
    pub publish_model: String,
    pub max_items: i32,
    pub title: Option<String>,
    pub description: Option<String>,
    pub deliver_payloads: bool,
    pub notify_delete: bool,
    pub notify_retract: bool,
    pub persist_items: bool,
    pub send_last_published_item: String,
    pub node_type: String,
    pub deliver_notifications: bool,
    pub notify_config: bool,
    pub notify_sub: bool,
    pub language: Option<String>,
    pub payload_type: Option<String>,
    pub max_payload_size: i32,
    pub children_max: i32,
    pub children_association_policy: String,
    pub children_association_whitelist: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct PubSubDiscoNode {
    pub node: String,
    pub title: Option<String>,
}

impl PubSubNode {
    pub fn config(&self) -> PubSubNodeConfig {
        PubSubNodeConfig {
            access_model: self.access_model.clone(),
            publish_model: self.publish_model.clone(),
            max_items: self.max_items,
            title: self.title.clone(),
            description: self.description.clone(),
            deliver_payloads: self.deliver_payloads,
            notify_delete: self.notify_delete,
            notify_retract: self.notify_retract,
            persist_items: self.persist_items,
            send_last_published_item: self.send_last_published_item.clone(),
            node_type: self.node_type.clone(),
            deliver_notifications: self.deliver_notifications,
            notify_config: self.notify_config,
            notify_sub: self.notify_sub,
            language: self.language.clone(),
            payload_type: self.payload_type.clone(),
            max_payload_size: self.max_payload_size,
            children_max: self.children_max,
            children_association_policy: self.children_association_policy.clone(),
            children_association_whitelist: self.children_association_whitelist.clone(),
            collections: Vec::new(),
            children: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubSubNodeConfig {
    pub access_model: String,
    pub publish_model: String,
    pub max_items: i32,
    pub title: Option<String>,
    pub description: Option<String>,
    pub deliver_payloads: bool,
    pub notify_delete: bool,
    pub notify_retract: bool,
    pub persist_items: bool,
    pub send_last_published_item: String,
    pub node_type: String,
    pub deliver_notifications: bool,
    pub notify_config: bool,
    pub notify_sub: bool,
    pub language: Option<String>,
    pub payload_type: Option<String>,
    pub max_payload_size: i32,
    pub children_max: i32,
    pub children_association_policy: String,
    pub children_association_whitelist: Vec<String>,
    /// XEP-0248 graph fields are populated by the protocol layer.  They are
    /// stored in `pubsub_collection_members`, not duplicated on the node row.
    pub collections: Vec<String>,
    pub children: Vec<String>,
}

impl Default for PubSubNodeConfig {
    fn default() -> Self {
        Self {
            access_model: "open".to_owned(),
            publish_model: "publishers".to_owned(),
            max_items: 100,
            title: None,
            description: None,
            deliver_payloads: true,
            notify_delete: true,
            notify_retract: true,
            persist_items: true,
            // This matches the advertised XEP-0060 `last-published`
            // feature: last items are sent both on subscription and when an
            // existing subscriber becomes available.
            send_last_published_item: "on_sub_and_presence".to_owned(),
            node_type: "leaf".to_owned(),
            deliver_notifications: true,
            notify_config: true,
            notify_sub: true,
            language: None,
            payload_type: None,
            max_payload_size: 1_048_576,
            children_max: 1_000,
            children_association_policy: "owner".to_owned(),
            children_association_whitelist: Vec::new(),
            collections: Vec::new(),
            children: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
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
        && expected.publish_model == actual.publish_model
        && expected.max_items == actual.max_items
        && expected.deliver_payloads == actual.deliver_payloads
        && expected.persist_items == actual.persist_items
        && expected.node_type == actual.node_type
        && expected.payload_type == actual.payload_type
        && expected.max_payload_size == actual.max_payload_size
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
    if matches!(affiliation.as_deref(), Some("outcast" | "publish-only")) {
        transaction.rollback().await?;
        return Ok(SubscribeOutcome::Forbidden);
    }
    let affiliated = matches!(
        affiliation.as_deref(),
        Some("owner" | "publisher" | "member")
    );
    let authorized_state = match node.access_model.as_str() {
        "open" => "subscribed",
        "whitelist" if affiliated => "subscribed",
        "whitelist" => {
            transaction.rollback().await?;
            return Ok(SubscribeOutcome::ClosedNode);
        }
        "authorize" if affiliated => "subscribed",
        "authorize" => "pending",
        _ => {
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

pub async fn get_owner_jids(pool: &PgPool, node_id: Uuid) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT jid FROM pubsub_affiliations WHERE node_id = $1 AND affiliation = 'owner' ORDER BY jid",
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(|row| row.get("jid")).collect())
}

pub async fn get_publisher_jids(pool: &PgPool, node_id: Uuid) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT jid FROM pubsub_affiliations WHERE node_id = $1 AND affiliation IN ('publisher', 'publish-only') ORDER BY jid",
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(|row| row.get("jid")).collect())
}

pub async fn active_subscriber_count(pool: &PgPool, node_id: Uuid) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM pubsub_subscriptions WHERE node_id = $1 AND state = 'subscribed' AND (expire IS NULL OR expire > NOW())")
        .bind(node_id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
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
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2",
    )
    .bind(fresh.id)
    .bind(&publisher_jid)
    .fetch_optional(&mut *transaction)
    .await?;
    if affiliation.as_deref() == Some("outcast") {
        transaction.rollback().await?;
        return Ok(PublishItemsOutcome::Forbidden);
    }
    let privileged = matches!(
        affiliation.as_deref(),
        Some("owner" | "publisher" | "publish-only")
    );
    let authorized = match fresh.publish_model.as_str() {
        "open" => true,
        "publishers" => privileged,
        "subscribers" => {
            privileged
                || sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(
                         SELECT 1 FROM pubsub_subscriptions
                          WHERE node_id = $1
                            AND (jid = $2 OR split_part(jid, '/', 1) = $2)
                            AND state = 'subscribed'
                            AND (expire IS NULL OR expire > $3)
                     )",
                )
                .bind(fresh.id)
                .bind(&publisher_jid)
                .bind(event_time)
                .fetch_one(&mut *transaction)
                .await?
        }
        _ => false,
    };
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
    for (item_id, xml_payload) in items {
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
            .bind(event_time)
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
    let affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2",
    )
    .bind(node_id)
    .bind(&publisher_jid)
    .fetch_optional(&mut *transaction)
    .await?;
    if affiliation.as_deref() == Some("outcast") {
        transaction.rollback().await?;
        return Ok(RetractItemsOutcome::Forbidden);
    }
    let privileged = matches!(
        affiliation.as_deref(),
        Some("owner" | "publisher" | "publish-only")
    );
    let can_publish = match node.publish_model.as_str() {
        "open" => true,
        "publishers" => privileged,
        "subscribers" => {
            privileged
                || sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(
                         SELECT 1 FROM pubsub_subscriptions
                          WHERE node_id = $1
                            AND (jid = $2 OR split_part(jid, '/', 1) = $2)
                            AND state = 'subscribed'
                            AND (expire IS NULL OR expire > $3)
                     )",
                )
                .bind(node_id)
                .bind(&publisher_jid)
                .bind(event_time)
                .fetch_one(&mut *transaction)
                .await?
        }
        _ => false,
    };
    if !can_publish {
        transaction.rollback().await?;
        return Ok(RetractItemsOutcome::Forbidden);
    }
    let can_retract_other_publishers = affiliation.as_deref() == Some("owner");
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

/// Visible root discovery is filtered and paged in PostgreSQL. The synthetic
/// serverinfo item participates in the same lexical UID order, so XEP-0059
/// cursors and counts remain exact without loading every tenant's nodes.
pub async fn visible_root_disco_count(pool: &PgPool, requester: &str) -> Result<i64> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    sqlx::query_scalar(
        "WITH visible AS (
             SELECT n.node
               FROM pubsub_nodes n
              WHERE NOT EXISTS (
                        SELECT 1 FROM pubsub_collection_members e
                         WHERE e.child_node_id=n.id
                    )
                AND NOT EXISTS (
                        SELECT 1 FROM pubsub_affiliations denied
                         WHERE denied.node_id=n.id AND denied.jid=$1
                           AND denied.affiliation='outcast'
                    )
                AND (
                    n.access_model='open'
                    OR EXISTS (
                        SELECT 1 FROM pubsub_affiliations allowed
                         WHERE allowed.node_id=n.id AND allowed.jid=$1
                           AND allowed.affiliation IN ('owner','publisher','member')
                    )
                    OR EXISTS (
                        SELECT 1 FROM pubsub_subscriptions s
                         WHERE s.node_id=n.id
                           AND split_part(s.jid,'/',1)=$1
                           AND s.state='subscribed'
                           AND (s.expire IS NULL OR s.expire>NOW())
                    )
                )
             UNION ALL SELECT 'serverinfo'
         ) SELECT COUNT(*) FROM visible",
    )
    .bind(requester)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

pub async fn visible_root_disco_cursor_exists(
    pool: &PgPool,
    requester: &str,
    cursor: &str,
) -> Result<bool> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    sqlx::query_scalar(
        "WITH visible AS (
             SELECT n.node
               FROM pubsub_nodes n
              WHERE NOT EXISTS (SELECT 1 FROM pubsub_collection_members e WHERE e.child_node_id=n.id)
                AND NOT EXISTS (SELECT 1 FROM pubsub_affiliations denied WHERE denied.node_id=n.id AND denied.jid=$1 AND denied.affiliation='outcast')
                AND (n.access_model='open'
                     OR EXISTS (SELECT 1 FROM pubsub_affiliations allowed WHERE allowed.node_id=n.id AND allowed.jid=$1 AND allowed.affiliation IN ('owner','publisher','member'))
                     OR EXISTS (SELECT 1 FROM pubsub_subscriptions s WHERE s.node_id=n.id AND split_part(s.jid,'/',1)=$1 AND s.state='subscribed' AND (s.expire IS NULL OR s.expire>NOW())))
             UNION ALL SELECT 'serverinfo'
         ) SELECT EXISTS(SELECT 1 FROM visible WHERE node=$2)",
    )
    .bind(requester)
    .bind(cursor)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

pub async fn visible_root_disco_index(pool: &PgPool, requester: &str, node: &str) -> Result<i64> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    sqlx::query_scalar(
        "WITH visible AS (
             SELECT n.node
               FROM pubsub_nodes n
              WHERE NOT EXISTS (SELECT 1 FROM pubsub_collection_members e WHERE e.child_node_id=n.id)
                AND NOT EXISTS (SELECT 1 FROM pubsub_affiliations denied WHERE denied.node_id=n.id AND denied.jid=$1 AND denied.affiliation='outcast')
                AND (n.access_model='open'
                     OR EXISTS (SELECT 1 FROM pubsub_affiliations allowed WHERE allowed.node_id=n.id AND allowed.jid=$1 AND allowed.affiliation IN ('owner','publisher','member'))
                     OR EXISTS (SELECT 1 FROM pubsub_subscriptions s WHERE s.node_id=n.id AND split_part(s.jid,'/',1)=$1 AND s.state='subscribed' AND (s.expire IS NULL OR s.expire>NOW())))
             UNION ALL SELECT 'serverinfo'
         ) SELECT COUNT(*) FROM visible WHERE node<$2",
    )
    .bind(requester)
    .bind(node)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

pub async fn visible_root_disco_page(
    pool: &PgPool,
    requester: &str,
    cursor: Option<&str>,
    backwards: bool,
    limit: i64,
) -> Result<Vec<PubSubDiscoNode>> {
    let requester = crate::jid::canonical_bare_key(requester)?;
    let order = if backwards { "DESC" } else { "ASC" };
    let comparison = if backwards { "<" } else { ">" };
    let sql = format!(
        "WITH visible AS (
             SELECT n.node,n.title
               FROM pubsub_nodes n
              WHERE NOT EXISTS (SELECT 1 FROM pubsub_collection_members e WHERE e.child_node_id=n.id)
                AND NOT EXISTS (SELECT 1 FROM pubsub_affiliations denied WHERE denied.node_id=n.id AND denied.jid=$1 AND denied.affiliation='outcast')
                AND (n.access_model='open'
                     OR EXISTS (SELECT 1 FROM pubsub_affiliations allowed WHERE allowed.node_id=n.id AND allowed.jid=$1 AND allowed.affiliation IN ('owner','publisher','member'))
                     OR EXISTS (SELECT 1 FROM pubsub_subscriptions s WHERE s.node_id=n.id AND split_part(s.jid,'/',1)=$1 AND s.state='subscribed' AND (s.expire IS NULL OR s.expire>NOW())))
             UNION ALL SELECT 'serverinfo',NULL::TEXT
         ) SELECT node,title FROM visible
            WHERE ($2::TEXT IS NULL OR node {comparison} $2)
            ORDER BY node {order} LIMIT $3"
    );
    let rows = sqlx::query(&sql)
        .bind(requester)
        .bind(cursor)
        .bind(limit.clamp(1, 1_000))
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .map(|row| PubSubDiscoNode {
            node: row.get("node"),
            title: row.get("title"),
        })
        .collect())
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
mod integration_tests {
    use super::*;
    use crate::db;
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
        fn wait(&self) {
            let mut released = self.released.lock().expect("render gate poisoned");
            while !*released {
                released = self.wake.wait(released).expect("render gate poisoned");
            }
        }

        fn release(&self) {
            *self.released.lock().expect("render gate poisoned") = true;
            self.wake.notify_all();
        }
    }

    struct RaceMutationRenderer {
        inner: crate::services::pubsub::PubSubService,
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
                gate.wait();
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
            delete_node_as_owner_with_redirect_and_outbox(
                &pool, current.id, &owner, None, &renderer,
            )
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
        let node =
            create_default_test_node(&pool, &format!("publish-audience-{suffix}"), &owner).await;
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
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1",
            )
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
        let collection_options = PubSubSubscriptionOptions::for_node_type("collection");
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
        sqlx::query("DELETE FROM pubsub_collection_members WHERE collection_node_id=$1 AND child_node_id=$2")
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
            graph_first_task.await.unwrap().unwrap(),
            RetractItemsOutcome::Retracted
        );
        let graph_first_observation = graph_first_rx.recv().await.unwrap();
        assert_eq!(graph_first_observation.kind, "retract");
        assert!(graph_first_observation.recipients.is_empty());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1",
            )
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
        let mutation_observation = mutation_rx.recv().await.unwrap();
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
            mutation_task.await.unwrap().unwrap(),
            RetractItemsOutcome::Retracted
        );
        assert_eq!(
            dissociate.await.unwrap().unwrap(),
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
        let post_outcast = outcast_rx.recv().await.unwrap();
        assert_eq!(post_outcast.kind, "collection");
        assert!(post_outcast.recipients.is_empty());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1",
            )
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
        let last_observation = last_rx.recv().await.unwrap();
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
        let purge_node =
            create_default_test_node(&pool, &format!("race-purge-{suffix}"), &owner).await;
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
        let (purge_observation_tx, mut purge_observation_rx) =
            tokio::sync::mpsc::unbounded_channel();
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
        sqlx::query(
            "SELECT ordering_key FROM pubsub_event_streams WHERE ordering_key=$1 FOR UPDATE",
        )
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
        let (config_observation_tx, mut config_observation_rx) =
            tokio::sync::mpsc::unbounded_channel();
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
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pubsub_event_outbox WHERE event_id=$1",
            )
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
        let (delete_observation_tx, mut delete_observation_rx) =
            tokio::sync::mpsc::unbounded_channel();
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
        let remaining_owner = get_owner_jids(&pool, first_id).await.unwrap().remove(0);
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
            visible_root_disco_count(&pool, &diamond_subscriber)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(root_total > 512);
        let mut root_cursor = None;
        let mut root_seen = std::collections::BTreeSet::new();
        loop {
            let page = visible_root_disco_page(
                &pool,
                &diamond_subscriber,
                root_cursor.as_deref(),
                false,
                100,
            )
            .await
            .unwrap();
            if page.is_empty() {
                break;
            }
            for node in page {
                assert!(
                    root_seen.insert(node.node.clone()),
                    "root disco keyset page returned a duplicate node"
                );
                root_cursor = Some(node.node);
            }
        }
        assert_eq!(root_seen.len(), root_total);
        assert!(root_seen.contains("serverinfo"));
        assert!(
            visible_root_disco_cursor_exists(&pool, &diamond_subscriber, "serverinfo")
                .await
                .unwrap()
        );
        assert_eq!(
            usize::try_from(
                visible_root_disco_index(&pool, &diamond_subscriber, "serverinfo")
                    .await
                    .unwrap()
            )
            .unwrap(),
            root_seen
                .iter()
                .take_while(|node| node.as_str() < "serverinfo")
                .count()
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
        let discovered = item_ids_for_disco(&pool, leaf_id).await.unwrap();
        assert_eq!(discovered.len(), 2);
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
        let node =
            create_default_test_node(&pool, &format!("config-conflict-{suffix}"), &owner).await;
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
            let node = create_default_test_node(
                &pool,
                &format!("prohibited-{affiliation}-{suffix}"),
                &owner,
            )
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
            let first_observation =
                tokio::time::timeout(Duration::from_secs(3), affiliation_rx.recv())
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
            let publish_observation =
                tokio::time::timeout(Duration::from_secs(3), publish_rx.recv())
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
        let child =
            create_default_test_node(&pool, &format!("associate-child-{suffix}"), &owner).await;
        let collection = get_node_by_id(&pool, collection_id).await.unwrap().unwrap();
        assert_eq!(
            associate_collection_child(&pool, &collection, &child, &owner)
                .await
                .unwrap(),
            CollectionUpdateOutcome::Updated
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
            create_default_test_node(&pool, &format!("collection-victim-leaf-{suffix}"), &victim)
                .await;

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
}
