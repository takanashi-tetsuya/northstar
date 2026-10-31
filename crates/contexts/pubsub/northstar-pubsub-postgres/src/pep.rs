use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub use northstar_pubsub_core::PEP_MAX_ITEMS;
pub const PEP_MAX_SUBSCRIBERS_PER_NODE: i64 = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepNodeConfig {
    pub access_model: String,
    pub max_items: i32,
    pub persist_items: bool,
    pub send_last_published_item: String,
    pub deliver_notifications: bool,
    pub roster_groups_allowed: Vec<String>,
    pub access_whitelist: Vec<String>,
}

pub async fn pep_node(pool: &PgPool, owner_id: Uuid, node: &str) -> Result<Option<PepNodeConfig>> {
    let row = sqlx::query(
        "SELECT access_model, max_items, persist_items, send_last_published_item, deliver_notifications, roster_groups_allowed, access_whitelist FROM pep_nodes WHERE owner_id = $1 AND node = $2",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| PepNodeConfig {
        access_model: row.get("access_model"),
        max_items: row.get("max_items"),
        persist_items: row.get("persist_items"),
        send_last_published_item: row.get("send_last_published_item"),
        deliver_notifications: row.get("deliver_notifications"),
        roster_groups_allowed: row.get("roster_groups_allowed"),
        access_whitelist: row.get("access_whitelist"),
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepPublishOutcome {
    Published,
    PreconditionFailed,
    MaxItemsExceeded,
    QuotaExceeded,
}

#[derive(Clone, Copy, Debug)]
pub struct PepQuotas {
    pub max_nodes: i64,
    pub max_storage_bytes: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepCreateOutcome {
    Created,
    Conflict,
    QuotaExceeded,
}

#[derive(Clone, Debug)]
pub struct PepSubscription {
    pub jid: String,
    pub subid: String,
}

#[derive(Clone, Debug)]
pub struct PepPresenceSubscription {
    pub owner_id: Uuid,
    pub owner_username: String,
    pub node: String,
}

#[derive(Clone, Debug)]
pub struct PepItem {
    pub item_id: String,
    pub payload: String,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_pep_node(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    config: &PepNodeConfig,
    max_nodes: i64,
) -> Result<PepCreateOutcome> {
    let mut transaction = super::pubsub::begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(owner_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pep_nodes WHERE owner_id = $1")
        .bind(owner_id)
        .fetch_one(&mut *transaction)
        .await?;
    if count >= max_nodes {
        transaction.rollback().await?;
        return Ok(PepCreateOutcome::QuotaExceeded);
    }
    let inserted = sqlx::query("INSERT INTO pep_nodes (owner_id, node, access_model, max_items, persist_items, send_last_published_item, deliver_notifications, roster_groups_allowed, access_whitelist) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING")
        .bind(owner_id)
        .bind(node)
        .bind(&config.access_model)
        .bind(config.max_items)
        .bind(config.persist_items)
        .bind(&config.send_last_published_item)
        .bind(config.deliver_notifications)
        .bind(&config.roster_groups_allowed)
        .bind(&config.access_whitelist)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(if inserted.rows_affected() == 1 {
        PepCreateOutcome::Created
    } else {
        PepCreateOutcome::Conflict
    })
}

#[cfg(any(test, feature = "test-support"))]
pub async fn purge_pep_node(pool: &PgPool, owner_id: Uuid, node: &str) -> Result<bool> {
    purge_pep_node_with_outbox(pool, owner_id, node, &[]).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn purge_pep_node_with_outbox(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<bool> {
    let mut transaction = super::pubsub::begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(owner_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let exists = sqlx::query_scalar::<_, Uuid>(
        "SELECT owner_id FROM pep_nodes WHERE owner_id=$1 AND node=$2 FOR UPDATE",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_optional(&mut *transaction)
    .await?;
    if exists.is_some() {
        sqlx::query("DELETE FROM pep_items WHERE owner_id=$1 AND node=$2")
            .bind(owner_id)
            .bind(node)
            .execute(&mut *transaction)
            .await?;
        super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    }
    transaction.commit().await?;
    Ok(exists.is_some())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn delete_pep_node(pool: &PgPool, owner_id: Uuid, node: &str) -> Result<bool> {
    delete_pep_node_with_outbox(pool, owner_id, node, &[]).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn delete_pep_node_with_outbox(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<bool> {
    let mut transaction = super::pubsub::begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(owner_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let deleted = sqlx::query("DELETE FROM pep_nodes WHERE owner_id=$1 AND node=$2")
        .bind(owner_id)
        .bind(node)
        .execute(&mut *transaction)
        .await?;
    if deleted.rows_affected() == 1 {
        super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    }
    transaction.commit().await?;
    Ok(deleted.rows_affected() == 1)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn update_pep_node_config(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    config: &PepNodeConfig,
) -> Result<bool> {
    update_pep_node_config_with_outbox(pool, owner_id, node, config, &[]).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn update_pep_node_config_with_outbox(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    config: &PepNodeConfig,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<bool> {
    let mut transaction = super::pubsub::begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(owner_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let updated = sqlx::query("UPDATE pep_nodes SET access_model=$3,max_items=$4,persist_items=$5,send_last_published_item=$6,deliver_notifications=$7,roster_groups_allowed=$8,access_whitelist=$9,updated_at=NOW() WHERE owner_id=$1 AND node=$2")
        .bind(owner_id).bind(node).bind(&config.access_model).bind(config.max_items)
        .bind(config.persist_items).bind(&config.send_last_published_item)
        .bind(config.deliver_notifications).bind(&config.roster_groups_allowed)
        .bind(&config.access_whitelist).execute(&mut *transaction).await?;
    if updated.rows_affected() == 0 {
        transaction.rollback().await?;
        return Ok(false);
    }
    if config.persist_items {
        sqlx::query("DELETE FROM pep_items WHERE owner_id=$1 AND node=$2 AND item_id NOT IN (SELECT item_id FROM pep_items WHERE owner_id=$1 AND node=$2 ORDER BY updated_at DESC,item_id DESC LIMIT $3)")
            .bind(owner_id).bind(node).bind(config.max_items).execute(&mut *transaction).await?;
    } else {
        sqlx::query("DELETE FROM pep_items WHERE owner_id=$1 AND node=$2")
            .bind(owner_id)
            .bind(node)
            .execute(&mut *transaction)
            .await?;
    }
    super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    transaction.commit().await?;
    Ok(true)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn subscribe_pep_node(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    subscriber_jid: &str,
    max_subscriptions: i64,
) -> Result<Option<PepSubscription>> {
    subscribe_pep_node_with_outbox(
        pool,
        owner_id,
        node,
        subscriber_jid,
        max_subscriptions,
        &Uuid::new_v4().to_string(),
        &[],
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "test-support"))]
pub async fn subscribe_pep_node_with_outbox(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    subscriber_jid: &str,
    max_subscriptions: i64,
    requested_subid: &str,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<Option<PepSubscription>> {
    let subscriber_jid = northstar_xmpp_types::jid::canonicalize(subscriber_jid)?;
    let subscriber_bare = northstar_xmpp_types::jid::canonical_bare_key(&subscriber_jid)?;
    let mut transaction = super::pubsub::begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4))")
        .bind(&subscriber_bare)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5))")
        .bind(format!("{owner_id}:{node}"))
        .execute(&mut *transaction)
        .await?;
    let existing = sqlx::query("SELECT subid FROM pep_subscriptions WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 FOR UPDATE")
        .bind(owner_id).bind(node).bind(&subscriber_jid).fetch_optional(&mut *transaction).await?;
    if let Some(row) = existing {
        super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
        transaction.commit().await?;
        return Ok(Some(PepSubscription {
            jid: subscriber_jid,
            subid: row.get("subid"),
        }));
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pep_subscriptions WHERE split_part(subscriber_jid, '/', 1)=$1",
    )
    .bind(&subscriber_bare)
    .fetch_one(&mut *transaction)
    .await?;
    if count >= max_subscriptions {
        transaction.rollback().await?;
        return Ok(None);
    }
    let node_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pep_subscriptions WHERE owner_id=$1 AND node=$2")
            .bind(owner_id)
            .bind(node)
            .fetch_one(&mut *transaction)
            .await?;
    if node_count >= PEP_MAX_SUBSCRIBERS_PER_NODE {
        transaction.rollback().await?;
        return Ok(None);
    }
    let subid = requested_subid.to_owned();
    sqlx::query(
        "INSERT INTO pep_subscriptions(owner_id,node,subscriber_jid,subid) VALUES($1,$2,$3,$4)",
    )
    .bind(owner_id)
    .bind(node)
    .bind(&subscriber_jid)
    .bind(&subid)
    .execute(&mut *transaction)
    .await?;
    super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    transaction.commit().await?;
    Ok(Some(PepSubscription {
        jid: subscriber_jid,
        subid,
    }))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn unsubscribe_pep_node(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    subscriber_jid: &str,
    subid: Option<&str>,
) -> Result<Option<String>> {
    let subscriber_jid = northstar_xmpp_types::jid::canonicalize(subscriber_jid)?;
    let mut transaction = super::pubsub::begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5))")
        .bind(format!("{owner_id}:{node}"))
        .execute(&mut *transaction)
        .await?;
    let row = sqlx::query("DELETE FROM pep_subscriptions WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 AND ($4::TEXT IS NULL OR subid=$4) RETURNING subid")
        .bind(owner_id).bind(node).bind(&subscriber_jid).bind(subid).fetch_optional(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(row.map(|row| row.get("subid")))
}

/// Atomically applies an owner's multi-subscription removal request.
/// Every `(jid, subid)` selector is validated while locked before any row is
/// deleted; a stale or invalid selector therefore cannot produce a partial
/// owner operation.
#[cfg(any(test, feature = "test-support"))]
pub async fn unsubscribe_pep_nodes_batch(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    changes: &[(String, Option<String>)],
) -> Result<bool> {
    let expected = changes
        .iter()
        .filter_map(|(jid, subid)| subid.as_ref().map(|subid| (jid.clone(), subid.clone())))
        .collect::<Vec<_>>();
    if expected.len() != changes.len() {
        // This compatibility wrapper cannot safely prepare an immutable
        // notification snapshot for selectors without a concrete subid.
        // Production callers resolve the current subid and commit the durable
        // event snapshot through `PubSubService`; this compatibility helper
        // intentionally exercises only the selector transaction.
        return unsubscribe_pep_nodes_batch_inner(pool, owner_id, node, changes, None, &[]).await;
    }
    unsubscribe_pep_nodes_batch_inner(pool, owner_id, node, changes, Some(&expected), &[]).await
}

#[cfg(any(test, feature = "test-support"))]
async fn unsubscribe_pep_nodes_batch_inner(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    changes: &[(String, Option<String>)],
    expected: Option<&[(String, String)]>,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<bool> {
    if changes.is_empty() {
        return Ok(false);
    }
    let mut canonical = Vec::with_capacity(changes.len());
    let mut unique = std::collections::BTreeSet::new();
    for (jid, subid) in changes {
        let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
        if !unique.insert((jid.clone(), subid.clone())) {
            return Ok(false);
        }
        canonical.push((jid, subid.as_deref()));
    }
    let expected = if let Some(expected) = expected {
        if expected.len() != canonical.len() {
            return Ok(false);
        }
        let mut canonical_expected = Vec::with_capacity(expected.len());
        let mut unique_expected = std::collections::BTreeSet::new();
        for (jid, subid) in expected {
            let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
            if subid.is_empty() || !unique_expected.insert(jid.clone()) {
                return Ok(false);
            }
            canonical_expected.push((jid, subid.clone()));
        }
        Some(canonical_expected)
    } else {
        None
    };
    let mut transaction = super::pubsub::begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 5))")
        .bind(format!("{owner_id}:{node}"))
        .execute(&mut *transaction)
        .await?;
    for (index, (jid, subid)) in canonical.iter().enumerate() {
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT subid FROM pep_subscriptions WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 FOR UPDATE",
        )
        .bind(owner_id)
        .bind(node)
        .bind(jid)
        .fetch_optional(&mut *transaction)
        .await?;
        if stored.as_deref().is_none()
            || subid.is_some_and(|expected| stored.as_deref() != Some(expected))
            || expected.as_ref().is_some_and(|expected| {
                expected[index].0 != *jid || stored.as_deref() != Some(expected[index].1.as_str())
            })
        {
            transaction.rollback().await?;
            return Ok(false);
        }
    }
    for (jid, subid) in canonical {
        let removed = sqlx::query("DELETE FROM pep_subscriptions WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 AND ($4::TEXT IS NULL OR subid=$4)")
            .bind(owner_id)
            .bind(node)
            .bind(jid)
            .bind(subid)
            .execute(&mut *transaction)
            .await?;
        if removed.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(false);
        }
    }
    super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn pep_subscribers(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
) -> Result<Vec<PepSubscription>> {
    let rows = sqlx::query("SELECT subscriber_jid, subid FROM pep_subscriptions WHERE owner_id=$1 AND node=$2 AND state='subscribed' ORDER BY subscriber_jid LIMIT 10000")
        .bind(owner_id).bind(node).fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|row| PepSubscription {
            jid: row.get("subscriber_jid"),
            subid: row.get("subid"),
        })
        .collect())
}

/// Returns explicit subscriptions which should receive a last-item event when
/// this exact resource becomes available. A bare subscription applies to all
/// of the subscriber's resources, while a full-JID subscription applies only
/// to the resource named by the subscription.
pub async fn pep_subscriptions_for_available_resource(
    pool: &PgPool,
    subscriber_jid: &str,
) -> Result<Vec<PepPresenceSubscription>> {
    let subscriber_jid = northstar_xmpp_types::jid::canonical_session_key(subscriber_jid)?;
    let subscriber_bare = northstar_xmpp_types::jid::canonical_bare_key(&subscriber_jid)?;
    let rows = sqlx::query(
        "SELECT p.owner_id, u.username, p.node FROM pep_subscriptions p JOIN users u ON u.id=p.owner_id WHERE p.state='subscribed' AND p.subscriber_jid IN ($1,$2) ORDER BY p.owner_id,p.node LIMIT 1000",
    )
    .bind(&subscriber_jid)
    .bind(&subscriber_bare)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|row| PepPresenceSubscription {
            owner_id: row.get("owner_id"),
            owner_username: row.get("username"),
            node: row.get("node"),
        })
        .collect())
}

/// Atomically publishes a batch and applies the node's retention policy.
///
/// `false` means an explicit publish-options precondition did not match the
/// existing node. No item in the batch is written in that case.
#[cfg(any(test, feature = "test-support"))]
pub async fn publish_pep_items(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    requested: PepNodeConfig,
    enforce_preconditions: bool,
    items: &[(&str, &str)],
    quotas: PepQuotas,
) -> Result<PepPublishOutcome> {
    Ok(publish_pep_items_with_change(
        pool,
        owner_id,
        node,
        requested,
        enforce_preconditions,
        items,
        quotas,
    )
    .await?
    .0)
}

/// Returns whether the publication changed at least one requested item.  The
/// comparison and write share the owner advisory lock, so concurrent retries
/// cannot both be classified as a content change and emit duplicate events.
#[cfg(any(test, feature = "test-support"))]
pub async fn publish_pep_items_with_change(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    requested: PepNodeConfig,
    enforce_preconditions: bool,
    items: &[(&str, &str)],
    quotas: PepQuotas,
) -> Result<(PepPublishOutcome, bool)> {
    publish_pep_items_with_change_and_outbox(
        pool,
        owner_id,
        node,
        requested,
        enforce_preconditions,
        items,
        quotas,
        &[],
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "test-support"))]
pub async fn publish_pep_items_with_change_and_outbox(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    requested: PepNodeConfig,
    enforce_preconditions: bool,
    items: &[(&str, &str)],
    quotas: PepQuotas,
    outbox: &[super::PubSubOutboxInsert],
) -> Result<(PepPublishOutcome, bool)> {
    publish_pep_items_with_change_and_outbox_policy(
        pool,
        owner_id,
        node,
        requested,
        enforce_preconditions,
        items,
        quotas,
        outbox,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "test-support"))]
async fn publish_pep_items_with_change_and_outbox_policy(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    requested: PepNodeConfig,
    enforce_preconditions: bool,
    items: &[(&str, &str)],
    quotas: PepQuotas,
    outbox: &[super::PubSubOutboxInsert],
    require_content_change: bool,
) -> Result<(PepPublishOutcome, bool)> {
    let mut transaction = super::pubsub::begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(owner_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let item_ids = items
        .iter()
        .map(|(item_id, _)| *item_id)
        .collect::<Vec<_>>();
    let previous = sqlx::query(
        "SELECT item_id,payload FROM pep_items WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3) FOR UPDATE",
    )
    .bind(owner_id)
    .bind(node)
    .bind(&item_ids)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .map(|row| (row.get::<String, _>("item_id"), row.get::<String, _>("payload")))
    .collect::<std::collections::HashMap<_, _>>();
    let changed = previous.len() != items.len()
        || items
            .iter()
            .any(|(item_id, payload)| previous.get(*item_id).map(String::as_str) != Some(*payload));
    let outcome = publish_pep_items_in_transaction(
        &mut transaction,
        owner_id,
        node,
        &requested,
        enforce_preconditions,
        items,
        quotas,
    )
    .await?;
    if outcome == PepPublishOutcome::Published {
        if changed || !require_content_change {
            super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
        }
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok((outcome, outcome == PepPublishOutcome::Published && changed))
}

pub async fn publish_pep_items_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    node: &str,
    requested: &PepNodeConfig,
    enforce_preconditions: bool,
    items: &[(&str, &str)],
    quotas: PepQuotas,
) -> Result<PepPublishOutcome> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pep_nodes WHERE owner_id = $1 AND node = $2)",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_one(&mut **transaction)
    .await?;
    if !exists {
        let node_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pep_nodes WHERE owner_id = $1")
                .bind(owner_id)
                .fetch_one(&mut **transaction)
                .await?;
        if node_count >= quotas.max_nodes {
            return Ok(PepPublishOutcome::QuotaExceeded);
        }
    }
    sqlx::query(
        "INSERT INTO pep_nodes (owner_id, node, access_model, max_items, persist_items, send_last_published_item, deliver_notifications, roster_groups_allowed, access_whitelist) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (owner_id, node) DO NOTHING",
    )
    .bind(owner_id)
    .bind(node)
    .bind(&requested.access_model)
    .bind(requested.max_items)
    .bind(requested.persist_items)
    .bind(&requested.send_last_published_item)
    .bind(requested.deliver_notifications)
    .bind(&requested.roster_groups_allowed)
    .bind(&requested.access_whitelist)
    .execute(&mut **transaction)
    .await?;
    let actual = sqlx::query(
        "SELECT access_model, max_items, persist_items, send_last_published_item, deliver_notifications, roster_groups_allowed, access_whitelist FROM pep_nodes WHERE owner_id = $1 AND node = $2 FOR UPDATE",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_one(&mut **transaction)
    .await?;
    let actual = PepNodeConfig {
        access_model: actual.get("access_model"),
        max_items: actual.get("max_items"),
        persist_items: actual.get("persist_items"),
        send_last_published_item: actual.get("send_last_published_item"),
        deliver_notifications: actual.get("deliver_notifications"),
        roster_groups_allowed: actual.get("roster_groups_allowed"),
        access_whitelist: actual.get("access_whitelist"),
    };
    if enforce_preconditions && actual != *requested {
        return Ok(PepPublishOutcome::PreconditionFailed);
    }
    if items.len() > actual.max_items as usize {
        return Ok(PepPublishOutcome::MaxItemsExceeded);
    }
    if actual.persist_items {
        for (item_id, payload) in items {
            sqlx::query("INSERT INTO pep_items (owner_id, node, item_id, payload) VALUES ($1, $2, $3, $4) ON CONFLICT (owner_id, node, item_id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()")
                .bind(owner_id).bind(node).bind(item_id).bind(payload).execute(&mut **transaction).await?;
        }
        sqlx::query(
            "DELETE FROM pep_items WHERE owner_id = $1 AND node = $2 AND item_id NOT IN (SELECT item_id FROM pep_items WHERE owner_id = $1 AND node = $2 ORDER BY updated_at DESC, item_id DESC LIMIT $3)",
        )
        .bind(owner_id)
        .bind(node)
        .bind(actual.max_items)
        .execute(&mut **transaction)
        .await?;
    }
    let stored_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(payload)), 0)::BIGINT FROM pep_items WHERE owner_id = $1",
    )
    .bind(owner_id)
    .fetch_one(&mut **transaction)
    .await?;
    if stored_bytes > quotas.max_storage_bytes {
        return Ok(PepPublishOutcome::QuotaExceeded);
    }
    Ok(PepPublishOutcome::Published)
}

pub async fn replace_pep_items_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    node: &str,
    config: &PepNodeConfig,
    items: &[(&str, &str)],
    quotas: PepQuotas,
) -> Result<PepPublishOutcome> {
    if items.len() > config.max_items as usize {
        return Ok(PepPublishOutcome::MaxItemsExceeded);
    }
    let node_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pep_nodes WHERE owner_id = $1")
        .bind(owner_id)
        .fetch_one(&mut **transaction)
        .await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pep_nodes WHERE owner_id = $1 AND node = $2)",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_one(&mut **transaction)
    .await?;
    if !exists && node_count >= quotas.max_nodes {
        return Ok(PepPublishOutcome::QuotaExceeded);
    }
    sqlx::query(
        "INSERT INTO pep_nodes (owner_id, node, access_model, max_items, persist_items, send_last_published_item, deliver_notifications, roster_groups_allowed, access_whitelist) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (owner_id, node) DO UPDATE SET access_model = EXCLUDED.access_model, max_items = EXCLUDED.max_items, persist_items = EXCLUDED.persist_items, send_last_published_item = EXCLUDED.send_last_published_item, deliver_notifications = EXCLUDED.deliver_notifications, roster_groups_allowed = EXCLUDED.roster_groups_allowed, access_whitelist = EXCLUDED.access_whitelist, updated_at = NOW()",
    )
    .bind(owner_id)
    .bind(node)
    .bind(&config.access_model)
    .bind(config.max_items)
    .bind(config.persist_items)
    .bind(&config.send_last_published_item)
    .bind(config.deliver_notifications)
    .bind(&config.roster_groups_allowed)
    .bind(&config.access_whitelist)
    .execute(&mut **transaction)
    .await?;
    sqlx::query("DELETE FROM pep_items WHERE owner_id = $1 AND node = $2")
        .bind(owner_id)
        .bind(node)
        .execute(&mut **transaction)
        .await?;
    if config.persist_items {
        for (item_id, payload) in items {
            sqlx::query(
                "INSERT INTO pep_items (owner_id, node, item_id, payload) VALUES ($1, $2, $3, $4)",
            )
            .bind(owner_id)
            .bind(node)
            .bind(item_id)
            .bind(payload)
            .execute(&mut **transaction)
            .await?;
        }
    }
    let stored_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(payload)), 0)::BIGINT FROM pep_items WHERE owner_id = $1",
    )
    .bind(owner_id)
    .fetch_one(&mut **transaction)
    .await?;
    if stored_bytes > quotas.max_storage_bytes {
        return Ok(PepPublishOutcome::QuotaExceeded);
    }
    Ok(PepPublishOutcome::Published)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn retract_pep_items(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    item_ids: &[&str],
) -> Result<Option<u64>> {
    retract_pep_items_with_outbox(pool, owner_id, node, item_ids, &[]).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn retract_pep_items_with_outbox(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    item_ids: &[&str],
    outbox: &[super::PubSubOutboxInsert],
) -> Result<Option<u64>> {
    let mut transaction = super::pubsub::begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
        .bind(owner_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM pep_nodes WHERE owner_id = $1 AND node = $2)",
    )
    .bind(owner_id)
    .bind(node)
    .fetch_one(&mut *transaction)
    .await?;
    if !exists {
        transaction.rollback().await?;
        return Ok(None);
    }
    let matched: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pep_items WHERE owner_id = $1 AND node = $2 AND item_id = ANY($3)",
    )
    .bind(owner_id)
    .bind(node)
    .bind(item_ids)
    .fetch_one(&mut *transaction)
    .await?;
    if matched != item_ids.len() as i64 {
        transaction.rollback().await?;
        return Ok(Some(0));
    }
    let result = sqlx::query(
        "DELETE FROM pep_items WHERE owner_id = $1 AND node = $2 AND item_id = ANY($3)",
    )
    .bind(owner_id)
    .bind(node)
    .bind(item_ids)
    .execute(&mut *transaction)
    .await?;
    super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    transaction.commit().await?;
    Ok(Some(result.rows_affected()))
}

pub async fn pep_nodes(pool: &PgPool, owner_id: Uuid) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT node FROM pep_nodes WHERE owner_id = $1 ORDER BY node")
        .bind(owner_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(|r| r.get("node")).collect())
}

pub fn default_pep_node_config(node: &str) -> PepNodeConfig {
    (&northstar_pubsub_core::default_pep_node_config(node)).into()
}

pub async fn pep_items(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    item_id: Option<&str>,
    limit: i64,
) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query("SELECT item_id, payload FROM pep_items WHERE owner_id = $1 AND node = $2 AND ($3::text IS NULL OR item_id = $3) ORDER BY updated_at DESC LIMIT $4")
        .bind(owner_id).bind(node).bind(item_id).bind(limit.clamp(1, 100)).fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|r| (r.get("item_id"), r.get("payload")))
        .collect())
}

pub async fn pep_items_by_ids(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    item_ids: &[&str],
    limit: i64,
) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query(
        "SELECT item_id, payload FROM pep_items WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3) ORDER BY updated_at DESC, item_id DESC LIMIT $4",
    )
    .bind(owner_id)
    .bind(node)
    .bind(item_ids)
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|row| (row.get("item_id"), row.get("payload")))
        .collect())
}

pub async fn pep_items_with_timestamp(
    pool: &PgPool,
    owner_id: Uuid,
    node: &str,
    limit: i64,
) -> Result<Vec<PepItem>> {
    let rows = sqlx::query("SELECT item_id, payload, updated_at FROM pep_items WHERE owner_id=$1 AND node=$2 ORDER BY updated_at DESC, item_id DESC LIMIT $3")
        .bind(owner_id).bind(node).bind(limit.clamp(1, 100)).fetch_all(pool).await?;
    Ok(rows
        .iter()
        .map(|row| PepItem {
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            updated_at: row.get("updated_at"),
        })
        .collect())
}
