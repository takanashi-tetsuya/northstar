//! Transaction helpers for locked PubSub mutations.

use anyhow::Result;
use northstar_time::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashMap;
use uuid::Uuid;

use super::{PubSubItem, PubSubNode, PubSubNotificationDelivery, PubSubSubscription};

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

pub(super) fn canonical_bare_jids(values: &[String]) -> Result<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut canonical = Vec::with_capacity(values.len());
    for value in values {
        let jid = northstar_xmpp_types::jid::canonical_bare_key(value)?;
        if !seen.insert(jid.clone()) {
            anyhow::bail!("PubSub JID list contains canonically equivalent duplicate {jid}");
        }
        canonical.push(jid);
    }
    Ok(canonical)
}

pub(super) async fn requester_is_owner(
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
pub(super) async fn requester_owns_locked_collection_child(
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

pub(super) async fn get_node_by_id_in_transaction(
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
pub(super) async fn lock_notification_authority(
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
pub(super) async fn locked_event_time(
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
pub(super) async fn enqueue_locked_mutation_outbox(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    deliveries: &[super::super::PubSubOutboxInsert],
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
            super::super::PubSubOutboxSource::PubSub => "pubsub",
            super::super::PubSubOutboxSource::Pep => "pep",
        };
        let delivery_kind = match delivery.delivery_kind {
            super::super::PubSubOutboxDeliveryKind::PubSubChildren => "pubsub-children",
            super::super::PubSubOutboxDeliveryKind::PubSubDigest => "pubsub-digest",
            super::super::PubSubOutboxDeliveryKind::PubSubDirect => "pubsub-direct",
            super::super::PubSubOutboxDeliveryKind::PepStanza => "pep-stanza",
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

pub(super) async fn notification_audience_in_transaction(
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

pub(super) async fn owner_jids_in_transaction(
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

pub(super) async fn latest_item_in_transaction(
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

pub(super) fn publish_preconditions_match(expected: &PubSubNode, actual: &PubSubNode) -> bool {
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
pub(super) async fn locked_publish_authorization(
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

pub(super) async fn edge_exceeds_max_depth(
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

pub(super) fn row_to_subscription(row: &sqlx::postgres::PgRow) -> PubSubSubscription {
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

pub(super) fn row_to_node(row: &sqlx::postgres::PgRow) -> PubSubNode {
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
