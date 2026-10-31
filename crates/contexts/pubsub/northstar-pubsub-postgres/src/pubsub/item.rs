//! PubSub item publication, retrieval and retraction persistence.

use super::*;

#[cfg(any(test, feature = "test-support"))]
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
        ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_purge(
            &self,
            _node: &PubSubNode,
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
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
        ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
            Ok(Vec::new())
        }

        fn render_configuration(
            &self,
            _node: &PubSubNode,
            _config: &PubSubNodeConfig,
            _audience: &[PubSubNotificationDelivery],
            _event_id: Uuid,
            _created_at: DateTime<Utc>,
        ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
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
        ) -> Result<Vec<super::super::PubSubOutboxInsert>> {
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
    let publisher_jid = northstar_xmpp_types::jid::canonical_bare_key(publisher_jid)?;
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

#[cfg(any(test, feature = "test-support"))]
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
    let publisher_jid = northstar_xmpp_types::jid::canonical_bare_key(publisher_jid)?;
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
