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
    // Low-level DB fixtures seed retained items that need not be protocol publications.
    publish_items_with_policy(
        pool,
        node,
        publisher_jid,
        items,
        None,
        max_storage_bytes_per_owner,
        &NoopMutationOutboxRenderer,
        PublishPolicyScope::Fixture,
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
    publish_items_with_options_and_renderer(
        pool,
        node,
        publisher_jid,
        items,
        None,
        max_storage_bytes_per_owner,
        renderer,
    )
    .await
}

pub async fn publish_items_with_options_and_renderer(
    pool: &PgPool,
    node: &PubSubNode,
    publisher_jid: &str,
    items: &[(String, String)],
    publish_options: Option<&PubSubNodeConfig>,
    max_storage_bytes_per_owner: i64,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<PublishItemsOutcome> {
    publish_items_with_policy(
        pool,
        node,
        publisher_jid,
        items,
        publish_options,
        max_storage_bytes_per_owner,
        renderer,
        PublishPolicyScope::Existing,
    )
    .await
}

pub(super) enum PublishPolicyScope<'a> {
    Existing,
    AutoCreate(&'a PubSubNodeConfig),
    #[cfg(any(test, feature = "test-support"))]
    Fixture,
}

#[allow(clippy::too_many_arguments)]
async fn publish_items_with_policy(
    pool: &PgPool,
    node: &PubSubNode,
    publisher_jid: &str,
    items: &[(String, String)],
    publish_options: Option<&PubSubNodeConfig>,
    max_storage_bytes_per_owner: i64,
    renderer: &dyn PubSubMutationOutboxRenderer,
    policy: PublishPolicyScope<'_>,
) -> Result<PublishItemsOutcome> {
    let publisher_jid = northstar_xmpp_types::jid::canonical_bare_key(publisher_jid)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    lock_creator_storage_quota(&mut transaction, &node.creator_jid).await?;
    let outcome = publish_items_in_transaction(
        &mut transaction,
        node,
        &publisher_jid,
        items,
        publish_options,
        max_storage_bytes_per_owner,
        renderer,
        policy,
    )
    .await?;
    if outcome == PublishItemsOutcome::Published {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok(outcome)
}

pub(super) async fn lock_creator_storage_quota(
    transaction: &mut Transaction<'_, Postgres>,
    creator_jid: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1))")
        .bind(creator_jid)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_items_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    node: &PubSubNode,
    publisher_jid: &str,
    items: &[(String, String)],
    publish_options: Option<&PubSubNodeConfig>,
    max_storage_bytes_per_owner: i64,
    renderer: &dyn PubSubMutationOutboxRenderer,
    policy: PublishPolicyScope<'_>,
) -> Result<PublishItemsOutcome> {
    super::node::lock_collection_graph(transaction).await?;
    // Subscription, collection and configuration mutations all lock their
    // affected node row before changing authorization. Locking the source and
    // every ancestor first makes the audience and item mutation one
    // linearizable event-time snapshot.
    lock_notification_authority(transaction, &[node.id]).await?;
    let event_time = locked_event_time(transaction).await?;
    let Some(fresh) = get_node_by_id_in_transaction(transaction, node.id).await? else {
        return Ok(PublishItemsOutcome::Conflict);
    };
    if !publish_identity_matches(node, &fresh) {
        return Ok(PublishItemsOutcome::PreconditionFailed);
    }
    let (authorized, _) =
        locked_publish_authorization(transaction, &fresh, publisher_jid, event_time).await?;
    if !authorized {
        return Ok(PublishItemsOutcome::Forbidden);
    }
    match policy {
        PublishPolicyScope::Existing => {
            if let Some(rejection) = northstar_pubsub_application::publish_policy_rejection(
                &fresh.config(),
                publish_options,
                items,
            ) {
                return Ok(PublishItemsOutcome::Rejected(rejection));
            }
        }
        // Auto-create prevalidates the requested config in the service and
        // compares that config in full after reloading the inserted row.
        PublishPolicyScope::AutoCreate(config) => {
            if config != &fresh.config() {
                return Ok(PublishItemsOutcome::PreconditionFailed);
            }
        }
        #[cfg(any(test, feature = "test-support"))]
        PublishPolicyScope::Fixture => {}
    }
    let audience =
        notification_audience_in_transaction(transaction, &fresh, "items", event_time).await?;
    let outbox = renderer.render_items(
        &fresh,
        items,
        &audience,
        renderer.new_event_id(),
        event_time,
    )?;
    if !fresh.persist_items {
        enqueue_locked_mutation_outbox(transaction, &outbox, event_time).await?;
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
    .fetch_one(&mut **transaction)
    .await?;
    for (ordinal, (item_id, xml_payload)) in items.iter().enumerate() {
        let item_time = first_item_time + northstar_time::Duration::microseconds(ordinal as i64);
        // XEP-0060 section 12.9 requires an authorized publisher to overwrite
        // an existing NodeID+ItemID rather than rejecting the publication.
        // Node-level authorization has already happened at the protocol
        // boundary; item authorship only constrains retraction.
        let result = sqlx::query("INSERT INTO pubsub_items (id, node_id, item_id, publisher_jid, xml_payload, created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (node_id, item_id) DO UPDATE SET publisher_jid = EXCLUDED.publisher_jid, xml_payload = EXCLUDED.xml_payload, created_at = EXCLUDED.created_at")
            .bind(Uuid::new_v4())
            .bind(fresh.id)
            .bind(item_id)
            .bind(publisher_jid)
            .bind(xml_payload)
            .bind(item_time)
            .execute(&mut **transaction)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(PublishItemsOutcome::Conflict);
        }
    }
    sqlx::query(
        "DELETE FROM pubsub_items WHERE node_id = $1 AND id NOT IN (SELECT id FROM pubsub_items WHERE node_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2)",
    )
    .bind(fresh.id)
    .bind(fresh.max_items)
    .execute(&mut **transaction)
    .await?;
    let stored_bytes: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(octet_length(i.xml_payload)), 0)::BIGINT FROM pubsub_items i JOIN pubsub_nodes n ON n.id = i.node_id WHERE n.creator_jid = $1",
    )
    .bind(&fresh.creator_jid)
    .fetch_one(&mut **transaction)
    .await?;
    if stored_bytes > max_storage_bytes_per_owner {
        return Ok(PublishItemsOutcome::QuotaExceeded);
    }
    enqueue_locked_mutation_outbox(transaction, &outbox, event_time).await?;
    Ok(PublishItemsOutcome::Published)
}

pub async fn get_items(
    pool: &PgPool,
    node_id: Uuid,
    item_ids: &[String],
    limit: i64,
) -> Result<Vec<PubSubItem>> {
    get_items_with_executor(pool, node_id, item_ids, limit).await
}

pub(super) async fn get_items_with_executor<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    node_id: Uuid,
    item_ids: &[String],
    limit: i64,
) -> Result<Vec<PubSubItem>> {
    let rows = if item_ids.is_empty() {
        sqlx::query("SELECT item_id, publisher_jid, xml_payload, created_at FROM pubsub_items WHERE node_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2")
            .bind(node_id)
            .bind(limit.clamp(1, 1_000))
            .fetch_all(executor)
            .await?
    } else {
        sqlx::query("SELECT item_id, publisher_jid, xml_payload, created_at FROM pubsub_items WHERE node_id = $1 AND item_id = ANY($2) ORDER BY created_at DESC, id DESC LIMIT $3")
            .bind(node_id)
            .bind(item_ids)
            .bind(limit.clamp(1, 1_000))
            .fetch_all(executor)
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
    if node.node_type != "leaf" {
        transaction.rollback().await?;
        return Ok(RetractItemsOutcome::NotLeafNode);
    }
    if !node.persist_items {
        transaction.rollback().await?;
        return Ok(RetractItemsOutcome::NotPersistent);
    }
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
        renderer.render_retract(
            &node,
            item_ids,
            &audience,
            renderer.new_event_id(),
            event_time,
        )?
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
