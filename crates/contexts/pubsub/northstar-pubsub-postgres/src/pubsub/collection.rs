//! PubSub collection graph persistence: parents, children, visible items and child association.

use super::*;

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
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
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

#[cfg(any(test, feature = "test-support"))]
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
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
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

#[cfg(any(test, feature = "test-support"))]
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
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
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
