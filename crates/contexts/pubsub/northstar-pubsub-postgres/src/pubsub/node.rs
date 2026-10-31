//! PubSub node lifecycle and configuration persistence.

use super::*;

#[cfg(any(test, feature = "test-support"))]
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
    let creator_jid = northstar_xmpp_types::jid::canonical_bare_key(creator_jid)?;
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

    Ok(row.as_ref().map(row_to_node))
}

/// Project one owner response from a consistent snapshot. Recheck current
/// authority before returning so a committed revocation can veto stale data.
pub async fn owner_read(
    pool: &PgPool,
    node_name: &str,
    requester: &str,
    kind: PubSubOwnerReadKind,
) -> Result<PubSubOwnerRead> {
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let row = sqlx::query("SELECT id, node, creator_jid, access_model, publish_model, max_items, title, description, deliver_payloads, notify_delete, notify_retract, persist_items, send_last_published_item, node_type, deliver_notifications, notify_config, notify_sub, language, payload_type, max_payload_size, children_max, children_association_policy, children_association_whitelist, created_at FROM pubsub_nodes WHERE node = $1")
        .bind(node_name)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(node) = row.as_ref().map(row_to_node) else {
        transaction.commit().await?;
        return Ok(PubSubOwnerRead::Missing);
    };
    let owner: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pubsub_affiliations WHERE node_id = $1 AND jid = $2 AND affiliation = 'owner')",
    )
    .bind(node.id)
    .bind(&requester)
    .fetch_one(&mut *transaction)
    .await?;
    if !owner {
        transaction.commit().await?;
        return Ok(PubSubOwnerRead::Forbidden);
    }
    let result = match kind {
        PubSubOwnerReadKind::CheckOnly => PubSubOwnerRead::Authorized,
        PubSubOwnerReadKind::Configure => {
            let mut config = node.config();
            config.collections = sqlx::query_scalar(
                "SELECT n.node FROM pubsub_collection_members e JOIN pubsub_nodes n ON n.id = e.collection_node_id WHERE e.child_node_id = $1 ORDER BY n.node",
            )
            .bind(node.id)
            .fetch_all(&mut *transaction)
            .await?;
            config.children = sqlx::query_scalar(
                "SELECT n.node FROM pubsub_collection_members e JOIN pubsub_nodes n ON n.id = e.child_node_id WHERE e.collection_node_id = $1 ORDER BY n.node LIMIT 1000",
            )
            .bind(node.id)
            .fetch_all(&mut *transaction)
            .await?;
            PubSubOwnerRead::Configure(Box::new(config))
        }
        PubSubOwnerReadKind::Subscriptions => {
            let rows = sqlx::query("SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id = s.node_id WHERE s.node_id = $1 AND (s.expire IS NULL OR s.expire > NOW()) ORDER BY s.jid")
                .bind(node.id)
                .fetch_all(&mut *transaction)
                .await?;
            PubSubOwnerRead::Subscriptions(
                rows.iter()
                    .map(row_to_subscription)
                    .map(Into::into)
                    .collect(),
            )
        }
        PubSubOwnerReadKind::Affiliations => {
            let rows = sqlx::query("SELECT n.node, a.jid, a.affiliation FROM pubsub_affiliations a JOIN pubsub_nodes n ON n.id = a.node_id WHERE a.node_id = $1 AND a.affiliation <> 'none' ORDER BY a.jid")
                .bind(node.id)
                .fetch_all(&mut *transaction)
                .await?;
            PubSubOwnerRead::Affiliations(
                rows.iter()
                    .map(row_to_affiliation)
                    .map(Into::into)
                    .collect(),
            )
        }
    };
    transaction.commit().await?;
    let current = sqlx::query(
        "SELECT EXISTS(SELECT 1 FROM pubsub_nodes WHERE id = $1 AND node = $2) AS node_exists, \
                EXISTS(SELECT 1 FROM pubsub_affiliations WHERE node_id = $1 AND jid = $3 AND affiliation = 'owner') AS owner",
    )
    .bind(node.id)
    .bind(node_name)
    .bind(&requester)
    .fetch_one(pool)
    .await?;
    if !current.get::<bool, _>("node_exists") {
        return Ok(PubSubOwnerRead::Missing);
    }
    if !current.get::<bool, _>("owner") {
        return Ok(PubSubOwnerRead::Forbidden);
    }
    Ok(result)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn get_node_by_id(pool: &PgPool, node_id: Uuid) -> Result<Option<PubSubNode>> {
    let row = sqlx::query("SELECT id, node, creator_jid, access_model, publish_model, max_items, title, description, deliver_payloads, notify_delete, notify_retract, persist_items, send_last_published_item, node_type, deliver_notifications, notify_config, notify_sub, language, payload_type, max_payload_size, children_max, children_association_policy, children_association_whitelist, created_at FROM pubsub_nodes WHERE id = $1")
        .bind(node_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(row_to_node))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn update_node_config_and_graph(
    pool: &PgPool,
    node: &PubSubNode,
    requester: &str,
    config: &PubSubNodeConfig,
) -> Result<PubSubConfigOutcome> {
    let renderer = northstar_pubsub_application::service::PubSubEventRenderer::new("example.test");
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
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
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

pub async fn purge_node_as_owner_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<OwnerMutationOutcome> {
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
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

#[cfg(any(test, feature = "test-support"))]
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
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
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
