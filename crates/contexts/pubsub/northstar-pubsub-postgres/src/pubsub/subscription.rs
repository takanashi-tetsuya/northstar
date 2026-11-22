//! PubSub subscription persistence and authorization.

use super::*;

pub async fn is_subscribed(pool: &PgPool, node_id: Uuid, jid: &str) -> Result<bool> {
    let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
    let bare = northstar_xmpp_types::jid::canonical_bare_key(&jid)?;
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

/// Read affiliation and active subscription from one statement snapshot.
/// Publication transactions still make their authoritative decision under
/// their existing locks.
pub async fn node_authorization_facts(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
) -> Result<(Option<String>, bool)> {
    node_authorization_facts_on(pool, node_id, requester, None).await
}

pub(super) async fn node_authorization_facts_on<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    node_id: Uuid,
    requester: &str,
    read_at: Option<DateTime<Utc>>,
) -> Result<(Option<String>, bool)> {
    let full = northstar_xmpp_types::jid::canonicalize(requester)?;
    let bare = northstar_xmpp_types::jid::canonical_bare_key(&full)?;
    let row = sqlx::query(
        "SELECT (SELECT affiliation FROM pubsub_affiliations \
                 WHERE node_id = $1 AND jid = $2) AS affiliation, \
                EXISTS(SELECT 1 FROM pubsub_subscriptions \
                       WHERE node_id = $1 \
                         AND (jid = $3 OR split_part(jid, '/', 1) = $2) \
                         AND state = 'subscribed' \
                         AND (expire IS NULL OR expire > COALESCE($4::TIMESTAMPTZ, NOW()))) AS subscribed",
    )
    .bind(node_id)
    .bind(bare)
    .bind(full)
    .bind(read_at)
    .fetch_one(executor)
    .await?;
    Ok((row.try_get("affiliation")?, row.try_get("subscribed")?))
}

pub async fn subscriptions_for_jid(
    pool: &PgPool,
    jid: &str,
    node: Option<&str>,
) -> Result<Vec<PubSubSubscription>> {
    subscriptions_for_jid_on(pool, jid, node).await
}

pub(super) async fn subscriptions_for_jid_on<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    jid: &str,
    node: Option<&str>,
) -> Result<Vec<PubSubSubscription>> {
    let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
    let bare = northstar_xmpp_types::jid::canonical_bare_key(&jid)?;
    subscriptions_for_bare_jid(executor, &bare, node, None).await
}

pub(super) async fn subscriptions_for_bare_jid<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    bare: &str,
    node: Option<&str>,
    read_at: Option<DateTime<Utc>>,
) -> Result<Vec<PubSubSubscription>> {
    let rows = sqlx::query("SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id = s.node_id WHERE split_part(s.jid, '/', 1) = $1 AND ($2::TEXT IS NULL OR n.node = $2) AND (s.expire IS NULL OR s.expire > COALESCE($3::TIMESTAMPTZ, NOW())) ORDER BY n.node, s.jid")
        .bind(bare)
        .bind(node)
        .bind(read_at)
        .fetch_all(executor)
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
    subscriptions_addressing_jid_page_on(pool, jid, after, limit, None).await
}

pub(super) async fn subscriptions_addressing_jid_page_on<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    jid: &str,
    after: Option<(&str, &str)>,
    limit: i64,
    read_at: Option<DateTime<Utc>>,
) -> Result<Vec<PubSubSubscription>> {
    let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
    let bare = northstar_xmpp_types::jid::canonical_bare_key(&jid)?;
    let (after_node, after_jid) = after.unzip();
    let rows = sqlx::query("SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id = s.node_id WHERE (s.jid = $1 OR s.jid = $2) AND (s.expire IS NULL OR s.expire > COALESCE($6::TIMESTAMPTZ, NOW())) AND ($3::TEXT IS NULL OR (n.node, s.jid) > ($3, $4)) ORDER BY n.node, s.jid LIMIT $5")
        .bind(jid)
        .bind(bare)
        .bind(after_node)
        .bind(after_jid)
        .bind(limit.clamp(1, 100))
        .bind(read_at)
        .fetch_all(executor)
        .await?;
    Ok(rows.iter().map(row_to_subscription).collect())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn set_subscription(pool: &PgPool, node_id: Uuid, jid: &str, state: &str) -> Result<()> {
    set_subscription_with_outbox(pool, node_id, jid, state, &[]).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn set_subscription_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
    state: &str,
    outbox: &[super::super::PubSubOutboxInsert],
) -> Result<()> {
    let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    sqlx::query("INSERT INTO pubsub_subscriptions (node_id, jid, state, subid) VALUES ($1, $2, $3, $4) ON CONFLICT (node_id, jid) DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()")
        .bind(node_id)
        .bind(jid)
        .bind(state)
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *transaction)
        .await?;
    super::super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
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
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
    let subscriber_jid = northstar_xmpp_types::jid::canonicalize(subscriber_jid)?;
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
        let subscriber_bare = northstar_xmpp_types::jid::canonical_bare_key(&subscriber_jid)?;
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
    let requester = northstar_xmpp_types::jid::canonical_bare_key(requester)?;
    let mut seen = std::collections::BTreeSet::new();
    let changes = changes
        .iter()
        .map(|(jid, state, expected_subid)| {
            let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
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
        let bare = northstar_xmpp_types::jid::canonical_bare_key(jid)?;
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

#[cfg(any(test, feature = "test-support"))]
pub async fn unsubscribe(pool: &PgPool, node_id: Uuid, jid: &str) -> Result<bool> {
    unsubscribe_with_outbox(pool, node_id, jid, &[]).await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn unsubscribe_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
    outbox: &[super::super::PubSubOutboxInsert],
) -> Result<bool> {
    let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
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
        super::super::enqueue_pubsub_outbox_in_transaction(&mut transaction, outbox).await?;
    }
    transaction.commit().await?;
    Ok(deleted.rows_affected() > 0)
}

pub async fn get_subscription(
    pool: &PgPool,
    node_id: Uuid,
    jid: &str,
) -> Result<Option<PubSubSubscription>> {
    get_subscription_with_executor(pool, node_id, jid).await
}

pub(super) const SUBSCRIPTION_ROW_SQL: &str = "SELECT n.node, s.jid, s.state, s.subid, s.deliver, s.digest, s.digest_frequency, s.expire, s.include_body, s.show_values, s.subscription_type, s.subscription_depth FROM pubsub_subscriptions s JOIN pubsub_nodes n ON n.id = s.node_id WHERE s.node_id = $1 AND s.jid = $2";

pub(super) async fn get_subscription_with_executor<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    node_id: Uuid,
    jid: &str,
) -> Result<Option<PubSubSubscription>> {
    let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
    let row = sqlx::query(SUBSCRIPTION_ROW_SQL)
        .bind(node_id)
        .bind(jid)
        .fetch_optional(executor)
        .await?;
    Ok(row.as_ref().map(row_to_subscription))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn set_subscription_limited(
    pool: &PgPool,
    local_domain: &str,
    node_id: Uuid,
    jid: &str,
    state: &str,
    max_subscriptions: i64,
) -> Result<bool> {
    Ok(set_subscription_limited_with_options(
        pool,
        local_domain,
        node_id,
        jid,
        state,
        max_subscriptions,
        None,
    )
    .await?
    .is_some())
}

/// Creates/renews a subscription and applies its options in one transaction.
/// Options and authorization are checked again under the node and subscription
/// locks before either the subscription or its notification outbox changes.
#[cfg(any(test, feature = "test-support"))]
pub async fn set_subscription_limited_with_options(
    pool: &PgPool,
    local_domain: &str,
    node_id: Uuid,
    jid: &str,
    state: &str,
    max_subscriptions: i64,
    options: Option<&PubSubSubscriptionOptions>,
) -> Result<Option<PubSubSubscription>> {
    let node = get_node_by_id(pool, node_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("PubSub test node does not exist"))?;
    let requester = northstar_xmpp_types::jid::canonical_bare_key(jid)?;
    Ok(
        match set_subscription_limited_with_options_and_outbox(
            pool,
            local_domain,
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
