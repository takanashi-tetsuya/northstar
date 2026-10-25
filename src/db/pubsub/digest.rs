//! PubSub digest queue persistence.

use super::*;

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
    let subscriber_jid = northstar_xmpp_types::jid::canonicalize(subscriber_jid)?;
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
    let subscriber_jid = northstar_xmpp_types::jid::canonicalize(subscriber_jid)?;
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
