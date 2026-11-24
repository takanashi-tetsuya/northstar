use anyhow::Result;
use northstar_message_application::push::PushBatch;
pub use northstar_message_application::push::{
    PushDelivery, PushEnableOutcome, PushResponseKind, PushResponseOutcome,
};
use northstar_message_core::ActorGenerationFence;
use northstar_time::{DateTime, Duration, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub const MAX_PUSH_SUBSCRIPTIONS_PER_USER: i64 = 16;
const MAX_ENABLE_ATTEMPTS_PER_MINUTE: i32 = 30;
const NOTIFICATION_COALESCE_SECONDS: i64 = 15;
const DELIVERY_CORRELATION_SECONDS: i64 = 300;
const EXPIRED_ATTEMPT_BATCH_SIZE: i64 = 128;

mod settlement;
use settlement::{delete_attempt, lock_attempt};

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub struct PushTarget {
    pub service_jid: String,
    pub node: String,
}

async fn lock_actor(
    transaction: &mut Transaction<'_, Postgres>,
    actor: ActorGenerationFence,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_lock_auth_generation($1,$2)")
            .bind(actor.account_id)
            .bind(actor.auth_generation)
            .fetch_one(&mut **transaction)
            .await?,
    )
}

async fn lock_account_incarnation(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT id FROM northstar_lock_user_rows_key_share(ARRAY[$1::uuid])")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn lock_account(transaction: &mut Transaction<'_, Postgres>, user_id: Uuid) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 7))")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub async fn enable_push_subscription(
    pool: &PgPool,
    actor: ActorGenerationFence,
    service_jid: &str,
    node: &str,
    options: Option<&str>,
) -> Result<PushEnableOutcome> {
    let service_jid = northstar_xmpp_types::jid::canonicalize_bare(service_jid)?;
    let user_id = actor.account_id;
    let mut transaction = pool.begin().await?;
    if !lock_actor(&mut transaction, actor).await? {
        return Ok(PushEnableOutcome::AccountUnavailable);
    }
    lock_account(&mut transaction, user_id).await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&mut *transaction)
        .await?;

    let attempts: i32 = sqlx::query_scalar(
        "INSERT INTO push_enable_rate_limits (user_id, window_started_at, attempts)
         VALUES ($1, $2, 1)
         ON CONFLICT (user_id) DO UPDATE SET
           window_started_at = CASE
             WHEN push_enable_rate_limits.window_started_at <= $2::TIMESTAMPTZ - INTERVAL '1 minute'
             THEN $2 ELSE push_enable_rate_limits.window_started_at END,
           attempts = CASE
             WHEN push_enable_rate_limits.window_started_at <= $2 - INTERVAL '1 minute'
             THEN 1 ELSE push_enable_rate_limits.attempts + 1 END
         RETURNING attempts",
    )
    .bind(user_id)
    .bind(now)
    .fetch_one(&mut *transaction)
    .await?;
    if attempts > MAX_ENABLE_ATTEMPTS_PER_MINUTE {
        transaction.commit().await?;
        return Ok(PushEnableOutcome::RateLimited);
    }

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM push_subscriptions
           WHERE user_id = $1 AND service_jid = $2 AND node = $3
         )",
    )
    .bind(user_id)
    .bind(&service_jid)
    .bind(node)
    .fetch_one(&mut *transaction)
    .await?;
    if !exists {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM push_subscriptions WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&mut *transaction)
                .await?;
        if count >= MAX_PUSH_SUBSCRIPTIONS_PER_USER {
            transaction.commit().await?;
            return Ok(PushEnableOutcome::QuotaExceeded);
        }
    }

    sqlx::query(
        "INSERT INTO push_subscriptions
           (user_id, service_jid, node, options, next_notification_at,
            consecutive_failures, updated_at)
         VALUES ($1, $2, $3, $4, '-infinity', 0, $5)
         ON CONFLICT (user_id, service_jid, node) DO UPDATE SET
           options = EXCLUDED.options,
           next_notification_at = '-infinity',
           consecutive_failures = 0,
           updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(&service_jid)
    .bind(node)
    .bind(options)
    .bind(now)
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        "DELETE FROM push_delivery_attempts
         WHERE user_id = $1 AND service_jid = $2 AND node = $3",
    )
    .bind(user_id)
    .bind(&service_jid)
    .bind(node)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(PushEnableOutcome::Enabled)
}

pub async fn disable_push_subscriptions(
    pool: &PgPool,
    user_id: Uuid,
    service_jid: &str,
    node: Option<&str>,
) -> Result<u64> {
    let mut transaction = pool.begin().await?;
    lock_account_incarnation(&mut transaction, user_id).await?;
    let removed =
        disable_subscriptions_in_transaction(&mut transaction, user_id, service_jid, node).await?;
    transaction.commit().await?;
    Ok(removed)
}

pub async fn disable_owned_push_subscriptions(
    pool: &PgPool,
    actor: ActorGenerationFence,
    service_jid: &str,
    node: Option<&str>,
) -> Result<Option<u64>> {
    let mut transaction = pool.begin().await?;
    if !lock_actor(&mut transaction, actor).await? {
        return Ok(None);
    }
    let removed =
        disable_subscriptions_in_transaction(&mut transaction, actor.account_id, service_jid, node)
            .await?;
    transaction.commit().await?;
    Ok(Some(removed))
}

async fn disable_subscriptions_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    service_jid: &str,
    node: Option<&str>,
) -> Result<u64> {
    let service_jid = northstar_xmpp_types::jid::canonicalize_bare(service_jid)?;
    lock_account(transaction, user_id).await?;
    delete_subscriptions(transaction, user_id, &service_jid, node).await
}

async fn delete_subscriptions(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    service_jid: &str,
    node: Option<&str>,
) -> Result<u64> {
    let result = sqlx::query(
        "DELETE FROM push_subscriptions
         WHERE user_id = $1 AND service_jid = $2
           AND ($3::TEXT IS NULL OR node = $3)",
    )
    .bind(user_id)
    .bind(service_jid)
    .bind(node)
    .execute(&mut **transaction)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn list_push_targets(pool: &PgPool, user_id: Uuid) -> Result<Vec<PushTarget>> {
    let rows = sqlx::query(
        "SELECT service_jid, node
         FROM push_subscriptions
         WHERE user_id = $1
         ORDER BY service_jid, node",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PushTarget {
            service_jid: row.get("service_jid"),
            node: row.get("node"),
        })
        .collect())
}

/// Atomically coalesce bursts and reserve a durable correlation id before a
/// notification is handed to a local session, another cluster node, or S2S.
pub async fn claim_push_deliveries(pool: &PgPool, user_id: Uuid) -> Result<PushBatch> {
    sqlx::query(
        "WITH expired AS (
             SELECT request_id FROM push_delivery_attempts WHERE expires_at <= now()
             ORDER BY expires_at, request_id LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM push_delivery_attempts AS attempt USING expired
          WHERE attempt.request_id = expired.request_id",
    )
    .bind(EXPIRED_ATTEMPT_BATCH_SIZE)
    .execute(pool)
    .await?;

    let mut transaction = pool.begin().await?;
    lock_account_incarnation(&mut transaction, user_id).await?;
    lock_account(&mut transaction, user_id).await?;
    let rows = sqlx::query(
        "WITH snapshot AS MATERIALIZED (
             SELECT now() AS claimed_at,
                    (SELECT COUNT(*) FROM offline_messages WHERE recipient_id = $1) AS message_count,
                    (SELECT COUNT(*) FROM pending_presence_subscriptions WHERE recipient_id = $1) +
                    (SELECT COUNT(*) FROM federated_presence_pending WHERE recipient_id = $1)
                        AS pending_subscription_count
         )
         SELECT snapshot.*, eligible.service_jid, eligible.node, eligible.options
           FROM snapshot LEFT JOIN LATERAL (
             SELECT service_jid, node, options FROM push_subscriptions
              WHERE user_id = $1 AND next_notification_at <= snapshot.claimed_at
              ORDER BY service_jid, node FOR UPDATE
           ) AS eligible ON TRUE
          ORDER BY eligible.service_jid, eligible.node",
    )
    .bind(user_id)
    .fetch_all(&mut *transaction)
    .await?;
    let snapshot = &rows[0];
    let now: DateTime<Utc> = snapshot.get("claimed_at");
    let message_count = snapshot.get("message_count");
    let pending_subscription_count = snapshot.get("pending_subscription_count");
    let next = now + Duration::seconds(NOTIFICATION_COALESCE_SECONDS);
    let expires_at = now + Duration::seconds(DELIVERY_CORRELATION_SECONDS);
    let mut deliveries = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(service_jid) = row.get::<Option<String>, _>("service_jid") else {
            continue;
        };
        let node: String = row.get("node");
        let options: Option<String> = row.get("options");
        let request_id = Uuid::new_v4();
        sqlx::query(
            "UPDATE push_subscriptions SET next_notification_at = $4
             WHERE user_id = $1 AND service_jid = $2 AND node = $3",
        )
        .bind(user_id)
        .bind(&service_jid)
        .bind(&node)
        .bind(next)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO push_delivery_attempts
               (request_id, user_id, service_jid, node, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(request_id)
        .bind(user_id)
        .bind(&service_jid)
        .bind(&node)
        .bind(expires_at)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        deliveries.push(PushDelivery {
            request_id,
            service_jid,
            node,
            options,
        });
    }
    transaction.commit().await?;
    Ok(PushBatch {
        message_count,
        pending_subscription_count,
        deliveries,
    })
}

pub async fn validate_push_handoff(
    pool: &PgPool,
    user_id: Uuid,
    delivery: &PushDelivery,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM push_delivery_attempts AS attempt
             JOIN push_subscriptions AS subscription USING (user_id, service_jid, node)
             WHERE attempt.request_id = $1 AND attempt.user_id = $2
               AND attempt.service_jid = $3 AND attempt.node = $4
               AND subscription.options IS NOT DISTINCT FROM $5
               AND attempt.expires_at > now()
         )",
    )
    .bind(delivery.request_id)
    .bind(user_id)
    .bind(&delivery.service_jid)
    .bind(&delivery.node)
    .bind(delivery.options.as_deref())
    .fetch_one(pool)
    .await?)
}

pub async fn mark_push_unroutable(pool: &PgPool, request_id: Uuid) -> Result<()> {
    let mut transaction = pool.begin().await?;
    if let Some(attempt) = lock_attempt(&mut transaction, request_id).await? {
        sqlx::query(
            "UPDATE push_subscriptions
             SET next_notification_at = GREATEST(next_notification_at, $4::TIMESTAMPTZ + INTERVAL '30 seconds')
             WHERE user_id = $1 AND service_jid = $2 AND node = $3",
        )
        .bind(attempt.user_id)
        .bind(attempt.service_jid)
        .bind(attempt.node)
        .bind(attempt.settled_at)
        .execute(&mut *transaction)
        .await?;
        delete_attempt(&mut transaction, request_id).await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn complete_push_response(
    pool: &PgPool,
    request_id: Uuid,
    sender_bare: &str,
    kind: PushResponseKind,
) -> Result<PushResponseOutcome> {
    let sender_bare = northstar_xmpp_types::jid::canonicalize_bare(sender_bare)?;
    let mut transaction = pool.begin().await?;
    let Some(attempt) = lock_attempt(&mut transaction, request_id).await? else {
        transaction.rollback().await?;
        return Ok(PushResponseOutcome::Unknown);
    };
    if attempt.service_jid != sender_bare {
        transaction.rollback().await?;
        return Ok(PushResponseOutcome::SenderMismatch);
    }
    if attempt.expires_at <= attempt.settled_at {
        delete_attempt(&mut transaction, request_id).await?;
        transaction.commit().await?;
        return Ok(PushResponseOutcome::Unknown);
    }

    let outcome = match kind {
        PushResponseKind::Success => {
            sqlx::query(
                "UPDATE push_subscriptions
                 SET consecutive_failures = 0, last_success_at = $4
                 WHERE user_id = $1 AND service_jid = $2 AND node = $3",
            )
            .bind(attempt.user_id)
            .bind(&attempt.service_jid)
            .bind(&attempt.node)
            .bind(attempt.settled_at)
            .execute(&mut *transaction)
            .await?;
            delete_attempt(&mut transaction, request_id).await?;
            PushResponseOutcome::Completed
        }
        PushResponseKind::PermanentError => {
            delete_subscriptions(
                &mut transaction,
                attempt.user_id,
                &attempt.service_jid,
                Some(&attempt.node),
            )
            .await?;
            PushResponseOutcome::SubscriptionDisabled
        }
    };
    transaction.commit().await?;
    Ok(outcome)
}
