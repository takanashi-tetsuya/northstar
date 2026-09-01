use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub const MAX_PUSH_SUBSCRIPTIONS_PER_USER: i64 = 16;
const MAX_ENABLE_ATTEMPTS_PER_MINUTE: i32 = 30;
const NOTIFICATION_COALESCE_SECONDS: i64 = 15;
const DELIVERY_CORRELATION_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushEnableOutcome {
    Enabled,
    QuotaExceeded,
    RateLimited,
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub struct PushTarget {
    pub service_jid: String,
    pub node: String,
}

#[derive(Clone, Debug)]
pub struct PushDelivery {
    pub request_id: Uuid,
    pub service_jid: String,
    pub node: String,
    pub options: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushResponseKind {
    Success,
    PermanentError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushResponseOutcome {
    Completed,
    SubscriptionDisabled,
    SenderMismatch,
    Unknown,
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
    user_id: Uuid,
    service_jid: &str,
    node: &str,
    options: Option<&str>,
) -> Result<PushEnableOutcome> {
    let service_jid = crate::jid::canonicalize_bare(service_jid)?;
    let mut transaction = pool.begin().await?;
    lock_account(&mut transaction, user_id).await?;

    let attempts: i32 = sqlx::query_scalar(
        "INSERT INTO push_enable_rate_limits (user_id, window_started_at, attempts)
         VALUES ($1, NOW(), 1)
         ON CONFLICT (user_id) DO UPDATE SET
           window_started_at = CASE
             WHEN push_enable_rate_limits.window_started_at <= NOW() - INTERVAL '1 minute'
             THEN NOW() ELSE push_enable_rate_limits.window_started_at END,
           attempts = CASE
             WHEN push_enable_rate_limits.window_started_at <= NOW() - INTERVAL '1 minute'
             THEN 1 ELSE push_enable_rate_limits.attempts + 1 END
         RETURNING attempts",
    )
    .bind(user_id)
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

    // A response to an earlier enable generation must never disable or alter
    // freshly supplied credentials for the same target.
    sqlx::query(
        "DELETE FROM push_delivery_attempts
         WHERE user_id = $1 AND service_jid = $2 AND node = $3",
    )
    .bind(user_id)
    .bind(&service_jid)
    .bind(node)
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        "INSERT INTO push_subscriptions
           (user_id, service_jid, node, options, next_notification_at,
            consecutive_failures, updated_at)
         VALUES ($1, $2, $3, $4, '-infinity', 0, NOW())
         ON CONFLICT (user_id, service_jid, node) DO UPDATE SET
           options = EXCLUDED.options,
           next_notification_at = '-infinity',
           consecutive_failures = 0,
           updated_at = NOW()",
    )
    .bind(user_id)
    .bind(&service_jid)
    .bind(node)
    .bind(options)
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
    let service_jid = crate::jid::canonicalize_bare(service_jid)?;
    let result = sqlx::query(
        "DELETE FROM push_subscriptions
         WHERE user_id = $1 AND service_jid = $2
           AND ($3::TEXT IS NULL OR node = $3)",
    )
    .bind(user_id)
    .bind(&service_jid)
    .bind(node)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
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
pub async fn claim_push_deliveries(pool: &PgPool, user_id: Uuid) -> Result<Vec<PushDelivery>> {
    let mut transaction = pool.begin().await?;
    lock_account(&mut transaction, user_id).await?;
    sqlx::query("DELETE FROM push_delivery_attempts WHERE expires_at <= NOW()")
        .execute(&mut *transaction)
        .await?;
    let rows = sqlx::query(
        "SELECT service_jid, node, options
         FROM push_subscriptions
         WHERE user_id = $1 AND next_notification_at <= NOW()
         ORDER BY service_jid, node
         FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut *transaction)
    .await?;
    let now = Utc::now();
    let next = now + Duration::seconds(NOTIFICATION_COALESCE_SECONDS);
    let expires_at = now + Duration::seconds(DELIVERY_CORRELATION_SECONDS);
    let mut deliveries = Vec::with_capacity(rows.len());
    for row in rows {
        let service_jid: String = row.get("service_jid");
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
               (request_id, user_id, service_jid, node, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(request_id)
        .bind(user_id)
        .bind(&service_jid)
        .bind(&node)
        .bind(expires_at)
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
    Ok(deliveries)
}

pub async fn mark_push_unroutable(pool: &PgPool, request_id: Uuid) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let attempt = sqlx::query(
        "DELETE FROM push_delivery_attempts WHERE request_id = $1
         RETURNING user_id, service_jid, node",
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(attempt) = attempt {
        sqlx::query(
            "UPDATE push_subscriptions
             SET next_notification_at = GREATEST(next_notification_at, NOW() + INTERVAL '30 seconds')
             WHERE user_id = $1 AND service_jid = $2 AND node = $3",
        )
        .bind(attempt.get::<Uuid, _>("user_id"))
        .bind(attempt.get::<String, _>("service_jid"))
        .bind(attempt.get::<String, _>("node"))
        .execute(&mut *transaction)
        .await?;
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
    let sender_bare = crate::jid::canonicalize_bare(sender_bare)?;
    let mut transaction = pool.begin().await?;
    let Some(attempt) = sqlx::query(
        "SELECT user_id, service_jid, node, expires_at
         FROM push_delivery_attempts WHERE request_id = $1 FOR UPDATE",
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?
    else {
        transaction.rollback().await?;
        return Ok(PushResponseOutcome::Unknown);
    };
    let service_jid: String = attempt.get("service_jid");
    if service_jid != sender_bare {
        transaction.rollback().await?;
        return Ok(PushResponseOutcome::SenderMismatch);
    }
    let user_id: Uuid = attempt.get("user_id");
    let node: String = attempt.get("node");
    let expires_at: DateTime<Utc> = attempt.get("expires_at");
    if expires_at <= Utc::now() {
        sqlx::query("DELETE FROM push_delivery_attempts WHERE request_id = $1")
            .bind(request_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        return Ok(PushResponseOutcome::Unknown);
    }

    let outcome = match kind {
        PushResponseKind::Success => {
            sqlx::query(
                "UPDATE push_subscriptions
                 SET consecutive_failures = 0, last_success_at = NOW()
                 WHERE user_id = $1 AND service_jid = $2 AND node = $3",
            )
            .bind(user_id)
            .bind(&service_jid)
            .bind(&node)
            .execute(&mut *transaction)
            .await?;
            PushResponseOutcome::Completed
        }
        PushResponseKind::PermanentError => {
            sqlx::query(
                "DELETE FROM push_subscriptions
                 WHERE user_id = $1 AND service_jid = $2 AND node = $3",
            )
            .bind(user_id)
            .bind(&service_jid)
            .bind(&node)
            .execute(&mut *transaction)
            .await?;
            PushResponseOutcome::SubscriptionDisabled
        }
    };
    // This may already have cascaded from a permanent disable.
    sqlx::query("DELETE FROM push_delivery_attempts WHERE request_id = $1")
        .bind(request_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(outcome)
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::db;

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn quota_upsert_and_durable_claim_are_atomic() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("push{}", &suffix[..12]);
        let user = db::create_user(
            &pool,
            &username,
            "test-password-long-enough",
            false,
            false,
            4096,
            false,
        )
        .await
        .unwrap();
        for index in 0..MAX_PUSH_SUBSCRIPTIONS_PER_USER {
            assert_eq!(
                enable_push_subscription(
                    &pool,
                    user.id,
                    "push.example.test",
                    &format!("node-{index}"),
                    None,
                )
                .await
                .unwrap(),
                PushEnableOutcome::Enabled
            );
        }
        assert_eq!(
            enable_push_subscription(&pool, user.id, "push.example.test", "over-quota", None,)
                .await
                .unwrap(),
            PushEnableOutcome::QuotaExceeded
        );
        // Updating an existing target never consumes an additional slot.
        assert_eq!(
            enable_push_subscription(
                &pool,
                user.id,
                "push.example.test",
                "node-0",
                Some("<x xmlns='jabber:x:data' type='submit'/>")
            )
            .await
            .unwrap(),
            PushEnableOutcome::Enabled
        );
        let first = claim_push_deliveries(&pool, user.id).await.unwrap();
        assert_eq!(first.len(), MAX_PUSH_SUBSCRIPTIONS_PER_USER as usize);
        assert!(claim_push_deliveries(&pool, user.id)
            .await
            .unwrap()
            .is_empty());
        let request_id = first[0].request_id;
        assert_eq!(
            complete_push_response(
                &pool,
                request_id,
                "attacker.example.test",
                PushResponseKind::Success
            )
            .await
            .unwrap(),
            PushResponseOutcome::SenderMismatch
        );
        assert_eq!(
            enable_push_subscription(
                &pool,
                user.id,
                "push.example.test",
                "node-0",
                Some("<x xmlns='jabber:x:data' type='submit'/>")
            )
            .await
            .unwrap(),
            PushEnableOutcome::Enabled
        );
        // An old correlated error/result cannot alter a freshly re-enabled
        // target or its new publish credentials.
        assert_eq!(
            complete_push_response(
                &pool,
                request_id,
                "push.example.test",
                PushResponseKind::Success
            )
            .await
            .unwrap(),
            PushResponseOutcome::Unknown
        );
        let renewed = claim_push_deliveries(&pool, user.id).await.unwrap();
        assert_eq!(renewed.len(), 1);
        assert_eq!(renewed[0].node, "node-0");
        assert_eq!(
            complete_push_response(
                &pool,
                renewed[0].request_id,
                "push.example.test",
                PushResponseKind::Success
            )
            .await
            .unwrap(),
            PushResponseOutcome::Completed
        );

        // Migration 0073 permits the wire-level omitted-node sentinel while
        // protocol parsing continues to reject an explicit node=''. It is a
        // distinct unique key and serializes without a fake empty attribute.
        assert_eq!(
            disable_push_subscriptions(&pool, user.id, "push.example.test", Some("node-15"))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            enable_push_subscription(&pool, user.id, "push.example.test", "", None)
                .await
                .unwrap(),
            PushEnableOutcome::Enabled
        );
        let optional = claim_push_deliveries(&pool, user.id).await.unwrap();
        assert_eq!(optional.len(), 1);
        assert!(optional[0].node.is_empty());
        let optional_request_id = optional[0].request_id;
        // Delivery correlation is PostgreSQL authority, not process memory:
        // an IQ error received after a server restart must still disable the
        // exact JID/omitted-node generation.
        pool.close().await;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        assert_eq!(
            complete_push_response(
                &pool,
                optional_request_id,
                "push.example.test",
                PushResponseKind::PermanentError,
            )
            .await
            .unwrap(),
            PushResponseOutcome::SubscriptionDisabled
        );
        assert!(list_push_targets(&pool, user.id)
            .await
            .unwrap()
            .iter()
            .all(|target| target.service_jid == "push.example.test" && !target.node.is_empty()));
        db::delete_user_with_roster(&pool, user.id, "example.test")
            .await
            .unwrap();
    }
}
