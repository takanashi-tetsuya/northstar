use super::{lock_account, lock_account_incarnation};
use anyhow::Result;
use northstar_time::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) struct LockedAttempt {
    pub(super) user_id: Uuid,
    pub(super) service_jid: String,
    pub(super) node: String,
    pub(super) expires_at: DateTime<Utc>,
    pub(super) settled_at: DateTime<Utc>,
}

pub(super) async fn lock_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<Option<LockedAttempt>> {
    let Some((user_id, service_jid, node)) = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT user_id, service_jid, node FROM push_delivery_attempts WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await?
    else {
        return Ok(None);
    };
    lock_account_incarnation(transaction, user_id).await?;
    lock_account(transaction, user_id).await?;
    let subscription = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM push_subscriptions
         WHERE user_id = $1 AND service_jid = $2 AND node = $3 FOR UPDATE",
    )
    .bind(user_id)
    .bind(&service_jid)
    .bind(&node)
    .fetch_optional(&mut **transaction)
    .await?;
    if subscription.is_none() {
        return Ok(None);
    }
    let times = sqlx::query_as::<_, (DateTime<Utc>, DateTime<Utc>)>(
        "SELECT expires_at, now() FROM push_delivery_attempts
         WHERE request_id = $1 AND user_id = $2 AND service_jid = $3 AND node = $4 FOR UPDATE",
    )
    .bind(request_id)
    .bind(user_id)
    .bind(&service_jid)
    .bind(&node)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(times.map(|(expires_at, settled_at)| LockedAttempt {
        user_id,
        service_jid,
        node,
        expires_at,
        settled_at,
    }))
}

pub(super) async fn delete_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<()> {
    sqlx::query("DELETE FROM push_delivery_attempts WHERE request_id = $1")
        .bind(request_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}
