//! Reads and locks of the `users` table the message context may take.

use anyhow::Result;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Lock a deterministic set of enabled account incarnations for the lifetime
/// of an application-owned write transaction.  Administrative disable/delete
/// takes an exclusive row lock, so a durable projection either commits before
/// that state change or observes the account as unavailable afterwards.
pub async fn lock_enabled_users_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_ids: &[Uuid],
) -> Result<bool> {
    if user_ids.is_empty() {
        return Ok(true);
    }
    let mut user_ids = user_ids.to_vec();
    user_ids.sort_unstable();
    user_ids.dedup();
    let candidates = sqlx::query_as::<_, (Uuid, i64)>(
        "SELECT id,auth_generation FROM users
          WHERE id=ANY($1) AND NOT is_disabled
          ORDER BY id",
    )
    .bind(&user_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if candidates.len() != user_ids.len() {
        return Ok(false);
    }
    for (user_id, generation) in candidates {
        let locked: bool = sqlx::query_scalar("SELECT northstar_lock_auth_generation($1,$2)")
            .bind(user_id)
            .bind(generation)
            .fetch_one(&mut **transaction)
            .await?;
        if !locked {
            return Ok(false);
        }
    }
    Ok(true)
}
