//! The account rows room persistence reads and locks. Writes to `users` belong to the auth context.

use anyhow::Result;
use northstar_auth_core::normalize_username;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

/// An account that exists and is enabled. A disabled account is indistinguishable from a missing one.
#[derive(Clone, Debug)]
pub struct EnabledAccount {
    pub id: Uuid,
    pub username: String,
}

fn enabled_account(row: sqlx::postgres::PgRow) -> EnabledAccount {
    EnabledAccount {
        id: row.get("id"),
        username: row.get("username"),
    }
}

pub async fn find_enabled_user(pool: &PgPool, username: &str) -> Result<Option<EnabledAccount>> {
    let Ok(username) = normalize_username(username) else {
        return Ok(None);
    };
    Ok(
        sqlx::query("SELECT id,username FROM users WHERE username=$1 AND NOT is_disabled")
            .bind(username)
            .fetch_optional(pool)
            .await?
            .map(enabled_account),
    )
}

pub async fn find_enabled_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<EnabledAccount>> {
    Ok(
        sqlx::query("SELECT id,username FROM users WHERE id=$1 AND NOT is_disabled")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .map(enabled_account),
    )
}

pub async fn enabled_user_id(pool: &PgPool, username: &str) -> Result<Option<Uuid>> {
    Ok(find_enabled_user(pool, username).await?.map(|user| user.id))
}

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
