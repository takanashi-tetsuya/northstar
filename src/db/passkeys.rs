use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(sqlx::FromRow, Serialize)]
pub(crate) struct Credential {
    pub id: Uuid,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub credential: Value,
    #[serde(skip)]
    pub revision: Uuid,
}

pub(crate) async fn credentials(pool: &PgPool, user: Uuid) -> Result<Vec<Credential>> {
    Ok(sqlx::query_as(
        "SELECT id,label,created_at,last_used_at,credential,revision
        FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at,id LIMIT 10",
    )
    .bind(user)
    .fetch_all(pool)
    .await?)
}

pub(crate) async fn credentials_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Vec<Credential>> {
    Ok(sqlx::query_as(
        "SELECT id,label,created_at,last_used_at,credential,revision
        FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at,id LIMIT 10",
    )
    .bind(user)
    .fetch_all(&mut **tx)
    .await?)
}

pub(crate) async fn challenge(
    pool: &PgPool,
    user: Uuid,
    generation: i64,
    kind: &str,
    session_hash: Option<&[u8]>,
    state: &Value,
) -> Result<Option<Uuid>> {
    Ok(
        sqlx::query_scalar("SELECT northstar_passkey_challenge($1,$2,$3,$4,$5)")
            .bind(user)
            .bind(generation)
            .bind(kind)
            .bind(session_hash)
            .bind(state)
            .fetch_one(pool)
            .await?,
    )
}

#[derive(sqlx::FromRow)]
pub(crate) struct Challenge {
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub state: Value,
}

pub(crate) async fn consume(
    pool: &PgPool,
    id: Uuid,
    kind: &str,
    session_hash: Option<&[u8]>,
) -> Result<Option<Challenge>> {
    Ok(
        sqlx::query_as("SELECT * FROM northstar_passkey_consume($1,$2,$3)")
            .bind(id)
            .bind(kind)
            .bind(session_hash)
            .fetch_optional(pool)
            .await?,
    )
}

pub(crate) async fn register(
    pool: &PgPool,
    user: Uuid,
    generation: i64,
    session_hash: &[u8],
    credential_id: &[u8],
    credential: &Value,
    label: &str,
) -> Result<Option<Uuid>> {
    Ok(
        sqlx::query_scalar("SELECT northstar_passkey_register($1,$2,$3,$4,$5,$6)")
            .bind(user)
            .bind(generation)
            .bind(session_hash)
            .bind(credential_id)
            .bind(credential)
            .bind(label)
            .fetch_one(pool)
            .await?,
    )
}

pub(crate) async fn accept(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    generation: i64,
    id: Uuid,
    revision: Uuid,
    credential: &Value,
    counter: u32,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_passkey_accept($1,$2,$3,$4,$5,$6)")
            .bind(user)
            .bind(generation)
            .bind(id)
            .bind(revision)
            .bind(credential)
            .bind(i64::from(counter))
            .fetch_one(&mut **tx)
            .await?,
    )
}

pub(crate) async fn remove(
    pool: &PgPool,
    user: Uuid,
    generation: i64,
    session_hash: &[u8],
    id: Uuid,
) -> Result<Option<i64>> {
    Ok(
        sqlx::query_scalar("SELECT northstar_passkey_remove($1,$2,$3,$4)")
            .bind(user)
            .bind(generation)
            .bind(session_hash)
            .bind(id)
            .fetch_one(pool)
            .await?,
    )
}

#[cfg(test)]
#[path = "passkeys_test.rs"]
mod tests;
