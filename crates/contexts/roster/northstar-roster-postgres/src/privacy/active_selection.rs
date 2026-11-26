use super::list_commands::privacy_list_exists_in_tx;
use super::LOCK_OWNER_FOR_SHARE_SQL;
use anyhow::Result;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub async fn set_active_privacy_list(
    pool: &PgPool,
    owner_id: Uuid,
    connection_id: Uuid,
    name: Option<&str>,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let updated =
        set_active_privacy_list_in_transaction(&mut tx, owner_id, connection_id, name).await?;
    if !updated {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Persist a connection's XEP-0016 selection inside a wider session
/// activation transaction. Callers already holding the authentication row
/// lock can therefore commit SM ownership, FAST state and privacy selection as
/// one unit instead of exposing a successfully resumed route before this write.
pub async fn set_active_privacy_list_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    connection_id: Uuid,
    name: Option<&str>,
) -> Result<bool> {
    // SM finalization already holds this shared authorization lock. Upgrading
    // it would deadlock concurrent resumes for different account resources.
    // List deletion takes the exclusive lock before checking active selections.
    let owner = sqlx::query_scalar::<_, Uuid>(LOCK_OWNER_FOR_SHARE_SQL)
        .bind(owner_id)
        .fetch_optional(&mut **tx)
        .await?;
    if owner.is_none() {
        return Ok(false);
    }
    if let Some(name) = name {
        if !privacy_list_exists_in_tx(tx, owner_id, name).await? {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO privacy_active_sessions(owner_id,connection_id,list_name) VALUES($1,$2,$3) \
             ON CONFLICT(owner_id,connection_id) DO UPDATE \
             SET list_name=EXCLUDED.list_name,updated_at=NOW(),expires_at=NOW()+INTERVAL '24 hours'",
        )
        .bind(owner_id)
        .bind(connection_id)
        .bind(name)
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query("DELETE FROM privacy_active_sessions WHERE owner_id=$1 AND connection_id=$2")
            .bind(owner_id)
            .bind(connection_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(true)
}

pub async fn clear_active_privacy_session(
    pool: &PgPool,
    owner_id: Uuid,
    connection_id: Uuid,
) -> Result<()> {
    sqlx::query("DELETE FROM privacy_active_sessions WHERE owner_id=$1 AND connection_id=$2")
        .bind(owner_id)
        .bind(connection_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn refresh_active_privacy_session(
    pool: &PgPool,
    owner_id: Uuid,
    connection_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "UPDATE privacy_active_sessions SET updated_at=NOW(),expires_at=NOW()+INTERVAL '24 hours' \
         WHERE owner_id=$1 AND connection_id=$2",
    )
    .bind(owner_id)
    .bind(connection_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Renew existing, unexpired selections for connections that own live leases.
pub async fn renew_active_privacy_selection(pool: &PgPool, connection_ids: &[Uuid]) -> Result<()> {
    sqlx::query(
        "UPDATE privacy_active_sessions
            SET updated_at=statement_timestamp(),expires_at=statement_timestamp()+INTERVAL '24 hours'
          WHERE connection_id=ANY($1) AND expires_at>statement_timestamp()",
    )
    .bind(connection_ids)
    .execute(pool)
    .await?;
    Ok(())
}
