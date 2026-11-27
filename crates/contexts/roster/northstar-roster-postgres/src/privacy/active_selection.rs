use super::list_commands::privacy_list_exists_in_tx;
use super::LOCK_OWNER_FOR_SHARE_SQL;
use anyhow::Result;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
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
        let _ = sqlx::query(
            "SELECT connection_id FROM privacy_active_sessions
              WHERE owner_id=$1 AND connection_id=$2 FOR UPDATE",
        )
        .bind(owner_id)
        .bind(connection_id)
        .fetch_optional(&mut **tx)
        .await?;
        sqlx::query(
            "WITH observed AS MATERIALIZED (SELECT clock_timestamp() AS at)
             INSERT INTO privacy_active_sessions(owner_id,connection_id,list_name,updated_at,expires_at)
             SELECT $1,$2,$3,at,at+INTERVAL '24 hours' FROM observed
             ON CONFLICT(owner_id,connection_id) DO UPDATE
             SET list_name=EXCLUDED.list_name,updated_at=EXCLUDED.updated_at,expires_at=EXCLUDED.expires_at",
        )
        .bind(owner_id)
        .bind(connection_id)
        .bind(name)
        .execute(&mut **tx)
        .await?;
    } else {
        clear_active_privacy_session(&mut **tx, owner_id, connection_id).await?;
    }
    Ok(true)
}

pub async fn clear_active_privacy_session<'e>(
    executor: impl PgExecutor<'e>,
    owner_id: Uuid,
    connection_id: Uuid,
) -> Result<()> {
    sqlx::query("DELETE FROM privacy_active_sessions WHERE owner_id=$1 AND connection_id=$2")
        .bind(owner_id)
        .bind(connection_id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Compatibility hook for callers moving to read-only policy queries. Only capacity maintenance renews leases.
pub async fn refresh_active_privacy_session(_: &PgPool, _: Uuid, _: Uuid) -> Result<()> {
    Ok(())
}

/// Renew existing, unexpired selections for connections that own live leases.
pub async fn renew_active_privacy_selection<'e>(
    executor: impl PgExecutor<'e>,
    connection_ids: &[Uuid],
) -> Result<()> {
    sqlx::query(
        "WITH locked AS MATERIALIZED (
             SELECT owner_id,connection_id,expires_at FROM privacy_active_sessions
              WHERE connection_id=ANY($1) AND expires_at>statement_timestamp()
              ORDER BY owner_id,connection_id FOR UPDATE
         ), observed AS MATERIALIZED (
             SELECT clock_timestamp() AS at FROM locked HAVING count(*)>0
         )
         UPDATE privacy_active_sessions AS active
            SET updated_at=observed.at,expires_at=observed.at+INTERVAL '24 hours'
           FROM locked CROSS JOIN observed
          WHERE active.owner_id=locked.owner_id AND active.connection_id=locked.connection_id
            AND locked.expires_at>observed.at",
    )
    .bind(connection_ids)
    .execute(executor)
    .await?;
    Ok(())
}

/// Expired rows confer no authority, even if their connection is still live.
pub async fn reap_expired_active_privacy_selections(pool: &PgPool, limit: i64) -> Result<u64> {
    let removed = sqlx::query(
        "WITH expired AS MATERIALIZED (
             SELECT owner_id,connection_id FROM privacy_active_sessions
              WHERE expires_at<=statement_timestamp()
              ORDER BY expires_at,owner_id,connection_id LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM privacy_active_sessions AS active USING expired
          WHERE active.owner_id=expired.owner_id AND active.connection_id=expired.connection_id
            AND active.expires_at<=statement_timestamp()",
    )
    .bind(limit.clamp(1, 10_000))
    .execute(pool)
    .await?;
    Ok(removed.rows_affected())
}
