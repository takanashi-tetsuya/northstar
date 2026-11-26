use super::{HashSet, MAX_BLOCKED_JIDS_PER_ACCOUNT};
use anyhow::Result;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockJidsUpdate {
    Changed(Vec<String>),
    QuotaExceeded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnblockJidsUpdate {
    Changed(Vec<String>),
    Unavailable,
}

pub async fn lock_enabled_block_owner_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
) -> Result<bool> {
    // The runtime role has no UPDATE on users, so the exclusive account lock
    // goes through the reviewed row-lock capability.
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM northstar_lock_user_rows_update(ARRAY[$1::uuid]) locked
          WHERE NOT locked.is_disabled",
    )
    .bind(owner_id)
    .fetch_optional(&mut **transaction)
    .await?
    .is_some())
}

pub fn canonical_blocking_jids(jids: &[String]) -> Result<Vec<String>> {
    let mut seen = HashSet::with_capacity(jids.len());
    let mut canonical = Vec::with_capacity(jids.len());
    for jid in jids {
        let jid = northstar_xmpp_types::jid::canonicalize(jid)?;
        if seen.insert(jid.clone()) {
            canonical.push(jid);
        }
    }
    Ok(canonical)
}

pub async fn block_jids(pool: &PgPool, owner_id: Uuid, jids: &[String]) -> Result<BlockJidsUpdate> {
    let jids = canonical_blocking_jids(jids)?;
    let mut transaction = pool.begin().await?;
    // Global account-row ordering is users -> block-policy advisory -> DML.
    // The blocked_jids FK can otherwise acquire a user key-share lock after
    // the advisory lock and deadlock with subscription admission, which owns
    // the user row while waiting for this advisory lock.
    if !lock_enabled_block_owner_in_transaction(&mut transaction, owner_id).await? {
        transaction.rollback().await?;
        return Ok(BlockJidsUpdate::Unavailable);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(owner_id)
        .execute(&mut *transaction)
        .await?;
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocked_jids WHERE owner_id = $1")
        .bind(owner_id)
        .fetch_one(&mut *transaction)
        .await?;
    let mut changed: Vec<String> = sqlx::query_scalar(
        "INSERT INTO blocked_jids (owner_id, blocked_jid) \
         SELECT $1, requested.jid FROM UNNEST($2::text[]) AS requested(jid) \
         ON CONFLICT DO NOTHING RETURNING blocked_jid",
    )
    .bind(owner_id)
    .bind(&jids)
    .fetch_all(&mut *transaction)
    .await?;
    if !changed.is_empty()
        && usize::try_from(existing)
            .unwrap_or(usize::MAX)
            .saturating_add(changed.len())
            > MAX_BLOCKED_JIDS_PER_ACCOUNT
    {
        transaction.rollback().await?;
        return Ok(BlockJidsUpdate::QuotaExceeded);
    }
    changed.sort_unstable();
    transaction.commit().await?;
    Ok(BlockJidsUpdate::Changed(changed))
}

pub async fn unblock_jids(
    pool: &PgPool,
    owner_id: Uuid,
    jids: Option<&[String]>,
) -> Result<UnblockJidsUpdate> {
    let canonical_jids = jids.map(canonical_blocking_jids).transpose()?;
    let mut transaction = pool.begin().await?;
    if !lock_enabled_block_owner_in_transaction(&mut transaction, owner_id).await? {
        transaction.rollback().await?;
        return Ok(UnblockJidsUpdate::Unavailable);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(owner_id)
        .execute(&mut *transaction)
        .await?;
    let mut changed: Vec<String> = if let Some(jids) = canonical_jids.as_deref() {
        sqlx::query_scalar(
            "DELETE FROM blocked_jids WHERE owner_id = $1 AND blocked_jid = ANY($2) RETURNING blocked_jid",
        )
            .bind(owner_id)
            .bind(jids)
            .fetch_all(&mut *transaction)
            .await?
    } else {
        sqlx::query_scalar("DELETE FROM blocked_jids WHERE owner_id = $1 RETURNING blocked_jid")
            .bind(owner_id)
            .fetch_all(&mut *transaction)
            .await?
    };
    changed.sort_unstable();
    transaction.commit().await?;
    Ok(UnblockJidsUpdate::Changed(changed))
}
