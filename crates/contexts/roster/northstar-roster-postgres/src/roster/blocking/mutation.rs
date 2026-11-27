use super::{
    blocked_jids, lock_block_policy_in_transaction, HashSet, MAX_BLOCKED_JIDS_PER_ACCOUNT,
};
use anyhow::Result;
use northstar_roster_application::blocking_mutation::{
    BlockingMutation, BlockingMutationOutcome, BlockingRouteCandidate, CommittedBlockingChange,
};
use northstar_roster_application::RosterActor;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

mod presence_facts;

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
    lock_block_policy_in_transaction(&mut transaction, owner_id).await?;
    let update = insert_blocks(&mut transaction, owner_id, &jids).await?;
    match &update {
        BlockJidsUpdate::Changed(changed) => {
            super::journal::append(&mut transaction, owner_id, "block", changed).await?;
            transaction.commit().await?;
        }
        _ => transaction.rollback().await?,
    }
    Ok(update)
}

async fn insert_blocks(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    jids: &[String],
) -> Result<BlockJidsUpdate> {
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocked_jids WHERE owner_id = $1")
        .bind(owner_id)
        .fetch_one(&mut **transaction)
        .await?;
    let mut changed: Vec<String> = sqlx::query_scalar(
        "INSERT INTO blocked_jids (owner_id, blocked_jid) \
         SELECT $1, requested.jid FROM UNNEST($2::text[]) AS requested(jid) \
         ON CONFLICT DO NOTHING RETURNING blocked_jid",
    )
    .bind(owner_id)
    .bind(jids)
    .fetch_all(&mut **transaction)
    .await?;
    if !changed.is_empty()
        && usize::try_from(existing)
            .unwrap_or(usize::MAX)
            .saturating_add(changed.len())
            > MAX_BLOCKED_JIDS_PER_ACCOUNT
    {
        return Ok(BlockJidsUpdate::QuotaExceeded);
    }
    changed.sort_unstable();
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
    lock_block_policy_in_transaction(&mut transaction, owner_id).await?;
    let changed = delete_blocks(&mut transaction, owner_id, canonical_jids.as_deref()).await?;
    let action = if jids.is_some() {
        "unblock"
    } else {
        "unblock-all"
    };
    super::journal::append(&mut transaction, owner_id, action, &changed).await?;
    transaction.commit().await?;
    Ok(UnblockJidsUpdate::Changed(changed))
}

async fn delete_blocks(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    jids: Option<&[String]>,
) -> Result<Vec<String>> {
    let mut changed: Vec<String> = if let Some(jids) = jids {
        sqlx::query_scalar(
            "DELETE FROM blocked_jids WHERE owner_id = $1 AND blocked_jid = ANY($2) RETURNING blocked_jid",
        )
            .bind(owner_id)
            .bind(jids)
            .fetch_all(&mut **transaction)
            .await?
    } else {
        sqlx::query_scalar("DELETE FROM blocked_jids WHERE owner_id = $1 RETURNING blocked_jid")
            .bind(owner_id)
            .fetch_all(&mut **transaction)
            .await?
    };
    changed.sort_unstable();
    Ok(changed)
}

pub(in super::super) async fn apply_blocking(
    pool: &PgPool,
    actor: &RosterActor,
    mutation: &BlockingMutation,
    route_candidates: &[BlockingRouteCandidate],
) -> Result<BlockingMutationOutcome> {
    use BlockingMutationOutcome::*;

    let Some(mut transaction) = super::super::begin_authorized_roster_mutation(
        pool,
        actor.account_id,
        actor.auth_generation,
    )
    .await?
    else {
        return Ok(Unavailable);
    };
    let requested = mutation
        .patterns()
        .map(|patterns| patterns.iter().map(ToString::to_string).collect::<Vec<_>>());
    let before = blocked_jids(&mut *transaction, actor.account_id).await?;
    let existing = before.iter().map(String::as_str).collect::<HashSet<_>>();
    // Check for a no-op under the owner lock before touching the roster.
    let changes = match mutation {
        BlockingMutation::Block(_) => requested
            .iter()
            .flatten()
            .any(|jid| !existing.contains(jid.as_str())),
        BlockingMutation::Unblock(_) => requested
            .iter()
            .flatten()
            .any(|jid| existing.contains(jid.as_str())),
        BlockingMutation::UnblockAll => !before.is_empty(),
    };
    if changes && !route_candidates.is_empty() {
        sqlx::query(
            "SELECT contact_jid FROM roster_items WHERE owner_id = $1
             ORDER BY contact_jid FOR UPDATE",
        )
        .bind(actor.account_id)
        .execute(&mut *transaction)
        .await?;
    }
    lock_block_policy_in_transaction(&mut transaction, actor.account_id).await?;
    let delta = if !changes {
        Vec::new()
    } else if let BlockingMutation::Block(_) = mutation {
        match insert_blocks(
            &mut transaction,
            actor.account_id,
            requested.as_deref().unwrap_or_default(),
        )
        .await?
        {
            BlockJidsUpdate::Changed(delta) => delta,
            BlockJidsUpdate::QuotaExceeded => {
                transaction.rollback().await?;
                return Ok(QuotaExceeded);
            }
            BlockJidsUpdate::Unavailable => unreachable!("owner already locked"),
        }
    } else {
        delete_blocks(&mut transaction, actor.account_id, requested.as_deref()).await?
    };
    let contacts = if delta.is_empty() || route_candidates.is_empty() {
        Vec::new()
    } else {
        presence_facts::capture(&mut transaction, actor, route_candidates, &before, &delta).await?
    };
    // The revision journal commits with the delta, under the same locks.
    let action = match mutation {
        BlockingMutation::Block(_) => "block",
        BlockingMutation::Unblock(_) => "unblock",
        BlockingMutation::UnblockAll => "unblock-all",
    };
    super::journal::append(&mut transaction, actor.account_id, action, &delta).await?;
    let change = CommittedBlockingChange { delta, contacts };
    transaction.commit().await?;
    Ok(Committed(change))
}
