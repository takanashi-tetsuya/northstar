//! Implement XEP-0191 blocklist persistence, limits, canonicalization, policy locking, and indexed matching.

use super::HashSet;
use anyhow::Result;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

mod candidates;
pub(super) mod journal;
mod mutation;

pub use candidates::{
    blocked_jid_matches, blocked_local_accounts_for_candidates, blocking_match_candidates,
};
pub(super) use mutation::apply_blocking;
pub use mutation::{
    block_jids, canonical_blocking_jids, lock_enabled_block_owner_in_transaction, unblock_jids,
    BlockJidsUpdate, UnblockJidsUpdate,
};

pub async fn blocked_jids<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    owner_id: Uuid,
) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT blocked_jid FROM blocked_jids WHERE owner_id = $1 ORDER BY blocked_jid",
    )
    .bind(owner_id)
    .fetch_all(executor)
    .await?;
    Ok(rows.iter().map(|row| row.get("blocked_jid")).collect())
}

pub async fn lock_block_policy_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
) -> Result<()> {
    // XEP-0191 block/unblock and profile audience snapshots use this exact
    // seed. Subscription admission takes it only after account/roster locks.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(owner_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub async fn is_blocked_for_account_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    owner_bare_jid: &str,
    candidate: &str,
) -> Result<bool> {
    let owner = northstar_xmpp_types::jid::CanonicalJid::parse_bare(owner_bare_jid)?;
    let candidate = northstar_xmpp_types::jid::CanonicalJid::parse(candidate)?;
    if candidate.localpart().is_some() && candidate.bare() == owner.bare() {
        return Ok(false);
    }
    is_blocked_candidates(&mut **transaction, owner_id, &candidate).await
}

/// A deliberately generous account-level ceiling. Existing deployments that
/// already exceed it remain readable and can always unblock entries; only new
/// additions are refused.
pub const MAX_BLOCKED_JIDS_PER_ACCOUNT: usize = 1024;

pub async fn is_blocked_for_account(
    pool: &PgPool,
    owner_id: Uuid,
    owner_bare_jid: &str,
    candidate: &str,
) -> Result<bool> {
    let owner = northstar_xmpp_types::jid::CanonicalJid::parse_bare(owner_bare_jid)?;
    let candidate = northstar_xmpp_types::jid::CanonicalJid::parse(candidate)?;
    // XEP-0191 forbids blocking communication between two resources of the
    // same account, even when a broader domain rule matches.
    if candidate.localpart().is_some() && candidate.bare() == owner.bare() {
        return Ok(false);
    }
    is_blocked_candidates(pool, owner_id, &candidate).await
}

/// Fast indexed XEP-0191 lookup for contexts that cannot represent traffic
/// between two resources of the owner (PEP, MIX, and other service actors).
pub async fn is_blocked<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    candidate: &str,
) -> Result<bool> {
    let candidate = northstar_xmpp_types::jid::CanonicalJid::parse(candidate)?;
    is_blocked_candidates(executor, owner_id, &candidate).await
}

pub async fn is_blocked_candidates<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    owner_id: Uuid,
    candidate: &northstar_xmpp_types::jid::CanonicalJid,
) -> Result<bool> {
    let candidates = blocking_match_candidates(candidate);
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM blocked_jids \
         WHERE owner_id = $1 AND blocked_jid = ANY($2::text[]))",
    )
    .bind(owner_id)
    .bind(&candidates)
    .fetch_one(executor)
    .await
    .map_err(Into::into)
}
