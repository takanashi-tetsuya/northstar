//! Implement XEP-0191 blocklist persistence, limits, canonicalization, policy locking, and indexed matching.

use super::*;

pub async fn blocked_jids(pool: &PgPool, owner_id: Uuid) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT blocked_jid FROM blocked_jids WHERE owner_id = $1 ORDER BY blocked_jid",
    )
    .bind(owner_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(|row| row.get("blocked_jid")).collect())
}

pub(super) async fn lock_block_policy_in_transaction(
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

pub(super) async fn is_blocked_for_account_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    owner_bare_jid: &str,
    candidate: &str,
) -> Result<bool> {
    let owner = crate::jid::CanonicalJid::parse_bare(owner_bare_jid)?;
    let candidate = crate::jid::CanonicalJid::parse(candidate)?;
    if candidate.localpart().is_some() && candidate.bare() == owner.bare() {
        return Ok(false);
    }
    let candidates = blocking_match_candidates(&candidate);
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM blocked_jids
          WHERE owner_id=$1 AND blocked_jid=ANY($2::text[]))",
    )
    .bind(owner_id)
    .bind(candidates)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

/// A deliberately generous account-level ceiling. Existing deployments that
/// already exceed it remain readable and can always unblock entries; only new
/// additions are refused.
pub const MAX_BLOCKED_JIDS_PER_ACCOUNT: usize = 1024;

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

pub(super) async fn lock_enabled_block_owner_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
          WHERE id=$1 AND NOT is_disabled FOR UPDATE",
    )
    .bind(owner_id)
    .fetch_optional(&mut **transaction)
    .await?
    .is_some())
}

pub(super) fn canonical_blocking_jids(jids: &[String]) -> Result<Vec<String>> {
    let mut seen = HashSet::with_capacity(jids.len());
    let mut canonical = Vec::with_capacity(jids.len());
    for jid in jids {
        let jid = crate::jid::canonicalize(jid)?;
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

pub async fn is_blocked_for_account(
    pool: &PgPool,
    owner_id: Uuid,
    owner_bare_jid: &str,
    candidate: &str,
) -> Result<bool> {
    let owner = crate::jid::CanonicalJid::parse_bare(owner_bare_jid)?;
    let candidate = crate::jid::CanonicalJid::parse(candidate)?;
    // XEP-0191 forbids blocking communication between two resources of the
    // same account, even when a broader domain rule matches.
    if candidate.localpart().is_some() && candidate.bare() == owner.bare() {
        return Ok(false);
    }
    is_blocked_candidates(pool, owner_id, &candidate).await
}

/// Fast indexed XEP-0191 lookup for contexts that cannot represent traffic
/// between two resources of the owner (PEP, MIX, and other service actors).
pub async fn is_blocked(pool: &PgPool, owner_id: Uuid, candidate: &str) -> Result<bool> {
    let candidate = crate::jid::CanonicalJid::parse(candidate)?;
    is_blocked_candidates(pool, owner_id, &candidate).await
}

pub(super) async fn is_blocked_candidates(
    pool: &PgPool,
    owner_id: Uuid,
    candidate: &crate::jid::CanonicalJid,
) -> Result<bool> {
    let candidates = blocking_match_candidates(candidate);
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM blocked_jids \
         WHERE owner_id = $1 AND blocked_jid = ANY($2::text[]))",
    )
    .bind(owner_id)
    .bind(&candidates)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Resolve a MUC broadcast's local blocked recipients with one indexed query,
/// rather than issuing one blocklist query per occupant. Returned values are
/// canonical bare account JIDs. Remote occupants are deliberately omitted;
/// their home server applies XEP-0191 to the room/nick sender.
pub async fn blocked_local_accounts_for_candidates(
    pool: &PgPool,
    local_domain: &str,
    occupant_jids: &[String],
    stanza_senders: &[String],
) -> Result<HashSet<String>> {
    let local_domain = crate::jid::prepare_domainpart(local_domain)?;
    let mut usernames = occupant_jids
        .iter()
        .filter_map(|jid| crate::jid::CanonicalJid::parse(jid).ok())
        .filter(|jid| jid.domainpart() == local_domain)
        .filter_map(|jid| jid.localpart().map(str::to_owned))
        .collect::<Vec<_>>();
    usernames.sort_unstable();
    usernames.dedup();
    if usernames.is_empty() || stanza_senders.is_empty() {
        return Ok(HashSet::new());
    }
    let senders = stanza_senders
        .iter()
        .map(|sender| crate::jid::CanonicalJid::parse(sender))
        .collect::<Result<Vec<_>>>()?;
    let mut lookup_keys = senders
        .iter()
        .flat_map(blocking_match_candidates)
        .collect::<Vec<_>>();
    lookup_keys.sort_unstable();
    lookup_keys.dedup();
    let rows = sqlx::query(
        "SELECT u.username, b.blocked_jid FROM users u \
         JOIN blocked_jids b ON b.owner_id=u.id \
         WHERE u.username=ANY($1::text[]) AND b.blocked_jid=ANY($2::text[])",
    )
    .bind(&usernames)
    .bind(&lookup_keys)
    .fetch_all(pool)
    .await?;
    let mut blocked = HashSet::new();
    for row in rows {
        let username: String = row.get("username");
        let pattern: String = row.get("blocked_jid");
        let owner = format!("{username}@{local_domain}");
        if senders.iter().any(|sender| {
            !(sender.localpart().is_some() && sender.bare() == owner)
                && blocked_jid_matches(&pattern, &sender.to_string())
        }) {
            blocked.insert(owner);
        }
    }
    Ok(blocked)
}

pub(super) fn blocking_match_candidates(candidate: &crate::jid::CanonicalJid) -> Vec<String> {
    let mut candidates = Vec::with_capacity(4);
    if let Some(resource) = candidate.resourcepart() {
        candidates.push(candidate.to_string());
        if candidate.localpart().is_some() {
            candidates.push(candidate.bare());
        }
        candidates.push(format!("{}/{}", candidate.domainpart(), resource));
    } else if candidate.localpart().is_some() {
        candidates.push(candidate.bare());
    }
    candidates.push(candidate.domainpart().to_owned());
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

pub(crate) fn blocked_jid_matches(pattern: &str, candidate: &str) -> bool {
    northstar_xmpp_types::jid_scope_matches(pattern, candidate)
}
