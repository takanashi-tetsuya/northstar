//! Offline message storage, deduplication capacity and delivery.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineStoreOutcome {
    Stored,
    Replay,
    QuotaExceeded,
    RecipientUnavailable,
}

#[derive(Debug, Clone, Copy)]
pub struct OfflineStorePolicy {
    pub max_messages: i64,
    pub max_bytes: i64,
    pub ttl_days: i64,
    /// True only when the exact stanza is already recoverable from personal
    /// MAM. Bind 2 may discard this duplicate but must retain temporary-only
    /// XEP-0334 no-permanent-store rows.
    pub mam_backed: bool,
}

pub(super) const OFFLINE_DEDUPE_CAPACITY_SHARDS: u8 = 64;
pub(super) const MAX_OFFLINE_DEDUPE_PER_SHARD: i32 = 32_768;
pub(super) const MAX_OFFLINE_DEDUPE_PER_RECIPIENT: i64 = 4_096;
pub(super) const OFFLINE_DEDUPE_FOREGROUND_CLEANUP: i64 = 128;

#[cfg(test)]
pub async fn store_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
) -> Result<OfflineStoreOutcome> {
    store_offline_idempotent_inner(
        pool,
        recipient_id,
        None,
        sender_jid,
        stanza,
        encrypted,
        policy,
        None,
        None,
    )
    .await
}

/// Authority-aware offline storage for application services which may carry
/// an explicit full-JID normal message (notably direct MUC invitations). The
/// resourcepart is derived from the stanza and the supplied bare JID is bound
/// to the recipient UUID before insertion.
pub async fn store_offline_for_recipient(
    pool: &PgPool,
    recipient_id: Uuid,
    recipient_bare_jid: &str,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
) -> Result<OfflineStoreOutcome> {
    store_offline_idempotent_inner(
        pool,
        recipient_id,
        Some(recipient_bare_jid),
        sender_jid,
        stanza,
        encrypted,
        policy,
        None,
        None,
    )
    .await
}

/// Atomically enqueue a temporary offline stanza and retain a compact replay
/// tombstone after transport-confirmed delivery removes the content row. The stable lookup
/// digest contains a random origin/challenge identity but no plaintext JID or
/// stanza. Rotating-key HMAC candidates authenticate the payload; an unknown
/// old key or any content mismatch fails closed instead of creating a second
/// queue entry.
#[cfg(test)]
pub async fn store_offline_idempotent(
    pool: &PgPool,
    recipient_id: Uuid,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
    identity: Option<&crate::services::abuse::MessageDedupeIdentity>,
) -> Result<OfflineStoreOutcome> {
    store_offline_idempotent_inner(
        pool,
        recipient_id,
        None,
        sender_jid,
        stanza,
        encrypted,
        policy,
        identity,
        None,
    )
    .await
}

/// Authority-aware variant of idempotent offline storage. This is the only
/// repository entry point for a potentially resource-affine normal stanza:
/// the target resource is derived from the XML while the target bare JID is
/// checked against the recipient UUID in the same transaction.
#[allow(clippy::too_many_arguments)]
pub async fn store_offline_idempotent_for_recipient(
    pool: &PgPool,
    recipient_id: Uuid,
    recipient_bare_jid: &str,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
    identity: Option<&crate::services::abuse::MessageDedupeIdentity>,
) -> Result<OfflineStoreOutcome> {
    store_offline_idempotent_inner(
        pool,
        recipient_id,
        Some(recipient_bare_jid),
        sender_jid,
        stanza,
        encrypted,
        policy,
        identity,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn store_offline_idempotent_for_recipient_with_direct_fence(
    pool: &PgPool,
    recipient_id: Uuid,
    recipient_bare_jid: &str,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
    identity: Option<&crate::services::abuse::MessageDedupeIdentity>,
    cluster: Option<&crate::cluster::ClusterAdmission>,
) -> Result<OfflineStoreOutcome> {
    let Some(cluster) = cluster else {
        return store_offline_idempotent_for_recipient(
            pool,
            recipient_id,
            recipient_bare_jid,
            sender_jid,
            stanza,
            encrypted,
            policy,
            identity,
        )
        .await;
    };
    store_offline_idempotent_inner(
        pool,
        recipient_id,
        Some(recipient_bare_jid),
        sender_jid,
        stanza,
        encrypted,
        policy,
        identity,
        Some(cluster),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn store_offline_idempotent_inner(
    pool: &PgPool,
    recipient_id: Uuid,
    recipient_bare_jid: Option<&str>,
    sender_jid: &str,
    stanza: &str,
    encrypted: bool,
    policy: OfflineStorePolicy,
    identity: Option<&crate::services::abuse::MessageDedupeIdentity>,
    cluster: Option<&crate::cluster::ClusterAdmission>,
) -> Result<OfflineStoreOutcome> {
    let (recipient_authority, target_resource) =
        normalized_offline_target_resource(stanza, recipient_bare_jid)?;
    if let Some(identity) = identity {
        anyhow::ensure!(
            identity.identity_digest.len() == 32 && !identity.candidates.is_empty(),
            "offline message identity is malformed"
        );
        anyhow::ensure!(
            identity.candidates.iter().all(|candidate| {
                !candidate.key_id.is_empty()
                    && candidate.key_id.len() <= 64
                    && candidate.payload_mac.len() == 32
            }),
            "offline message payload authenticator is malformed"
        );
    }
    let mut transaction = pool.begin().await?;
    if let Some(cluster) = cluster {
        super::super::cluster_keys::lock_direct_spool_instance_claims_in_transaction(
            &mut transaction,
        )
        .await?;
        if let Some(authority) =
            cluster.check_direct_eligibility(crate::cluster::DirectSpoolEligibility::LiveOnly)?
        {
            super::super::fence_direct_message_authority_in_transaction(
                &mut transaction,
                authority,
            )
            .await?;
        }
    }
    // Linearize durable delivery against account disable/delete.  The
    // administrator's FOR UPDATE cannot pass this shared row lock until the
    // queue projection commits, while a disable that won first is observed as
    // unavailable before any admission/tombstone row is created.
    if !super::super::lock_enabled_users_in_transaction(&mut transaction, &[recipient_id]).await? {
        transaction.rollback().await?;
        return Ok(OfflineStoreOutcome::RecipientUnavailable);
    }
    if let Some(recipient_authority) = recipient_authority.as_ref() {
        let recipient = northstar_xmpp_types::jid::CanonicalJid::parse_bare(recipient_authority)?;
        let recipient_matches: bool =
            sqlx::query_scalar("SELECT northstar_lock_enabled_user_name($1,$2)")
                .bind(recipient_id)
                .bind(recipient.localpart().unwrap_or_default())
                .fetch_one(&mut *transaction)
                .await?;
        anyhow::ensure!(
            recipient_matches,
            "offline recipient account is unavailable or authority does not match"
        );
    }
    // The global queue gate gives the administrator clear operation exact
    // snapshot semantics without enumerating recipient locks. Normal enqueue
    // remains concurrent because this is a shared advisory lock.
    sqlx::query("SELECT pg_advisory_xact_lock_shared(5645368709120102)")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 3))")
        .bind(recipient_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *transaction)
        .await?;
    if let Some(identity) = identity {
        // Expired retention can never mask the live key being considered.
        // The trigger releases its capacity slot in this same transaction.
        sqlx::query(
            "DELETE FROM offline_message_admissions
              WHERE identity_digest=$1 AND offline_message_id IS NULL
                AND expires_at IS NOT NULL AND expires_at <= $2",
        )
        .bind(&identity.identity_digest)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        if let Some(row) = sqlx::query(
            "SELECT recipient_id,payload_key_id,payload_mac
               FROM offline_message_admissions
              WHERE identity_digest=$1 FOR UPDATE",
        )
        .bind(&identity.identity_digest)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let stored_key_id: String = row.get("payload_key_id");
            let stored_payload_mac: Vec<u8> = row.get("payload_mac");
            let exact = row.get::<Uuid, _>("recipient_id") == recipient_id
                && identity.candidates.iter().any(|candidate| {
                    candidate.key_id == stored_key_id
                        && bool::from(
                            candidate
                                .payload_mac
                                .as_slice()
                                .ct_eq(stored_payload_mac.as_slice()),
                        )
                });
            anyhow::ensure!(exact, "conflicting offline message identity");
            commit_live_direct_offline_transaction(transaction, cluster, None).await?;
            return Ok(OfflineStoreOutcome::Replay);
        }
    }
    {
        sqlx::query(
            "WITH expired AS MATERIALIZED (
                 SELECT message.id FROM offline_messages message
                  WHERE message.recipient_id=$1
                    AND COALESCE(
                        (SELECT retention.offline_message_days
                           FROM user_retention_policies retention
                          WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                    ) IS NOT NULL
                    AND message.created_at < clock_timestamp()-(
                        COALESCE(
                            (SELECT retention.offline_message_days
                               FROM user_retention_policies retention
                              WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                        )::BIGINT*INTERVAL '1 day')
                    AND (message.delivery_claim_id IS NULL
                         OR message.delivery_claim_expires_at<=clock_timestamp())
                    AND NOT EXISTS (
                        SELECT 1 FROM sm_resume_stanzas sm
                         WHERE sm.delivery_message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM bosh_delivery_fences bosh
                         WHERE bosh.message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM legal_holds hold
                         WHERE hold.released_at IS NULL AND (
                             EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                                      WHERE link.hold_id=hold.id AND link.message_id=message.id)
                             OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                        WHERE scope_link.hold_id=hold.id
                                          AND scope_link.scope_type='offline_message_recipient'
                                          AND scope_link.subject_id=message.recipient_id)
                         )
                    )
                  FOR UPDATE OF message SKIP LOCKED
             )
             DELETE FROM offline_messages message USING expired
              WHERE message.id=expired.id",
        )
        .bind(recipient_id)
        .bind(policy.ttl_days)
        .execute(&mut *transaction)
        .await?;
    }
    let (current_messages, current_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT, COALESCE(SUM(octet_length(stanza)), 0)::BIGINT
           FROM offline_messages WHERE recipient_id = $1",
    )
    .bind(recipient_id)
    .fetch_one(&mut *transaction)
    .await?;
    let stanza_bytes = i64::try_from(stanza.len()).unwrap_or(i64::MAX);
    if current_messages >= policy.max_messages
        || current_bytes
            .checked_add(stanza_bytes)
            .is_none_or(|projected| projected > policy.max_bytes)
    {
        return Ok(OfflineStoreOutcome::QuotaExceeded);
    }
    let offline_message_id = Uuid::new_v4();
    if let Some(identity) = identity {
        let capacity_shard =
            i16::from(identity.identity_digest[0] % OFFLINE_DEDUPE_CAPACITY_SHARDS);
        sqlx::query(
            "WITH doomed AS (
                 SELECT identity_digest FROM offline_message_admissions
                  WHERE capacity_shard=$1 AND offline_message_id IS NULL
                    AND expires_at IS NOT NULL AND expires_at <= $2
                  ORDER BY expires_at,identity_digest
                  LIMIT $3 FOR UPDATE SKIP LOCKED
             )
             DELETE FROM offline_message_admissions AS target
              USING doomed WHERE target.identity_digest=doomed.identity_digest",
        )
        .bind(capacity_shard)
        .bind(now)
        .bind(OFFLINE_DEDUPE_FOREGROUND_CLEANUP)
        .execute(&mut *transaction)
        .await?;
        let recipient_active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM offline_message_admissions
              WHERE recipient_id=$1 AND (expires_at IS NULL OR expires_at > $2)",
        )
        .bind(recipient_id)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await?;
        if recipient_active >= MAX_OFFLINE_DEDUPE_PER_RECIPIENT {
            return Ok(OfflineStoreOutcome::QuotaExceeded);
        }
        let capacity_reserved = sqlx::query_scalar::<_, i32>(
            "UPDATE offline_message_admission_capacity
                SET active_records=active_records+1
              WHERE shard=$1 AND active_records < $2
              RETURNING active_records",
        )
        .bind(capacity_shard)
        .bind(MAX_OFFLINE_DEDUPE_PER_SHARD)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !capacity_reserved {
            return Ok(OfflineStoreOutcome::QuotaExceeded);
        }
        let current = identity
            .candidates
            .first()
            .expect("validated offline dedupe identity has a current HMAC");
        sqlx::query(
            "INSERT INTO offline_message_admissions
             (identity_digest,payload_key_id,recipient_id,offline_message_id,
              capacity_shard,payload_mac,expires_at)
             VALUES($1,$2,$3,$4,$5,$6,
                    CASE WHEN $7::bigint=0 THEN NULL
                         ELSE $8 + (($7 + 1) * INTERVAL '1 day') END)",
        )
        .bind(&identity.identity_digest)
        .bind(&current.key_id)
        .bind(recipient_id)
        .bind(offline_message_id)
        .bind(capacity_shard)
        .bind(&current.payload_mac)
        .bind(policy.ttl_days)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query("INSERT INTO offline_messages (id, recipient_id, sender_jid, stanza, target_resource, encrypted, mam_backed) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(offline_message_id).bind(recipient_id).bind(sender_jid).bind(stanza).bind(target_resource).bind(encrypted).bind(policy.mam_backed)
        .execute(&mut *transaction).await?;
    commit_live_direct_offline_transaction(transaction, cluster, Some(recipient_id)).await?;
    Ok(OfflineStoreOutcome::Stored)
}

pub(super) async fn commit_live_direct_offline_transaction(
    mut transaction: sqlx::Transaction<'_, sqlx::Postgres>,
    cluster: Option<&crate::cluster::ClusterAdmission>,
    wake_recipient: Option<Uuid>,
) -> Result<()> {
    if let Some(cluster) = cluster {
        let (turn, authority) =
            cluster.begin_direct_commit_turn(crate::cluster::DirectSpoolEligibility::LiveOnly)?;
        if let Some(authority) = authority {
            super::super::fence_direct_message_authority_in_transaction(
                &mut transaction,
                authority,
            )
            .await?;
            if let Some(recipient_id) = wake_recipient {
                super::super::direct_spool_wake_repository::record_direct_spool_wake_in_transaction(
                    &mut transaction,
                    &authority.key_identity.xmpp_domain,
                    recipient_id,
                )
                .await?;
            }
        }
        transaction.commit().await?;
        // This legacy offline API has no postcommit mode. Its callers must
        // independently suppress live effects if health changed during COMMIT.
        let _mode = turn.finish();
    } else {
        transaction.commit().await?;
    }
    Ok(())
}

pub(super) fn normalized_offline_target_resource(
    stanza: &str,
    recipient_bare_jid: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let document = roxmltree::Document::parse(stanza)?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "offline projection must contain one message stanza"
    );
    let recipient_authority = recipient_bare_jid
        .map(northstar_xmpp_types::jid::canonicalize_bare)
        .transpose()?;
    if let (Some(raw), Some(canonical)) = (recipient_bare_jid, recipient_authority.as_deref()) {
        anyhow::ensure!(
            raw == canonical,
            "offline recipient authority must be canonical"
        );
    }
    let Some(raw_target) = root.attribute("to") else {
        return Ok((recipient_authority, None));
    };
    let target = northstar_xmpp_types::jid::CanonicalJid::parse(raw_target)?;
    if let Some(recipient_authority) = recipient_authority.as_deref() {
        anyhow::ensure!(
            target.bare() == recipient_authority,
            "offline stanza target does not match recipient authority"
        );
    }
    let target_resource = if root.attribute("type").unwrap_or("normal") == "normal" {
        match target.resourcepart() {
            Some(resource) => {
                anyhow::ensure!(
                    recipient_authority.is_some(),
                    "resource-affine offline delivery requires recipient authority"
                );
                Some(resource.to_owned())
            }
            None => None,
        }
    } else {
        None
    };
    Ok((recipient_authority, target_resource))
}

/// Deliver queued offline messages without deleting a stanza until it has
/// been accepted by the connection's outbound queue. The per-recipient
/// advisory lock prevents two resources that announce presence concurrently
/// from claiming the same rows. If the connection closes or remains
/// backpressured, the unsent suffix stays durable for the next availability
/// transition.
#[cfg(test)]
pub async fn deliver_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::xmpp::outbound::OutboundSender,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    deliver_offline_mode(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        false,
        active_privacy_list,
    )
    .await
}

/// Bind 2 MAM catch-up consumes permanently archived queue duplicates but
/// still delivers temporary-only XEP-0334 no-permanent-store messages.
#[cfg(test)]
pub async fn deliver_bind2_offline(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::xmpp::outbound::OutboundSender,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    deliver_offline_mode(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        true,
        active_privacy_list,
    )
    .await
}

#[cfg(test)]
pub(super) async fn deliver_offline_mode(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::xmpp::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    super::super::replay::deliver_offline_leased(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        bind2_mam_catchup,
        active_privacy_list,
    )
    .await
}

pub async fn offline_message_count(pool: &PgPool, recipient_id: Uuid) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages WHERE recipient_id = $1")
        .bind(recipient_id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}
