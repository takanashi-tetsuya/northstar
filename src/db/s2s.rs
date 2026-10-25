use crate::platform::delivery_counters::S2S_OUTBOX_CAPACITY_REJECTIONS_TOTAL;
use anyhow::{Context, Result};

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use sqlx::{Postgres, Transaction};
use std::sync::atomic::Ordering;
use uuid::Uuid;

const OUTBOX_ADVISORY_LOCK: i64 = 0x4e53_5332_534f_5554;
pub use northstar_federation_core::{
    ExpiredS2sOutboxItem, S2sOutboxItem, S2sOutboxPolicy, MAX_S2S_STANZA_BYTES,
};

/// One internally consistent PostgreSQL view of the durable delivery queue.
///
/// `due_rows` counts only unlocked, unexpired domain heads which a dispatcher
/// could claim now. Successors hidden behind a per-domain head-of-line item do
/// not make the queue look healthier than it is. Component rows remain part of
/// the global totals and are also broken out separately.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct S2sOutboxSnapshot {
    pub pending_rows: i64,
    pub pending_bytes: i64,
    pub oldest_age_seconds: f64,
    pub due_rows: i64,
    pub locked_rows: i64,
    pub component_pending_rows: i64,
}

#[cfg(test)]
pub async fn s2s_outbox_snapshot(
    pool: &PgPool,
    component_domains: &[String],
) -> Result<S2sOutboxSnapshot> {
    let row = sqlx::query(
        "WITH active AS MATERIALIZED (
            SELECT target_domain, stanza, created_at, next_attempt_at,
                   locked_until, enqueue_sequence
            FROM s2s_outbox
            WHERE expires_at > NOW()
        ), domain_heads AS (
            SELECT DISTINCT ON (target_domain)
                   target_domain, next_attempt_at, locked_until
            FROM active
            ORDER BY target_domain, enqueue_sequence
        )
        SELECT
            (SELECT COUNT(*)::BIGINT FROM active) AS pending_rows,
            (SELECT COALESCE(SUM(octet_length(stanza)), 0)::BIGINT FROM active) AS pending_bytes,
            (SELECT COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(created_at))), 0)::DOUBLE PRECISION FROM active) AS oldest_age_seconds,
            (SELECT COUNT(*)::BIGINT FROM active WHERE locked_until > NOW()) AS locked_rows,
            (SELECT COUNT(*)::BIGINT FROM active WHERE target_domain = ANY($1::TEXT[])) AS component_pending_rows,
            (SELECT COUNT(*)::BIGINT FROM domain_heads
             WHERE next_attempt_at <= NOW()
               AND (locked_until IS NULL OR locked_until <= NOW())) AS due_rows",
    )
    .bind(component_domains)
    .fetch_one(pool)
    .await?;

    Ok(S2sOutboxSnapshot {
        pending_rows: row.try_get("pending_rows")?,
        pending_bytes: row.try_get("pending_bytes")?,
        oldest_age_seconds: row.try_get::<f64, _>("oldest_age_seconds")?.max(0.0),
        due_rows: row.try_get("due_rows")?,
        locked_rows: row.try_get("locked_rows")?,
        component_pending_rows: row.try_get("component_pending_rows")?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S2sFailureDisposition {
    RetryScheduled,
    Expired,
    Dropped,
    LeaseLost,
}

/// Observation of one target's FIFO head for a process-local authenticated
/// route recovery hint. This is not a delivery lease or routing authority.
/// Keep stanza contents out of Debug output; the caller must validate their
/// exact source and target against the authenticated connection before waking.
pub(crate) struct S2sRouteRecoveryHead {
    pub(crate) id: Uuid,
    pub(crate) target_domain: String,
    pub(crate) stanza: String,
    pub(crate) attempt_count: i32,
    pub(crate) retry_due: bool,
    pub(crate) claim_in_flight: bool,
}

/// Observe the oldest unexpired row even while it is leased or in backoff.
/// Filtering either state would let a recovery hint bind to a successor.
pub(crate) async fn s2s_route_recovery_head(
    pool: &PgPool,
    canonical_target: &str,
) -> Result<Option<S2sRouteRecoveryHead>> {
    let row = sqlx::query(
        "SELECT id, target_domain, stanza, attempt_count,
                next_attempt_at <= NOW() AS retry_due,
                (lock_token IS NOT NULL OR COALESCE(locked_until > NOW(), FALSE)) AS claim_in_flight
         FROM s2s_outbox
         WHERE target_domain = $1 AND expires_at > NOW()
         ORDER BY enqueue_sequence
         LIMIT 1",
    )
    .bind(canonical_target)
    .fetch_optional(pool)
    .await?;
    row.map(|row| {
        Ok(S2sRouteRecoveryHead {
            id: row.try_get("id")?,
            target_domain: row.try_get("target_domain")?,
            stanza: row.try_get("stanza")?,
            attempt_count: row.try_get("attempt_count")?,
            retry_due: row.try_get("retry_due")?,
            claim_in_flight: row.try_get("claim_in_flight")?,
        })
    })
    .transpose()
}

/// Accelerate only the observed, unleased FIFO head and attempt. The caller
/// owns the one-use authenticated-route hint; ordinary claiming still owns
/// token creation, attempt accounting, FIFO, and every delivery decision.
/// A lease, including an expired token not yet cleared by its owner, is never
/// modified here. A later failure/claim cannot be mistaken for this attempt.
pub(crate) async fn wake_s2s_route_recovery_head(
    pool: &PgPool,
    id: Uuid,
    target_domain: &str,
    expected_attempt: i32,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE s2s_outbox AS current
         SET next_attempt_at = NOW()
         WHERE current.id = $1 AND current.target_domain = $2
           AND current.attempt_count = $3
           AND current.expires_at > NOW()
           AND current.lock_token IS NULL
           AND (current.locked_until IS NULL OR current.locked_until <= NOW())
           AND current.next_attempt_at > NOW()
           AND NOT EXISTS (
               SELECT 1 FROM s2s_outbox AS earlier
               WHERE earlier.target_domain = current.target_domain
                 AND earlier.expires_at > NOW()
                 AND earlier.enqueue_sequence < current.enqueue_sequence
           )",
    )
    .bind(id)
    .bind(target_domain)
    .bind(expected_attempt)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

#[allow(clippy::too_many_arguments)]
pub async fn enqueue_s2s_outbox(
    pool: &PgPool,
    target_domain: &str,
    stanza: &str,
    bounce_to: Option<&str>,
    ttl_seconds: u64,
    max_rows: i64,
    max_bytes: i64,
    max_per_domain: i64,
) -> Result<Uuid> {
    let policy = S2sOutboxPolicy {
        ttl_seconds,
        max_rows,
        max_bytes,
        max_per_domain,
    };
    let mut transaction = pool.begin().await?;
    let id = enqueue_s2s_outbox_in_transaction(
        &mut transaction,
        target_domain,
        stanza,
        bounce_to,
        policy,
    )
    .await?;
    transaction.commit().await?;
    Ok(id)
}

/// Insert an outbox row as part of a caller-owned transaction.  Protocols
/// whose durable state changes when a federated stanza is accepted (notably
/// RFC 6121 presence subscriptions) MUST use this function so an outbox quota
/// failure or process crash cannot commit only half of the operation.
pub async fn enqueue_s2s_outbox_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    target_domain: &str,
    stanza: &str,
    bounce_to: Option<&str>,
    policy: S2sOutboxPolicy,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    enqueue_s2s_outbox_with_id_in_transaction(
        transaction,
        id,
        target_domain,
        stanza,
        bounce_to,
        policy,
    )
    .await?;
    Ok(id)
}

/// Insert a caller-allocated outbox identity. Personal-message admission uses
/// this variant so its XEP-0359 identity row can reference the exact durable
/// federation projection before the deferred foreign key is checked at
/// commit. All other callers should use `enqueue_s2s_outbox_in_transaction`.
pub(crate) async fn enqueue_s2s_outbox_with_id_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
    target_domain: &str,
    stanza: &str,
    bounce_to: Option<&str>,
    policy: S2sOutboxPolicy,
) -> Result<()> {
    let target_domain = northstar_xmpp_types::jid::prepare_domainpart(target_domain)
        .context("federation target domain is invalid")?;
    if stanza.is_empty() || stanza.len() > MAX_S2S_STANZA_BYTES {
        anyhow::bail!("federation stanza must contain 1 byte to 1 MiB");
    }
    let bounce_to = bounce_to
        .map(northstar_xmpp_types::jid::canonicalize)
        .transpose()
        .context("federation bounce address is invalid")?;
    // XMPP does not define byte-identical stanzas as duplicates.  Every
    // admission therefore receives its own durable identity; retries operate
    // on that row and never re-enqueue by content.  The legacy column name is
    // retained for migration compatibility, but its value is an admission
    // key rather than a payload fingerprint.
    let stanza = durable_federation_stanza(stanza, id)?;
    if stanza.len() > MAX_S2S_STANZA_BYTES {
        anyhow::bail!("federation stanza exceeds 1 MiB after server identity stamping");
    }
    let admission_key = Sha256::digest(id.as_bytes());
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(OUTBOX_ADVISORY_LOCK)
        .execute(&mut **transaction)
        .await?;

    let totals = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS row_count, COALESCE(SUM(octet_length(stanza)), 0)::BIGINT AS byte_count FROM s2s_outbox WHERE expires_at > NOW()",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let row_count: i64 = totals.try_get("row_count")?;
    let byte_count: i64 = totals.try_get("byte_count")?;
    let stanza_bytes = i64::try_from(stanza.len()).context("federation stanza is too large")?;
    if row_count >= policy.max_rows || byte_count.saturating_add(stanza_bytes) > policy.max_bytes {
        S2S_OUTBOX_CAPACITY_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("durable federation outbox reached its global capacity");
    }

    let domain_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM s2s_outbox WHERE target_domain = $1 AND expires_at > NOW()",
    )
    .bind(&target_domain)
    .fetch_one(&mut **transaction)
    .await?;
    if domain_count >= policy.max_per_domain {
        S2S_OUTBOX_CAPACITY_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("durable federation outbox reached its per-domain capacity");
    }

    sqlx::query(
        "INSERT INTO s2s_outbox (id, target_domain, bounce_to, stanza, dedupe_hash, expires_at) VALUES ($1, $2, $3, $4, $5, NOW() + ($6 * INTERVAL '1 second'))",
    )
    .bind(id)
    .bind(&target_domain)
    .bind(bounce_to)
    .bind(&stanza)
    .bind(admission_key.as_slice())
    .bind(i64::try_from(policy.ttl_seconds).context("S2S outbox TTL is too large")?)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Give every durable message one server-authoritative XEP-0359 identity
/// derived from its outbox row. Socket retries therefore carry byte-identical
/// identity, allowing conforming peers (and Northstar's inbound admission)
/// to suppress a write-before-delete replay without guessing from content.
fn durable_federation_stanza(stanza: &str, outbox_id: Uuid) -> Result<String> {
    let document = roxmltree::Document::parse(stanza).context("federation stanza is malformed")?;
    let root = document.root_element();
    if root.tag_name().name() != "message" {
        return Ok(stanza.to_owned());
    }
    let from = root
        .attribute("from")
        .context("durable federation message is missing its from address")?;
    let authority = northstar_xmpp_types::jid::CanonicalJid::parse(from)
        .context("federation message from JID is invalid")?
        .bare();
    let sanitized = crate::services::xml_util::strip_stanza_ids_by_domain(
        stanza,
        northstar_xmpp_types::jid::CanonicalJid::parse(&authority)
            .expect("authority was parsed above")
            .domainpart(),
    );
    Ok(crate::services::xml_util::add_stanza_id(
        &sanitized, &authority, outbox_id,
    ))
}

#[cfg(test)]
pub async fn claim_due_s2s_outbox(
    pool: &PgPool,
    batch_size: i64,
    lease_seconds: u64,
) -> Result<Vec<S2sOutboxItem>> {
    claim_due_s2s_outbox_scoped(pool, batch_size, lease_seconds, &[], &[]).await
}

/// Claim only rows whose target is one of `domains`.  External-component
/// sessions use this pull model so a component connected to one cluster node
/// is never pre-empted by a federation dispatcher on another node.
pub async fn claim_due_s2s_outbox_for_domains(
    pool: &PgPool,
    batch_size: i64,
    lease_seconds: u64,
    domains: &[String],
) -> Result<Vec<S2sOutboxItem>> {
    if domains.is_empty() {
        return Ok(Vec::new());
    }
    claim_due_s2s_outbox_scoped(pool, batch_size, lease_seconds, domains, &[]).await
}

/// Claim rows except for the supplied domains.  The normal S2S dispatcher
/// excludes configured component domains; connected component sessions claim
/// those rows directly with `claim_due_s2s_outbox_for_domains`.
pub async fn claim_due_s2s_outbox_excluding_domains(
    pool: &PgPool,
    batch_size: i64,
    lease_seconds: u64,
    excluded_domains: &[String],
) -> Result<Vec<S2sOutboxItem>> {
    claim_due_s2s_outbox_scoped(pool, batch_size, lease_seconds, &[], excluded_domains).await
}

async fn claim_due_s2s_outbox_scoped(
    pool: &PgPool,
    batch_size: i64,
    lease_seconds: u64,
    included_domains: &[String],
    excluded_domains: &[String],
) -> Result<Vec<S2sOutboxItem>> {
    let lock_token = Uuid::new_v4();
    let rows = sqlx::query(
        "WITH candidates AS (
            SELECT current.id
            FROM s2s_outbox AS current
            WHERE current.expires_at > NOW()
              AND current.next_attempt_at <= NOW()
              AND (current.locked_until IS NULL OR current.locked_until <= NOW())
              AND ($4::BOOLEAN OR current.target_domain = ANY($5::TEXT[]))
              AND ($6::BOOLEAN OR NOT (current.target_domain = ANY($7::TEXT[])))
              AND NOT EXISTS (
                  SELECT 1
                  FROM s2s_outbox AS earlier
                  WHERE earlier.target_domain = current.target_domain
                    AND earlier.expires_at > NOW()
                    AND earlier.enqueue_sequence < current.enqueue_sequence
              )
            ORDER BY current.next_attempt_at, current.enqueue_sequence
            FOR UPDATE OF current SKIP LOCKED
            LIMIT $1
        ), claimed AS (
            UPDATE s2s_outbox AS outbox
            SET locked_until = NOW() + ($2 * INTERVAL '1 second'),
                lock_token = $3,
                attempt_count = outbox.attempt_count + 1
            FROM candidates
            WHERE outbox.id = candidates.id
            RETURNING outbox.id, outbox.target_domain, outbox.bounce_to, outbox.stanza,
                      outbox.attempt_count, outbox.lock_token, outbox.enqueue_sequence
        )
        SELECT id, target_domain, bounce_to, stanza, attempt_count, lock_token
        FROM claimed
        ORDER BY enqueue_sequence",
    )
    .bind(batch_size)
    .bind(i64::try_from(lease_seconds).context("S2S outbox lease is too large")?)
    .bind(lock_token)
    .bind(included_domains.is_empty())
    .bind(included_domains)
    .bind(excluded_domains.is_empty())
    .bind(excluded_domains)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(S2sOutboxItem {
                id: row.try_get("id")?,
                target_domain: row.try_get("target_domain")?,
                bounce_to: row.try_get("bounce_to")?,
                stanza: row.try_get("stanza")?,
                attempt_count: row.try_get("attempt_count")?,
                lock_token: row.try_get("lock_token")?,
            })
        })
        .collect()
}

pub async fn complete_s2s_outbox(pool: &PgPool, id: Uuid, lock_token: Uuid) -> Result<bool> {
    Ok(
        sqlx::query("DELETE FROM s2s_outbox WHERE id = $1 AND lock_token = $2")
            .bind(id)
            .bind(lock_token)
            .execute(pool)
            .await?
            .rows_affected()
            == 1,
    )
}

/// A terminal MIX-PAM response may remove its request before the peer's SM
/// acknowledgement reaches us. That response is authoritative for this exact
/// request, so its later transport acknowledgement can advance the stream.
/// A live row still requires the original fenced token.
pub(crate) async fn complete_s2s_outbox_for_sm(
    pool: &PgPool,
    id: Uuid,
    lock_token: Uuid,
) -> Result<bool> {
    if complete_s2s_outbox(pool, id, lock_token).await? {
        return Ok(true);
    }
    // Run this as a fresh statement so it observes a terminal-response
    // transaction that won the race against the fenced DELETE above.
    sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM s2s_outbox WHERE id = $1)
            AND EXISTS (
                SELECT 1 FROM mix_pam_operations
                WHERE request_outbox_id = $1 AND state = 'terminal'
            )",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Extend an active delivery lease while DNS, TLS and authentication are in
/// progress. The token predicate is the fencing boundary: a worker which no
/// longer owns the exact claim can never revive it.
pub async fn renew_s2s_outbox_lease(
    pool: &PgPool,
    id: Uuid,
    lock_token: Uuid,
    lease_seconds: u64,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE s2s_outbox
         SET locked_until = NOW() + ($3 * INTERVAL '1 second')
         WHERE id = $1 AND lock_token = $2
           AND locked_until > NOW()
           AND expires_at > NOW()",
    )
    .bind(id)
    .bind(lock_token)
    .bind(i64::try_from(lease_seconds).context("S2S outbox lease is too large")?)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

#[allow(clippy::too_many_arguments)]
pub async fn fail_s2s_outbox(
    pool: &PgPool,
    item: &S2sOutboxItem,
    error: &str,
    retry_base_seconds: u64,
    retry_max_seconds: u64,
    max_attempts: i32,
    permanent: bool,
) -> Result<S2sFailureDisposition> {
    let error = truncate_utf8(error, 2048);
    if permanent || item.attempt_count >= max_attempts {
        let deleted = sqlx::query("DELETE FROM s2s_outbox WHERE id = $1 AND lock_token = $2")
            .bind(item.id)
            .bind(item.lock_token)
            .execute(pool)
            .await?
            .rows_affected();
        return Ok(if deleted == 1 {
            S2sFailureDisposition::Dropped
        } else {
            S2sFailureDisposition::LeaseLost
        });
    }

    let delay = retry_delay_seconds(
        item.attempt_count,
        retry_base_seconds,
        retry_max_seconds,
        item.id,
    );
    let updated = sqlx::query(
        "UPDATE s2s_outbox
         SET locked_until = NULL, lock_token = NULL,
             next_attempt_at = NOW() + ($3 * INTERVAL '1 second'), last_error = $4
         WHERE id = $1 AND lock_token = $2 AND expires_at > NOW()",
    )
    .bind(item.id)
    .bind(item.lock_token)
    .bind(i64::try_from(delay).context("S2S retry delay is too large")?)
    .bind(error)
    .execute(pool)
    .await?
    .rows_affected();
    if updated == 1 {
        return Ok(S2sFailureDisposition::RetryScheduled);
    }

    let deleted = sqlx::query("DELETE FROM s2s_outbox WHERE id = $1 AND lock_token = $2")
        .bind(item.id)
        .bind(item.lock_token)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(if deleted == 1 {
        S2sFailureDisposition::Expired
    } else {
        S2sFailureDisposition::LeaseLost
    })
}

pub async fn expire_s2s_outbox(pool: &PgPool, limit: i64) -> Result<Vec<ExpiredS2sOutboxItem>> {
    let rows = sqlx::query(
        "WITH expired AS (
            SELECT id FROM s2s_outbox
            WHERE expires_at <= NOW()
            ORDER BY expires_at, id
            FOR UPDATE SKIP LOCKED
            LIMIT $1
        )
        DELETE FROM s2s_outbox AS outbox
        USING expired
        WHERE outbox.id = expired.id
        RETURNING outbox.id, outbox.target_domain, outbox.bounce_to, outbox.stanza,
                  outbox.attempt_count, outbox.created_at",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ExpiredS2sOutboxItem {
                id: row.try_get("id")?,
                target_domain: row.try_get("target_domain")?,
                bounce_to: row.try_get("bounce_to")?,
                stanza: row.try_get("stanza")?,
                attempt_count: row.try_get("attempt_count")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}

pub(crate) fn retry_delay_seconds(
    attempt_count: i32,
    base_seconds: u64,
    max_seconds: u64,
    id: Uuid,
) -> u64 {
    let exponent = u32::try_from(attempt_count.saturating_sub(1))
        .unwrap_or_default()
        .min(31);
    let exponential = base_seconds
        .saturating_mul(1_u64 << exponent)
        .min(max_seconds);
    let jitter_window = (exponential / 4).max(1);
    let bytes = id.as_bytes();
    let seed = u16::from_be_bytes([bytes[0], bytes[1]]) as u64;
    exponential
        .saturating_add(seed % (jitter_window + 1))
        .min(max_seconds)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests;
