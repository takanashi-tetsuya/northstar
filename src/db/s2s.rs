use anyhow::{Context, Result};

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use sqlx::{Postgres, Transaction};
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

const OUTBOX_ADVISORY_LOCK: i64 = 0x4e53_5332_534f_5554;
static OUTBOX_CAPACITY_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub use northstar_federation_core::{
    ExpiredS2sOutboxItem, S2sOutboxItem, S2sOutboxPolicy, MAX_S2S_STANZA_BYTES,
};

/// One internally consistent PostgreSQL view of the durable delivery queue.
///
/// `due_rows` counts only unlocked, unexpired domain heads which a dispatcher
/// could claim now. Successors hidden behind a per-domain head-of-line item do
/// not make the queue look healthier than it is. Component rows remain part of
/// the global totals and are also broken out separately.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct S2sOutboxSnapshot {
    pub pending_rows: i64,
    pub pending_bytes: i64,
    pub oldest_age_seconds: f64,
    pub due_rows: i64,
    pub locked_rows: i64,
    pub component_pending_rows: i64,
}

pub fn s2s_outbox_capacity_rejections_total() -> u64 {
    OUTBOX_CAPACITY_REJECTIONS_TOTAL.load(Ordering::Relaxed)
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
    let target_domain = crate::jid::prepare_domainpart(target_domain)
        .context("federation target domain is invalid")?;
    if stanza.is_empty() || stanza.len() > MAX_S2S_STANZA_BYTES {
        anyhow::bail!("federation stanza must contain 1 byte to 1 MiB");
    }
    let bounce_to = bounce_to
        .map(crate::jid::canonicalize)
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
        OUTBOX_CAPACITY_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("durable federation outbox reached its global capacity");
    }

    let domain_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM s2s_outbox WHERE target_domain = $1 AND expires_at > NOW()",
    )
    .bind(&target_domain)
    .fetch_one(&mut **transaction)
    .await?;
    if domain_count >= policy.max_per_domain {
        OUTBOX_CAPACITY_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
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
    let authority = crate::jid::CanonicalJid::parse(from)
        .context("federation message from JID is invalid")?
        .bare();
    let sanitized = crate::xmpp::xml_util::strip_stanza_ids_by_domain(
        stanza,
        crate::jid::CanonicalJid::parse(&authority)
            .expect("authority was parsed above")
            .domainpart(),
    );
    Ok(crate::xmpp::xml_util::add_stanza_id(
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
mod tests {
    use super::*;

    #[test]
    fn durable_message_retries_keep_one_authoritative_identity() {
        let outbox_id = Uuid::from_u128(0x1234);
        let input = "<message from='Alice@Example.COM/Phone' to='bob@remote.test'><stanza-id xmlns='urn:xmpp:sid:0' by='alice@example.com' id='forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='mallory@example.com' id='same-domain-forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='remote.test' id='peer-id'/><body>hello</body></message>";

        let first = durable_federation_stanza(input, outbox_id).unwrap();
        let retry = durable_federation_stanza(input, outbox_id).unwrap();
        assert_eq!(first, retry, "the same outbox row must retry identically");

        let document = roxmltree::Document::parse(&first).unwrap();
        let ids = document
            .root_element()
            .children()
            .filter(|child| {
                child.is_element()
                    && child.tag_name().namespace() == Some("urn:xmpp:sid:0")
                    && child.tag_name().name() == "stanza-id"
            })
            .map(|child| {
                (
                    child.attribute("by").unwrap().to_owned(),
                    child.attribute("id").unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&("remote.test".to_owned(), "peer-id".to_owned())));
        assert!(ids.contains(&("alice@example.com".to_owned(), outbox_id.to_string())));
        assert!(!first.contains("forged"));
        assert!(!first.contains("same-domain-forged"));
    }

    #[test]
    fn non_message_outbox_stanzas_are_not_rewritten() {
        let iq = "<iq from='alice@example.com' to='remote.test' type='get' id='one'/>";
        assert_eq!(
            durable_federation_stanza(iq, Uuid::from_u128(7)).unwrap(),
            iq
        );
    }

    #[test]
    fn durable_messages_require_an_identity_authority() {
        let error = durable_federation_stanza("<message><body>hello</body></message>", Uuid::nil())
            .unwrap_err();
        assert!(error.to_string().contains("missing its from address"));
    }

    #[test]
    fn retry_delay_is_bounded_exponential_with_jitter() {
        let id = Uuid::from_u128(0x1234);
        let one = retry_delay_seconds(1, 5, 3600, id);
        let two = retry_delay_seconds(2, 5, 3600, id);
        let ten = retry_delay_seconds(20, 5, 3600, id);
        assert!((5..=6).contains(&one));
        assert!((10..=12).contains(&two));
        assert!(two > one);
        assert_eq!(ten, 3600);
    }

    #[test]
    fn utf8_error_truncation_does_not_split_a_character() {
        let error = "x".repeat(2047) + "界";
        let truncated = truncate_utf8(&error, 2048);
        assert_eq!(truncated.len(), 2047);
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn claim_preserves_mam_results_before_fin() {
        use std::time::Duration;

        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("s2s_ordering_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        eprintln!("isolated_schema_created={schema}");
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let domain = format!("ordering-{}.invalid", Uuid::new_v4());
        let admitted = [
            "<message from='archive@local.test' id='mam-result-1'/>",
            "<message from='archive@local.test' id='mam-result-2'/>",
            "<iq from='local.test' id='mam-fin'/>",
        ];
        for stanza in admitted {
            enqueue_s2s_outbox(&pool, &domain, stanza, None, 300, 100, 1024 * 1024, 100)
                .await
                .unwrap();
        }
        for expected_id in ["mam-result-1", "mam-result-2", "mam-fin"] {
            let claimed = claim_due_s2s_outbox(&pool, 10_000, 60).await.unwrap();
            let ours = claimed
                .into_iter()
                .filter(|item| item.target_domain == domain)
                .collect::<Vec<_>>();
            assert_eq!(ours.len(), 1, "only the domain head may be leased");
            assert!(ours[0].stanza.contains(&format!("id='{expected_id}'")));
            assert!(complete_s2s_outbox(&pool, ours[0].id, ours[0].lock_token)
                .await
                .unwrap());
        }
        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn scoped_claims_are_cross_worker_ordered_and_component_safe() {
        use std::time::Duration;

        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("s2s_outbox_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        eprintln!("isolated_schema_created={schema}");
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(6)
            .acquire_timeout(Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let policy = S2sOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 100,
            max_bytes: 1_000_000,
            max_per_domain: 100,
        };
        for (domain, stanza) in [
            (
                "a.remote.test",
                "<message from='sender@local.test' id='a1'/>",
            ),
            (
                "a.remote.test",
                "<message from='sender@local.test' id='a2'/>",
            ),
            (
                "b.remote.test",
                "<message from='sender@local.test' id='b1'/>",
            ),
            (
                "gateway.local.test",
                "<message from='sender@local.test' id='component'/>",
            ),
        ] {
            let mut transaction = pool.begin().await.unwrap();
            enqueue_s2s_outbox_in_transaction(&mut transaction, domain, stanza, None, policy)
                .await
                .unwrap();
            transaction.commit().await.unwrap();
        }

        let component_domains = vec!["gateway.local.test".to_owned()];
        let snapshot = s2s_outbox_snapshot(&pool, &component_domains)
            .await
            .unwrap();
        assert_eq!(snapshot.pending_rows, 4);
        assert!(snapshot.pending_bytes > 0);
        assert!(snapshot.oldest_age_seconds >= 0.0);
        assert_eq!(snapshot.due_rows, 3, "only one head per domain is due");
        assert_eq!(snapshot.locked_rows, 0);
        assert_eq!(snapshot.component_pending_rows, 1);
        let federated = claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains)
            .await
            .unwrap();
        assert_eq!(federated.len(), 2, "one head from each remote domain");
        assert!(federated.iter().any(|item| item.stanza.contains("a1")));
        assert!(federated.iter().any(|item| item.stanza.contains("b1")));
        assert!(!federated.iter().any(|item| item.stanza.contains("a2")));
        assert!(!federated
            .iter()
            .any(|item| item.target_domain == "gateway.local.test"));

        let competing = claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains)
            .await
            .unwrap();
        assert!(
            competing.is_empty(),
            "another cluster worker must not overtake leased domain heads"
        );

        let a1 = federated
            .iter()
            .find(|item| item.target_domain == "a.remote.test")
            .unwrap();
        assert!(
            renew_s2s_outbox_lease(&pool, a1.id, a1.lock_token, 120)
                .await
                .unwrap(),
            "the owning worker must be able to fence and renew its lease"
        );
        assert!(
            !renew_s2s_outbox_lease(&pool, a1.id, Uuid::new_v4(), 120)
                .await
                .unwrap(),
            "a stale worker token must not revive another worker's lease"
        );
        sqlx::query(
            "UPDATE s2s_outbox SET locked_until = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(a1.id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            !renew_s2s_outbox_lease(&pool, a1.id, a1.lock_token, 120)
                .await
                .unwrap(),
            "an expired claim must not be revived even when its old fencing token remains"
        );
        assert_eq!(
            fail_s2s_outbox(&pool, a1, "injected outage", 60, 60, 5, false)
                .await
                .unwrap(),
            S2sFailureDisposition::RetryScheduled
        );
        let b1 = federated
            .iter()
            .find(|item| item.target_domain == "b.remote.test")
            .unwrap();
        assert!(complete_s2s_outbox(&pool, b1.id, b1.lock_token)
            .await
            .unwrap());

        let component = claim_due_s2s_outbox_for_domains(&pool, 10, 60, &component_domains)
            .await
            .unwrap();
        assert_eq!(component.len(), 1);
        assert_eq!(component[0].target_domain, "gateway.local.test");
        assert!(
            complete_s2s_outbox(&pool, component[0].id, component[0].lock_token)
                .await
                .unwrap()
        );

        // A scheduled retry is the domain head and therefore blocks a2.
        assert!(
            claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains,)
                .await
                .unwrap()
                .is_empty()
        );
        sqlx::query(
            "UPDATE s2s_outbox SET next_attempt_at=NOW() WHERE target_domain='a.remote.test'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let retried = claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains)
            .await
            .unwrap();
        assert_eq!(retried.len(), 1);
        assert!(retried[0].stanza.contains("a1"));
        assert!(
            complete_s2s_outbox(&pool, retried[0].id, retried[0].lock_token)
                .await
                .unwrap()
        );
        let successor = claim_due_s2s_outbox_excluding_domains(&pool, 10, 60, &component_domains)
            .await
            .unwrap();
        assert_eq!(successor.len(), 1);
        assert!(successor[0].stanza.contains("a2"));
        assert!(
            complete_s2s_outbox(&pool, successor[0].id, successor[0].lock_token)
                .await
                .unwrap()
        );

        // Two user actions can legally produce byte-identical XML (including
        // stanzas without an id). They are two admissions, not a dedupe key.
        for _ in 0..2 {
            let mut transaction = pool.begin().await.unwrap();
            enqueue_s2s_outbox_in_transaction(
                &mut transaction,
                "duplicates.remote.test",
                "<message from='sender@local.test'><body>same</body></message>",
                None,
                policy,
            )
            .await
            .unwrap();
            transaction.commit().await.unwrap();
        }
        let duplicates: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='duplicates.remote.test'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            duplicates, 2,
            "byte-identical stanzas must not be collapsed"
        );

        let rejected_before = s2s_outbox_capacity_rejections_total();
        let mut transaction = pool.begin().await.unwrap();
        let rejected = enqueue_s2s_outbox_in_transaction(
            &mut transaction,
            "capacity.remote.test",
            "<message from='sender@local.test'/>",
            None,
            S2sOutboxPolicy {
                max_rows: 0,
                ..policy
            },
        )
        .await;
        assert!(rejected.is_err());
        transaction.rollback().await.unwrap();
        assert!(s2s_outbox_capacity_rejections_total() > rejected_before);

        // A claimed head remains durable across a process/pool restart. Once
        // its lease expires, a new worker receives the same row with a fresh
        // fencing token; a stale pre-crash token can no longer complete it.
        let mut transaction = pool.begin().await.unwrap();
        enqueue_s2s_outbox_in_transaction(
            &mut transaction,
            "restart.remote.test",
            "<message from='sender@local.test' id='restart-head'/>",
            None,
            policy,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        let before_restart =
            claim_due_s2s_outbox_excluding_domains(&pool, 10, 1, &component_domains)
                .await
                .unwrap()
                .into_iter()
                .find(|item| item.target_domain == "restart.remote.test")
                .expect("restart test head was not claimed");
        pool.close().await;
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let restart_schema = schema.clone();
        let restarted_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(6)
            .acquire_timeout(Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {restart_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        let after_restart =
            claim_due_s2s_outbox_excluding_domains(&restarted_pool, 10, 60, &component_domains)
                .await
                .unwrap()
                .into_iter()
                .find(|item| item.target_domain == "restart.remote.test")
                .expect("expired pre-restart lease was not reclaimed");
        assert_eq!(after_restart.id, before_restart.id);
        assert_ne!(after_restart.lock_token, before_restart.lock_token);
        assert!(
            !complete_s2s_outbox(
                &restarted_pool,
                before_restart.id,
                before_restart.lock_token,
            )
            .await
            .unwrap(),
            "a pre-restart fencing token completed a reclaimed row"
        );
        assert!(
            complete_s2s_outbox(&restarted_pool, after_restart.id, after_restart.lock_token)
                .await
                .unwrap()
        );
        restarted_pool.close().await;

        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
