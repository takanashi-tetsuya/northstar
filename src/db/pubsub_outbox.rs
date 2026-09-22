use anyhow::{Context, Result};
use chrono::Utc;
pub use northstar_pubsub_core::{
    security_sensitive_pep_node, ClaimedPubSubOutboxDelivery, PepOutboxAuthorizationMode,
    PepOutboxEventKind, PepOutboxSubject, PubSubOutboxDeliveryKind, PubSubOutboxFailureDisposition,
    PubSubOutboxInsert, PubSubOutboxSnapshot, PubSubOutboxSource,
};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};
use uuid::Uuid;

pub const PUBSUB_OUTBOX_MAX_ATTEMPTS: i32 = 20;
const PUBSUB_OUTBOX_LEASE_SECONDS: i64 = 30;

static CAPACITY_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static DEAD_LETTERS_TOTAL: AtomicU64 = AtomicU64::new(0);
static LEASE_LOST_TOTAL: AtomicU64 = AtomicU64::new(0);
static RETRIES_TOTAL: AtomicU64 = AtomicU64::new(0);
static UNVERIFIABLE_PEP_DROPS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Insert an immutable audience snapshot inside the caller's mutation
/// transaction. A capacity error aborts the mutation: accepting a state change
/// without its required event is never an allowed degradation.
pub async fn enqueue_pubsub_outbox_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    deliveries: &[PubSubOutboxInsert],
) -> Result<()> {
    if deliveries.is_empty() {
        return Ok(());
    }
    let mut sequences = HashMap::<(String, Uuid), i64>::new();
    for delivery in deliveries {
        anyhow::ensure!(
            match delivery.delivery_kind {
                PubSubOutboxDeliveryKind::PepStanza => {
                    delivery.source == PubSubOutboxSource::Pep
                        && delivery.pep_subject.is_some()
                        && !delivery.legacy_unverifiable
                }
                _ =>
                    delivery.source != PubSubOutboxSource::Pep
                        && delivery.pep_subject.is_none()
                        && !delivery.legacy_unverifiable,
            },
            "PubSub outbox delivery lacks its required structured identity"
        );
        let key = (delivery.ordering_key.clone(), delivery.event_id);
        if !sequences.contains_key(&key) {
            let sequence: i64 = sqlx::query_scalar(
                "INSERT INTO pubsub_event_streams(ordering_key,next_sequence) VALUES($1,2)
                 ON CONFLICT(ordering_key) DO UPDATE
                    SET next_sequence=pubsub_event_streams.next_sequence+1,
                        updated_at=clock_timestamp()
                 RETURNING next_sequence-1",
            )
            .bind(&delivery.ordering_key)
            .fetch_one(&mut **transaction)
            .await?;
            sequences.insert(key.clone(), sequence);
        }
        let sequence = sequences[&key];
        let shard = i16::from(delivery.delivery_id.as_bytes()[0] & 63);
        let result = sqlx::query(
            "INSERT INTO pubsub_event_outbox(
                 delivery_id,event_id,ordering_key,event_sequence,source_kind,source_node,delivery_kind,
                 recipient_jid,target_domain,payload_xml,payload_digest,show_values,
                 subscription_node_id,digest_frequency_ms,
                 security_sensitive,coalesce_key,capacity_shard,expires_at,
                 pep_sender_account_id,pep_sender_bare_jid,pep_sender_connection_id,
                 pep_recipient_account_id,pep_recipient_is_local,pep_event_kind,pep_authorization_mode,
                 pep_legacy_unverifiable)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                    $19,$20,$21,$22,$23,$24,$25,$26)",
        )
        .bind(delivery.delivery_id)
        .bind(delivery.event_id)
        .bind(&delivery.ordering_key)
        .bind(sequence)
        .bind(delivery.source.as_str())
        .bind(&delivery.source_node)
        .bind(delivery.delivery_kind.as_str())
        .bind(&delivery.recipient_jid)
        .bind(&delivery.target_domain)
        .bind(&delivery.payload_xml)
        .bind(delivery.payload_digest.as_slice())
        .bind(&delivery.show_values)
        .bind(delivery.subscription_node_id)
        .bind(delivery.digest_frequency_ms)
        .bind(delivery.security_sensitive)
        .bind(&delivery.coalesce_key)
        .bind(shard)
        .bind(delivery.expires_at)
        .bind(
            delivery
                .pep_subject
                .as_ref()
                .map(|subject| subject.sender_account_id),
        )
        .bind(
            delivery
                .pep_subject
                .as_ref()
                .map(|subject| subject.sender_bare_jid.as_str()),
        )
        .bind(
            delivery
                .pep_subject
                .as_ref()
                .and_then(|subject| subject.sender_connection_id),
        )
        .bind(
            delivery
                .pep_subject
                .as_ref()
                .and_then(|subject| subject.recipient_account_id),
        )
        .bind(
            delivery
                .pep_subject
                .as_ref()
                .map(|subject| subject.recipient_is_local),
        )
        .bind(
            delivery
                .pep_subject
                .as_ref()
                .map(|subject| subject.event_kind.as_str()),
        )
        .bind(
            delivery
                .pep_subject
                .as_ref()
                .map(|subject| subject.authorization_mode.as_str()),
        )
        .bind(delivery.legacy_unverifiable)
        .execute(&mut **transaction)
        .await;
        if let Err(error) = result {
            if error.to_string().contains("pubsub_event_outbox_capacity")
                || error.to_string().contains("queued_rows")
                || error.to_string().contains("queued_bytes")
            {
                CAPACITY_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            return Err(error).context("failed to atomically project PubSub notification outbox");
        }
    }
    Ok(())
}

pub async fn claim_pubsub_outbox(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<ClaimedPubSubOutboxDelivery>> {
    anyhow::ensure!(
        (1..=1_000).contains(&limit),
        "invalid PubSub outbox claim limit"
    );
    let lease_token = Uuid::new_v4();
    let rows = sqlx::query(
        "WITH eligible AS (
             SELECT current.delivery_id,
                    row_number() OVER (
                        PARTITION BY current.target_domain
                        ORDER BY current.next_attempt_at,current.created_at,current.delivery_id
                    ) AS domain_rank
               FROM pubsub_event_outbox current
              WHERE current.expires_at > clock_timestamp()
                AND current.next_attempt_at <= clock_timestamp()
                AND (current.lease_until IS NULL OR current.lease_until <= clock_timestamp())
                AND NOT EXISTS (
                    SELECT 1 FROM pubsub_event_outbox earlier
                     WHERE earlier.ordering_key=current.ordering_key
                       AND earlier.event_sequence < current.event_sequence
                )
         ), candidates AS (
             SELECT current.delivery_id
               FROM pubsub_event_outbox current
               JOIN eligible ON eligible.delivery_id=current.delivery_id
              ORDER BY eligible.domain_rank,current.next_attempt_at,current.created_at,current.delivery_id
              FOR UPDATE OF current SKIP LOCKED
              LIMIT $1
         ), claimed AS (
             UPDATE pubsub_event_outbox current
                SET lease_token=$2,
                    lease_until=clock_timestamp()+($3*INTERVAL '1 second'),
                    attempt_count=current.attempt_count+1
               FROM candidates
              WHERE current.delivery_id=candidates.delivery_id
          RETURNING current.*
         )
         SELECT delivery_id,event_id,ordering_key,event_sequence,source_kind,source_node,delivery_kind,
                recipient_jid,target_domain,payload_xml,payload_digest,show_values,
                subscription_node_id,digest_frequency_ms,
                attempt_count,lease_token,expires_at,security_sensitive,
                pep_sender_account_id,pep_sender_bare_jid,pep_sender_connection_id,
                pep_recipient_account_id,pep_recipient_is_local,pep_event_kind,pep_authorization_mode,
                pep_legacy_unverifiable
           FROM claimed
          ORDER BY event_sequence,delivery_id",
    )
    .bind(limit)
    .bind(lease_token)
    .bind(PUBSUB_OUTBOX_LEASE_SECONDS)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(row_to_claim).collect()
}

fn row_to_claim(row: sqlx::postgres::PgRow) -> Result<ClaimedPubSubOutboxDelivery> {
    let digest = row.get::<Vec<u8>, _>("payload_digest");
    let payload_digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid PubSub outbox payload digest"))?;
    let source = match row.get::<String, _>("source_kind").as_str() {
        "pubsub" => PubSubOutboxSource::PubSub,
        "pep" => PubSubOutboxSource::Pep,
        other => anyhow::bail!("unknown PubSub outbox source kind {other}"),
    };
    let legacy_unverifiable: bool = row.get("pep_legacy_unverifiable");
    let sender_account_id: Option<Uuid> = row.get("pep_sender_account_id");
    let sender_bare_jid: Option<String> = row.get("pep_sender_bare_jid");
    let recipient_is_local: Option<bool> = row.get("pep_recipient_is_local");
    let event_kind: Option<String> = row.get("pep_event_kind");
    let authorization_mode: Option<String> = row.get("pep_authorization_mode");
    let pep_subject = match (
        sender_account_id,
        sender_bare_jid,
        recipient_is_local,
        event_kind,
        authorization_mode,
    ) {
        (
            Some(sender_account_id),
            Some(sender_bare_jid),
            Some(recipient_is_local),
            Some(event_kind),
            Some(mode),
        ) => Some(PepOutboxSubject {
            sender_account_id,
            sender_bare_jid,
            sender_connection_id: row.get("pep_sender_connection_id"),
            recipient_account_id: row.get("pep_recipient_account_id"),
            recipient_is_local,
            event_kind: PepOutboxEventKind::parse(&event_kind)?,
            authorization_mode: PepOutboxAuthorizationMode::parse(&mode)?,
        }),
        (None, None, None, None, None) => None,
        _ => None,
    };
    Ok(ClaimedPubSubOutboxDelivery {
        delivery_id: row.get("delivery_id"),
        event_id: row.get("event_id"),
        ordering_key: row.get("ordering_key"),
        event_sequence: row.get("event_sequence"),
        source,
        source_node: row.get("source_node"),
        delivery_kind: PubSubOutboxDeliveryKind::parse(
            row.get::<String, _>("delivery_kind").as_str(),
        )?,
        recipient_jid: row.get("recipient_jid"),
        target_domain: row.get("target_domain"),
        payload_xml: row.get("payload_xml"),
        payload_digest,
        show_values: row.get("show_values"),
        subscription_node_id: row.get("subscription_node_id"),
        digest_frequency_ms: row.get("digest_frequency_ms"),
        attempt_count: row.get("attempt_count"),
        lease_token: row.get("lease_token"),
        expires_at: row.get("expires_at"),
        security_sensitive: row.get("security_sensitive"),
        pep_subject,
        legacy_unverifiable,
    })
}

pub async fn acknowledge_pubsub_outbox(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    Ok(
        sqlx::query("DELETE FROM pubsub_event_outbox WHERE delivery_id=$1 AND lease_token=$2")
            .bind(delivery_id)
            .bind(lease_token)
            .execute(pool)
            .await?
            .rows_affected()
            == 1,
    )
}

pub async fn renew_pubsub_outbox_lease(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE pubsub_event_outbox
            SET lease_until=clock_timestamp()+($3*INTERVAL '1 second')
          WHERE delivery_id=$1 AND lease_token=$2 AND expires_at>clock_timestamp()",
    )
    .bind(delivery_id)
    .bind(lease_token)
    .bind(PUBSUB_OUTBOX_LEASE_SECONDS)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn retry_pubsub_outbox(
    pool: &PgPool,
    item: &ClaimedPubSubOutboxDelivery,
    error: &str,
) -> Result<PubSubOutboxFailureDisposition> {
    let now = Utc::now();
    if item.expires_at <= now || item.attempt_count >= PUBSUB_OUTBOX_MAX_ATTEMPTS {
        return dead_letter_pubsub_outbox(
            pool,
            item.delivery_id,
            item.lease_token,
            if item.expires_at <= now {
                "expired"
            } else {
                "attempt-limit"
            },
            error,
        )
        .await;
    }
    let delay = retry_delay_seconds(item.attempt_count);
    let updated = sqlx::query(
        "UPDATE pubsub_event_outbox
            SET lease_token=NULL,lease_until=NULL,
                next_attempt_at=clock_timestamp()+($3*INTERVAL '1 second'),
                last_error=left($4,1024)
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(item.delivery_id)
    .bind(item.lease_token)
    .bind(delay)
    .bind(error)
    .execute(pool)
    .await?
    .rows_affected();
    if updated == 1 {
        RETRIES_TOTAL.fetch_add(1, Ordering::Relaxed);
        Ok(PubSubOutboxFailureDisposition::Retry)
    } else {
        LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
        Ok(PubSubOutboxFailureDisposition::LeaseLost)
    }
}

fn retry_delay_seconds(attempt_count: i32) -> i64 {
    let exponent = attempt_count.clamp(0, 8) as u32;
    2_i64.saturating_pow(exponent).min(300)
}

pub async fn dead_letter_pubsub_outbox(
    pool: &PgPool,
    delivery_id: Uuid,
    lease_token: Uuid,
    reason: &str,
    error: &str,
) -> Result<PubSubOutboxFailureDisposition> {
    let mut transaction = pool.begin().await?;
    let inserted = sqlx::query(
        "WITH moved AS (
             DELETE FROM pubsub_event_outbox
              WHERE delivery_id=$1 AND lease_token=$2
          RETURNING delivery_id,event_id,ordering_key,event_sequence,source_kind,
                    source_node,delivery_kind,recipient_jid,target_domain,payload_digest,
                    attempt_count,created_at,pep_sender_account_id,pep_sender_bare_jid,
                    pep_sender_connection_id,pep_recipient_account_id,pep_recipient_is_local,pep_event_kind,
                    pep_authorization_mode,pep_legacy_unverifiable
         )
         INSERT INTO pubsub_event_dead_letters(
             delivery_id,event_id,ordering_key,event_sequence,source_kind,source_node,delivery_kind,
             recipient_jid,target_domain,payload_digest,attempt_count,terminal_reason,
             last_error,created_at,pep_sender_account_id,pep_sender_bare_jid,
             pep_sender_connection_id,pep_recipient_account_id,pep_recipient_is_local,pep_event_kind,
             pep_authorization_mode,pep_legacy_unverifiable)
         SELECT delivery_id,event_id,ordering_key,event_sequence,source_kind,source_node,delivery_kind,
                recipient_jid,target_domain,payload_digest,attempt_count,$3,left($4,1024),created_at,
                pep_sender_account_id,pep_sender_bare_jid,pep_sender_connection_id,
                pep_recipient_account_id,pep_recipient_is_local,pep_event_kind,pep_authorization_mode,
                pep_legacy_unverifiable
           FROM moved
         ON CONFLICT(delivery_id) DO NOTHING",
    )
    .bind(delivery_id)
    .bind(lease_token)
    .bind(reason)
    .bind(error)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    transaction.commit().await?;
    if inserted == 1 {
        DEAD_LETTERS_TOTAL.fetch_add(1, Ordering::Relaxed);
        Ok(PubSubOutboxFailureDisposition::DeadLettered)
    } else {
        LEASE_LOST_TOTAL.fetch_add(1, Ordering::Relaxed);
        Ok(PubSubOutboxFailureDisposition::LeaseLost)
    }
}

pub async fn expire_pubsub_outbox(pool: &PgPool, limit: i64) -> Result<u64> {
    let result = sqlx::query(
        "WITH victims AS (
             SELECT delivery_id FROM pubsub_event_outbox
              WHERE expires_at<=clock_timestamp()
              ORDER BY expires_at,delivery_id
              FOR UPDATE SKIP LOCKED LIMIT $1
         ), moved AS (
             DELETE FROM pubsub_event_outbox current USING victims
              WHERE current.delivery_id=victims.delivery_id
           RETURNING current.delivery_id,current.event_id,current.ordering_key,
                     current.event_sequence,current.source_kind,current.source_node,current.delivery_kind,
                     current.recipient_jid,current.target_domain,current.payload_digest,
                     current.attempt_count,current.created_at,current.last_error,
                     current.pep_sender_account_id,current.pep_sender_bare_jid,
                     current.pep_sender_connection_id,current.pep_recipient_account_id,
                     current.pep_recipient_is_local,
                     current.pep_event_kind,current.pep_authorization_mode,
                     current.pep_legacy_unverifiable
         )
         INSERT INTO pubsub_event_dead_letters(
             delivery_id,event_id,ordering_key,event_sequence,source_kind,source_node,delivery_kind,
             recipient_jid,target_domain,payload_digest,attempt_count,terminal_reason,
             last_error,created_at,pep_sender_account_id,pep_sender_bare_jid,
             pep_sender_connection_id,pep_recipient_account_id,pep_recipient_is_local,pep_event_kind,
             pep_authorization_mode,pep_legacy_unverifiable)
         SELECT delivery_id,event_id,ordering_key,event_sequence,source_kind,source_node,delivery_kind,
                recipient_jid,target_domain,payload_digest,attempt_count,'expired',
                last_error,created_at,pep_sender_account_id,pep_sender_bare_jid,
                pep_sender_connection_id,pep_recipient_account_id,pep_recipient_is_local,pep_event_kind,
                pep_authorization_mode,pep_legacy_unverifiable FROM moved
         ON CONFLICT(delivery_id) DO NOTHING",
    )
    .bind(limit)
    .execute(pool)
    .await?;
    DEAD_LETTERS_TOTAL.fetch_add(result.rows_affected(), Ordering::Relaxed);
    Ok(result.rows_affected())
}

pub async fn cleanup_pubsub_dead_letters(pool: &PgPool, limit: i64) -> Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM pubsub_event_dead_letters WHERE delivery_id IN (
             SELECT delivery_id FROM pubsub_event_dead_letters
              WHERE purge_after<=clock_timestamp()
              ORDER BY purge_after,delivery_id LIMIT $1
         )",
    )
    .bind(limit)
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn cleanup_idle_pubsub_event_streams(pool: &PgPool, limit: i64) -> Result<u64> {
    Ok(sqlx::query(
        "WITH candidates AS (
             SELECT candidate.ordering_key
               FROM pubsub_event_streams candidate
              WHERE candidate.updated_at<=clock_timestamp()-INTERVAL '30 days'
                AND NOT EXISTS (
                    SELECT 1 FROM pubsub_event_outbox queued
                     WHERE queued.ordering_key=candidate.ordering_key
                )
              ORDER BY candidate.updated_at,candidate.ordering_key
              FOR UPDATE SKIP LOCKED
              LIMIT $1
         )
         DELETE FROM pubsub_event_streams streams USING candidates
          WHERE streams.ordering_key=candidates.ordering_key",
    )
    .bind(limit.clamp(1, 10_000))
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn pubsub_outbox_snapshot(pool: &PgPool) -> Result<PubSubOutboxSnapshot> {
    let row = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS pending_rows,
                COALESCE(SUM(octet_length(payload_xml)),0)::BIGINT AS pending_bytes,
                COUNT(*) FILTER(WHERE lease_until>clock_timestamp())::BIGINT AS leased_rows,
                COUNT(*) FILTER(WHERE next_attempt_at<=clock_timestamp()
                                  AND (lease_until IS NULL OR lease_until<=clock_timestamp())
                                  AND expires_at>clock_timestamp())::BIGINT AS due_rows
           FROM pubsub_event_outbox",
    )
    .fetch_one(pool)
    .await?;
    let dead_letter_rows =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::BIGINT FROM pubsub_event_dead_letters")
            .fetch_one(pool)
            .await?;
    Ok(PubSubOutboxSnapshot {
        pending_rows: row.get("pending_rows"),
        pending_bytes: row.get("pending_bytes"),
        leased_rows: row.get("leased_rows"),
        due_rows: row.get("due_rows"),
        dead_letter_rows,
    })
}

pub fn pubsub_outbox_capacity_rejections_total() -> u64 {
    CAPACITY_REJECTIONS_TOTAL.load(Ordering::Relaxed)
}

pub fn pubsub_outbox_dead_letters_total() -> u64 {
    DEAD_LETTERS_TOTAL.load(Ordering::Relaxed)
}

pub fn pubsub_outbox_lease_lost_total() -> u64 {
    LEASE_LOST_TOTAL.load(Ordering::Relaxed)
}

pub fn pubsub_outbox_retries_total() -> u64 {
    RETRIES_TOTAL.load(Ordering::Relaxed)
}

pub fn record_unverifiable_pep_drop() {
    UNVERIFIABLE_PEP_DROPS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn pubsub_outbox_unverifiable_pep_drops_total() -> u64 {
    UNVERIFIABLE_PEP_DROPS_TOTAL.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omemo_family_nodes_are_never_coalescible() {
        for node in [
            "urn:xmpp:omemo:2:devices",
            "eu.siacs.conversations.axolotl.bundles:42",
            "urn:example:device-list",
            "urn:example:prekeys",
        ] {
            assert!(security_sensitive_pep_node(node), "{node}");
            assert!(PubSubOutboxInsert::new(
                Uuid::new_v4(),
                "pep:owner:node",
                PubSubOutboxSource::Pep,
                PubSubOutboxDeliveryKind::PepStanza,
                "alice@example.test",
                "<message/>",
                None,
                None,
                node,
                Some("latest".to_owned()),
                Utc::now(),
            )
            .is_err());
        }
    }

    #[test]
    fn pep_constructor_requires_structured_local_identity_and_forces_live_sensitive_acl() {
        let sender_id = Uuid::new_v4();
        let recipient_id = Uuid::new_v4();
        let now = Utc::now();
        assert!(PubSubOutboxInsert::new_pep_stanza(
            Uuid::new_v4(),
            sender_id,
            "alice@example.test",
            None,
            "bob@example.test/phone",
            None,
            PepOutboxEventKind::Publish,
            PepOutboxAuthorizationMode::CausalAudience,
            "<message/>",
            "urn:example:ordinary",
            "example.test",
            now,
        )
        .is_err());
        assert!(PubSubOutboxInsert::new_pep_stanza(
            Uuid::new_v4(),
            sender_id,
            "alice@example.test",
            None,
            "bob@remote.test/phone",
            Some(recipient_id),
            PepOutboxEventKind::Publish,
            PepOutboxAuthorizationMode::CausalAudience,
            "<message/>",
            "urn:example:ordinary",
            "example.test",
            now,
        )
        .is_err());
        assert!(PubSubOutboxInsert::new_pep_stanza(
            Uuid::new_v4(),
            sender_id,
            "alice@example.test",
            None,
            "bob@remote.test/phone",
            None,
            PepOutboxEventKind::Delete,
            PepOutboxAuthorizationMode::LiveNodeAccess,
            "<message/>",
            "urn:example:ordinary",
            "example.test",
            now,
        )
        .is_err());
        let sensitive = PubSubOutboxInsert::new_pep_stanza(
            Uuid::new_v4(),
            sender_id,
            "alice@example.test",
            None,
            "bob@example.test/phone",
            Some(recipient_id),
            PepOutboxEventKind::Publish,
            PepOutboxAuthorizationMode::CausalAudience,
            "<message/>",
            "urn:xmpp:omemo:2:devices",
            "example.test",
            now,
        )
        .unwrap();
        assert_eq!(
            sensitive.pep_subject.unwrap().authorization_mode,
            PepOutboxAuthorizationMode::LiveNodeAccess
        );
    }

    #[test]
    fn pep_authorization_migration_is_isolated_schema_safe() {
        let migration = include_str!("../../migrations/0116_pep_outbox_authorization.sql");
        let lower = migration.to_ascii_lowercase();
        assert!(!lower.contains("public."));
        for invalid in [
            "pg_catalog.bigint",
            "pg_catalog.boolean",
            "pg_catalog.integer",
            "pg_catalog.timestamp",
            "pg_catalog.varchar",
        ] {
            assert!(
                !lower.contains(invalid),
                "invalid qualified alias {invalid}"
            );
        }
        assert!(lower.contains("set search_path = pg_catalog, pg_temp"));
    }

    #[test]
    fn payload_digest_binds_exact_bytes() {
        let insert = PubSubOutboxInsert::new(
            Uuid::new_v4(),
            "pubsub:test",
            PubSubOutboxSource::PubSub,
            PubSubOutboxDeliveryKind::PubSubDirect,
            "alice@example.test",
            "<message id='stable'/>",
            None,
            None,
            "urn:example:news",
            None,
            Utc::now(),
        )
        .unwrap();
        let claimed = ClaimedPubSubOutboxDelivery {
            delivery_id: insert.delivery_id,
            event_id: insert.event_id,
            ordering_key: insert.ordering_key,
            event_sequence: 1,
            source: insert.source,
            source_node: insert.source_node,
            delivery_kind: insert.delivery_kind,
            recipient_jid: insert.recipient_jid,
            target_domain: insert.target_domain,
            payload_xml: insert.payload_xml,
            payload_digest: insert.payload_digest,
            show_values: None,
            subscription_node_id: None,
            digest_frequency_ms: None,
            attempt_count: 1,
            lease_token: Uuid::new_v4(),
            expires_at: insert.expires_at,
            security_sensitive: insert.security_sensitive,
            pep_subject: insert.pep_subject,
            legacy_unverifiable: insert.legacy_unverifiable,
        };
        assert!(claimed.payload_binding_valid());
        let mut changed = claimed;
        changed.payload_xml.push(' ');
        assert!(!changed.payload_binding_valid());
    }

    #[test]
    fn backoff_is_exponential_and_bounded() {
        assert_eq!(retry_delay_seconds(0), 1);
        assert_eq!(retry_delay_seconds(1), 2);
        assert_eq!(retry_delay_seconds(8), 256);
        assert_eq!(retry_delay_seconds(100), 256);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn commit_claim_lease_takeover_payload_binding_and_ack_are_fenced() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let ordering_key = format!("pubsub:fixture:{suffix}");

        let rolled_back = PubSubOutboxInsert::new(
            Uuid::new_v4(),
            format!("{ordering_key}:rollback"),
            PubSubOutboxSource::PubSub,
            PubSubOutboxDeliveryKind::PubSubDirect,
            format!("rollback-{suffix}@example.test"),
            "<message id='rollback'/>",
            None,
            None,
            "urn:example:fixture",
            None,
            Utc::now(),
        )
        .unwrap();
        let rolled_back_id = rolled_back.delivery_id;
        let mut transaction = pool.begin().await.unwrap();
        enqueue_pubsub_outbox_in_transaction(&mut transaction, &[rolled_back])
            .await
            .unwrap();
        transaction.rollback().await.unwrap();
        assert!(!sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pubsub_event_outbox WHERE delivery_id=$1)",
        )
        .bind(rolled_back_id)
        .fetch_one(&pool)
        .await
        .unwrap());

        // Capacity rejection must poison and roll back the entire originating
        // transaction, including its stream allocation.  The ledger edit is
        // itself transactional and is not left behind by this fixture.
        let capacity_limited = PubSubOutboxInsert::new(
            Uuid::new_v4(),
            format!("{ordering_key}:capacity"),
            PubSubOutboxSource::PubSub,
            PubSubOutboxDeliveryKind::PubSubDirect,
            format!("capacity-{suffix}@example.test"),
            "<message id='capacity'/>",
            None,
            None,
            "urn:example:fixture",
            None,
            Utc::now(),
        )
        .unwrap();
        let capacity_delivery_id = capacity_limited.delivery_id;
        let capacity_shard = i16::from(capacity_delivery_id.as_bytes()[0] & 63);
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query("UPDATE pubsub_event_outbox_capacity SET queued_rows=10000 WHERE shard=$1")
            .bind(capacity_shard)
            .execute(&mut *transaction)
            .await
            .unwrap();
        assert!(
            enqueue_pubsub_outbox_in_transaction(&mut transaction, &[capacity_limited])
                .await
                .is_err()
        );
        transaction.rollback().await.unwrap();
        assert!(!sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pubsub_event_outbox WHERE delivery_id=$1)",
        )
        .bind(capacity_delivery_id)
        .fetch_one(&pool)
        .await
        .unwrap());

        let event_id = Uuid::new_v4();
        let insert = PubSubOutboxInsert::new(
            event_id,
            ordering_key.clone(),
            PubSubOutboxSource::PubSub,
            PubSubOutboxDeliveryKind::PubSubDirect,
            format!("alice-{suffix}@example.test"),
            format!("<message id='{event_id}'><body>{suffix}</body></message>"),
            None,
            None,
            "urn:example:fixture",
            None,
            Utc::now(),
        )
        .unwrap();
        let delivery_id = insert.delivery_id;
        let mut transaction = pool.begin().await.unwrap();
        enqueue_pubsub_outbox_in_transaction(&mut transaction, &[insert])
            .await
            .unwrap();
        transaction.commit().await.unwrap();

        let first = claim_pubsub_outbox(&pool, 100)
            .await
            .unwrap()
            .into_iter()
            .find(|item| item.delivery_id == delivery_id)
            .unwrap();
        assert!(first.payload_binding_valid());
        sqlx::query(
            "UPDATE pubsub_event_outbox SET lease_until=clock_timestamp()-INTERVAL '1 second'
              WHERE delivery_id=$1",
        )
        .bind(delivery_id)
        .execute(&pool)
        .await
        .unwrap();
        let takeover = claim_pubsub_outbox(&pool, 100)
            .await
            .unwrap()
            .into_iter()
            .find(|item| item.delivery_id == delivery_id)
            .unwrap();
        assert_eq!(takeover.event_id, first.event_id);
        assert_eq!(takeover.payload_xml, first.payload_xml);
        assert_ne!(takeover.lease_token, first.lease_token);
        assert!(
            !acknowledge_pubsub_outbox(&pool, delivery_id, first.lease_token)
                .await
                .unwrap()
        );
        assert!(
            acknowledge_pubsub_outbox(&pool, delivery_id, takeover.lease_token)
                .await
                .unwrap()
        );

        let first_event = Uuid::new_v4();
        let second_event = Uuid::new_v4();
        let ordered_recipient = format!("ordered-{suffix}@example.test");
        let first_batch = ["one", "two"]
            .into_iter()
            .map(|marker| {
                PubSubOutboxInsert::new(
                    first_event,
                    ordering_key.clone(),
                    PubSubOutboxSource::PubSub,
                    PubSubOutboxDeliveryKind::PubSubDirect,
                    ordered_recipient.clone(),
                    format!("<message id='{first_event}' data-marker='{marker}'/>"),
                    None,
                    None,
                    "urn:example:fixture",
                    None,
                    Utc::now(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let ordered_stream = first_batch[0].ordering_key.clone();
        let second = PubSubOutboxInsert::new(
            second_event,
            ordering_key.clone(),
            PubSubOutboxSource::PubSub,
            PubSubOutboxDeliveryKind::PubSubDirect,
            ordered_recipient,
            format!("<message id='{second_event}'/>"),
            None,
            None,
            "urn:example:fixture",
            None,
            Utc::now(),
        )
        .unwrap();
        let mut transaction = pool.begin().await.unwrap();
        enqueue_pubsub_outbox_in_transaction(&mut transaction, &first_batch)
            .await
            .unwrap();
        enqueue_pubsub_outbox_in_transaction(&mut transaction, &[second])
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        let first_claim = claim_pubsub_outbox(&pool, 100)
            .await
            .unwrap()
            .into_iter()
            .filter(|item| item.ordering_key == ordered_stream)
            .collect::<Vec<_>>();
        assert_eq!(first_claim.len(), 2);
        assert!(first_claim.iter().all(|item| item.event_id == first_event));
        for item in first_claim {
            assert!(
                acknowledge_pubsub_outbox(&pool, item.delivery_id, item.lease_token)
                    .await
                    .unwrap()
            );
        }
        let second_claim = claim_pubsub_outbox(&pool, 100)
            .await
            .unwrap()
            .into_iter()
            .find(|item| item.ordering_key == ordered_stream)
            .unwrap();
        assert_eq!(second_claim.event_id, second_event);
        assert!(acknowledge_pubsub_outbox(
            &pool,
            second_claim.delivery_id,
            second_claim.lease_token,
        )
        .await
        .unwrap());

        // A busy target domain cannot monopolize a bounded claim.  All rows
        // use independent streams so only domain interleaving determines the
        // first batch.
        let fairness_a = (0..4)
            .map(|index| {
                PubSubOutboxInsert::new(
                    Uuid::new_v4(),
                    format!("{ordering_key}:fair-a:{index}"),
                    PubSubOutboxSource::PubSub,
                    PubSubOutboxDeliveryKind::PubSubDirect,
                    format!("a-{index}-{suffix}@busy.example"),
                    format!("<message id='fair-a-{index}'/>"),
                    None,
                    None,
                    "urn:example:fixture",
                    None,
                    Utc::now(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let fairness_b = PubSubOutboxInsert::new(
            Uuid::new_v4(),
            format!("{ordering_key}:fair-b"),
            PubSubOutboxSource::PubSub,
            PubSubOutboxDeliveryKind::PubSubDirect,
            format!("b-{suffix}@quiet.example"),
            "<message id='fair-b'/>",
            None,
            None,
            "urn:example:fixture",
            None,
            Utc::now(),
        )
        .unwrap();
        let fairness_ids = fairness_a
            .iter()
            .map(|item| item.delivery_id)
            .chain(std::iter::once(fairness_b.delivery_id))
            .collect::<Vec<_>>();
        let mut fairness = fairness_a;
        fairness.push(fairness_b);
        let mut transaction = pool.begin().await.unwrap();
        enqueue_pubsub_outbox_in_transaction(&mut transaction, &fairness)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        let fairness_claim = claim_pubsub_outbox(&pool, 2).await.unwrap();
        assert_eq!(fairness_claim.len(), 2);
        assert_eq!(
            fairness_claim
                .iter()
                .map(|item| item.target_domain.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["busy.example", "quiet.example"])
        );
        for item in fairness_claim {
            assert!(
                acknowledge_pubsub_outbox(&pool, item.delivery_id, item.lease_token)
                    .await
                    .unwrap()
            );
        }
        // Remove the unclaimed busy-domain rows with ordinary deletes so the
        // capacity trigger is exercised during fixture cleanup too.
        sqlx::query("DELETE FROM pubsub_event_outbox WHERE delivery_id=ANY($1)")
            .bind(&fairness_ids)
            .execute(&pool)
            .await
            .unwrap();

        let mut expiring = PubSubOutboxInsert::new(
            Uuid::new_v4(),
            format!("{ordering_key}:ttl"),
            PubSubOutboxSource::PubSub,
            PubSubOutboxDeliveryKind::PubSubDirect,
            format!("ttl-{suffix}@example.test"),
            "<message id='ttl'><body>not copied to dead letters</body></message>",
            None,
            None,
            "urn:example:fixture",
            None,
            Utc::now(),
        )
        .unwrap();
        let expiring_id = expiring.delivery_id;
        expiring.expires_at = Utc::now() + chrono::Duration::milliseconds(250);
        let mut transaction = pool.begin().await.unwrap();
        enqueue_pubsub_outbox_in_transaction(&mut transaction, &[expiring])
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(expire_pubsub_outbox(&pool, 100).await.unwrap(), 1);
        let dead_letter = sqlx::query(
            "SELECT terminal_reason,payload_digest FROM pubsub_event_dead_letters
              WHERE delivery_id=$1",
        )
        .bind(expiring_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(dead_letter.get::<String, _>("terminal_reason"), "expired");
        assert_eq!(dead_letter.get::<Vec<u8>, _>("payload_digest").len(), 32);

        let ordering_prefix = format!("{ordering_key}%");
        sqlx::query(
            "DELETE FROM pubsub_event_dead_letters WHERE ordering_key=$1 OR ordering_key LIKE $2",
        )
        .bind(&ordering_key)
        .bind(&ordering_prefix)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "DELETE FROM pubsub_event_streams WHERE ordering_key=$1 OR ordering_key LIKE $2",
        )
        .bind(&ordering_key)
        .bind(&ordering_prefix)
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn pep_subject_foreign_keys_cascade_locally_and_allow_only_remote_null_recipient() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let sender_id = Uuid::new_v4();
        let recipient_id = Uuid::new_v4();
        let sender_username = format!("pep-sender-{}", &suffix[..12]);
        let recipient_username = format!("pep-recipient-{}", &suffix[..12]);
        for (id, username) in [
            (sender_id, sender_username.as_str()),
            (recipient_id, recipient_username.as_str()),
        ] {
            sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
                .bind(id)
                .bind(username)
                .execute(&pool)
                .await
                .unwrap();
        }
        let sender_bare = format!("{sender_username}@example.test");
        let local_recipient = format!("{recipient_username}@example.test/phone");
        let local = PubSubOutboxInsert::new_pep_stanza(
            Uuid::new_v4(),
            sender_id,
            &sender_bare,
            None,
            local_recipient,
            Some(recipient_id),
            PepOutboxEventKind::Publish,
            PepOutboxAuthorizationMode::CausalAudience,
            "<message id='local'/>",
            "urn:example:pep",
            "example.test",
            Utc::now(),
        )
        .unwrap();
        let local_id = local.delivery_id;
        let remote = PubSubOutboxInsert::new_pep_stanza(
            Uuid::new_v4(),
            sender_id,
            &sender_bare,
            None,
            format!("remote-{suffix}@remote.test/phone"),
            None,
            PepOutboxEventKind::Publish,
            PepOutboxAuthorizationMode::CausalAudience,
            "<message id='remote'/>",
            "urn:example:pep",
            "example.test",
            Utc::now(),
        )
        .unwrap();
        let remote_id = remote.delivery_id;
        let ordering_keys = vec![local.ordering_key.clone(), remote.ordering_key.clone()];
        let mut transaction = pool.begin().await.unwrap();
        enqueue_pubsub_outbox_in_transaction(&mut transaction, &[local, remote])
            .await
            .unwrap();
        transaction.commit().await.unwrap();

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(recipient_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pubsub_event_outbox WHERE delivery_id=$1)",
        )
        .bind(local_id)
        .fetch_one(&pool)
        .await
        .unwrap());
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pubsub_event_outbox WHERE delivery_id=$1 AND pep_recipient_account_id IS NULL)",
        )
        .bind(remote_id)
        .fetch_one(&pool)
        .await
        .unwrap());
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(sender_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pubsub_event_outbox WHERE delivery_id=$1)",
        )
        .bind(remote_id)
        .fetch_one(&pool)
        .await
        .unwrap());
        sqlx::query("DELETE FROM pubsub_event_streams WHERE ordering_key=ANY($1)")
            .bind(&ordering_keys)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }
}
