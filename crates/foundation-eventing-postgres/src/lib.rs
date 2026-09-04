//! PostgreSQL implementation of the transactional eventing boundary.
//!
//! The caller owns the business transaction and passes its `Transaction`
//! through every operation. This adapter never opens a second connection or
//! commits on behalf of the caller, so state and outbox/inbox records remain
//! atomic. Delivery transport is still at-least-once; consumers must make
//! visible side effects idempotent.

use chrono::{DateTime, Utc};
use foundation_eventing::{ConsumerInboxEntry, OutboxEvent};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

/// Render migrations for a validated service schema. The SQL is applied by a
/// dedicated migrator role; runtime services must not execute it. Keeping the
/// schema explicit prevents a pre-existing `public` object from being used as
/// an authority table through search-path shadowing.
pub fn migration_sql(schema: &str) -> Result<String, EventingStoreError> {
    let schema = quote_identifier(schema)?;
    Ok(format!(
        r#"CREATE TABLE IF NOT EXISTS {schema}.event_outbox (
    event_id UUID PRIMARY KEY,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    aggregate_version BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    payload BYTEA NOT NULL,
    traceparent TEXT,
    correlation_id UUID,
    causation_id UUID,
    created_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS event_outbox_pending_idx
    ON {schema}.event_outbox (created_at, event_id)
    WHERE published_at IS NULL;
CREATE TABLE IF NOT EXISTS {schema}.event_inbox (
    consumer_name TEXT NOT NULL,
    event_id UUID NOT NULL,
    processed_at TIMESTAMPTZ,
    result_digest BYTEA,
    lease_owner TEXT,
    lease_until TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (consumer_name, event_id)
);
CREATE INDEX IF NOT EXISTS event_inbox_lease_idx
    ON {schema}.event_inbox (consumer_name, lease_until)
    WHERE processed_at IS NULL;
"#
    ))
}

fn quote_identifier(value: &str) -> Result<String, EventingStoreError> {
    if value.is_empty()
        || value.len() > 63
        || !value.bytes().enumerate().all(|(index, byte)| {
            (index == 0 && (byte.is_ascii_alphabetic() || byte == b'_') || index > 0)
                && (byte == b'_' || byte.is_ascii_alphanumeric())
        })
    {
        return Err(EventingStoreError::InvalidSchema);
    }
    Ok(format!("\"{}\"", value.replace('"', "\"\"")))
}

#[derive(Debug, Error)]
pub enum EventingStoreError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("claim limit must be between 1 and 1000")]
    InvalidLimit,
    #[error("event payload exceeds the 1 MiB eventing limit")]
    PayloadTooLarge,
    #[error("event field exceeds its bounded storage limit")]
    FieldTooLarge,
    #[error("service schema is not a safe PostgreSQL identifier")]
    InvalidSchema,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxLease {
    pub event: OutboxEvent,
    pub lease_owner: String,
    pub lease_until: DateTime<Utc>,
    pub attempts: i32,
}

fn validate_event(event: &OutboxEvent) -> Result<(), EventingStoreError> {
    if event.payload.len() > 1024 * 1024
        || event.aggregate_type.len() > 128
        || event.aggregate_id.len() > 256
        || event.event_type.len() > 256
        || event
            .traceparent
            .as_ref()
            .is_some_and(|value| value.len() > 128)
    {
        return Err(if event.payload.len() > 1024 * 1024 {
            EventingStoreError::PayloadTooLarge
        } else {
            EventingStoreError::FieldTooLarge
        });
    }
    Ok(())
}

fn validate_claim(limit: u32, owner: &str) -> Result<(), EventingStoreError> {
    if !(1..=1000).contains(&limit) {
        return Err(EventingStoreError::InvalidLimit);
    }
    if owner.is_empty() || owner.len() > 128 {
        return Err(EventingStoreError::FieldTooLarge);
    }
    Ok(())
}

pub struct PostgresEventing;

impl PostgresEventing {
    /// Insert an outbox event idempotently inside the caller's transaction.
    pub async fn append(
        tx: &mut Transaction<'_, Postgres>,
        event: &OutboxEvent,
    ) -> Result<bool, EventingStoreError> {
        validate_event(event)?;
        let result = sqlx::query(
            "INSERT INTO event_outbox
                (event_id, aggregate_type, aggregate_id, aggregate_version,
                 event_type, schema_version, payload, traceparent,
                 correlation_id, causation_id, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(event.event_id)
        .bind(&event.aggregate_type)
        .bind(&event.aggregate_id)
        .bind(i64::try_from(event.aggregate_version).unwrap_or(i64::MAX))
        .bind(&event.event_type)
        .bind(i32::try_from(event.schema_version).unwrap_or(i32::MAX))
        .bind(&event.payload)
        .bind(&event.traceparent)
        .bind(event.correlation_id)
        .bind(event.causation_id)
        .bind(event.created_at)
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Claim pending events with row locks and a bounded lease. `owner` is a
    /// workload identity, not a user-provided arbitrary SQL fragment.
    pub async fn claim(
        tx: &mut Transaction<'_, Postgres>,
        owner: &str,
        limit: u32,
        lease_until: DateTime<Utc>,
    ) -> Result<Vec<OutboxLease>, EventingStoreError> {
        validate_claim(limit, owner)?;
        let rows = sqlx::query(
            "WITH candidates AS (
                 SELECT event_id
                   FROM event_outbox
                  WHERE published_at IS NULL
                    AND (lease_until IS NULL OR lease_until <= now())
                  ORDER BY created_at, event_id
                  FOR UPDATE SKIP LOCKED
                  LIMIT $1
             )
             UPDATE event_outbox AS event
                SET lease_owner = $2,
                    lease_until = $3,
                    attempts = event.attempts + 1
              WHERE event.event_id IN (SELECT event_id FROM candidates)
             RETURNING event.event_id, event.aggregate_type, event.aggregate_id,
                       event.aggregate_version, event.event_type,
                       event.schema_version, event.payload, event.traceparent,
                       event.correlation_id, event.causation_id, event.created_at,
                       event.lease_until, event.attempts",
        )
        .bind(i64::from(limit))
        .bind(owner)
        .bind(lease_until)
        .fetch_all(&mut **tx)
        .await?;
        rows.into_iter()
            .map(|row| {
                let aggregate_version: i64 = row.try_get("aggregate_version")?;
                let schema_version: i32 = row.try_get("schema_version")?;
                let lease_until: DateTime<Utc> = row.try_get("lease_until")?;
                Ok(OutboxLease {
                    event: OutboxEvent {
                        event_id: row.try_get("event_id")?,
                        aggregate_type: row.try_get("aggregate_type")?,
                        aggregate_id: row.try_get("aggregate_id")?,
                        aggregate_version: u64::try_from(aggregate_version).unwrap_or(0),
                        event_type: row.try_get("event_type")?,
                        schema_version: u32::try_from(schema_version).unwrap_or(0),
                        payload: row.try_get("payload")?,
                        traceparent: row.try_get("traceparent")?,
                        correlation_id: row.try_get("correlation_id")?,
                        causation_id: row.try_get("causation_id")?,
                        created_at: row.try_get("created_at")?,
                        published_at: None,
                    },
                    lease_owner: owner.to_owned(),
                    lease_until,
                    attempts: row.try_get("attempts")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(EventingStoreError::Sqlx)
    }

    pub async fn mark_published(
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
        owner: &str,
        published_at: DateTime<Utc>,
    ) -> Result<bool, EventingStoreError> {
        validate_claim(1, owner)?;
        let result = sqlx::query(
            "UPDATE event_outbox
                SET published_at = $1, lease_owner = NULL, lease_until = NULL
              WHERE event_id = $2 AND lease_owner = $3 AND published_at IS NULL",
        )
        .bind(published_at)
        .bind(event_id)
        .bind(owner)
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Claim the consumer's event exactly once. A duplicate returns `false`;
    /// the caller must not execute the visible side effect in that case.
    pub async fn claim_inbox(
        tx: &mut Transaction<'_, Postgres>,
        entry: &ConsumerInboxEntry,
        owner: &str,
        lease_until: DateTime<Utc>,
    ) -> Result<bool, EventingStoreError> {
        validate_claim(1, owner)?;
        let result = sqlx::query(
            "INSERT INTO event_inbox
                (consumer_name, event_id, lease_owner, lease_until, attempts)
             VALUES ($1,$2,$3,$4,1)
             ON CONFLICT (consumer_name, event_id) DO NOTHING",
        )
        .bind(&entry.consumer_name)
        .bind(entry.event_id)
        .bind(owner)
        .bind(lease_until)
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn complete_inbox(
        tx: &mut Transaction<'_, Postgres>,
        entry: &ConsumerInboxEntry,
        owner: &str,
    ) -> Result<bool, EventingStoreError> {
        validate_claim(1, owner)?;
        let result = sqlx::query(
            "UPDATE event_inbox
                SET processed_at = $1, result_digest = $2,
                    lease_owner = NULL, lease_until = NULL
              WHERE consumer_name = $3 AND event_id = $4
                AND lease_owner = $5 AND processed_at IS NULL",
        )
        .bind(entry.processed_at)
        .bind(&entry.result_digest)
        .bind(&entry.consumer_name)
        .bind(entry.event_id)
        .bind(owner)
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_bounds_and_claim_identity_are_fail_closed() {
        let mut event = OutboxEvent::new("account", "id", 1, "account.created.v1", vec![0; 16]);
        assert!(validate_event(&event).is_ok());
        event.payload = vec![0; 1024 * 1024 + 1];
        assert!(matches!(
            validate_event(&event),
            Err(EventingStoreError::PayloadTooLarge)
        ));
        assert!(matches!(
            validate_claim(0, "worker"),
            Err(EventingStoreError::InvalidLimit)
        ));
        assert!(matches!(
            validate_claim(1, ""),
            Err(EventingStoreError::FieldTooLarge)
        ));
        assert!(migration_sql("identity_private")
            .unwrap()
            .contains("\"identity_private\".event_outbox"));
        assert!(matches!(
            migration_sql("public;drop"),
            Err(EventingStoreError::InvalidSchema)
        ));
    }
}
