//! PostgreSQL-backed adapter for exact rated-message proof admission leases.
use crate::{
    abuse::{
        AbuseGuard, MessageAdmissionAcceptance, MessageAdmissionRequest, MessageAdmissionStart,
    },
    services::message_admission::MessageAdmissionRepository,
};
use anyhow::Result;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresMessageAdmissionRepository {
    guard: Arc<AbuseGuard>,
    pool: PgPool,
}

impl PostgresMessageAdmissionRepository {
    pub(crate) fn new(guard: Arc<AbuseGuard>, pool: PgPool) -> Self {
        Self { guard, pool }
    }
}

/// Finalize only the exact lease issued before routing. This transaction
/// remains independent of the durable message/outbox write: callers invoke it
/// after that write accepts the stanza and report any failure separately.
pub(crate) async fn accept_message_admission(
    pool: &PgPool,
    acceptance: &MessageAdmissionAcceptance<'_>,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(northstar_abuse_policy::message_admission_lock_id(
            acceptance.admission_key(),
        ))
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query(
        "SELECT payload_mac,state,lease_token FROM abuse_message_admissions
         WHERE admission_key=$1 FOR UPDATE",
    )
    .bind(acceptance.admission_key())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("message admission disappeared before acceptance");
    };
    let stored_mac: Vec<u8> = row.get("payload_mac");
    anyhow::ensure!(
        bool::from(stored_mac.as_slice().ct_eq(acceptance.payload_mac())),
        "message admission payload changed before acceptance"
    );
    if row.get::<String, _>("state") == "accepted" {
        tx.commit().await?;
        return Ok(());
    }
    anyhow::ensure!(
        row.get::<Uuid, _>("lease_token") == acceptance.lease_token(),
        "message admission fencing lease was lost before acceptance"
    );
    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE abuse_message_admissions
         SET state='accepted',accepted_at=$2,updated_at=$2,expires_at=$3
         WHERE admission_key=$1",
    )
    .bind(acceptance.admission_key())
    .bind(now)
    .bind(
        now + chrono::Duration::seconds(
            i64::try_from(northstar_abuse_policy::MESSAGE_ADMISSION_ACCEPTED_TTL.as_secs())
                .unwrap_or(i64::MAX),
        ),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

impl MessageAdmissionRepository for PostgresMessageAdmissionRepository {
    async fn begin(&self, request: &MessageAdmissionRequest<'_>) -> Result<MessageAdmissionStart> {
        self.guard.begin_message_admission(request).await
    }

    async fn accept(&self, acceptance: &MessageAdmissionAcceptance<'_>) -> Result<()> {
        accept_message_admission(&self.pool, acceptance).await
    }
}
