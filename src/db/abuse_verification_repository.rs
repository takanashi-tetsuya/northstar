//! One-use PoW consumption under the same transaction as actor state and the
//! protected business operation.

use crate::{
    abuse::{GuardError, WorkRequirement},
    db::abuse_actor_state_repository::{lock_db_states, persist_db_states, DbActorState},
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub(crate) struct ConsumedChallenge {
    pub(crate) action: String,
    pub(crate) subject_hash: Vec<u8>,
    pub(crate) key_id: String,
    pub(crate) prefix: String,
    pub(crate) work_factor: i64,
    pub(crate) not_before: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) actor_sequences: serde_json::Value,
    pub(crate) requirement: serde_json::Value,
    pub(crate) protocol_version: i16,
    pub(crate) intent_method: Option<String>,
    pub(crate) intent_path: Option<String>,
    pub(crate) body_sha256: Option<Vec<u8>>,
    pub(crate) server_nonce: Option<String>,
    pub(crate) issued_at: Option<DateTime<Utc>>,
}

pub(crate) struct VerificationDecision {
    pub(crate) outcome: std::result::Result<WorkRequirement, GuardError>,
    pub(crate) persist_states: bool,
}

pub(crate) async fn verify(
    pool: &PgPool,
    state_keys: &[String],
    challenge_id: Option<Uuid>,
    decide: impl FnOnce(
        &mut [DbActorState],
        DateTime<Utc>,
        Option<ConsumedChallenge>,
    ) -> Result<VerificationDecision>,
) -> Result<std::result::Result<WorkRequirement, GuardError>> {
    let mut tx = pool.begin().await?;
    let outcome = verify_in_tx(&mut tx, state_keys, challenge_id, decide).await?;
    tx.commit().await?;
    Ok(outcome)
}

pub(crate) async fn verify_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    state_keys: &[String],
    challenge_id: Option<Uuid>,
    decide: impl FnOnce(
        &mut [DbActorState],
        DateTime<Utc>,
        Option<ConsumedChallenge>,
    ) -> Result<VerificationDecision>,
) -> Result<std::result::Result<WorkRequirement, GuardError>> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let mut states = lock_db_states(tx, state_keys, now).await?;
    let challenge = match challenge_id {
        Some(id) => sqlx::query(
            "DELETE FROM abuse_pow_challenges WHERE id=$1
             RETURNING action,subject_hash,key_id,prefix,work_factor,not_before,
                       expires_at,actor_sequences,requirement,protocol_version,
                       intent_method,intent_path,body_sha256,server_nonce,issued_at",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(|row| ConsumedChallenge {
            action: row.get("action"),
            subject_hash: row.get("subject_hash"),
            key_id: row.get("key_id"),
            prefix: row.get("prefix"),
            work_factor: row.get("work_factor"),
            not_before: row.get("not_before"),
            expires_at: row.get("expires_at"),
            actor_sequences: row.get("actor_sequences"),
            requirement: row.get("requirement"),
            protocol_version: row.get("protocol_version"),
            intent_method: row.get("intent_method"),
            intent_path: row.get("intent_path"),
            body_sha256: row.get("body_sha256"),
            server_nonce: row.get("server_nonce"),
            issued_at: row.get("issued_at"),
        }),
        None => None,
    };
    let decision = decide(&mut states, now, challenge)?;
    if decision.persist_states {
        persist_db_states(tx, &states).await?;
    }
    Ok(decision.outcome)
}
