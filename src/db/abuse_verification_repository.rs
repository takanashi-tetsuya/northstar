//! One-use PoW consumption under the same transaction as actor state and the
//! protected business operation.

use crate::services::message_admission::witness::commit_observed;
use crate::{
    db::abuse_actor_state_repository::{lock_db_states, persist_db_states},
    services::abuse::{
        records::{ConsumedChallenge, DbActorState, VerificationDecision},
        GuardError, WorkRequirement,
    },
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_abuse_policy::admission_execution::AdmissionCommitObserver;
use northstar_abuse_policy::admission_execution::{CommitFact, GuardDecision, TransactionScope};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub(crate) async fn verify(
    pool: &PgPool,
    state_keys: &[String],
    challenge_id: Option<Uuid>,
    decide: impl FnOnce(
        &mut [DbActorState],
        DateTime<Utc>,
        Option<ConsumedChallenge>,
    ) -> Result<VerificationDecision>,
    witness: Option<&dyn AdmissionCommitObserver>,
) -> Result<std::result::Result<WorkRequirement, GuardError>> {
    let mut tx = pool.begin().await?;
    let outcome = verify_in_tx(&mut tx, state_keys, challenge_id, decide).await?;
    if let Some(witness) = witness {
        let decision = if outcome.is_ok() {
            GuardDecision::Allowed
        } else {
            GuardDecision::Denied
        };
        commit_observed(
            tx,
            witness,
            TransactionScope::GuardOnlyVerification,
            CommitFact::GuardOnly(decision),
        )
        .await?;
    } else {
        tx.commit().await?;
    }
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
