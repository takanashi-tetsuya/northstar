//! PostgreSQL-backed adapter for exact rated-message proof admission leases.
use crate::{
    abuse::{
        AbuseAction, AbuseGuard, MessageAdmissionAcceptance, MessageAdmissionCandidate,
        MessageAdmissionLease, MessageAdmissionRequest, MessageAdmissionStart,
        MessageDedupeIdentity, PersistentVerificationInput, PowIntent,
    },
    db::{abuse_actor_state_repository, abuse_verification_repository},
    services::message_admission::{
        acceptance_fence,
        witness::{commit_observed, AdmissionWitness},
        MessageAdmissionRepository,
    },
};
use anyhow::Result;
use northstar_abuse_policy::admission_execution::{
    BeginCommitPurpose, Command, CommitFact, Effect, FinalizeSuccess, ReconcileResult,
    TransactionScope,
};
use northstar_abuse_policy::admission_transaction::{
    self as decision, AdmissionCandidate, AdmissionFence, AdmissionRow, BeginRowDecision,
    CapacityDecision, FinalizeDecision, RowState,
};
use sqlx::{PgPool, Row};
use std::sync::Arc;
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

/// Reserve a pending admission under the same transaction as any one-use PoW
/// proof and actor-state advance. Delivery happens only after this commits.
pub(crate) async fn begin_message_admission(
    pool: &PgPool,
    guard: &AbuseGuard,
    request: &MessageAdmissionRequest<'_>,
    candidates: &[MessageAdmissionCandidate],
    offline_dedupe: MessageDedupeIdentity,
    witness: &AdmissionWitness,
) -> Result<MessageAdmissionStart> {
    let candidate_keys = candidates
        .iter()
        .map(|candidate| candidate.admission_key.clone())
        .collect::<Vec<_>>();
    let mut lock_ids = candidate_keys
        .iter()
        .map(|key| northstar_abuse_policy::message_admission_lock_id(key))
        .collect::<Vec<_>>();
    lock_ids.sort_unstable();
    lock_ids.dedup();

    let mut tx = pool.begin().await?;
    for lock_id in lock_ids {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_id)
            .execute(&mut *tx)
            .await?;
    }
    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM abuse_message_admissions
         WHERE admission_key=ANY($1::bytea[]) AND expires_at <= $2",
    )
    .bind(&candidate_keys)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let rows = sqlx::query(
        "SELECT admission_key,key_id,actor_id,payload_mac,state,
                lease_token,lease_expires_at,expires_at
         FROM abuse_message_admissions
         WHERE admission_key=ANY($1::bytea[])
         ORDER BY admission_key FOR UPDATE",
    )
    .bind(&candidate_keys)
    .fetch_all(&mut *tx)
    .await?;
    let locked_rows = rows.iter().map(admission_row).collect::<Result<Vec<_>>>()?;
    let candidates = candidates
        .iter()
        .map(|candidate| AdmissionCandidate {
            key_id: candidate.key_id.clone(),
            admission_key: candidate.admission_key.clone(),
            payload_mac: candidate.payload_mac.clone(),
        })
        .collect::<Vec<_>>();
    let row_decision = decision::decide_begin(request.actor_id, &candidates, &locked_rows, now)?;
    let state_keys = guard.persistent_actor_state_keys(AbuseAction::Message, request.actors);
    match row_decision {
        BeginRowDecision::Conflict => {
            tx.rollback().await?;
            return Ok(MessageAdmissionStart::Conflict);
        }
        BeginRowDecision::ReplayAccepted => {
            commit_observed(
                tx,
                witness,
                TransactionScope::RatedBegin(BeginCommitPurpose::ReplayRead),
                CommitFact::ReplayAccepted,
            )
            .await?;
            return Ok(MessageAdmissionStart::ReplayAccepted);
        }
        BeginRowDecision::InProgress {
            retry_after_seconds,
        } => {
            let mut requirement =
                abuse_actor_state_repository::apply_in_tx(&mut tx, &state_keys, |states, now| {
                    guard.current_requirement_decision(
                        AbuseAction::Message,
                        request.actors,
                        states,
                        now,
                    )
                })
                .await?;
            requirement.retry_after_seconds =
                requirement.retry_after_seconds.max(retry_after_seconds);
            commit_observed(
                tx,
                witness,
                TransactionScope::RatedBegin(BeginCommitPurpose::PendingRequirement),
                CommitFact::InProgress,
            )
            .await?;
            return Ok(MessageAdmissionStart::InProgress { requirement });
        }
        BeginRowDecision::Reclaim => {
            let row = locked_rows.first().expect("reclaim requires locked row");
            let lease_token = Uuid::new_v4();
            sqlx::query(
                "UPDATE abuse_message_admissions
                 SET lease_token=$2,lease_expires_at=$3,updated_at=$4
                 WHERE admission_key=$1",
            )
            .bind(&row.admission_key)
            .bind(lease_token)
            .bind(decision::lease_expiry(now))
            .bind(now)
            .execute(&mut *tx)
            .await?;
            let requirement =
                abuse_actor_state_repository::apply_in_tx(&mut tx, &state_keys, |states, now| {
                    guard.current_requirement_decision(
                        AbuseAction::Message,
                        request.actors,
                        states,
                        now,
                    )
                })
                .await?;
            let fence = AdmissionFence {
                admission_key: row.admission_key.clone(),
                payload_mac: row.payload_mac.clone(),
                lease_token,
            };
            commit_observed(
                tx,
                witness,
                TransactionScope::RatedBegin(BeginCommitPurpose::Reclaim),
                CommitFact::Reserved(fence),
            )
            .await?;
            return Ok(MessageAdmissionStart::Proceed {
                lease: Some(MessageAdmissionLease::new(
                    row.admission_key.clone(),
                    row.payload_mac.clone(),
                    lease_token,
                    offline_dedupe,
                )),
                requirement,
            });
        }
        BeginRowDecision::VerifyGuard => {}
    }

    let intent = PowIntent::xmpp(
        AbuseAction::Message,
        "/xmpp/message",
        request.pow_intent_payload.as_bytes(),
    );
    let guard_outcome = abuse_verification_repository::verify_in_tx(
        &mut tx,
        &state_keys,
        request.proof.map(|proof| proof.challenge_id),
        |states, now, challenge| {
            guard.decide_persistent_verification(
                PersistentVerificationInput {
                    action: AbuseAction::Message,
                    subject: request.subject,
                    actors: request.actors,
                    proof: request.proof,
                    intent: Some(&intent),
                },
                states,
                now,
                challenge,
            )
        },
    )
    .await?;
    let requirement = match guard_outcome {
        Ok(requirement) => requirement,
        Err(error) => {
            commit_observed(
                tx,
                witness,
                TransactionScope::RatedBegin(BeginCommitPurpose::GuardDenial),
                CommitFact::Denied,
            )
            .await?;
            return Ok(MessageAdmissionStart::Denied(error));
        }
    };
    let primary = candidates
        .first()
        .expect("primary message-admission key is always present");
    let capacity_shard =
        northstar_abuse_policy::message_admission_capacity_shard(&primary.admission_key);
    // Bound foreground cleanup when the periodic worker is delayed.
    sqlx::query(
        "WITH doomed AS (
             SELECT admission_key FROM abuse_message_admissions
              WHERE capacity_shard=$1 AND expires_at <= $2
              ORDER BY expires_at,admission_key
              LIMIT 128 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM abuse_message_admissions AS target
          USING doomed WHERE target.admission_key=doomed.admission_key",
    )
    .bind(capacity_shard)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let active_for_user: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_message_admissions
         WHERE actor_id=$1 AND expires_at > $2",
    )
    .bind(request.actor_id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    if decision::decide_actor_capacity(active_for_user) == CapacityDecision::Limited {
        tx.rollback().await?;
        return Ok(MessageAdmissionStart::CapacityLimited);
    }
    let capacity_reserved = sqlx::query_scalar::<_, i32>(
        "UPDATE abuse_message_admission_capacity
         SET active_records=active_records+1
         WHERE shard=$1 AND active_records < $2
         RETURNING active_records",
    )
    .bind(capacity_shard)
    .bind(northstar_abuse_policy::MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD)
    .fetch_optional(&mut *tx)
    .await?;
    if decision::decide_shard_reservation(capacity_reserved) == CapacityDecision::Limited {
        tx.rollback().await?;
        return Ok(MessageAdmissionStart::CapacityLimited);
    }
    let lease_token = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO abuse_message_admissions
         (admission_key,key_id,actor_id,capacity_shard,payload_mac,
          proof_challenge_id,state,lease_token,lease_expires_at,expires_at)
         VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9)",
    )
    .bind(&primary.admission_key)
    .bind(&primary.key_id)
    .bind(request.actor_id)
    .bind(capacity_shard)
    .bind(&primary.payload_mac)
    .bind(request.proof.map(|proof| proof.challenge_id))
    .bind(lease_token)
    .bind(decision::lease_expiry(now))
    .bind(decision::pending_expiry(now))
    .execute(&mut *tx)
    .await?;
    let fence = AdmissionFence {
        admission_key: primary.admission_key.clone(),
        payload_mac: primary.payload_mac.clone(),
        lease_token,
    };
    commit_observed(
        tx,
        witness,
        TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
        CommitFact::Reserved(fence),
    )
    .await?;
    Ok(MessageAdmissionStart::Proceed {
        lease: Some(MessageAdmissionLease::new(
            primary.admission_key.clone(),
            primary.payload_mac.clone(),
            lease_token,
            offline_dedupe,
        )),
        requirement,
    })
}

fn admission_row(row: &sqlx::postgres::PgRow) -> Result<AdmissionRow> {
    let state = match row.get::<String, _>("state").as_str() {
        "pending" => RowState::Pending,
        "accepted" => RowState::Accepted,
        _ => anyhow::bail!("invalid message admission state"),
    };
    Ok(AdmissionRow {
        admission_key: row.get("admission_key"),
        key_id: row.get("key_id"),
        actor_id: row.get("actor_id"),
        payload_mac: row.get("payload_mac"),
        state,
        lease_token: row.get("lease_token"),
        lease_expires_at: row.get("lease_expires_at"),
        expires_at: row.get("expires_at"),
    })
}

/// Independent finalization. Accepted identity precedes token comparison.
async fn accept_observed(
    pool: &PgPool,
    acceptance: &MessageAdmissionAcceptance<'_>,
    witness: &AdmissionWitness,
) -> Result<FinalizeDecision> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(northstar_abuse_policy::message_admission_lock_id(
            acceptance.admission_key(),
        ))
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query(
        "SELECT admission_key,key_id,actor_id,payload_mac,state,lease_token,lease_expires_at,expires_at
         FROM abuse_message_admissions WHERE admission_key=$1 FOR UPDATE",
    ).bind(acceptance.admission_key()).fetch_optional(&mut *tx).await?;
    let row = row.as_ref().map(admission_row).transpose()?;
    let fence = acceptance_fence(acceptance);
    let result = decision::decide_finalize(row.as_ref(), &fence);
    let success = match result {
        FinalizeDecision::AlreadyAccepted => FinalizeSuccess::AlreadyAccepted,
        FinalizeDecision::AcceptPending => {
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
            .bind(decision::accepted_expiry(now))
            .execute(&mut *tx)
            .await?;
            FinalizeSuccess::PendingAccepted
        }
        FinalizeDecision::Missing
        | FinalizeDecision::PayloadConflict
        | FinalizeDecision::LostFence => return Ok(result),
    };
    commit_observed(
        tx,
        witness,
        TransactionScope::AdmissionFinalize,
        CommitFact::Finalized {
            fence,
            result: success,
        },
    )
    .await?;
    Ok(result)
}

#[cfg(test)]
pub(crate) async fn accept_message_admission(
    pool: &PgPool,
    acceptance: &MessageAdmissionAcceptance<'_>,
) -> Result<()> {
    let (_, witness) = crate::services::message_admission::operation(
        northstar_abuse_policy::admission_execution::Command::Finalize(acceptance_fence(
            acceptance,
        )),
    );
    match accept_observed(pool, acceptance, &witness).await? {
        FinalizeDecision::AlreadyAccepted | FinalizeDecision::AcceptPending => Ok(()),
        FinalizeDecision::Missing => {
            anyhow::bail!("message admission disappeared before acceptance")
        }
        FinalizeDecision::PayloadConflict => {
            anyhow::bail!("message admission payload changed before acceptance")
        }
        FinalizeDecision::LostFence => {
            anyhow::bail!("message admission fencing lease was lost before acceptance")
        }
    }
}

impl MessageAdmissionRepository for PostgresMessageAdmissionRepository {
    async fn begin(
        &self,
        request: &MessageAdmissionRequest<'_>,
        witness: &AdmissionWitness,
    ) -> Result<MessageAdmissionStart> {
        self.guard
            .begin_message_admission_observed(request, witness)
            .await
    }
    async fn accept(
        &self,
        acceptance: &MessageAdmissionAcceptance<'_>,
        witness: &AdmissionWitness,
    ) -> Result<FinalizeDecision> {
        accept_observed(&self.pool, acceptance, witness).await
    }
    async fn reconcile(&self, effect: &Effect) -> Result<ReconcileResult> {
        let Command::Reconcile { fence, .. } = &effect.command else {
            anyhow::bail!("admission reconciliation requires a reconcile effect");
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(northstar_abuse_policy::message_admission_lock_id(
                &fence.admission_key,
            ))
            .execute(&mut *tx)
            .await?;
        let row = sqlx::query(
            "SELECT admission_key,key_id,actor_id,payload_mac,state,lease_token,lease_expires_at,expires_at
             FROM abuse_message_admissions WHERE admission_key=$1 FOR UPDATE",
        ).bind(&fence.admission_key).fetch_optional(&mut *tx).await?;
        let row = row.as_ref().map(admission_row).transpose()?;
        let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let observation = decision::reconcile(row.as_ref(), fence, now);
        tx.rollback().await?;
        Ok(ReconcileResult {
            effect: Box::new(effect.clone()),
            observation,
        })
    }
}
