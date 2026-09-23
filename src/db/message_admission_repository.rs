//! PostgreSQL-backed adapter for exact rated-message proof admission leases.
use crate::{
    abuse::{
        AbuseAction, AbuseGuard, MessageAdmissionAcceptance, MessageAdmissionCandidate,
        MessageAdmissionLease, MessageAdmissionRequest, MessageAdmissionStart,
        MessageDedupeIdentity, PersistentVerificationInput, PowIntent,
    },
    db::{abuse_actor_state_repository, abuse_verification_repository},
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

/// Reserve a pending admission under the same transaction as any one-use PoW
/// proof and actor-state advance. Delivery happens only after this commits.
pub(crate) async fn begin_message_admission(
    pool: &PgPool,
    guard: &AbuseGuard,
    request: &MessageAdmissionRequest<'_>,
    candidates: &[MessageAdmissionCandidate],
    offline_dedupe: MessageDedupeIdentity,
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
                lease_token,lease_expires_at
         FROM abuse_message_admissions
         WHERE admission_key=ANY($1::bytea[])
         ORDER BY admission_key FOR UPDATE",
    )
    .bind(&candidate_keys)
    .fetch_all(&mut *tx)
    .await?;
    anyhow::ensure!(
        rows.len() <= 1,
        "message admission exists under multiple rotation keys"
    );
    let state_keys = guard.persistent_actor_state_keys(AbuseAction::Message, request.actors);
    if let Some(row) = rows.first() {
        let stored_key: Vec<u8> = row.get("admission_key");
        let stored_key_id: String = row.get("key_id");
        let stored_payload_mac: Vec<u8> = row.get("payload_mac");
        let exact = candidates.iter().any(|candidate| {
            candidate.key_id == stored_key_id
                && bool::from(
                    stored_key
                        .as_slice()
                        .ct_eq(candidate.admission_key.as_slice()),
                )
                && bool::from(
                    stored_payload_mac
                        .as_slice()
                        .ct_eq(candidate.payload_mac.as_slice()),
                )
        }) && row.get::<Uuid, _>("actor_id") == request.actor_id;
        if !exact {
            tx.rollback().await?;
            return Ok(MessageAdmissionStart::Conflict);
        }
        if row.get::<String, _>("state") == "accepted" {
            tx.commit().await?;
            return Ok(MessageAdmissionStart::ReplayAccepted);
        }
        let lease_expires_at: chrono::DateTime<chrono::Utc> = row.get("lease_expires_at");
        if lease_expires_at > now {
            let retry_after_seconds = u64::try_from(
                lease_expires_at
                    .signed_duration_since(now)
                    .num_milliseconds()
                    .saturating_add(999)
                    / 1_000,
            )
            .unwrap_or(u64::MAX)
            .max(1);
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
            tx.commit().await?;
            return Ok(MessageAdmissionStart::InProgress { requirement });
        }
        let lease_token = Uuid::new_v4();
        sqlx::query(
            "UPDATE abuse_message_admissions
             SET lease_token=$2,lease_expires_at=$3,updated_at=$4
             WHERE admission_key=$1",
        )
        .bind(&stored_key)
        .bind(lease_token)
        .bind(now + duration(northstar_abuse_policy::MESSAGE_ADMISSION_LEASE))
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
        tx.commit().await?;
        return Ok(MessageAdmissionStart::Proceed {
            lease: Some(MessageAdmissionLease::new(
                stored_key,
                stored_payload_mac,
                lease_token,
                offline_dedupe,
            )),
            requirement,
        });
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
            tx.commit().await?;
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
    if active_for_user >= northstar_abuse_policy::MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER {
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
    .await?
    .is_some();
    if !capacity_reserved {
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
    .bind(now + duration(northstar_abuse_policy::MESSAGE_ADMISSION_LEASE))
    .bind(now + duration(northstar_abuse_policy::MESSAGE_ADMISSION_PENDING_TTL))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
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

fn duration(value: std::time::Duration) -> chrono::Duration {
    chrono::Duration::seconds(i64::try_from(value.as_secs()).unwrap_or(i64::MAX))
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
