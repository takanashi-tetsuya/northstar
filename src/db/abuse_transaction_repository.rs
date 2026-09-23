//! Compose anti-abuse decisions with caller-owned business transactions.

use crate::{
    abuse::{
        AbuseAction, AbuseGuard, PersistentVerificationInput, PowIntent, PowProof,
        TransactionalGuardOutcome, WorkRequirement,
    },
    db::{abuse_actor_state_repository, abuse_verification_repository},
};
use anyhow::Result;
use sqlx::{Postgres, Transaction};

pub(crate) async fn verify_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    guard: &AbuseGuard,
    action: AbuseAction,
    subject: &str,
    actors: &[String],
    proof: Option<&PowProof>,
    intent: Option<&PowIntent>,
) -> Result<TransactionalGuardOutcome> {
    anyhow::ensure!(
        guard.persistent_storage_enabled(),
        "transactional abuse decisions require persistent storage"
    );
    let keys = guard.persistent_actor_state_keys(action, actors);
    let input = PersistentVerificationInput {
        action,
        subject,
        actors,
        proof,
        intent,
    };
    let result = abuse_verification_repository::verify_in_tx(
        tx,
        &keys,
        input.proof.map(|proof| proof.challenge_id),
        |states, now, challenge| {
            guard.decide_persistent_verification(input, states, now, challenge)
        },
    )
    .await?;
    Ok(match result {
        Ok(_) => TransactionalGuardOutcome::Allowed,
        Err(error) => TransactionalGuardOutcome::DeniedNeedsCommit(error),
    })
}

pub(crate) async fn current_requirement_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    guard: &AbuseGuard,
    action: AbuseAction,
    actors: &[String],
) -> Result<WorkRequirement> {
    anyhow::ensure!(
        guard.persistent_storage_enabled(),
        "transactional abuse decisions require persistent storage"
    );
    let keys = guard.persistent_actor_state_keys(action, actors);
    abuse_actor_state_repository::apply_in_tx(tx, &keys, |states, now| {
        guard.current_requirement_decision(action, actors, states, now)
    })
    .await
}

pub(crate) async fn record_failure_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    guard: &AbuseGuard,
    action: AbuseAction,
    actors: &[String],
) -> Result<()> {
    anyhow::ensure!(
        guard.persistent_storage_enabled(),
        "transactional abuse decisions require persistent storage"
    );
    let keys = guard.persistent_actor_state_keys(action, actors);
    abuse_actor_state_repository::apply_in_tx(tx, &keys, |states, now| {
        guard.record_failure_decision(action, actors, states, now)
    })
    .await
}
