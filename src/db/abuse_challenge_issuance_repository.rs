//! Atomic issuance-window, capacity, actor-state, and challenge persistence.

use crate::{
    abuse::{AbuseAction, ChallengeCapacityExceeded, PowChallenge},
    db::abuse_actor_state_repository::{lock_db_states, persist_db_states, DbActorState},
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

pub(crate) struct IssueRequest {
    pub(crate) issue_groups: Vec<(Vec<String>, usize)>,
    pub(crate) capacity_groups: Vec<(Vec<String>, usize)>,
    pub(crate) actor_state_keys: Vec<String>,
    pub(crate) window: Duration,
}

/// The application signs this record after the repository has locked the
/// actor state. All cryptographic and rotation decisions stay with the guard.
pub(crate) struct IssueRecord {
    pub(crate) action: AbuseAction,
    pub(crate) challenge: PowChallenge,
    pub(crate) subject_hash: Vec<u8>,
    pub(crate) actor_sequences: serde_json::Value,
    pub(crate) intent_method: Option<String>,
    pub(crate) intent_path: Option<String>,
    pub(crate) body_sha256: Option<Vec<u8>>,
}

pub(crate) async fn issue(
    pool: &PgPool,
    request: IssueRequest,
    sign: impl FnOnce(&mut [DbActorState], DateTime<Utc>) -> Result<IssueRecord>,
) -> Result<PowChallenge> {
    let mut tx = pool.begin().await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    // This transaction-wide gate makes the global and per-actor active-row
    // checks exact across processes.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(northstar_abuse_policy::CHALLENGE_CAPACITY_ADVISORY_LOCK)
        .execute(&mut *tx)
        .await?;

    let mut issue_keys = request
        .issue_groups
        .iter()
        .flat_map(|(keys, _)| keys.iter().cloned())
        .collect::<Vec<_>>();
    issue_keys.sort();
    issue_keys.dedup();
    for key in &issue_keys {
        sqlx::query("INSERT INTO abuse_challenge_issue_windows (actor_key) VALUES ($1) ON CONFLICT (actor_key) DO NOTHING")
            .bind(key).execute(&mut *tx).await?;
    }
    let rows = sqlx::query(
        "SELECT actor_key,event_times FROM abuse_challenge_issue_windows
         WHERE actor_key=ANY($1) ORDER BY actor_key FOR UPDATE",
    )
    .bind(&issue_keys)
    .fetch_all(&mut *tx)
    .await?;
    let issue_state = rows
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>("actor_key"),
                row.get::<Vec<DateTime<Utc>>, _>("event_times"),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut merged_issue_state = BTreeMap::new();
    for (group, limit) in request.issue_groups {
        let mut events = group
            .iter()
            .filter_map(|key| issue_state.get(key))
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        events.sort();
        events.dedup();
        trim_issue_events(&mut events, now, request.window);
        if events.len() >= limit {
            let retry_after_seconds = events
                .first()
                .map(|oldest| retry_after_db(Some(*oldest + duration(request.window)), now))
                .unwrap_or(1);
            return Err(ChallengeCapacityExceeded {
                retry_after_seconds,
            }
            .into());
        }
        events.push(now);
        for key in group {
            merged_issue_state.insert(key, events.clone());
        }
    }
    for (key, events) in merged_issue_state {
        sqlx::query("UPDATE abuse_challenge_issue_windows SET event_times=$2, updated_at=$3 WHERE actor_key=$1")
            .bind(key).bind(events).bind(now).execute(&mut *tx).await?;
    }

    let capacity_actor_keys = request
        .capacity_groups
        .iter()
        .flat_map(|(keys, _)| keys.iter().cloned())
        .collect::<Vec<_>>();
    let (global_count, global_available_at): (i64, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT COUNT(*)::bigint,MIN(expires_at)
         FROM abuse_pow_challenges WHERE expires_at > $1",
    )
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    if global_count
        >= i64::try_from(northstar_abuse_policy::MAX_ACTIVE_POW_CHALLENGES_GLOBAL)
            .unwrap_or(i64::MAX)
    {
        return Err(ChallengeCapacityExceeded {
            retry_after_seconds: retry_after_db(global_available_at, now),
        }
        .into());
    }
    for (group, limit) in &request.capacity_groups {
        let (count, available_at): (i64, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT COUNT(*)::bigint,MIN(expires_at)
             FROM abuse_pow_challenges
             WHERE expires_at > $1 AND capacity_actor_keys && $2::text[]",
        )
        .bind(now)
        .bind(group)
        .fetch_one(&mut *tx)
        .await?;
        if count >= i64::try_from(*limit).unwrap_or(i64::MAX) {
            return Err(ChallengeCapacityExceeded {
                retry_after_seconds: retry_after_db(available_at, now),
            }
            .into());
        }
    }

    let mut states = lock_db_states(&mut tx, &request.actor_state_keys, now).await?;
    let record = sign(&mut states, now)?;
    persist_db_states(&mut tx, &states).await?;
    let challenge = record.challenge;
    sqlx::query(
        "INSERT INTO abuse_pow_challenges (id,action,subject_hash,key_id,prefix,work_factor,not_before,expires_at,actor_sequences,requirement,capacity_actor_keys,protocol_version,intent_method,intent_path,body_sha256,server_nonce,issued_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
    )
    .bind(challenge.challenge_id)
    .bind(record.action.as_str())
    .bind(record.subject_hash)
    .bind(&challenge.key_id)
    .bind(&challenge.prefix)
    .bind(i64::try_from(challenge.requirement.work_factor).unwrap_or(i64::MAX))
    .bind(now + duration(Duration::from_secs(challenge.requirement.hard_wait_seconds)))
    .bind(challenge.expires_at)
    .bind(record.actor_sequences)
    .bind(serde_json::to_value(&challenge.requirement)?)
    .bind(capacity_actor_keys)
    .bind(i16::try_from(challenge.version).unwrap_or(i16::MAX))
    .bind(record.intent_method)
    .bind(record.intent_path)
    .bind(record.body_sha256)
    .bind(&challenge.server_nonce)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(challenge)
}

fn duration(value: Duration) -> chrono::Duration {
    chrono::Duration::seconds(i64::try_from(value.as_secs()).unwrap_or(i64::MAX))
}

fn trim_issue_events(events: &mut Vec<DateTime<Utc>>, now: DateTime<Utc>, window: Duration) {
    let cutoff = now - duration(window);
    events.retain(|event| *event >= cutoff && *event <= now);
    if events.len() > 4_096 {
        events.drain(..events.len() - 4_096);
    }
}

fn retry_after_db(available_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> u64 {
    available_at
        .map(|available_at| {
            u64::try_from(
                available_at
                    .signed_duration_since(now)
                    .num_milliseconds()
                    .max(1)
                    .saturating_add(999)
                    / 1_000,
            )
            .unwrap_or(u64::MAX)
        })
        .unwrap_or(1)
        .max(1)
}
