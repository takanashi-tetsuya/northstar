//! PostgreSQL row locking and persistence for anti-abuse actor state.

use crate::abuse::AbuseStateBusy;
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};

#[derive(Debug)]
pub(crate) struct DbActorState {
    pub(crate) key: String,
    pub(crate) events: Vec<DateTime<Utc>>,
    pub(crate) penalty_level: u32,
    pub(crate) last_activity: DateTime<Utc>,
    pub(crate) blocked_until: DateTime<Utc>,
    pub(crate) sequence: i64,
}

pub(crate) async fn lock_db_states(
    tx: &mut Transaction<'_, Postgres>,
    keys: &[String],
    now: DateTime<Utc>,
) -> Result<Vec<DbActorState>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut keys = keys.to_vec();
    keys.sort();
    keys.dedup();

    // Fixed in-process stripes protect the current node. Try-locks also
    // protect first-use rows across nodes without exhausting the pool while
    // waiting for a hot account or NAT address.
    for key in &keys {
        let acquired: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_xact_lock(hashtextextended($1::text, $2::bigint))",
        )
        .bind(key)
        .bind(northstar_abuse_policy::ABUSE_STATE_ADVISORY_HASH_SEED)
        .fetch_one(&mut **tx)
        .await?;
        if !acquired {
            return Err(AbuseStateBusy.into());
        }
    }
    sqlx::query(
        "INSERT INTO abuse_actor_states (state_key, last_activity, blocked_until)
         SELECT key, $2, $2 FROM UNNEST($1::text[]) AS key
         ON CONFLICT (state_key) DO NOTHING",
    )
    .bind(&keys)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    let rows = sqlx::query("SELECT state_key, event_times, penalty_level, last_activity, blocked_until, sequence FROM abuse_actor_states WHERE state_key = ANY($1) ORDER BY state_key FOR UPDATE NOWAIT")
        .bind(&keys)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref()
                == Some("55P03")
            {
                anyhow::Error::new(AbuseStateBusy)
            } else {
                anyhow::Error::new(error)
            }
        })?;
    Ok(rows
        .into_iter()
        .map(|row| DbActorState {
            key: row.get("state_key"),
            events: row.get("event_times"),
            penalty_level: u32::try_from(row.get::<i32, _>("penalty_level")).unwrap_or(10),
            last_activity: row.get("last_activity"),
            blocked_until: row.get("blocked_until"),
            sequence: row.get("sequence"),
        })
        .collect())
}

pub(crate) async fn persist_db_states(
    tx: &mut Transaction<'_, Postgres>,
    states: &[DbActorState],
) -> Result<()> {
    if states.is_empty() {
        return Ok(());
    }
    let mut query = QueryBuilder::<Postgres>::new(
        "UPDATE abuse_actor_states AS target SET event_times=incoming.event_times, penalty_level=incoming.penalty_level, last_activity=incoming.last_activity, blocked_until=incoming.blocked_until, sequence=incoming.sequence FROM (",
    );
    query.push_values(states, |mut row, state| {
        row.push_bind(&state.key)
            .push_bind(&state.events)
            .push_bind(i32::try_from(state.penalty_level).unwrap_or(10))
            .push_bind(state.last_activity)
            .push_bind(state.blocked_until)
            .push_bind(state.sequence);
    });
    query.push(") AS incoming(state_key,event_times,penalty_level,last_activity,blocked_until,sequence) WHERE target.state_key=incoming.state_key");
    query.build().execute(&mut **tx).await?;
    Ok(())
}

/// Lock, apply an application decision, persist, and commit one failure as a
/// unit. The callback is synchronous, so it cannot hold row locks across
/// unrelated I/O; all policy and key-rotation decisions stay in the caller.
pub(crate) async fn record_failure(
    pool: &PgPool,
    keys: &[String],
    decide: impl FnOnce(&mut [DbActorState], DateTime<Utc>),
) -> Result<()> {
    let mut tx = pool.begin().await?;
    apply_in_tx(&mut tx, keys, decide).await?;
    tx.commit().await?;
    Ok(())
}

/// Read and persist a requirement under the same actor-state locks. Decay and
/// key-rotation policy remain in the application callback.
pub(crate) async fn current_requirement<R>(
    pool: &PgPool,
    keys: &[String],
    decide: impl FnOnce(&mut [DbActorState], DateTime<Utc>) -> R,
) -> Result<R> {
    let mut tx = pool.begin().await?;
    let requirement = apply_in_tx(&mut tx, keys, decide).await?;
    tx.commit().await?;
    Ok(requirement)
}

/// Apply a policy decision inside a larger business transaction. The actor
/// rows and the decision's persistence commit with that transaction.
pub(crate) async fn apply_in_tx<R>(
    tx: &mut Transaction<'_, Postgres>,
    keys: &[String],
    decide: impl FnOnce(&mut [DbActorState], DateTime<Utc>) -> R,
) -> Result<R> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let mut states = lock_db_states(tx, keys, now).await?;
    let requirement = decide(&mut states, now);
    persist_db_states(tx, &states).await?;
    Ok(requirement)
}
