//! Bounded PostgreSQL cleanup for durable anti-abuse state.

use crate::effects::AbuseEffects;
use anyhow::Result;
use sqlx::PgPool;

/// Each statement commits independently, as it did before this repository
/// boundary. A failed later deletion does not roll back an earlier batch.
pub(crate) async fn cleanup(
    pool: &PgPool,
    effects: &impl AbuseEffects,
    issue_window_seconds: u64,
    actor_stale_seconds: u64,
) -> Result<()> {
    // A flood must not turn one maintenance tick into an unbounded delete or
    // lock spike on the same database that serves live sessions.
    sqlx::query(
        "WITH doomed AS (
            SELECT ctid FROM abuse_pow_challenges
            WHERE expires_at <= clock_timestamp()
            ORDER BY expires_at LIMIT 1000
         )
         DELETE FROM abuse_pow_challenges AS target
         USING doomed WHERE target.ctid=doomed.ctid",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "WITH doomed AS (
            SELECT ctid FROM abuse_challenge_issue_windows
            WHERE updated_at < clock_timestamp() - ($1::bigint * INTERVAL '1 second')
            ORDER BY updated_at LIMIT 1000
         )
         DELETE FROM abuse_challenge_issue_windows AS target
         USING doomed WHERE target.ctid=doomed.ctid",
    )
    .bind(i64::try_from(issue_window_seconds).unwrap_or(i64::MAX))
    .execute(pool)
    .await?;
    sqlx::query(
        "WITH doomed AS (
            SELECT ctid FROM abuse_actor_states
            WHERE GREATEST(last_activity, blocked_until) < clock_timestamp() - ($1::bigint * INTERVAL '1 second')
            ORDER BY GREATEST(last_activity, blocked_until) LIMIT 1000
         )
         DELETE FROM abuse_actor_states AS target
         USING doomed WHERE target.ctid=doomed.ctid",
    )
    .bind(i64::try_from(actor_stale_seconds).unwrap_or(i64::MAX))
    .execute(pool)
    .await?;
    sqlx::query(
        "WITH doomed AS (
            SELECT admission_key FROM abuse_message_admissions
            WHERE expires_at <= clock_timestamp()
            ORDER BY expires_at,admission_key
            LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM abuse_message_admissions AS target
         USING doomed WHERE target.admission_key=doomed.admission_key",
    )
    .bind(northstar_abuse_policy::MESSAGE_ADMISSION_CLEANUP_BATCH)
    .execute(pool)
    .await?;
    effects.delete_expired_offline_admissions(pool).await
}
