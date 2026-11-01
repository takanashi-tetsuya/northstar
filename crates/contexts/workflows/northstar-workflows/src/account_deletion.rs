//! Durable recovery leases for XEP-0077 account removal.
//!
//! The account row remains the deletion authority. This table only records
//! that a client-authorized quiesce has committed and gives one process at a
//! time a bounded lease to finish teardown and deletion after a crash.

use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub use northstar_auth_application::account::DeletionRecoveryJob as AccountDeletionJob;

pub async fn claim_account_deletion_jobs(
    pool: &PgPool,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<AccountDeletionJob>> {
    anyhow::ensure!((1..=128).contains(&limit), "invalid deletion claim limit");
    anyhow::ensure!(
        (30..=3_600).contains(&lease_seconds),
        "invalid deletion claim lease"
    );
    let claim_token = Uuid::new_v4();
    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT request.user_id
               FROM account_deletion_requests AS request
              WHERE request.recovery_after <= clock_timestamp()
                AND (request.claim_until IS NULL OR request.claim_until <= clock_timestamp())
              ORDER BY request.recovery_after,request.requested_at,request.user_id
              LIMIT $1
              FOR UPDATE SKIP LOCKED
         )
         UPDATE account_deletion_requests AS request
            SET claim_token=$2,
                claim_until=clock_timestamp() + $3 * INTERVAL '1 second',
                attempts=request.attempts+1
           FROM candidates,users
          WHERE request.user_id=candidates.user_id
            AND users.id=request.user_id
         RETURNING request.user_id,users.username,request.attempts",
    )
    .bind(limit)
    .bind(claim_token)
    .bind(lease_seconds)
    .fetch_all(pool)
    .await
    .context("could not claim durable account-deletion recovery jobs")?;
    Ok(rows
        .into_iter()
        .map(|row| {
            AccountDeletionJob::from_lease(
                row.get("user_id"),
                row.get("username"),
                claim_token,
                row.get("attempts"),
            )
        })
        .collect())
}

pub async fn release_account_deletion_job(
    pool: &PgPool,
    job: &AccountDeletionJob,
    error_code: &str,
) -> Result<bool> {
    anyhow::ensure!(
        !error_code.is_empty()
            && error_code.len() <= 128
            && !error_code.chars().any(char::is_control),
        "invalid account-deletion recovery error code"
    );
    // A bounded exponential retry keeps a broken storage or SM dependency from
    // becoming a tight database loop. The durable row remains visible to
    // operators while another process may claim it after this delay.
    let exponent = u32::try_from(job.attempts().clamp(1, 10)).unwrap_or(10);
    let retry_seconds = 2_i64.saturating_pow(exponent).clamp(2, 3_600);
    Ok(sqlx::query(
        "UPDATE account_deletion_requests
            SET claim_token=NULL,
                claim_until=NULL,
                recovery_after=clock_timestamp() + $3 * INTERVAL '1 second',
                last_error_code=$4
          WHERE user_id=$1 AND claim_token=$2",
    )
    .bind(job.user_id)
    .bind(job.claim_token())
    .bind(retry_seconds)
    .bind(error_code)
    .execute(pool)
    .await
    .context("could not release durable account-deletion recovery job")?
    .rows_affected()
        == 1)
}
