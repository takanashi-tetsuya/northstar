//! Durable recovery leases for XEP-0077 account removal.
//!
//! The account row remains the deletion authority. This table only records
//! that a client-authorized quiesce has committed and gives one process at a
//! time a bounded lease to finish teardown and deletion after a crash.

use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct AccountDeletionJob {
    pub user_id: Uuid,
    pub username: String,
    pub claim_token: Uuid,
    pub attempts: i32,
}

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
        .map(|row| AccountDeletionJob {
            user_id: row.get("user_id"),
            username: row.get("username"),
            claim_token,
            attempts: row.get("attempts"),
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
    let exponent = u32::try_from(job.attempts.clamp(1, 10)).unwrap_or(10);
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
    .bind(job.claim_token)
    .bind(retry_seconds)
    .bind(error_code)
    .execute(pool)
    .await
    .context("could not release durable account-deletion recovery job")?
    .rows_affected()
        == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn deletion_recovery_is_delayed_single_owner_and_cascading() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let username = format!("delete-recovery-{}", Uuid::new_v4());
        let user = crate::db::create_user(
            &pool,
            &username,
            "recovery-passphrase",
            false,
            true,
            4096,
            false,
        )
        .await
        .unwrap();
        assert!(crate::db::begin_account_deletion_quiesce(&pool, user.id)
            .await
            .unwrap());
        assert!(claim_account_deletion_jobs(&pool, 8, 60)
            .await
            .unwrap()
            .is_empty());

        sqlx::query(
            "UPDATE account_deletion_requests SET recovery_after=clock_timestamp()-INTERVAL '1 second' WHERE user_id=$1",
        )
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();
        let left = claim_account_deletion_jobs(&pool, 8, 60);
        let right = claim_account_deletion_jobs(&pool, 8, 60);
        let (left, right) = tokio::join!(left, right);
        let mut claimed = left.unwrap();
        claimed.extend(right.unwrap());
        assert_eq!(claimed.len(), 1);
        let job = claimed.pop().unwrap();
        assert_eq!(job.user_id, user.id);
        assert_eq!(job.username, username);

        let mut wrong = job.clone();
        wrong.claim_token = Uuid::new_v4();
        assert!(
            !release_account_deletion_job(&pool, &wrong, "injected-failure")
                .await
                .unwrap()
        );
        assert!(
            release_account_deletion_job(&pool, &job, "injected-failure")
                .await
                .unwrap()
        );

        crate::db::delete_user_with_roster_audited(
            &pool,
            user.id,
            "example.test",
            serde_json::json!({"source":"test"}),
        )
        .await
        .unwrap()
        .unwrap();
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM account_deletion_requests WHERE user_id=$1")
                .bind(user.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 0);
    }
}
