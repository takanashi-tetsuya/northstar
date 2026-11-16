//! Bounded startup admission and retry delays for PostgreSQL pool connections.

use anyhow::Context;
use std::time::Duration;

pub const RUNTIME_CONTROL_STARTUP_RETRY_MAX_DELAY: Duration = Duration::from_millis(500);

pub fn runtime_control_startup_retry_delay(attempt: u32, process_id: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(5);
    let exponential_millis = 10_u64.saturating_mul(1_u64 << exponent);
    // A process-local deterministic spread avoids another synchronized
    // connection wave without introducing shared startup state or a random
    // source into the authority boundary.
    let jitter_millis = u64::from(process_id)
        .wrapping_mul(0x9e37_79b9)
        .wrapping_add(u64::from(attempt).wrapping_mul(0x85eb_ca6b))
        % 97;
    Duration::from_millis(
        exponential_millis
            .saturating_add(jitter_millis)
            .min(RUNTIME_CONTROL_STARTUP_RETRY_MAX_DELAY.as_millis() as u64),
    )
}

pub async fn startup_database_connect<T, Connect, ConnectFuture>(
    deadline: tokio::time::Instant,
    attempt_limit: Duration,
    pool_name: &'static str,
    mut connect: Connect,
) -> anyhow::Result<T>
where
    Connect: FnMut(Duration) -> ConnectFuture,
    ConnectFuture: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let mut attempts = 0_u32;
    let admission = tokio::time::timeout_at(deadline, async {
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(sqlx::Error::PoolTimedOut);
            }
            let attempt_budget = remaining.min(attempt_limit);
            attempts = attempts.saturating_add(1);
            let result = tokio::time::timeout(attempt_budget, connect(attempt_budget))
                .await
                .unwrap_or(Err(sqlx::Error::PoolTimedOut));
            match result {
                Ok(pool) => return Ok(pool),
                Err(sqlx::Error::PoolTimedOut) => {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let delay = runtime_control_startup_retry_delay(attempts, std::process::id())
                        .min(remaining);
                    tokio::time::sleep(delay).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .unwrap_or(Err(sqlx::Error::PoolTimedOut));
    admission.with_context(|| {
        format!("could not create isolated {pool_name} database pool after {attempts} bounded startup admission attempts")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn auxiliary_pools_share_the_remaining_deadline_and_cancel_inflight_connect() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        startup_database_connect(deadline, Duration::from_secs(2), "command", |_| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        })
        .await
        .unwrap();
        let result: anyhow::Result<()> =
            startup_database_connect(deadline, Duration::from_secs(2), "OMEMO", |budget| {
                assert!(budget < Duration::from_secs(2));
                std::future::pending()
            })
            .await;
        assert!(result.unwrap_err().to_string().contains("OMEMO"));
        let result: anyhow::Result<()> =
            startup_database_connect(deadline, Duration::from_secs(2), "command", |_| async {
                panic!("a later pool must not reset an exhausted shared deadline")
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn auxiliary_pool_retry_preserves_its_acquisition_limit() {
        let attempts = AtomicU32::new(0);
        startup_database_connect(
            tokio::time::Instant::now() + Duration::from_secs(15),
            Duration::from_secs(2),
            "OMEMO",
            |budget| {
                assert_eq!(budget, Duration::from_secs(2));
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt == 0 {
                        Err(sqlx::Error::PoolTimedOut)
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn runtime_control_startup_backoff_is_bounded_and_decorrelates_processes() {
        let first = runtime_control_startup_retry_delay(1, 17);
        assert!(first >= Duration::from_millis(10));
        assert!(first <= Duration::from_millis(500));

        let saturated = runtime_control_startup_retry_delay(128, 17);
        assert!(saturated <= Duration::from_millis(500));
        assert!(saturated >= first);

        let delays = (10_u32..110)
            .map(|process_id| runtime_control_startup_retry_delay(3, process_id))
            .collect::<BTreeSet<_>>();
        assert!(
            delays.len() > 16,
            "a cold-start cohort must not retry in one synchronized wave"
        );
    }
}
