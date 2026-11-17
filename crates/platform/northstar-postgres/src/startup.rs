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
    async fn startup_retries_share_one_budget_and_only_retry_timeouts() {
        struct CancelledAttempt<'a>(&'a AtomicU32);

        impl Drop for CancelledAttempt<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        for (label, timeout, expected_attempts) in [
            ("pool timeout retries", true, 2),
            ("protocol failure stops", false, 1),
        ] {
            let started = tokio::time::Instant::now();
            let deadline = started + Duration::from_secs(1);
            let mut budgets = Vec::new();
            let result = startup_database_connect(
                deadline,
                Duration::from_secs(2),
                "budget-matrix",
                |budget| {
                    budgets.push(budget);
                    std::future::ready(if budgets.len() > 1 {
                        Ok(7_u8)
                    } else if timeout {
                        Err(sqlx::Error::PoolTimedOut)
                    } else {
                        Err(sqlx::Error::Protocol("invalid handshake".to_owned()))
                    })
                },
            )
            .await;
            assert_eq!(budgets.len(), expected_attempts, "{label}");
            assert!(budgets[0] <= deadline - started, "{label}");
            assert!(!budgets[0].is_zero(), "{label}");
            if timeout {
                assert_eq!(result.unwrap(), 7, "{label}");
                assert!(budgets[1] < budgets[0], "{label}: shared deadline shrinks");
                assert!(!budgets[1].is_zero(), "{label}");
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error.to_string(),
                    "could not create isolated budget-matrix database pool after 1 bounded startup admission attempts",
                    "{label}"
                );
                assert!(
                    matches!(
                        error.downcast_ref::<sqlx::Error>(),
                        Some(sqlx::Error::Protocol(message)) if message == "invalid handshake"
                    ),
                    "{label}: preserve the original error"
                );
            }
        }

        let cancelled = AtomicU32::new(0);
        let mut budgets = Vec::new();
        let value = startup_database_connect(
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_millis(5),
            "attempt-timeout",
            |budget| {
                budgets.push(budget);
                let first = budgets.len() == 1;
                let cancelled = &cancelled;
                async move {
                    if first {
                        let _attempt = CancelledAttempt(cancelled);
                        std::future::pending::<Result<u8, sqlx::Error>>().await
                    } else {
                        assert_eq!(cancelled.load(Ordering::Relaxed), 1);
                        Ok(9)
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(value, 9, "elapsed attempt retries");
        assert_eq!(
            budgets,
            vec![Duration::from_millis(5); 2],
            "elapsed attempt retries: cap each connection attempt"
        );
        assert_eq!(cancelled.load(Ordering::Relaxed), 1);
    }

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
