//! Ordered PostgreSQL maintenance before a clustered-MUC outbox claim.
//! Each repository call keeps its existing independent commit boundary.

use anyhow::Result;
use std::future::Future;

pub(crate) trait ClusterMucOutboxPreclaimRepository: Send + Sync {
    fn expire_occupancies(&self, room_limit: i64) -> impl Future<Output = Result<u64>> + Send;
    fn dead_letter_expired(&self, limit: i64) -> impl Future<Output = Result<u64>> + Send;
}

pub(crate) struct ClusterMucOutboxPreclaimService<R> {
    repository: R,
}

impl<R: ClusterMucOutboxPreclaimRepository> ClusterMucOutboxPreclaimService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn prepare_pass(&self, room_limit: i64, outbox_limit: i64) -> Result<()> {
        self.repository.expire_occupancies(room_limit).await?;
        self.repository.dead_letter_expired(outbox_limit).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Copy)]
    enum Failure {
        None,
        Expiry,
        DeadLetter,
    }

    struct StubRepository {
        calls: Mutex<Vec<&'static str>>,
        failure: Failure,
    }

    impl ClusterMucOutboxPreclaimRepository for &StubRepository {
        async fn expire_occupancies(&self, room_limit: i64) -> Result<u64> {
            assert_eq!(room_limit, 32);
            self.calls.lock().unwrap().push("occupancy-expiry");
            if matches!(self.failure, Failure::Expiry) {
                anyhow::bail!("occupancy expiry failed");
            }
            Ok(3)
        }

        async fn dead_letter_expired(&self, limit: i64) -> Result<u64> {
            assert_eq!(limit, 256);
            self.calls.lock().unwrap().push("outbox-dead-letter");
            if matches!(self.failure, Failure::DeadLetter) {
                anyhow::bail!("dead-letter failed");
            }
            Ok(5)
        }
    }

    #[tokio::test]
    async fn maintenance_runs_in_order_with_the_original_limits() {
        let repository = StubRepository {
            calls: Mutex::new(Vec::new()),
            failure: Failure::None,
        };
        ClusterMucOutboxPreclaimService::new(&repository)
            .prepare_pass(32, 256)
            .await
            .unwrap();
        assert_eq!(
            *repository.calls.lock().unwrap(),
            vec!["occupancy-expiry", "outbox-dead-letter"]
        );
    }

    #[tokio::test]
    async fn first_failure_skips_dead_letter_and_second_keeps_first_complete() {
        for (failure, expected_calls, expected_error) in [
            (
                Failure::Expiry,
                vec!["occupancy-expiry"],
                "occupancy expiry failed",
            ),
            (
                Failure::DeadLetter,
                vec!["occupancy-expiry", "outbox-dead-letter"],
                "dead-letter failed",
            ),
        ] {
            let repository = StubRepository {
                calls: Mutex::new(Vec::new()),
                failure,
            };
            let error = ClusterMucOutboxPreclaimService::new(&repository)
                .prepare_pass(32, 256)
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected_error));
            assert_eq!(*repository.calls.lock().unwrap(), expected_calls);
        }
    }
}
