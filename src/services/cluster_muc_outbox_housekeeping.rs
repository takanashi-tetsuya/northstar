//! Bounded post-delivery cleanup and gauge reads for the clustered MUC outbox.
//! The worker keeps each call inside its own database turn and owns cadence.

use anyhow::Result;
use std::future::Future;

const DEAD_LETTER_PURGE_LIMIT: i64 = 256;
const HISTORY_RETENTION_DAYS: i64 = 90;
const HISTORY_PURGE_LIMIT: i64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClusterMucOutboxGaugeSnapshot {
    pub(crate) queued_rows: i64,
    pub(crate) dead_letter_rows: i64,
    pub(crate) oldest_age_seconds: i64,
}

pub(crate) trait ClusterMucOutboxHousekeepingRepository: Send + Sync {
    fn purge_expired_dead_letters(&self, limit: i64) -> impl Future<Output = Result<u64>> + Send;

    fn purge_history(
        &self,
        retention_days: i64,
        limit: i64,
    ) -> impl Future<Output = Result<(u64, u64)>> + Send;

    fn snapshot(&self) -> impl Future<Output = Result<ClusterMucOutboxGaugeSnapshot>> + Send;
}

pub(crate) struct ClusterMucOutboxHousekeepingService<R> {
    repository: R,
}

impl<R: ClusterMucOutboxHousekeepingRepository> ClusterMucOutboxHousekeepingService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn purge_expired_dead_letters(&self) -> Result<()> {
        self.repository
            .purge_expired_dead_letters(DEAD_LETTER_PURGE_LIMIT)
            .await?;
        Ok(())
    }

    pub(crate) async fn purge_history(&self) -> Result<()> {
        self.repository
            .purge_history(HISTORY_RETENTION_DAYS, HISTORY_PURGE_LIMIT)
            .await?;
        Ok(())
    }

    pub(crate) async fn snapshot(&self) -> Result<ClusterMucOutboxGaugeSnapshot> {
        self.repository.snapshot().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct StubRepository {
        calls: Mutex<Vec<&'static str>>,
    }

    impl ClusterMucOutboxHousekeepingRepository for &StubRepository {
        async fn purge_expired_dead_letters(&self, limit: i64) -> Result<u64> {
            assert_eq!(limit, 256);
            self.calls.lock().unwrap().push("dead-letters");
            Ok(1)
        }

        async fn purge_history(&self, retention_days: i64, limit: i64) -> Result<(u64, u64)> {
            assert_eq!((retention_days, limit), (90, 256));
            self.calls.lock().unwrap().push("history");
            Ok((2, 3))
        }

        async fn snapshot(&self) -> Result<ClusterMucOutboxGaugeSnapshot> {
            self.calls.lock().unwrap().push("snapshot");
            Ok(ClusterMucOutboxGaugeSnapshot {
                queued_rows: 4,
                dead_letter_rows: 5,
                oldest_age_seconds: 6,
            })
        }
    }

    #[tokio::test]
    async fn housekeeping_uses_bounded_arguments_and_preserves_separate_calls() {
        let repository = StubRepository {
            calls: Mutex::new(Vec::new()),
        };
        let service = ClusterMucOutboxHousekeepingService::new(&repository);
        service.purge_expired_dead_letters().await.unwrap();
        service.purge_history().await.unwrap();
        assert_eq!(
            service.snapshot().await.unwrap(),
            ClusterMucOutboxGaugeSnapshot {
                queued_rows: 4,
                dead_letter_rows: 5,
                oldest_age_seconds: 6,
            }
        );
        assert_eq!(
            *repository.calls.lock().unwrap(),
            ["dead-letters", "history", "snapshot"]
        );
    }
}
