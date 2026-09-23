//! Bounded replay cleanup followed by fail-closed capacity-authority validation.

use anyhow::Result;
use std::future::Future;

pub(crate) trait ClusterReplayMaintenanceRepository: Send + Sync {
    fn cleanup_replays(&self, limit: i32) -> impl Future<Output = Result<u64>> + Send;
    fn validate_capacity_authority(&self) -> impl Future<Output = Result<()>> + Send;
}

pub(crate) struct ClusterReplayMaintenanceService<R> {
    repository: R,
}

impl<R: ClusterReplayMaintenanceRepository> ClusterReplayMaintenanceService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn cleanup_and_validate(&self, limit: i32) -> Result<u64> {
        let removed = self.repository.cleanup_replays(limit).await?;
        self.repository.validate_capacity_authority().await?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Copy)]
    enum Failure {
        None,
        Cleanup,
        Validation,
    }

    struct StubRepository {
        calls: Mutex<Vec<&'static str>>,
        failure: Failure,
    }

    impl StubRepository {
        fn new(failure: Failure) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                failure,
            }
        }
    }

    impl ClusterReplayMaintenanceRepository for &StubRepository {
        async fn cleanup_replays(&self, limit: i32) -> Result<u64> {
            assert_eq!(limit, 4096);
            self.calls.lock().unwrap().push("cleanup");
            if matches!(self.failure, Failure::Cleanup) {
                anyhow::bail!("replay cleanup failed");
            }
            Ok(7)
        }

        async fn validate_capacity_authority(&self) -> Result<()> {
            self.calls.lock().unwrap().push("validate");
            if matches!(self.failure, Failure::Validation) {
                anyhow::bail!("cluster replay capacity authority failed reconciliation");
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn cleanup_precedes_validation_and_preserves_batch_size() {
        let repository = StubRepository::new(Failure::None);
        let service = ClusterReplayMaintenanceService::new(&repository);
        assert_eq!(service.cleanup_and_validate(4096).await.unwrap(), 7);
        assert_eq!(
            repository.calls.lock().unwrap().as_slice(),
            &["cleanup", "validate"]
        );
    }

    #[tokio::test]
    async fn cleanup_failure_skips_validation() {
        let repository = StubRepository::new(Failure::Cleanup);
        let service = ClusterReplayMaintenanceService::new(&repository);
        assert!(service.cleanup_and_validate(4096).await.is_err());
        assert_eq!(repository.calls.lock().unwrap().as_slice(), &["cleanup"]);
    }

    #[tokio::test]
    async fn validation_failure_is_fail_closed() {
        let repository = StubRepository::new(Failure::Validation);
        let service = ClusterReplayMaintenanceService::new(&repository);
        let error = service.cleanup_and_validate(4096).await.unwrap_err();
        assert!(error.to_string().contains("capacity authority failed"));
        assert_eq!(
            repository.calls.lock().unwrap().as_slice(),
            &["cleanup", "validate"]
        );
    }
}
