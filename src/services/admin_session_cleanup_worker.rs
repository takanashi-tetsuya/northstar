//! Fenced persistence authority for the administrator session-cleanup worker.
//! Delivery to local sessions and the cluster stays outside every database
//! call, so a network wait never holds a PostgreSQL transaction.

use anyhow::{ensure, Result};
use std::future::Future;
use uuid::Uuid;

pub(crate) use crate::db::{AdminSessionCleanupKind, AdminSessionCleanupLease};

const LEASE_SECONDS: i32 = 60;

pub(crate) trait AdminSessionCleanupRepository: Send + Sync {
    fn claim(
        &self,
        worker_id: Uuid,
        lease_seconds: i32,
    ) -> impl Future<Output = Result<Option<AdminSessionCleanupLease>>> + Send;
    fn renew(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
        lease_seconds: i32,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn complete(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn retry(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
        error_code: &'static str,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn target_current(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
    ) -> impl Future<Output = Result<bool>> + Send;
}

pub(crate) struct AdminSessionCleanupWorkerService<R> {
    repository: R,
}

impl<R: AdminSessionCleanupRepository> AdminSessionCleanupWorkerService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn claim(&self, worker_id: Uuid) -> Result<Option<AdminSessionCleanupLease>> {
        self.repository.claim(worker_id, LEASE_SECONDS).await
    }

    /// A lost renewal fence must cancel the concurrent effect future.
    pub(crate) async fn renew_or_fail(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
    ) -> Result<()> {
        ensure!(
            self.repository
                .renew(lease, worker_id, LEASE_SECONDS)
                .await?,
            "administrator session-cleanup lease fencing was lost"
        );
        Ok(())
    }

    pub(crate) async fn complete(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
    ) -> Result<bool> {
        self.repository.complete(lease, worker_id).await
    }

    pub(crate) async fn retry(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
        error_code: &'static str,
    ) -> Result<bool> {
        self.repository.retry(lease, worker_id, error_code).await
    }

    pub(crate) async fn target_current(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
    ) -> Result<bool> {
        self.repository.target_current(lease, worker_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct LeaseRepository {
        renews: Mutex<Vec<(Uuid, Uuid, Uuid, i32)>>,
        renewal_succeeds: bool,
    }

    impl AdminSessionCleanupRepository for LeaseRepository {
        async fn claim(&self, _: Uuid, _: i32) -> Result<Option<AdminSessionCleanupLease>> {
            unreachable!("renewal test does not claim")
        }

        async fn renew(
            &self,
            lease: &AdminSessionCleanupLease,
            worker_id: Uuid,
            lease_seconds: i32,
        ) -> Result<bool> {
            self.renews.lock().unwrap().push((
                lease.id,
                lease.lease_token,
                worker_id,
                lease_seconds,
            ));
            Ok(self.renewal_succeeds)
        }

        async fn complete(&self, _: &AdminSessionCleanupLease, _: Uuid) -> Result<bool> {
            unreachable!("renewal test does not complete")
        }

        async fn retry(
            &self,
            _: &AdminSessionCleanupLease,
            _: Uuid,
            _: &'static str,
        ) -> Result<bool> {
            unreachable!("renewal test does not retry")
        }

        async fn target_current(&self, _: &AdminSessionCleanupLease, _: Uuid) -> Result<bool> {
            unreachable!("renewal test does not query target")
        }
    }

    #[tokio::test]
    async fn lost_exact_lease_fence_returns_renewal_error() {
        let worker_id = Uuid::from_u128(1);
        let lease = AdminSessionCleanupLease {
            id: Uuid::from_u128(2),
            command_operation_id: Uuid::from_u128(3),
            kind: AdminSessionCleanupKind::ExactConnection,
            user_id: Uuid::from_u128(4),
            auth_generation: 5,
            bare_jid: None,
            full_jid: Some("alice@example.test/phone".into()),
            connection_id: Some(Uuid::from_u128(6)),
            lease_token: Uuid::from_u128(7),
            attempts: 1,
        };
        let service = AdminSessionCleanupWorkerService::new(LeaseRepository {
            renews: Mutex::new(Vec::new()),
            renewal_succeeds: false,
        });
        let error = service.renew_or_fail(&lease, worker_id).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "administrator session-cleanup lease fencing was lost"
        );
        assert_eq!(
            *service.repository.renews.lock().unwrap(),
            vec![(lease.id, lease.lease_token, worker_id, LEASE_SECONDS)]
        );
    }
}
