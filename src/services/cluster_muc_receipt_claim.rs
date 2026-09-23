//! Renew the exact MUC outbox lease while a transport receipt is pending.

use anyhow::{ensure, Result};
use std::{future::Future, time::Duration};

pub(crate) trait ClusterMucReceiptClaimRepository: Send + Sync {
    type Delivery: Sync;

    fn renew_exact(
        &self,
        delivery: &Self::Delivery,
        lease: Duration,
    ) -> impl Future<Output = Result<bool>> + Send;
}

pub(crate) struct ClusterMucReceiptClaimService<R> {
    repository: R,
}

impl<R: ClusterMucReceiptClaimRepository> ClusterMucReceiptClaimService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn renew_exact(&self, delivery: &R::Delivery, lease: Duration) -> Result<()> {
        ensure!(
            self.repository.renew_exact(delivery, lease).await?,
            "cluster MUC transport receipt lost its exact outbox claim"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingRepository {
        calls: Mutex<Vec<(u64, Duration)>>,
        renewed: bool,
    }

    impl ClusterMucReceiptClaimRepository for &RecordingRepository {
        type Delivery = u64;

        async fn renew_exact(&self, delivery: &u64, lease: Duration) -> Result<bool> {
            self.calls.lock().unwrap().push((*delivery, lease));
            Ok(self.renewed)
        }
    }

    #[tokio::test]
    async fn passes_the_exact_claim_and_lease_to_the_repository() {
        let repository = RecordingRepository {
            calls: Mutex::new(Vec::new()),
            renewed: true,
        };
        ClusterMucReceiptClaimService::new(&repository)
            .renew_exact(&37, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(
            *repository.calls.lock().unwrap(),
            [(37, Duration::from_secs(30))]
        );
    }

    #[tokio::test]
    async fn lost_claim_fails_the_receipt_wait() {
        let repository = RecordingRepository {
            calls: Mutex::new(Vec::new()),
            renewed: false,
        };
        let error = ClusterMucReceiptClaimService::new(&repository)
            .renew_exact(&37, Duration::from_secs(30))
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("transport receipt lost its exact outbox claim"));
    }
}
