//! Bounded, node-scoped claim of the next clustered-MUC outbox batch.
//! The PostgreSQL repository owns the atomic claim; callers receive only
//! committed delivery leases before beginning any network delivery.

use anyhow::Result;
use std::{future::Future, time::Duration};

pub(crate) trait ClusterMucOutboxClaimRepository: Send + Sync {
    type Delivery;

    fn claim_batch(
        &self,
        node_id: &str,
        limit: i64,
        lease: Duration,
    ) -> impl Future<Output = Result<Vec<Self::Delivery>>> + Send;
}

pub(crate) struct ClusterMucOutboxClaimService<R> {
    repository: R,
}

impl<R: ClusterMucOutboxClaimRepository> ClusterMucOutboxClaimService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn claim_batch(
        &self,
        node_id: &str,
        limit: i64,
        lease: Duration,
    ) -> Result<Vec<R::Delivery>> {
        self.repository.claim_batch(node_id, limit, lease).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct RecordingRepository {
        calls: Mutex<Vec<(String, i64, Duration)>>,
    }

    impl ClusterMucOutboxClaimRepository for &RecordingRepository {
        type Delivery = u32;

        async fn claim_batch(
            &self,
            node_id: &str,
            limit: i64,
            lease: Duration,
        ) -> Result<Vec<u32>> {
            self.calls
                .lock()
                .unwrap()
                .push((node_id.to_owned(), limit, lease));
            Ok(vec![31, 29])
        }
    }

    #[tokio::test]
    async fn claim_preserves_node_batch_lease_and_repository_order() {
        let repository = RecordingRepository {
            calls: Mutex::new(Vec::new()),
        };
        let service = ClusterMucOutboxClaimService::new(&repository);
        let deliveries = service
            .claim_batch("cluster-node-1", 16, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(deliveries, vec![31, 29]);
        assert_eq!(
            *repository.calls.lock().unwrap(),
            vec![("cluster-node-1".to_owned(), 16, Duration::from_secs(30))]
        );
    }
}
