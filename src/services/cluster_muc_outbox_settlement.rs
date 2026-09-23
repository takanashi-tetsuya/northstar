//! Exact claim settlement for a clustered-MUC outbox delivery.
//! The caller owns delivery and database-admission timing; this capability
//! only records an ACK or the existing retry/dead-letter transition.

use anyhow::Result;
use std::future::Future;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AckOutcome {
    Acknowledged,
    LostClaim,
}

pub(crate) trait ClusterMucOutboxSettlementRepository: Send + Sync {
    type Delivery;

    fn ack_exact(&self, delivery: &Self::Delivery) -> impl Future<Output = Result<bool>> + Send;

    fn record_retry(
        &self,
        delivery: &Self::Delivery,
        error: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
}

pub(crate) struct ClusterMucOutboxSettlementService<R> {
    repository: R,
}

impl<R: ClusterMucOutboxSettlementRepository> ClusterMucOutboxSettlementService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn acknowledge(&self, delivery: &R::Delivery) -> Result<AckOutcome> {
        if self.repository.ack_exact(delivery).await? {
            Ok(AckOutcome::Acknowledged)
        } else {
            Ok(AckOutcome::LostClaim)
        }
    }

    /// A false repository result is not an error: the original retry path
    /// counts a successful SQL call even when its exact claim had already
    /// vanished or been dead-lettered by a concurrent worker.
    pub(crate) async fn retry(&self, delivery: &R::Delivery, error: &str) -> Result<()> {
        let _ = self.repository.record_retry(delivery, error).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct StubRepository {
        events: Mutex<Vec<String>>,
        acked: bool,
        retried: bool,
    }

    impl ClusterMucOutboxSettlementRepository for &StubRepository {
        type Delivery = ();

        async fn ack_exact(&self, _: &()) -> Result<bool> {
            self.events.lock().unwrap().push("ack".to_owned());
            Ok(self.acked)
        }

        async fn record_retry(&self, _: &(), error: &str) -> Result<bool> {
            self.events.lock().unwrap().push(format!("retry:{error}"));
            Ok(self.retried)
        }
    }

    #[tokio::test]
    async fn exact_ack_distinguishes_a_lost_claim() {
        for (acked, expected) in [
            (true, AckOutcome::Acknowledged),
            (false, AckOutcome::LostClaim),
        ] {
            let repository = StubRepository {
                events: Mutex::new(Vec::new()),
                acked,
                retried: false,
            };
            let service = ClusterMucOutboxSettlementService::new(&repository);
            assert_eq!(service.acknowledge(&()).await.unwrap(), expected);
            assert_eq!(*repository.events.lock().unwrap(), vec!["ack".to_owned()]);
        }
    }

    #[tokio::test]
    async fn retry_keeps_a_false_transition_nonfatal() {
        let repository = StubRepository {
            events: Mutex::new(Vec::new()),
            acked: false,
            retried: false,
        };
        let service = ClusterMucOutboxSettlementService::new(&repository);
        service.retry(&(), "delivery timed out").await.unwrap();
        assert_eq!(
            *repository.events.lock().unwrap(),
            vec!["retry:delivery timed out".to_owned()]
        );
    }
}
