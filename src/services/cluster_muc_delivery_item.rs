//! Progress for one stable clustered-MUC audience item.
//! The caller owns database admission and the transport receipt between these
//! two independent database operations; no transaction spans network I/O.

use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

pub(crate) trait ClusterMucDeliveryItemRepository: Send + Sync {
    type Delivery;

    fn completed(
        &self,
        delivery_id: Uuid,
        ordinal: i32,
        stable_id: &str,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn complete_exact(
        &self,
        delivery: &Self::Delivery,
        ordinal: i32,
        stable_id: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
}

pub(crate) struct ClusterMucDeliveryItemService<R> {
    repository: R,
}

impl<R: ClusterMucDeliveryItemRepository> ClusterMucDeliveryItemService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn completed(
        &self,
        delivery_id: Uuid,
        ordinal: i32,
        stable_id: &str,
    ) -> Result<bool> {
        self.repository
            .completed(delivery_id, ordinal, stable_id)
            .await
    }

    /// False means the exact claim or stable item identity was lost. The
    /// delivery caller must fail its attempt rather than ACK the outbox row.
    pub(crate) async fn complete_exact(
        &self,
        delivery: &R::Delivery,
        ordinal: i32,
        stable_id: &str,
    ) -> Result<bool> {
        self.repository
            .complete_exact(delivery, ordinal, stable_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, PartialEq)]
    enum Call {
        Completed(Uuid, i32, String),
        CompleteExact(u32, i32, String),
    }

    struct StubRepository {
        calls: Mutex<Vec<Call>>,
        completed_result: std::result::Result<bool, &'static str>,
        complete_result: std::result::Result<bool, &'static str>,
    }

    impl ClusterMucDeliveryItemRepository for &StubRepository {
        type Delivery = u32;

        async fn completed(
            &self,
            delivery_id: Uuid,
            ordinal: i32,
            stable_id: &str,
        ) -> Result<bool> {
            self.calls.lock().unwrap().push(Call::Completed(
                delivery_id,
                ordinal,
                stable_id.to_owned(),
            ));
            self.completed_result.map_err(anyhow::Error::msg)
        }

        async fn complete_exact(
            &self,
            delivery: &u32,
            ordinal: i32,
            stable_id: &str,
        ) -> Result<bool> {
            self.calls.lock().unwrap().push(Call::CompleteExact(
                *delivery,
                ordinal,
                stable_id.to_owned(),
            ));
            self.complete_result.map_err(anyhow::Error::msg)
        }
    }

    #[tokio::test]
    async fn forwards_exact_item_identity_and_repository_results() {
        let delivery_id = Uuid::from_u128(17);
        let repository = StubRepository {
            calls: Mutex::new(Vec::new()),
            completed_result: Ok(false),
            complete_result: Ok(true),
        };
        let service = ClusterMucDeliveryItemService::new(&repository);
        assert!(!service.completed(delivery_id, 3, "event:3").await.unwrap());
        assert!(service.complete_exact(&29, 3, "event:3").await.unwrap());
        assert_eq!(
            *repository.calls.lock().unwrap(),
            vec![
                Call::Completed(delivery_id, 3, "event:3".to_owned()),
                Call::CompleteExact(29, 3, "event:3".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn preserves_completed_skip_and_lost_exact_claim_results() {
        let repository = StubRepository {
            calls: Mutex::new(Vec::new()),
            completed_result: Ok(true),
            complete_result: Ok(false),
        };
        let service = ClusterMucDeliveryItemService::new(&repository);
        assert!(service
            .completed(Uuid::from_u128(18), 4, "event:4")
            .await
            .unwrap());
        assert!(!service.complete_exact(&30, 4, "event:4").await.unwrap());
    }

    #[tokio::test]
    async fn propagates_each_database_error_without_conversion() {
        let repository = StubRepository {
            calls: Mutex::new(Vec::new()),
            completed_result: Err("item lookup failed"),
            complete_result: Err("item completion failed"),
        };
        let service = ClusterMucDeliveryItemService::new(&repository);
        assert_eq!(
            service
                .completed(Uuid::from_u128(19), 5, "event:5")
                .await
                .unwrap_err()
                .to_string(),
            "item lookup failed"
        );
        assert_eq!(
            service
                .complete_exact(&31, 5, "event:5")
                .await
                .unwrap_err()
                .to_string(),
            "item completion failed"
        );
    }
}
