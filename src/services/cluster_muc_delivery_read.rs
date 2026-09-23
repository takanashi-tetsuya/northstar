//! Read-only projections for one committed clustered-MUC audience delivery.
//! The caller admits each read separately and keeps the cached-recipient path
//! free of audience queries.

use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

pub(crate) trait ClusterMucDeliveryReadRepository: Send + Sync {
    type Delivery;
    type EventContext;
    type AudienceSnapshot;

    fn event_context(
        &self,
        operation_id: Uuid,
    ) -> impl Future<Output = Result<Option<Self::EventContext>>> + Send;

    fn recipient_snapshot(
        &self,
        delivery: &Self::Delivery,
    ) -> impl Future<Output = Result<Option<Self::AudienceSnapshot>>> + Send;

    fn original_audience_snapshot(
        &self,
        delivery: &Self::Delivery,
    ) -> impl Future<Output = Result<Option<Self::AudienceSnapshot>>> + Send;

    fn audience_is_current(
        &self,
        delivery: &Self::Delivery,
    ) -> impl Future<Output = Result<bool>> + Send;
}

pub(crate) struct ClusterMucDeliveryReadService<R> {
    repository: R,
}

impl<R: ClusterMucDeliveryReadRepository> ClusterMucDeliveryReadService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn event_context(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<R::EventContext>> {
        self.repository.event_context(operation_id).await
    }

    pub(crate) async fn recipient_snapshot(
        &self,
        delivery: &R::Delivery,
    ) -> Result<Option<R::AudienceSnapshot>> {
        self.repository.recipient_snapshot(delivery).await
    }

    pub(crate) async fn original_audience_snapshot(
        &self,
        delivery: &R::Delivery,
    ) -> Result<Option<R::AudienceSnapshot>> {
        self.repository.original_audience_snapshot(delivery).await
    }

    pub(crate) async fn audience_is_current(&self, delivery: &R::Delivery) -> Result<bool> {
        self.repository.audience_is_current(delivery).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Repository {
        calls: Mutex<Vec<String>>,
    }

    impl ClusterMucDeliveryReadRepository for &Repository {
        type Delivery = u32;
        type EventContext = u32;
        type AudienceSnapshot = u32;

        async fn event_context(&self, operation_id: Uuid) -> Result<Option<u32>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("context:{operation_id}"));
            Ok(Some(3))
        }

        async fn recipient_snapshot(&self, delivery: &u32) -> Result<Option<u32>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("snapshot:{delivery}"));
            Ok(None)
        }

        async fn original_audience_snapshot(&self, delivery: &u32) -> Result<Option<u32>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("original:{delivery}"));
            Ok(Some(17))
        }

        async fn audience_is_current(&self, delivery: &u32) -> Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("current:{delivery}"));
            Ok(false)
        }
    }

    #[tokio::test]
    async fn reads_preserve_exact_operation_and_delivery_identities() {
        let repository = Repository {
            calls: Mutex::new(Vec::new()),
        };
        let service = ClusterMucDeliveryReadService::new(&repository);
        let operation_id = Uuid::from_u128(17);
        assert_eq!(service.event_context(operation_id).await.unwrap(), Some(3));
        assert_eq!(service.recipient_snapshot(&29).await.unwrap(), None);
        assert_eq!(
            service.original_audience_snapshot(&29).await.unwrap(),
            Some(17)
        );
        assert!(!service.audience_is_current(&29).await.unwrap());
        assert_eq!(
            *repository.calls.lock().unwrap(),
            [
                format!("context:{operation_id}"),
                "snapshot:29".to_owned(),
                "original:29".to_owned(),
                "current:29".to_owned(),
            ]
        );
    }
}
