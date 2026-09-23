//! Durable digest claims and their policy-checked delivery endpoint.

use super::{pubsub_notification_delivery::PubSubNotificationDelivery, AppState};
use crate::{
    db::pubsub_repository::PostgresPubSubRepository,
    services::pubsub::{DuePubSubDigest, PubSubService},
};
use anyhow::Result;
use uuid::Uuid;

pub(crate) struct PubSubDigestWorkerContext {
    service: PubSubService<PostgresPubSubRepository>,
    notification: PubSubNotificationDelivery,
}

impl AppState {
    pub(crate) fn pubsub_digest_worker_context(&self) -> PubSubDigestWorkerContext {
        PubSubDigestWorkerContext {
            service: self.pubsub_service.clone(),
            notification: self.pubsub_notification_delivery(),
        }
    }
}

impl PubSubDigestWorkerContext {
    pub(crate) fn notification(&self) -> &PubSubNotificationDelivery {
        &self.notification
    }

    pub(crate) async fn claim_due(&self) -> Result<Vec<DuePubSubDigest>> {
        self.service.claim_due_pubsub_digests(1_000).await
    }

    pub(crate) async fn current_show_values(
        &self,
        node_id: Uuid,
        subscriber_jid: &str,
    ) -> Result<Option<Vec<String>>> {
        Ok(self
            .service
            .outbox_get_subscription(node_id, subscriber_jid)
            .await?
            .filter(|subscription| subscription.deliver && subscription.is_active())
            .map(|subscription| subscription.show_values))
    }

    pub(crate) async fn release(&self, ids: &[Uuid]) -> Result<()> {
        self.service.release_pubsub_digests(ids).await
    }

    pub(crate) async fn acknowledge(&self, ids: &[Uuid]) -> Result<()> {
        self.service.acknowledge_pubsub_digests(ids).await
    }
}
