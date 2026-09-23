//! Durable PubSub event delivery and its exact routing and metrics capabilities.

use super::{
    pep_last_items::PepLastItemsContext, pubsub_notification_delivery::PubSubNotificationDelivery,
    AppState,
};
use crate::{
    db::pubsub_repository::PostgresPubSubRepository,
    metrics::{DurationHistogram, DurationTimer},
    services::pubsub::{
        ClaimedPubSubOutboxDelivery, PepOutboxAuthorizationOutcome, PubSubOutboxDeliveryKind,
        PubSubService,
    },
    xmpp::capabilities::PubSubOutboxTelemetry,
};
use anyhow::Result;
use std::sync::{atomic::AtomicU64, Arc};

pub(crate) struct PubSubEventOutboxWorkerContext {
    service: PubSubService<PostgresPubSubRepository>,
    notification: PubSubNotificationDelivery,
    pep: PepLastItemsContext,
    delivery_duration: Arc<DurationHistogram>,
    pending_rows: Arc<AtomicU64>,
    pending_bytes: Arc<AtomicU64>,
    dead_letter_rows: Arc<AtomicU64>,
}

impl AppState {
    pub(crate) fn pubsub_event_outbox_worker_context(&self) -> PubSubEventOutboxWorkerContext {
        PubSubEventOutboxWorkerContext {
            service: self.pubsub_service.clone(),
            notification: self.pubsub_notification_delivery(),
            pep: self.pep_last_items_context(),
            delivery_duration: Arc::clone(&self.metrics.outbox_delivery_duration_seconds),
            pending_rows: Arc::clone(&self.metrics.pubsub_event_outbox_pending_rows),
            pending_bytes: Arc::clone(&self.metrics.pubsub_event_outbox_pending_bytes),
            dead_letter_rows: Arc::clone(&self.metrics.pubsub_event_outbox_dead_letter_rows),
        }
    }
}

impl PubSubEventOutboxWorkerContext {
    pub(crate) fn start_delivery_timer(&self) -> DurationTimer<'_> {
        self.delivery_duration.start_timer()
    }

    pub(crate) async fn claim(&self) -> Result<Vec<ClaimedPubSubOutboxDelivery>> {
        self.service.claim_pubsub_outbox(256).await
    }

    pub(crate) async fn renew(&self, item: &ClaimedPubSubOutboxDelivery) -> Result<bool> {
        self.service
            .renew_pubsub_outbox_lease(item.delivery_id, item.lease_token)
            .await
    }

    pub(crate) async fn acknowledge(&self, item: &ClaimedPubSubOutboxDelivery) -> Result<bool> {
        self.service
            .acknowledge_pubsub_outbox(item.delivery_id, item.lease_token)
            .await
    }

    pub(crate) async fn dead_letter_integrity(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
        error: &str,
    ) -> Result<()> {
        self.service
            .dead_letter_pubsub_outbox(
                item.delivery_id,
                item.lease_token,
                "payload-integrity",
                error,
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn retry(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
        error: &str,
    ) -> Result<()> {
        self.service.retry_pubsub_outbox(item, error).await?;
        Ok(())
    }

    pub(crate) async fn maintain(&self) -> Result<()> {
        self.service.expire_pubsub_outbox(1_000).await?;
        self.service.cleanup_pubsub_dead_letters(1_000).await?;
        self.service
            .cleanup_idle_pubsub_event_streams(1_000)
            .await?;
        let snapshot = self.service.pubsub_outbox_snapshot().await?;
        PubSubOutboxTelemetry::new(
            &self.pending_rows,
            &self.pending_bytes,
            &self.dead_letter_rows,
        )
        .publish_snapshot(
            snapshot.pending_rows,
            snapshot.pending_bytes,
            snapshot.dead_letter_rows,
        );
        Ok(())
    }

    pub(crate) async fn deliver(&self, item: &ClaimedPubSubOutboxDelivery) -> Result<()> {
        if !item.payload_binding_valid() {
            anyhow::bail!("PubSub outbox payload digest mismatch");
        }
        match item.delivery_kind {
            PubSubOutboxDeliveryKind::PubSubChildren => {
                self.notification
                    .route_children(
                        &item.recipient_jid,
                        &item.payload_xml,
                        item.show_values.as_deref(),
                        item.event_id,
                    )
                    .await
            }
            PubSubOutboxDeliveryKind::PubSubDigest => {
                self.service
                    .enqueue_pubsub_digest_snapshot(
                        item.delivery_id,
                        item.subscription_node_id.ok_or_else(|| {
                            anyhow::anyhow!("digest outbox row lacks subscription node")
                        })?,
                        &item.recipient_jid,
                        &item.payload_xml,
                        item.digest_frequency_ms
                            .ok_or_else(|| anyhow::anyhow!("digest outbox row lacks frequency"))?,
                        item.show_values.as_deref().unwrap_or(&[]),
                    )
                    .await
            }
            PubSubOutboxDeliveryKind::PubSubDirect => {
                self.notification
                    .route_service_message(
                        &self.notification.service_domain(),
                        &item.recipient_jid,
                        item.payload_xml.clone(),
                    )
                    .await
            }
            PubSubOutboxDeliveryKind::PepStanza => {
                match self.service.authorize_pep_outbox_delivery(item).await? {
                    PepOutboxAuthorizationOutcome::Deliver => {}
                    PepOutboxAuthorizationOutcome::Drop(reason) => {
                        tracing::warn!(
                            delivery_id = %item.delivery_id,
                            event_id = %item.event_id,
                            ?reason,
                            "ACK-dropping PEP outbox delivery after live authorization denial"
                        );
                        return Ok(());
                    }
                }
                let Some(subject) = item.pep_subject.as_ref() else {
                    // Authorization already fail-closes and counts every missing
                    // subject before it can return Deliver.
                    tracing::error!(
                        delivery_id = %item.delivery_id,
                        "ACK-dropping PEP outbox delivery without a structured subject"
                    );
                    return Ok(());
                };
                self.pep
                    .route_message(
                        &subject.sender_bare_jid,
                        &item.recipient_jid,
                        item.payload_xml.clone(),
                        None,
                    )
                    .await
            }
        }
    }
}
