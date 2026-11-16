//! Root construction and routes for policy-checked durable PubSub notification delivery.

use crate::node::{adapters::pep_last_items::PepLastItemsAdapters, ServerNode};
use anyhow::Result;
use northstar_pubsub_xmpp::delivery::{PubSubDigestWorkerContext, PubSubEventOutboxWorkerContext};
use northstar_pubsub_xmpp::notification_delivery::PubSubNotificationDelivery;
use northstar_pubsub_xmpp::pep_last_items::PepLastItemsContext;
use northstar_stream::local_routes::session_table::LocalSessionTable;
use northstar_workflows::pubsub_repository::PostgresPubSubRepository;
use std::sync::Arc;
use uuid::Uuid;

impl ServerNode {
    pub(crate) fn pubsub_notification_delivery(
        &self,
    ) -> PubSubNotificationDelivery<PostgresPubSubRepository, PepLastItemsAdapters> {
        PubSubNotificationDelivery::new(
            self.pubsub.pubsub_service.clone(),
            LocalSessionTable::new(Arc::clone(&self.sessions)),
            self.config.domain.clone(),
            self.pep_last_items_adapters(),
        )
    }
}

/// The root routes the PubSub delivery workers use.
pub(crate) struct PubSubRootRoutes {
    notification: PubSubNotificationDelivery<PostgresPubSubRepository, PepLastItemsAdapters>,
    pep: PepLastItemsContext<PostgresPubSubRepository, PepLastItemsAdapters>,
}

impl ServerNode {
    pub(crate) fn pubsub_root_routes(&self) -> PubSubRootRoutes {
        PubSubRootRoutes {
            notification: self.pubsub_notification_delivery(),
            pep: self.pep_last_items_context(),
        }
    }

    pub(crate) fn pubsub_digest_worker_context(
        &self,
    ) -> PubSubDigestWorkerContext<PostgresPubSubRepository, PubSubRootRoutes> {
        PubSubDigestWorkerContext::new(
            self.pubsub.pubsub_service.clone(),
            self.pubsub_root_routes(),
        )
    }

    pub(crate) fn pubsub_event_outbox_worker_context(
        &self,
    ) -> PubSubEventOutboxWorkerContext<PostgresPubSubRepository, PubSubRootRoutes> {
        PubSubEventOutboxWorkerContext::new(
            self.pubsub.pubsub_service.clone(),
            self.pubsub_root_routes(),
            Arc::clone(&self.metrics.outbox_delivery_duration_seconds),
            Arc::clone(&self.metrics.pubsub_event_outbox_pending_rows),
            Arc::clone(&self.metrics.pubsub_event_outbox_pending_bytes),
            Arc::clone(&self.metrics.pubsub_event_outbox_dead_letter_rows),
        )
    }
}

impl northstar_pubsub_xmpp::delivery::PubSubDeliveryRoutes for PubSubRootRoutes {
    fn service_domain(&self) -> String {
        self.notification.service_domain()
    }

    async fn route_children(
        &self,
        recipient: &str,
        children: &str,
        show_values: Option<&[String]>,
        message_id: Uuid,
    ) -> Result<()> {
        self.notification
            .route_children(recipient, children, show_values, message_id)
            .await
    }

    async fn route_service_message(
        &self,
        service: &str,
        recipient: &str,
        message: String,
    ) -> Result<()> {
        self.notification
            .route_service_message(service, recipient, message)
            .await
    }

    async fn route_pep_message(
        &self,
        sender_bare_jid: &str,
        recipient: &str,
        message: String,
    ) -> Result<()> {
        self.pep
            .route_message(sender_bare_jid, recipient, message, None)
            .await
    }
}
