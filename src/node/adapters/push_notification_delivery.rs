//! Push notification transport for the application-owned post-commit dispatch.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_message_application::push::{
    PushDelivery, PushNotificationCounts, PushNotificationRouter,
};
use northstar_stream::local_routes::push_targets::deliver_to_best_local_resource;

impl ServerNode {
    pub(crate) async fn dispatch_push_notification(&self, recipient_id: uuid::Uuid) -> Result<()> {
        northstar_message_xmpp::push_routing::dispatch_push_notification(
            self.config
                .xmpp_extension_enabled(northstar_xep_0357::XEP_ID),
            self.message.push_service(),
            recipient_id,
            self,
        )
        .await
    }

    fn push_delivery_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::PushDeliveryTelemetry<'_> {
        northstar_session_application::telemetry::PushDeliveryTelemetry::new(
            &self.metrics.push_notifications_failed_total,
            &self.metrics.push_notifications_routed_total,
            &self.metrics.push_notifications_attempted_total,
        )
    }
}

impl northstar_message_xmpp::push_routing::PushNotificationRoutes for ServerNode {
    fn local_domain(&self) -> &str {
        self.config.domain.as_str()
    }

    async fn deliver_local(&self, service_jid: &str, notification: &str) -> bool {
        deliver_to_best_local_resource(self.sessions.session_entries_for(service_jid), notification)
            .await
    }

    async fn route_cluster(&self, service_jid: &str, notification: &str) -> bool {
        self.cluster
            .route_push_service_notification_remote(service_jid, notification)
            .await
    }

    fn remote_domain_allowed(&self, domain: &str) -> bool {
        self.federation_domain_allowed(domain)
    }

    async fn send_federation(&self, domain: &str, notification: String) -> bool {
        self.federation
            .federation_outbox
            .send(domain, notification, None)
            .await
    }
}

impl PushNotificationRouter for ServerNode {
    async fn route(&self, delivery: &PushDelivery, counts: PushNotificationCounts) -> Result<bool> {
        northstar_message_xmpp::push_routing::route_push_notification(self, delivery, counts).await
    }

    fn routed(&self) {
        self.push_delivery_telemetry().routed();
    }

    fn failed(&self) {
        self.push_delivery_telemetry().failed();
    }

    fn attempted(&self) {
        self.push_delivery_telemetry().attempted();
    }
}
