//! Push notification transport for the application-owned post-commit dispatch.

use super::AppState;
use crate::services::push::{PushDelivery, PushNotificationCounts, PushNotificationRouter};
use anyhow::Result;
use std::sync::atomic::Ordering;

impl AppState {
    pub(crate) async fn dispatch_push_notification(&self, recipient_id: uuid::Uuid) -> Result<()> {
        if !self.xmpp_extension_enabled(northstar_xep_0357::XEP_ID) {
            return Ok(());
        }
        self.push_service()
            .dispatch_after_commit(recipient_id, self)
            .await
    }
}

impl PushNotificationRouter for AppState {
    async fn route(&self, delivery: &PushDelivery, counts: PushNotificationCounts) -> Result<bool> {
        let request_id = format!("push-{}", delivery.request_id);
        let summary = northstar_xep_0357::PushSummary::new()
            .with_message_count(counts.message_count as u64)
            .with_pending_subscription_count(counts.pending_subscription_count as u64);
        let notification = northstar_xep_0357::build_notification_iq(
            self.local_domain(),
            &delivery.service_jid,
            &request_id,
            (!delivery.node.is_empty()).then_some(delivery.node.as_str()),
            &summary,
            delivery.options.as_deref(),
        )?;
        let mut delivered = false;
        let service = crate::jid::CanonicalJid::parse_bare(&delivery.service_jid).ok();
        if service
            .as_ref()
            .is_some_and(|jid| jid.domainpart() == self.local_domain())
        {
            let mut local_targets = self.session_entries_for(&delivery.service_jid);
            // Select the highest-priority available local resource, with its
            // full JID as a stable tie-breaker.
            local_targets.retain(|(_, session)| {
                session.available.load(Ordering::Relaxed)
                    && session.priority.load(Ordering::Relaxed) >= 0
            });
            local_targets.sort_by(|(left_jid, left), (right_jid, right)| {
                right
                    .priority
                    .load(Ordering::Relaxed)
                    .cmp(&left.priority.load(Ordering::Relaxed))
                    .then_with(|| left_jid.cmp(right_jid))
            });
            let local_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            for (_, target) in local_targets {
                if tokio::time::timeout_at(local_deadline, target.sender.send(notification.clone()))
                    .await
                    .is_ok_and(|result| result.is_ok())
                {
                    delivered = true;
                    break;
                }
            }
            if !delivered {
                delivered = self
                    .route_push_service_notification_remote(&delivery.service_jid, &notification)
                    .await;
            }
        } else if let Some(domain) = service.as_ref().map(|jid| jid.domainpart()) {
            if self.federation_domain_allowed(domain) {
                delivered = self
                    .federation_outbox()
                    .send(domain, notification.clone(), None)
                    .await;
            }
        }
        Ok(delivered)
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
