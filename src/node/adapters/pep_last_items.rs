//! Root construction and shared adapters for PEP send-last and PubSub notification delivery.

use crate::node::FederationRouter;
use crate::node::ServerNode;
use anyhow::Result;
use northstar_cluster::{ClusterListenerPresenceRoutes, ClusterNodeDelivery};
use northstar_federation_application::effective_policy::EffectiveFederationPolicy;
use northstar_protocol_runtime::caps::{
    remove_local_caps_epoch, CapsObservationSnapshot, CapsResourceIndex, PendingCapsIndex,
};
use northstar_pubsub_xmpp::notification_delivery::PubSubNotificationPorts;
use northstar_pubsub_xmpp::pep_last_items::{PepLastItemsContext, PepLastItemsPorts};
use northstar_roster_application::notification_admission::{
    NotificationAdmission, NotificationHandoff, NotificationRecipient, NotificationSource,
};
use northstar_session_core::LocalCapsEpoch;
use northstar_stream::local_routes::session_table::LocalSessionTable;
use northstar_workflows::pubsub_repository::PostgresPubSubRepository;
use std::sync::Arc;

pub(crate) struct PepLastItemsAdapters {
    notification_admission: PostgresPubSubRepository,
    observations: Arc<CapsResourceIndex>,
    pending_caps: Arc<PendingCapsIndex>,
    remote_routes: ClusterListenerPresenceRoutes,
    remote_sender: ClusterNodeDelivery,
    federation: FederationRouter,
    policy: EffectiveFederationPolicy,
}

impl ServerNode {
    pub(crate) fn pep_last_items_context(
        &self,
    ) -> PepLastItemsContext<PostgresPubSubRepository, PepLastItemsAdapters> {
        PepLastItemsContext::new(
            self.pubsub.pubsub_service.clone(),
            LocalSessionTable::new(Arc::clone(self.session.live().sessions())),
            self.config.domain.clone(),
            self.pep_last_items_adapters(),
        )
    }

    pub(crate) fn pep_last_items_adapters(&self) -> PepLastItemsAdapters {
        PepLastItemsAdapters {
            notification_admission: PostgresPubSubRepository::new(
                self.pool.clone(),
                &self.config.domain,
            ),
            observations: Arc::clone(self.session.live().caps_by_jid()),
            pending_caps: Arc::clone(self.session.live().pending_caps()),
            remote_routes: self.cluster.listener_presence_routes(),
            remote_sender: self.cluster.node_delivery(),
            federation: self.federation.federation_outbox.clone(),
            policy: self.federation.effective_policy.clone(),
        }
    }
}

impl PepLastItemsPorts for PepLastItemsAdapters {
    type CapsSnapshot = CapsObservationSnapshot;

    fn caps_snapshot(&self, full_jid: &str) -> Option<CapsObservationSnapshot> {
        self.observations.snapshot(full_jid)
    }

    fn caps_snapshot_local_epoch(
        &self,
        snapshot: &CapsObservationSnapshot,
    ) -> Option<LocalCapsEpoch> {
        snapshot.local_epoch()
    }

    fn caps_snapshot_notify_nodes(&self, snapshot: CapsObservationSnapshot) -> Vec<String> {
        snapshot.into_notify_nodes()
    }

    fn remove_local_caps_epoch(&self, full_jid: &str, epoch: LocalCapsEpoch) {
        remove_local_caps_epoch(&self.pending_caps, &self.observations, full_jid, epoch);
    }
}

impl NotificationAdmission for PepLastItemsAdapters {
    async fn authorize_notification(
        &self,
        recipient: NotificationRecipient<'_>,
        source: NotificationSource<'_>,
    ) -> Result<bool> {
        self.notification_admission
            .authorize_notification(recipient, source)
            .await
    }
}

impl PubSubNotificationPorts for PepLastItemsAdapters {
    async fn remote_nodes(&self, recipient: &str) -> Result<Vec<String>> {
        self.remote_routes.remote_nodes(recipient).await
    }

    async fn send_pubsub_notification(
        &self,
        node_id: &str,
        recipient: &str,
        message: &str,
        expected_account: Option<uuid::Uuid>,
    ) -> Result<NotificationHandoff> {
        self.remote_sender
            .send_pubsub_notification(node_id, recipient, message, expected_account)
            .await
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        self.policy.prepared_domain_allowed(domain)
    }

    async fn send_federated(&self, domain: &str, message: String, sender: Option<String>) -> bool {
        self.federation.send(domain, message, sender).await
    }
}
