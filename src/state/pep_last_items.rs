//! Root construction and adapters for CAPS-triggered PEP send-last delivery.

use super::{AppState, OnlineSession, RuntimeFederationPolicy};
use crate::{
    cluster::{ClusterListenerPresenceRoutes, ClusterNodeDelivery},
    s2s::FederationRouter,
};
use anyhow::Result;
use northstar_config::ExternalRouteDomainPolicy;
use northstar_message_application::messaging::MessageService;
use northstar_protocol_runtime::caps::{
    CapsObservationOwner, CapsObservationSnapshot, CapsResourceIndex, PendingCapsIndex,
};
use northstar_pubsub_xmpp::pep_last_items::{PepLastItemsContext, PepLastItemsPorts};
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_session_core::LocalCapsEpoch;
use northstar_stream::local_routes::session_table::LocalSessionTable;
use northstar_workflows::message_repository::PostgresMessageRepository;
use northstar_workflows::pubsub_repository::PostgresPubSubRepository;
use std::sync::Arc;

pub(crate) struct PepLastItemsAdapters {
    privacy: MessageService<PostgresMessageRepository>,
    observations: Arc<CapsResourceIndex>,
    pending_caps: Arc<PendingCapsIndex>,
    remote_routes: ClusterListenerPresenceRoutes,
    remote_sender: ClusterNodeDelivery,
    federation: FederationRouter,
    static_policy: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
}

impl AppState {
    pub(crate) fn pep_last_items_context(
        &self,
    ) -> PepLastItemsContext<PostgresPubSubRepository, PepLastItemsAdapters> {
        PepLastItemsContext::new(
            self.pubsub.pubsub_service.clone(),
            LocalSessionTable::new(Arc::clone(&self.sessions)),
            self.config.domain.clone(),
            PepLastItemsAdapters {
                privacy: self.message.message_service.clone(),
                observations: Arc::clone(&self.caps_by_jid),
                pending_caps: Arc::clone(&self.pending_caps),
                remote_routes: self.cluster.listener_presence_routes(),
                remote_sender: self.cluster.node_delivery(),
                federation: self.federation.federation_outbox.clone(),
                static_policy: self.config.external_route_domain_policy(),
                runtime_policy: Arc::clone(&self.federation.federation_runtime_policy),
            },
        )
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
        match snapshot.owner {
            CapsObservationOwner::Local(epoch) => Some(epoch),
            CapsObservationOwner::Federated { .. } => None,
        }
    }

    fn caps_snapshot_notify_nodes(&self, snapshot: CapsObservationSnapshot) -> Vec<String> {
        snapshot.summary.map_or_else(Vec::new, |summary| {
            summary.notify_nodes().map(str::to_owned).collect()
        })
    }

    fn remove_local_caps_epoch(&self, full_jid: &str, epoch: LocalCapsEpoch) {
        self.pending_caps.remove_local_epoch(full_jid, epoch);
        self.observations.remove_local_epoch(full_jid, epoch);
    }

    async fn privacy_allows_session(&self, session: &OnlineSession, peer: &str) -> Result<bool> {
        let active = session
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.privacy
            .privacy_allows_session(
                session.user_id,
                session.connection_id,
                active.as_deref(),
                peer,
                PrivacyStanzaKind::Message,
            )
            .await
    }

    async fn remote_nodes(&self, recipient: &str) -> Result<Vec<String>> {
        self.remote_routes.remote_nodes(recipient).await
    }

    async fn send_pubsub_notification(
        &self,
        node_id: &str,
        recipient: &str,
        message: &str,
    ) -> Result<bool> {
        self.remote_sender
            .send_pubsub_notification(node_id, recipient, message)
            .await
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        self.static_policy.federation_domain_allowed(domain)
            && self.runtime_policy.load().allows_domain(domain)
    }

    async fn send_federated(&self, domain: &str, message: String) -> bool {
        self.federation.send(domain, message, None).await
    }
}
