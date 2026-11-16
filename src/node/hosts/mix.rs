//! The node's side of the MIX context's handlers.

use crate::node::adapters::mix_iq_relay::MixIqRelayRoute;
use crate::node::adapters::mix_outbox::MixOutboxContext;
use crate::node::FederationRouter;
use crate::node::ServerNode;
use anyhow::Result;
use northstar_mix_xmpp::ports::{MixHost, MixOutboxPort};
use northstar_room_application::mix_service::MixService;
use northstar_room_core::mix::{MixSessionCapability, CORE_NS, PAM_NS};
use northstar_room_core::mix_iq_relay::MixIqRelayIndex;
use northstar_roster_core::RosterChange;
use northstar_stream::local_routes::session::OnlineSession;
use roxmltree::Node;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

impl MixHost for ServerNode {
    type Repository = <MixOutboxContext as MixOutboxPort>::Repository;
    type Session = OnlineSession;
    type Federation = FederationRouter;
    type IqRelayRoute = MixIqRelayRoute;
    type OutboxContext = MixOutboxContext;

    fn mix_service(&self) -> &MixService<Self::Repository> {
        self.room.mix_service()
    }

    fn federation_outbox(&self) -> &FederationRouter {
        &self.federation.federation_outbox
    }

    fn local_domain(&self) -> &str {
        &self.config.domain
    }

    fn server_name(&self) -> &str {
        &self.config.server_name
    }

    fn pending_mix_iq(&self) -> &MixIqRelayIndex {
        ServerNode::pending_mix_iq(self)
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        ServerNode::federation_domain_allowed(self, domain)
    }

    fn mix_muc_mirror_enabled(&self) -> bool {
        self.config.mix_muc_mirror_enabled
    }

    fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool {
        self.config.xmpp_extension_enabled(id)
    }

    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        self.sessions.session_entries_for(jid)
    }

    fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        self.sessions.sessions_for(jid)
    }

    fn mix_iq_relay_route(&self) -> MixIqRelayRoute {
        ServerNode::mix_iq_relay_route(self)
    }

    fn mix_outbox_context(&self) -> MixOutboxContext {
        ServerNode::mix_outbox_context(self)
    }

    fn session_mix_capability(&self, full_jid: &str) -> MixSessionCapability {
        match crate::xmpp::protocol::caps::verified_caps_has_any_feature(
            self,
            full_jid,
            &[CORE_NS, PAM_NS],
        ) {
            Some(true) => MixSessionCapability::Supported,
            Some(false) => MixSessionCapability::Unsupported,
            None => MixSessionCapability::Unknown,
        }
    }

    fn validate_routed_message(&self, root: Node<'_, '_>) -> Result<(), &'static str> {
        northstar_message_core::validation::validate_routed_message(
            root,
            &self.config.xmpp_extensions,
        )
    }

    fn local_mix_presence_route_is_current(
        &self,
        full_jid: &str,
        expected_connection_id: Uuid,
        expected_gate: &Arc<Mutex<()>>,
        require_available: bool,
    ) -> bool {
        self.sessions.local_mix_presence_route_is_current(
            full_jid,
            expected_connection_id,
            expected_gate,
            require_available,
        )
    }

    async fn deliver_roster_change(
        &self,
        owner_id: Uuid,
        owner: &str,
        change: &RosterChange,
        participant_id: Option<&str>,
    ) -> Result<()> {
        northstar_roster_xmpp::RosterSessionHost::deliver_committed_roster_change(
            self,
            owner_id,
            owner,
            change,
            participant_id,
        )
        .await
    }
}

impl ServerNode {
    pub(crate) fn pending_mix_iq(&self) -> &northstar_room_core::mix_iq_relay::MixIqRelayIndex {
        self.room.pending_mix_iq.as_ref()
    }
}
