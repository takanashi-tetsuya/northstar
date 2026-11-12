//! The node's side of the MIX context's handlers.

use super::mix_iq_relay::MixIqRelayRoute;
use super::mix_outbox::MixOutboxContext;
use super::AppState;
use crate::s2s::FederationRouter;
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

impl MixHost for AppState {
    type Repository = <MixOutboxContext as MixOutboxPort>::Repository;
    type Session = OnlineSession;
    type Federation = FederationRouter;
    type IqRelayRoute = MixIqRelayRoute;
    type OutboxContext = MixOutboxContext;

    fn mix_service(&self) -> &MixService<Self::Repository> {
        AppState::mix_service(self)
    }

    fn federation_outbox(&self) -> &FederationRouter {
        AppState::federation_outbox(self)
    }

    fn local_domain(&self) -> &str {
        AppState::local_domain(self)
    }

    fn server_name(&self) -> &str {
        AppState::server_name(self)
    }

    fn pending_mix_iq(&self) -> &MixIqRelayIndex {
        AppState::pending_mix_iq(self)
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        AppState::federation_domain_allowed(self, domain)
    }

    fn mix_muc_mirror_enabled(&self) -> bool {
        AppState::mix_muc_mirror_enabled(self)
    }

    fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool {
        AppState::xmpp_extension_enabled(self, id)
    }

    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        self.sessions.session_entries_for(jid)
    }

    fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        self.sessions.sessions_for(jid)
    }

    fn mix_iq_relay_route(&self) -> MixIqRelayRoute {
        AppState::mix_iq_relay_route(self)
    }

    fn mix_outbox_context(&self) -> MixOutboxContext {
        AppState::mix_outbox_context(self)
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
        AppState::validate_routed_message(self, root)
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
