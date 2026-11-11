//! XEP-0369 MIX Core, XEP-0405 MIX-PAM, and XEP-0406 MIX Administration.
//!
//! `northstar-mix-xmpp` holds the handlers. This seam gives them the live
//! sessions, routes and federation outbox the root crate still owns, and maps
//! their replies back to session actions.

use super::{Action, ProtocolSession};
use crate::s2s::FederationRouter;
use crate::state::mix_iq_relay::MixIqRelayRoute;
use crate::state::mix_outbox::MixOutboxContext;
use crate::state::AppState;
use anyhow::Result;
use dashmap::DashSet;
use northstar_mix_xmpp::ports::{
    MixFrameObserver, MixHost, MixOutboxPort, MixSession, MixSessionUser,
};
use northstar_room_application::mix_service::MixService;
use northstar_room_core::mix::{MixSessionCapability, CORE_NS, PAM_NS};
use northstar_room_core::mix_iq_relay::MixIqRelayIndex;
use northstar_roster_core::RosterChange;
use northstar_stream::local_routes::session::OnlineSession;
use roxmltree::Node;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[cfg(test)]
pub(crate) mod stage4_saved;

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
        AppState::session_entries_for(self, jid)
    }

    fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        AppState::sessions_for(self, jid)
    }

    fn mix_iq_relay_route(&self) -> MixIqRelayRoute {
        AppState::mix_iq_relay_route(self)
    }

    fn mix_outbox_context(&self) -> MixOutboxContext {
        AppState::mix_outbox_context(self)
    }

    fn session_mix_capability(&self, full_jid: &str) -> MixSessionCapability {
        match super::caps::verified_caps_has_any_feature(self, full_jid, &[CORE_NS, PAM_NS]) {
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
        AppState::local_mix_presence_route_is_current(
            self,
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
        super::roster::deliver_roster_change(self, owner_id, owner, change, participant_id).await
    }
}

impl MixSession for ProtocolSession {
    type Host = AppState;

    fn host(&self) -> &Arc<AppState> {
        &self.host
    }

    fn user(&self) -> Option<MixSessionUser<'_>> {
        self.authenticated.as_ref().map(|user| MixSessionUser {
            id: user.id,
            username: &user.username,
        })
    }

    fn full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn connection_id(&self) -> Uuid {
        self.connection_id
    }

    fn mix_presence_gate(&self) -> &Arc<Mutex<()>> {
        &self.presence.mix_presence_gate
    }

    fn mix_presence_fallback_suppressed(&self) -> &DashSet<String> {
        &self.presence.mix_presence_fallback_suppressed
    }

    fn frame_observer(&self) -> &dyn MixFrameObserver {
        &self.frame_executions
    }
}

impl ProtocolSession {
    pub(crate) async fn try_mix_iq(&self, raw: &str) -> Result<Option<Action>> {
        let action = northstar_mix_xmpp::session::try_mix_iq(self, raw).await?;
        Ok(action.map(Action::from))
    }

    pub(crate) async fn try_mix_message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<Action>> {
        let action = northstar_mix_xmpp::session::try_mix_message(self, root, raw).await?;
        Ok(action.map(Action::from))
    }

    pub(crate) async fn try_mix_presence(
        &self,
        root: Node<'_, '_>,
        raw: &str,
    ) -> Result<Option<Action>> {
        let action = northstar_mix_xmpp::session::try_mix_presence(self, root, raw).await?;
        Ok(action.map(Action::from))
    }

    pub(crate) async fn forward_presence_to_mix_channels(
        &self,
        kind: &str,
        advertised_capability: MixSessionCapability,
        raw: &str,
    ) -> Result<()> {
        northstar_mix_xmpp::session::forward_presence_to_mix_channels(
            self,
            kind,
            advertised_capability,
            raw,
        )
        .await
    }
}

#[cfg(test)]
use futures::{future::BoxFuture, stream::FuturesUnordered};
#[cfg(test)]
use northstar_mix_xmpp::{
    channel_delivery::*, claimed::*, federation::*, iq_parse::*, local_delivery::*, message::*,
    payloads::*, relay::*, session::*, worker::*,
};
#[cfg(test)]
use northstar_room_application::mix_service::outbox;
#[cfg(test)]
use northstar_room_application::mix_service::outbox::core as mix_worker;
#[cfg(test)]
use northstar_room_application::mix_service::{
    MamArchiveQuery, MixBusinessReplay, MixParticipant, PamMembership, StoreEventOutcome,
    NODE_MESSAGES, NODE_PRESENCE,
};
#[cfg(test)]
use northstar_room_core::mix_iq_relay::MixIqRelayStage;
#[cfg(test)]
use northstar_stream::local_routes::session_table::{
    mix_presence_epoch_is_current, mix_presence_fallback_is_suppressed,
};
#[cfg(test)]
use northstar_xmpp_types::jid::CanonicalJid;
#[cfg(test)]
use roxmltree::Document;
#[cfg(test)]
use std::time::{Duration, Instant};

#[cfg(test)]
#[path = "mix_tests.rs"]
mod tests;

#[cfg(test)]
mod shared_claimed_delivery_policy_tests;
