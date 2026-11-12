//! XEP-0369 MIX Core, XEP-0405 MIX-PAM, and XEP-0406 MIX Administration.
//!
//! `northstar-mix-xmpp` holds the handlers. This seam gives them the live
//! sessions, routes and federation outbox the root crate still owns, and maps
//! their replies back to session actions.

use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use dashmap::DashSet;
use northstar_mix_xmpp::ports::{MixFrameObserver, MixHost, MixSession, MixSessionUser};
use northstar_room_core::mix::MixSessionCapability;
use roxmltree::Node;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[cfg(test)]
pub(crate) mod stage4_saved;

impl<H: SessionHost + MixHost> MixSession for ProtocolSession<H> {
    type Host = H;

    fn host(&self) -> &Arc<H> {
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

impl<H: SessionHost + MixHost> ProtocolSession<H> {
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
