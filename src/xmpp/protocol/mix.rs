//! XEP-0369 MIX Core, XEP-0405 MIX-PAM, and XEP-0406 MIX Administration.
//!
//! `northstar-mix-xmpp` holds the handlers. This seam gives them the live
//! sessions, routes and federation outbox the root crate still owns, and maps
//! their replies back to session actions.

use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_mix_xmpp::ports::MixHost;
use northstar_room_core::mix::MixSessionCapability;
use roxmltree::Node;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
pub(crate) mod stage4_saved;

/// The session handlers of mix.rs.
pub(crate) trait MixHandlers {
    async fn try_mix_iq(&self, raw: &str) -> Result<Option<Action>>;

    async fn try_mix_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Option<Action>>;

    async fn try_mix_presence(&self, root: Node<'_, '_>, raw: &str) -> Result<Option<Action>>;

    async fn forward_presence_to_mix_channels(
        &self,
        kind: &str,
        advertised_capability: MixSessionCapability,
        raw: &str,
    ) -> Result<()>;
}

impl<H: SessionHost + MixHost> MixHandlers for ProtocolSession<H> {
    async fn try_mix_iq(&self, raw: &str) -> Result<Option<Action>> {
        let action = northstar_mix_xmpp::session::try_mix_iq(self, raw).await?;
        Ok(action.map(Action::from))
    }

    async fn try_mix_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Option<Action>> {
        let action = northstar_mix_xmpp::session::try_mix_message(self, root, raw).await?;
        Ok(action.map(Action::from))
    }

    async fn try_mix_presence(&self, root: Node<'_, '_>, raw: &str) -> Result<Option<Action>> {
        let action = northstar_mix_xmpp::session::try_mix_presence(self, root, raw).await?;
        Ok(action.map(Action::from))
    }

    async fn forward_presence_to_mix_channels(
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
