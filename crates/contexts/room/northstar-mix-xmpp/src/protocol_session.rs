//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`, and the handlers the root's IQ, message and presence
//! dispatch calls on it.

use crate::ports::{MixFrameObserver, MixHost, MixSession, MixSessionUser};
use anyhow::Result;
use dashmap::DashSet;
use northstar_room_core::mix::MixSessionCapability;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_stream::transport::Action;
use roxmltree::Node;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

// From src/xmpp/protocol/mix.rs.
impl<H: SessionHost + MixHost> MixSession for ProtocolSession<H> {
    type Host = H;

    fn host(&self) -> &Arc<H> {
        self.host()
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

/// The MIX handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait MixHandlers {
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
        let action = crate::session::try_mix_iq(self, raw).await?;
        Ok(action.map(Action::from))
    }

    async fn try_mix_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Option<Action>> {
        let action = crate::session::try_mix_message(self, root, raw).await?;
        Ok(action.map(Action::from))
    }

    async fn try_mix_presence(&self, root: Node<'_, '_>, raw: &str) -> Result<Option<Action>> {
        let action = crate::session::try_mix_presence(self, root, raw).await?;
        Ok(action.map(Action::from))
    }

    async fn forward_presence_to_mix_channels(
        &self,
        kind: &str,
        advertised_capability: MixSessionCapability,
        raw: &str,
    ) -> Result<()> {
        crate::session::forward_presence_to_mix_channels(self, kind, advertised_capability, raw)
            .await
    }
}
