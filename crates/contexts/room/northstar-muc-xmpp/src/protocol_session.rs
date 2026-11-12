//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`, and the handlers the root's IQ, message and presence
//! dispatch calls on it.

use crate::muc as handlers;
use crate::ports::Occupant;
use crate::ports::{MucFrameStage, MucHost, MucSession, MucSessionUser};
use anyhow::Result;
use dashmap::DashMap;
use northstar_room_application::discussion;
use northstar_session_core::JoinedMucMembership;
use northstar_stream::frame_execution::Stage;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_stream::transport::Action;
use roxmltree::Node;
use uuid::Uuid;

// From src/xmpp/protocol/muc.rs.
impl<H: SessionHost + MucHost<Outbound = OutboundSender>> MucSession for ProtocolSession<H> {
    type Host = H;

    fn host(&self) -> &H {
        self.host()
    }

    fn user(&self) -> Option<MucSessionUser<'_>> {
        self.authenticated.as_ref().map(|user| MucSessionUser {
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

    fn sm_db_id(&self) -> Option<Uuid> {
        self.sm.db_id
    }

    fn joined_rooms(&self) -> &DashMap<String, JoinedMucMembership> {
        &self.joined_rooms
    }

    fn outbound(&self) -> &OutboundSender {
        &self.outbound
    }

    fn enter_frame_stage(&self, stage: MucFrameStage) {
        ProtocolSession::enter_frame_stage(
            self,
            match stage {
                MucFrameStage::Policy => Stage::MucPolicy,
                MucFrameStage::GateWait => Stage::MucGateWait,
                MucFrameStage::Authority => Stage::MucAuthority,
                MucFrameStage::Admission => Stage::MucAdmission,
                MucFrameStage::ClusterFanout => Stage::MucClusterFanout,
                MucFrameStage::LocalFanout => Stage::MucLocalFanout,
            },
        );
    }

    fn muc_discussion_operation(
        &self,
        prepared: &discussion::PreparedDiscussion,
    ) -> Result<Option<discussion::Observation>, discussion::Rejected> {
        ProtocolSession::muc_discussion_operation(self, prepared)
    }
}

/// The MUC handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait MucHandlers {
    /// The session host whose occupancy records the handlers return.
    type Host: MucHost;

    async fn authorized_muc_occupant(&self, room_jid: &str)
        -> Result<Option<Occupant<Self::Host>>>;

    async fn muc_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action>;

    async fn muc_presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action>;

    async fn muc_admin_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn muc_admin_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn muc_moderate(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        moderate: Node<'_, '_>,
    ) -> Result<Action>;

    async fn muc_owner_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action>;

    async fn muc_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn muc_register_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action>;

    async fn muc_register_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;
}

impl<H: SessionHost + MucHost<Outbound = OutboundSender>> MucHandlers for ProtocolSession<H> {
    type Host = H;

    async fn authorized_muc_occupant(&self, room_jid: &str) -> Result<Option<Occupant<H>>> {
        handlers::authorized_muc_occupant(self, room_jid).await
    }

    async fn muc_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        Ok(handlers::groupchat::muc_message(self, root, raw)
            .await?
            .into())
    }

    async fn muc_presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        Ok(handlers::join::muc_presence(&*self, root, raw)
            .await?
            .into())
    }

    async fn muc_admin_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::admin::muc_admin_get(self, id, iq, query)
            .await?
            .into())
    }

    async fn muc_admin_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::admin::muc_admin_set(self, id, iq, query)
            .await?
            .into())
    }

    async fn muc_moderate(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        moderate: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::moderate::muc_moderate(self, id, iq, moderate)
            .await?
            .into())
    }

    async fn muc_owner_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        Ok(handlers::owner::muc_owner_get(self, id, iq).await?.into())
    }

    async fn muc_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::owner::muc_owner_set(self, id, iq, query)
            .await?
            .into())
    }

    async fn muc_register_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        Ok(handlers::register::muc_register_get(self, id, iq)
            .await?
            .into())
    }

    async fn muc_register_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::register::muc_register_set(self, id, iq, query)
            .await?
            .into())
    }
}
