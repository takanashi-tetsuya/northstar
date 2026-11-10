//! XEP-0045 multi-user chat for local clients.
//!
//! `northstar-muc-xmpp` holds the handlers. This seam gives them the live
//! session and maps their replies back to session actions.

use super::{Action, ProtocolSession};
use crate::state::AppState;
use anyhow::Result;
use dashmap::DashMap;
use northstar_muc_xmpp::muc as handlers;
use northstar_muc_xmpp::ports::{MucFrameStage, MucSession, MucSessionUser};
use northstar_room_application::discussion;
use northstar_session_core::JoinedMucMembership;
use northstar_stream::frame_execution::Stage;
use northstar_stream::local_routes::muc::MucOccupant;
use northstar_stream::outbound::OutboundSender;
use roxmltree::Node;
use uuid::Uuid;

#[cfg(test)]
pub(crate) mod saved_stage4;

impl MucSession for ProtocolSession {
    type Host = AppState;

    fn host(&self) -> &AppState {
        &self.host
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

impl ProtocolSession {
    pub(crate) fn muc_domain(&self) -> String {
        handlers::muc_domain(self)
    }

    pub(crate) async fn authorized_muc_occupant(
        &self,
        room_jid: &str,
    ) -> Result<Option<MucOccupant>> {
        handlers::authorized_muc_occupant(self, room_jid).await
    }

    pub(crate) async fn muc_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        Ok(handlers::groupchat::muc_message(self, root, raw)
            .await?
            .into())
    }

    pub(crate) async fn muc_presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        Ok(handlers::join::muc_presence(&*self, root, raw)
            .await?
            .into())
    }

    pub(crate) async fn muc_admin_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::admin::muc_admin_get(self, id, iq, query)
            .await?
            .into())
    }

    pub(crate) async fn muc_admin_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::admin::muc_admin_set(self, id, iq, query)
            .await?
            .into())
    }

    pub(crate) async fn muc_moderate(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        moderate: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::moderate::muc_moderate(self, id, iq, moderate)
            .await?
            .into())
    }

    pub(crate) async fn muc_owner_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        Ok(handlers::owner::muc_owner_get(self, id, iq).await?.into())
    }

    pub(crate) async fn muc_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::owner::muc_owner_set(self, id, iq, query)
            .await?
            .into())
    }

    pub(crate) async fn muc_register_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        Ok(handlers::register::muc_register_get(self, id, iq)
            .await?
            .into())
    }

    pub(crate) async fn muc_register_set(
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

#[cfg(test)]
use handlers::{admin_batch::*, discussion::*, join::*, moderate::*, *};
#[cfg(test)]
use northstar_room_application::muc_service::{
    MucAdminBatchChange, MucAdminBatchOutcome, MucAffiliationTarget, MucDiscussionAdmission,
};
#[cfg(test)]
use northstar_room_application::{
    PostCommitAdmissionError as MucPostCommitAdmissionError, PostCommitPlan as MucPostCommitPlan,
};
#[cfg(test)]
use northstar_xml_builder::message_policy::encrypted_archive_stanza;

#[cfg(test)]
#[path = "muc_tests.rs"]
mod tests;
