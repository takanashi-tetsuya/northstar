//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`.

use crate::ports::{MucFrameStage, MucHost, MucSession, MucSessionUser};
use anyhow::Result;
use dashmap::DashMap;
use northstar_room_application::discussion;
use northstar_session_core::JoinedMucMembership;
use northstar_stream::frame_execution::Stage;
use northstar_stream::outbound::OutboundSender;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
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
