//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`.

use crate::extdisco::{ExtDiscoHost, ExtDiscoSession};
use crate::ports::{MessageFrameStage, MessageHost, MessageSession};
use anyhow::Result;
use northstar_message_application::extdisco::ExtDiscoService;
use northstar_message_application::message_admission::witness::DirectOperationHandle;
use northstar_stream::frame_execution::Stage;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_stream::transport::Action;
use roxmltree::Node;
use std::net::IpAddr;
use uuid::Uuid;

// From src/xmpp/protocol/extdisco.rs.
impl<H: SessionHost + ExtDiscoHost> ExtDiscoSession for ProtocolSession<H> {
    type Action = Action;

    fn extdisco_service(&self) -> &ExtDiscoService {
        self.host().extdisco_service()
    }

    fn authenticated_username(&self) -> Option<&str> {
        self.authenticated
            .as_ref()
            .map(|user| user.username.as_str())
    }

    fn full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }
}

// From src/xmpp/protocol/messaging.rs.
impl<H: SessionHost + MessageHost> MessageSession for ProtocolSession<H> {
    type Host = H;
    type Action = Action;

    fn host(&self) -> &H {
        self.host()
    }

    fn enter_frame_stage(&self, stage: MessageFrameStage) {
        self.enter_frame_stage(match stage {
            MessageFrameStage::Handler => Stage::Handler,
            MessageFrameStage::Policy => Stage::MessagePolicy,
            MessageFrameStage::Admission => Stage::MessageAdmission,
            MessageFrameStage::Routing => Stage::MessageRouting,
            MessageFrameStage::Followup => Stage::MessageFollowup,
        });
    }

    fn account_id(&self) -> Option<Uuid> {
        self.authenticated.as_ref().map(|user| user.id)
    }

    fn full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn peer_ip(&self) -> std::net::IpAddr {
        self.peer_ip
    }

    fn muc_domain(&self) -> String {
        self.host().muc_domain()
    }

    fn upload_domain(&self) -> String {
        self.host().upload_domain()
    }

    fn pubsub_domain(&self) -> String {
        self.host().pubsub_domain()
    }

    fn message_operation(&self) -> Option<DirectOperationHandle> {
        ProtocolSession::message_operation(self)
    }

    fn active_privacy(&self) -> Option<String> {
        self.privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn joined_room_nick(&self, room_jid: &str) -> Option<String> {
        self.joined_rooms
            .get(room_jid)
            .map(|membership| membership.nick.clone())
    }

    async fn pubsub_authorization_response(&self, root: Node<'_, '_>) -> Result<bool> {
        H::dispatch_pubsub_authorization_response(self, root).await
    }

    async fn push_disable_message(&self, root: Node<'_, '_>, from: &str, to: &str) -> Result<bool> {
        ProtocolSession::push_disable_message(self, root, from, to).await
    }

    async fn try_mix_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Option<Action>> {
        H::dispatch_mix_message(self, root, raw).await
    }

    async fn muc_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        H::dispatch_muc_message(self, root, raw).await
    }
}
