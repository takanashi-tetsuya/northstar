//! Binds the message handlers of `northstar-message-xmpp` to the client session.

use super::{Action, ProtocolSession};
use crate::xmpp::protocol::ClientSession;
use crate::xmpp::protocol::SessionHost;
use anyhow::Result;
#[cfg(test)]
use northstar_abuse_policy::message_admission::MessageAdmissionStart;
#[cfg(test)]
use northstar_abuse_policy::MessageAdmissionRequest;
#[cfg(test)]
use northstar_message_application::direct_commit::TransactionOutcome;
use northstar_message_application::message_admission::witness::DirectOperationHandle;
#[cfg(test)]
use northstar_message_application::messaging::direct_workflow::{
    continue_prepared_local_direct, ContinuedLocalDirect, PreparedHandoffNext,
};
#[cfg(test)]
use northstar_message_application::messaging::{
    ArchiveWrite, DirectMessageRouter, DirectRouteDelivery, DirectRouteOutcome, DirectRouteRequest,
    DirectRouteTarget, DurableAdmissionOutcome, IdentityAuthority, LocalDelivery, MessageIdentity,
    MessagePostCommit, PersonalMessageDestination, ValidatedPersonalMessage,
};
#[cfg(test)]
use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility};
use northstar_message_xmpp::messaging as handlers;
#[cfg(test)]
use northstar_message_xmpp::messaging::preparation_fixture::*;
use northstar_message_xmpp::ports::{MessageFrameStage, MessageHost, MessageSession};
use northstar_mix_xmpp::ports::MixHost;
use northstar_muc_xmpp::ports::MucHost;
use northstar_pubsub_xmpp::pubsub::PubSubHost;
use northstar_stream::frame_execution::Stage;
#[cfg(test)]
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;
#[cfg(test)]
use std::future::Future;
use uuid::Uuid;

#[cfg(test)]
mod saved_case;

impl<H: SessionHost + MessageHost> MessageSession for ProtocolSession<H> {
    type Host = H;
    type Action = Action;

    fn host(&self) -> &H {
        &self.host
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
        self.host.muc_domain()
    }

    fn upload_domain(&self) -> String {
        self.host.upload_domain()
    }

    fn pubsub_domain(&self) -> String {
        self.host.pubsub_domain()
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

impl ClientSession {
    /// Ordinary controlled tests use the actual frame owner without constructing
    /// a session. The returned runner owns observation before child polling.
    #[cfg(test)]
    pub(crate) fn retained_direct_frame_for_test<C, F, T>(
        child: C,
    ) -> (
        DirectOperationHandle,
        impl Future<Output = std::result::Result<T, northstar_stream::frame_execution::FrameFailure>>,
    )
    where
        C: FnOnce(DirectOperationHandle) -> F,
        F: Future<Output = Result<T>>,
    {
        let execution = northstar_stream::frame_execution::FrameExecution::new(
            northstar_stream::transport::ClientTransport::Tcp,
            direct_preparation_tests::FRAME_MESSAGE,
        );
        let operation = execution.direct_operation();
        let future = child(operation.clone());
        (operation, execution.run(future))
    }
}

impl<
        H: SessionHost
            + MessageHost
            + MucHost<Outbound = northstar_stream::outbound::OutboundSender>
            + MixHost
            + PubSubHost,
    > ProtocolSession<H>
{
    pub(crate) async fn message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        client_raw: &str,
    ) -> Result<Action> {
        handlers::message(self, root, raw, client_raw).await
    }
}

#[cfg(test)]
mod direct_preparation_tests;

#[cfg(test)]
mod direct_continuation_tests;
#[cfg(test)]
mod direct_workflow_tests;
