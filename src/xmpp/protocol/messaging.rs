//! Binds the message handlers of `northstar-message-xmpp` to the client session.

use super::{Action, ProtocolSession};
use crate::xmpp::protocol::SessionHost;
use anyhow::Result;
#[cfg(test)]
use northstar_abuse_policy::message_admission::MessageAdmissionStart;
#[cfg(test)]
use northstar_abuse_policy::MessageAdmissionRequest;
#[cfg(test)]
use northstar_message_application::direct_commit::TransactionOutcome;
#[cfg(test)]
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
use northstar_message_xmpp::ports::MessageHost;
use northstar_mix_xmpp::ports::MixHost;
use northstar_muc_xmpp::ports::MucHost;
use northstar_pubsub_xmpp::pubsub::PubSubHost;
#[cfg(test)]
use northstar_stream::frame_execution::Stage;
#[cfg(test)]
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;
#[cfg(test)]
use std::future::Future;

#[cfg(test)]
mod saved_case;

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

/// The session handlers of messaging.rs.
pub(crate) trait MessageHandlers {
    async fn message(&self, root: Node<'_, '_>, raw: &str, client_raw: &str) -> Result<Action>;
}

impl<
        H: SessionHost
            + MessageHost
            + MucHost<Outbound = northstar_stream::outbound::OutboundSender>
            + MixHost
            + PubSubHost,
    > MessageHandlers for ProtocolSession<H>
{
    async fn message(&self, root: Node<'_, '_>, raw: &str, client_raw: &str) -> Result<Action> {
        handlers::message(self, root, raw, client_raw).await
    }
}

#[cfg(test)]
mod direct_preparation_tests;

#[cfg(test)]
mod direct_continuation_tests;
#[cfg(test)]
mod direct_workflow_tests;
