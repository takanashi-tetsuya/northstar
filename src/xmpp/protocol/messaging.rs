//! Messaging tests of the client session over `northstar-message-xmpp`, and the saved Stage 4 case.

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
#[cfg(test)]
use northstar_message_xmpp::messaging::preparation_fixture::*;
#[cfg(test)]
use northstar_stream::frame_execution::Stage;
#[cfg(test)]
use northstar_xmpp_types::jid_text::bare_jid;
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

#[cfg(test)]
mod direct_preparation_tests;

#[cfg(test)]
mod direct_continuation_tests;
#[cfg(test)]
mod direct_workflow_tests;
