//! Saved direct-message replay case over `northstar-message-xmpp`.

use anyhow::Result;
#[cfg(test)]
use northstar_abuse_policy::message_admission::MessageAdmissionStart;
#[cfg(test)]
use northstar_abuse_policy::MessageAdmissionRequest;
#[cfg(test)]
use northstar_message_application::message_admission::witness::DirectOperationHandle;
#[cfg(test)]
use northstar_message_application::messaging::direct_workflow::{
    continue_prepared_local_direct, ContinuedLocalDirect,
};
#[cfg(test)]
use northstar_message_application::messaging::{
    ArchiveWrite, IdentityAuthority, LocalDelivery, MessageIdentity, MessagePostCommit,
    PersonalMessageDestination, ValidatedPersonalMessage,
};
#[cfg(test)]
use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility};
#[cfg(test)]
use northstar_message_xmpp::messaging::preparation_fixture::{
    direct_spool_eligibility, LocalArchiveEligibility, LocalProjectionAuthority,
    OriginalDirectMessage,
};
#[cfg(test)]
use northstar_stream::frame_execution::Stage;
#[cfg(test)]
use northstar_xmpp_types::jid_text::bare_jid;

#[cfg(test)]
mod saved_case;
