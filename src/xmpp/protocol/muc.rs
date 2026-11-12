//! Tests of the MUC session glue, which lives in `northstar-muc-xmpp`.

#[cfg(test)]
use northstar_muc_xmpp::muc as handlers;

#[cfg(test)]
pub(crate) mod saved_stage4;

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
