//! Regression tests for the MUC session glue.

use crate::muc as handlers;
use handlers::{admin_batch::*, discussion::*, join::*, moderate::*, *};
use northstar_room_application::muc_service::{
    MucAdminBatchChange, MucAdminBatchOutcome, MucAffiliationTarget, MucDiscussionAdmission,
};
use northstar_xml_builder::message_policy::encrypted_archive_stanza;

#[path = "muc_tests.rs"]
mod tests;
