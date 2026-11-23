//! MIX channel administration: information, configuration and access lists.

use super::MixMutationAdmission;

mod access;
mod forms;

pub use self::access::{authorized_mix_access_entries, set_mix_access_entry};
pub(crate) use self::forms::{apply_config_patch, apply_info_patch};
pub use self::forms::{update_mix_config, update_mix_info};

pub struct MixInfoUpdate<'a> {
    pub item_id: &'a str,
    pub expected_revision: i64,
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub contacts: &'a [String],
}

pub struct MixConfigUpdate<'a> {
    pub item_id: &'a str,
    pub expected_revision: i64,
    pub access_model: &'a str,
    pub jid_visibility: &'a str,
    pub nick_required: bool,
    pub max_participants: i32,
    pub max_events: i32,
    pub allow_private_messages: bool,
    pub allow_participant_invites: bool,
    pub allow_user_message_retraction: bool,
    pub administrator_retraction_rights: &'a str,
    pub enforce_registered_nick: bool,
}

pub struct MixRoleUpdate<'a> {
    /// `None` preserves the current list; `Some` atomically replaces it.
    pub owners: Option<&'a [String]>,
    pub administrators: Option<&'a [String]>,
}

#[derive(Clone, Debug)]
pub enum MixMutationOutcome {
    Applied(Box<MixMutationAdmission>),
    Conflict,
    Forbidden,
    NotFound,
}
