//! Capability-injected roster application boundary, typed commands and
//! validation rules, with the blocking, privacy, presence and
//! federated-roster services.

#![forbid(unsafe_code)]

pub use northstar_auth_core::normalize_username;
pub use northstar_federation_core::S2sOutboxPolicy;
pub use northstar_roster_core::*;
pub mod blocking;
pub mod presence;
pub mod privacy;
pub mod repository;
pub mod s2s_roster_authorization;
pub mod service;
pub use repository::*;
pub use service::RosterService;
use uuid::Uuid;

/// Typed command for fetching a roster snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterGetCommand {
    pub owner_id: Uuid,
    pub expected_auth_generation: i64,
    pub requested_version: Option<i64>,
    pub annotations_requested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterGetValidationError {
    InvalidVersion,
}

pub fn validate_roster_get_command(cmd: &RosterGetCommand) -> Result<(), RosterGetValidationError> {
    if let Some(version) = cmd.requested_version {
        if version < 0 {
            return Err(RosterGetValidationError::InvalidVersion);
        }
    }
    Ok(())
}

/// Typed command for adding or updating a roster item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterUpsertCommand {
    pub owner_id: Uuid,
    pub expected_auth_generation: i64,
    pub jid: String,
    pub name: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterUpsertValidationError {
    EmptyJid,
    InvalidJid,
    NameTooLong,
    TooManyGroups,
    GroupTooLong,
}

pub fn validate_roster_upsert_command(
    cmd: &RosterUpsertCommand,
) -> Result<(), RosterUpsertValidationError> {
    if cmd.jid.trim().is_empty() {
        return Err(RosterUpsertValidationError::EmptyJid);
    }
    if northstar_xmpp_types::CanonicalJid::parse_bare(&cmd.jid).is_err() {
        return Err(RosterUpsertValidationError::InvalidJid);
    }
    if let Some(name) = &cmd.name {
        if name.len() > 1024 {
            return Err(RosterUpsertValidationError::NameTooLong);
        }
    }
    if cmd.groups.len() > 128 {
        return Err(RosterUpsertValidationError::TooManyGroups);
    }
    for group in &cmd.groups {
        if group.len() > 1024 {
            return Err(RosterUpsertValidationError::GroupTooLong);
        }
    }
    Ok(())
}

/// Delivery route target for roster item removal stanzas.
#[derive(Clone, Copy, Debug)]
pub enum RosterRemovalRoute<'a> {
    Local {
        owner_jid: &'a str,
        contact_username: Option<&'a str>,
    },
    Remote {
        target_domain: &'a str,
        unsubscribe_stanza: &'a str,
        unsubscribed_stanza: &'a str,
        bounce_to: Option<&'a str>,
        policy: S2sOutboxPolicy,
    },
}

/// Typed command for removing a contact from a user's roster.
#[derive(Clone, Copy, Debug)]
pub struct RosterRemoveCommand<'a> {
    pub owner_id: Uuid,
    pub expected_auth_generation: i64,
    pub jid: &'a str,
    pub route: RosterRemovalRoute<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterRemoveValidationError {
    EmptyJid,
    InvalidJid,
}

pub fn validate_roster_remove_command(
    cmd: &RosterRemoveCommand<'_>,
) -> Result<(), RosterRemoveValidationError> {
    if cmd.jid.trim().is_empty() {
        return Err(RosterRemoveValidationError::EmptyJid);
    }
    if northstar_xmpp_types::CanonicalJid::parse_bare(cmd.jid).is_err() {
        return Err(RosterRemoveValidationError::InvalidJid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_validation() {
        let valid_get = RosterGetCommand {
            owner_id: Uuid::new_v4(),
            expected_auth_generation: 1,
            requested_version: Some(5),
            annotations_requested: false,
        };
        assert!(validate_roster_get_command(&valid_get).is_ok());

        let invalid_get = RosterGetCommand {
            owner_id: Uuid::new_v4(),
            expected_auth_generation: 1,
            requested_version: Some(-1),
            annotations_requested: false,
        };
        assert_eq!(
            validate_roster_get_command(&invalid_get),
            Err(RosterGetValidationError::InvalidVersion)
        );

        let valid_upsert = RosterUpsertCommand {
            owner_id: Uuid::new_v4(),
            expected_auth_generation: 1,
            jid: "contact@example.test".to_string(),
            name: Some("Friend".to_string()),
            groups: vec!["Friends".to_string()],
        };
        assert!(validate_roster_upsert_command(&valid_upsert).is_ok());

        let mut invalid_upsert = valid_upsert.clone();
        invalid_upsert.jid = "not a jid".to_string();
        assert_eq!(
            validate_roster_upsert_command(&invalid_upsert),
            Err(RosterUpsertValidationError::InvalidJid)
        );

        let valid_remove = RosterRemoveCommand {
            owner_id: Uuid::new_v4(),
            expected_auth_generation: 1,
            jid: "contact@example.test",
            route: RosterRemovalRoute::Local {
                owner_jid: "user@example.test",
                contact_username: Some("contact"),
            },
        };
        assert!(validate_roster_remove_command(&valid_remove).is_ok());
    }
}
