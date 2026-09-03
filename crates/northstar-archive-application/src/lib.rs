//! Capability-injected MAM application boundary, typed commands,
//! validation rules, and repository contracts.

#![forbid(unsafe_code)]

pub use northstar_archive_core::*;
use uuid::Uuid;

/// Query scope representing the archive target (Personal, local MUC Room, or Federated Room).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MamQueryScope {
    Personal {
        owner_id: Uuid,
    },
    Room {
        localpart: String,
        viewer_id: Uuid,
        currently_joined: bool,
    },
    FederatedRoom {
        localpart: String,
        viewer_bare_jid: String,
        currently_joined: bool,
    },
}

/// Typed command for executing a MAM archive query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MamQueryCommand {
    pub scope: MamQueryScope,
    pub query: MamArchiveQuery,
}

/// Typed command for retrieving archive boundary metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MamMetadataCommand {
    pub scope: MamQueryScope,
}

/// Typed command for reading MAM preferences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MamPreferencesGetCommand {
    pub owner_id: Uuid,
}

/// Typed command for updating MAM preferences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MamPreferencesSetCommand {
    pub owner_id: Uuid,
    pub preferences: MamPreferences,
}

/// Outcome of executing a MAM query command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MamQueryResult {
    Page {
        room: Option<MamRoomAccess>,
        page: ArchivePage,
    },
    ItemNotFound,
    Forbidden,
}

/// Outcome of executing a MAM metadata command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MamMetadataResult {
    Boundaries {
        room: Option<MamRoomAccess>,
        start: Option<ArchiveBoundary>,
        end: Option<ArchiveBoundary>,
    },
    ItemNotFound,
    Forbidden,
}

/// Authorization and paging context for one atomic federated room archive response.
#[derive(Clone, Copy, Debug)]
pub struct FederatedMamStreamRequest<'a> {
    pub target_domain: &'a str,
    pub localpart: &'a str,
    pub viewer_bare_jid: &'a str,
    pub currently_joined: bool,
    pub query: &'a MamArchiveQuery,
}

impl<'a> FederatedMamStreamRequest<'a> {
    pub fn new(
        target_domain: &'a str,
        localpart: &'a str,
        viewer_bare_jid: &'a str,
        currently_joined: bool,
        query: &'a MamArchiveQuery,
    ) -> Self {
        Self {
            target_domain,
            localpart,
            viewer_bare_jid,
            currently_joined,
            query,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MamQueryValidationError {
    InvalidTimeRange,
    NegativeMaxResults,
    ExcessiveMaxResults,
    InvalidWithJid,
    InvalidPreferenceMode,
}

/// Maximum page size allowed by Northstar policy.
pub const MAX_MAM_PAGE_SIZE: i64 = 1000;

/// Pure validation of a MAM query command.
pub fn validate_mam_query_command(
    cmd: &MamQueryCommand,
) -> Result<(), MamQueryValidationError> {
    if !validate_query_time_range(cmd.query.start, cmd.query.end) {
        return Err(MamQueryValidationError::InvalidTimeRange);
    }
    if cmd.query.max < 0 {
        return Err(MamQueryValidationError::NegativeMaxResults);
    }
    if cmd.query.max > MAX_MAM_PAGE_SIZE {
        return Err(MamQueryValidationError::ExcessiveMaxResults);
    }
    if let Some(with_jid) = &cmd.query.with_jid {
        if northstar_xmpp_types::CanonicalJid::parse(with_jid).is_err() {
            return Err(MamQueryValidationError::InvalidWithJid);
        }
    }
    Ok(())
}

/// Pure validation of MAM preferences.
pub fn validate_mam_preferences(
    prefs: &MamPreferences,
) -> Result<(), MamQueryValidationError> {
    if !matches!(prefs.default_policy.as_str(), "always" | "never" | "roster") {
        return Err(MamQueryValidationError::InvalidPreferenceMode);
    }
    for jid in prefs.always.iter().chain(prefs.never.iter()) {
        if northstar_xmpp_types::CanonicalJid::parse(jid).is_err() {
            return Err(MamQueryValidationError::InvalidWithJid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn command_validation_rules() {
        let valid_query = MamArchiveQuery {
            with_jid: Some("alice@example.test".to_string()),
            start: Some(Utc::now()),
            end: Some(Utc::now() + chrono::Duration::seconds(10)),
            before_id: None,
            after_id: None,
            ids: Vec::new(),
            page: MamRsmPage::First,
            max: 50,
        };
        let cmd = MamQueryCommand {
            scope: MamQueryScope::Personal {
                owner_id: Uuid::new_v4(),
            },
            query: valid_query.clone(),
        };
        assert!(validate_mam_query_command(&cmd).is_ok());

        let mut invalid_time = cmd.clone();
        invalid_time.query.start = Some(Utc::now() + chrono::Duration::seconds(100));
        invalid_time.query.end = Some(Utc::now());
        assert_eq!(
            validate_mam_query_command(&invalid_time),
            Err(MamQueryValidationError::InvalidTimeRange)
        );

        let mut invalid_jid = cmd.clone();
        invalid_jid.query.with_jid = Some("not a jid".to_string());
        assert_eq!(
            validate_mam_query_command(&invalid_jid),
            Err(MamQueryValidationError::InvalidWithJid)
        );

        let mut invalid_max = cmd.clone();
        invalid_max.query.max = -1;
        assert_eq!(
            validate_mam_query_command(&invalid_max),
            Err(MamQueryValidationError::NegativeMaxResults)
        );
    }

    #[test]
    fn preferences_validation() {
        let valid_prefs = MamPreferences {
            default_policy: "roster".to_string(),
            always: vec!["bob@example.test".to_string()],
            never: vec!["mallory@example.test".to_string()],
        };
        assert!(validate_mam_preferences(&valid_prefs).is_ok());

        let mut invalid_mode = valid_prefs.clone();
        invalid_mode.default_policy = "unknown".to_string();
        assert_eq!(
            validate_mam_preferences(&invalid_mode),
            Err(MamQueryValidationError::InvalidPreferenceMode)
        );

        let mut invalid_jid = valid_prefs.clone();
        invalid_jid.always = vec!["invalid jid".to_string()];
        assert_eq!(
            validate_mam_preferences(&invalid_jid),
            Err(MamQueryValidationError::InvalidWithJid)
        );
    }
}
