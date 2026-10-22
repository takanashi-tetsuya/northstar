//! Capability-injected MAM application boundary, typed commands,
//! validation rules, and repository contracts.

#![forbid(unsafe_code)]

pub use northstar_archive_core::*;
pub mod repository;
pub use repository::*;
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

/// A federated metadata request carries the canonical actor derived from an
/// authenticated S2S connection. Page reads still use atomic stream admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederatedMamMetadataCommand {
    localpart: String,
    viewer_bare_jid: String,
    currently_joined: bool,
}

impl FederatedMamMetadataCommand {
    /// `authenticated_domain` must come from the authenticated S2S connection;
    /// this constructor checks the binding but cannot authenticate the caller.
    pub fn from_authenticated_actor(
        localpart: String,
        authenticated_domain: &str,
        actor_full_jid: &str,
        currently_joined: bool,
    ) -> Option<Self> {
        let domain = northstar_xmpp_types::CanonicalJid::parse(authenticated_domain).ok()?;
        let actor = northstar_xmpp_types::CanonicalJid::parse(actor_full_jid).ok()?;
        if domain.localpart().is_some()
            || domain.resourcepart().is_some()
            || actor.localpart().is_none()
            || actor.resourcepart().is_none()
            || actor.domainpart() != domain.domainpart()
        {
            return None;
        }
        Some(Self {
            localpart,
            viewer_bare_jid: actor.bare(),
            currently_joined,
        })
    }

    pub fn localpart(&self) -> &str {
        &self.localpart
    }

    pub fn viewer_bare_jid(&self) -> &str {
        &self.viewer_bare_jid
    }

    pub fn currently_joined(&self) -> bool {
        self.currently_joined
    }
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
    ValidationFailed(MamQueryValidationError),
}

impl MamQueryResult {
    /// An authorized room with no page still has an unresolved archive ID.
    pub fn from_room_read(outcome: MamRoomReadOutcome<Option<ArchivePage>>) -> Self {
        match outcome {
            MamRoomReadOutcome::Allowed {
                access,
                value: Some(page),
            } => Self::Page {
                room: Some(access),
                page,
            },
            MamRoomReadOutcome::Allowed { value: None, .. } | MamRoomReadOutcome::Missing => {
                Self::ItemNotFound
            }
            MamRoomReadOutcome::Forbidden => Self::Forbidden,
        }
    }
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

impl MamMetadataResult {
    pub fn from_room_read(
        outcome: MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>,
    ) -> Self {
        match outcome {
            MamRoomReadOutcome::Allowed {
                access,
                value: (start, end),
            } => Self::Boundaries {
                room: Some(access),
                start,
                end,
            },
            MamRoomReadOutcome::Missing => Self::ItemNotFound,
            MamRoomReadOutcome::Forbidden => Self::Forbidden,
        }
    }
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
    ExcessiveIdFilter,
    InvalidRsmIndex,
    InvalidWithJid,
    InvalidPreferenceMode,
    ExcessivePreferences,
}

/// Keep service admission aligned with the XEP parser's wire-level limit.
pub const MAX_MAM_PAGE_SIZE: i64 = northstar_xep_0313::MAX_MAM_RESULTS as i64;

/// Pure validation of a MAM query command.
pub fn validate_mam_query_command(cmd: &MamQueryCommand) -> Result<(), MamQueryValidationError> {
    if !validate_query_time_range(cmd.query.start, cmd.query.end) {
        return Err(MamQueryValidationError::InvalidTimeRange);
    }
    if cmd.query.max < 0 {
        return Err(MamQueryValidationError::NegativeMaxResults);
    }
    if cmd.query.max > MAX_MAM_PAGE_SIZE {
        return Err(MamQueryValidationError::ExcessiveMaxResults);
    }
    if cmd.query.ids.len() > northstar_xep_0313::MAX_MAM_IDS {
        return Err(MamQueryValidationError::ExcessiveIdFilter);
    }
    if let MamRsmPage::Index(index) = cmd.query.page {
        if index < 0 || index as u64 > northstar_xep_0313::MAX_MAM_RSM_INDEX {
            return Err(MamQueryValidationError::InvalidRsmIndex);
        }
    }
    if let Some(with_jid) = &cmd.query.with_jid {
        if northstar_xmpp_types::CanonicalJid::parse(with_jid).is_err() {
            return Err(MamQueryValidationError::InvalidWithJid);
        }
    }
    Ok(())
}

/// Pure validation of MAM preferences.
pub fn validate_mam_preferences(prefs: &MamPreferences) -> Result<(), MamQueryValidationError> {
    if !matches!(prefs.default_policy.as_str(), "always" | "never" | "roster") {
        return Err(MamQueryValidationError::InvalidPreferenceMode);
    }
    if prefs.always.len().saturating_add(prefs.never.len()) > northstar_xep_0313::MAX_PREFS_JIDS {
        return Err(MamQueryValidationError::ExcessivePreferences);
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
    fn federated_metadata_command_requires_authenticated_full_jid() {
        let command = FederatedMamMetadataCommand::from_authenticated_actor(
            "room".to_owned(),
            "REMOTE.TEST",
            "alice@remote.test/phone",
            false,
        )
        .expect("authenticated actor");
        assert_eq!(command.localpart(), "room");
        assert_eq!(command.viewer_bare_jid(), "alice@remote.test");
        assert!(!command.currently_joined());
        for actor in [
            "alice@evil.test/phone",
            "alice@remote.test",
            "remote.test/phone",
            "alice@@remote.test/phone",
        ] {
            assert!(FederatedMamMetadataCommand::from_authenticated_actor(
                "room".to_owned(),
                "remote.test",
                actor,
                false,
            )
            .is_none());
        }
        assert!(FederatedMamMetadataCommand::from_authenticated_actor(
            "room".to_owned(),
            "alice@remote.test",
            "alice@remote.test/phone",
            false,
        )
        .is_none());
    }

    #[test]
    fn room_query_result_distinguishes_missing_page_from_denied_access() {
        let access = MamRoomAccess::new("room".to_owned(), vec![7; 32], false);
        let page = ArchivePage {
            rows: Vec::new(),
            total: 0,
            first_index: 0,
            complete: true,
        };

        assert_eq!(
            MamQueryResult::from_room_read(MamRoomReadOutcome::Allowed {
                access: access.clone(),
                value: Some(page.clone()),
            }),
            MamQueryResult::Page {
                room: Some(access.clone()),
                page: page.clone(),
            }
        );
        assert_eq!(
            MamQueryResult::from_room_read(MamRoomReadOutcome::Allowed {
                access,
                value: None,
            }),
            MamQueryResult::ItemNotFound
        );
        assert_eq!(
            MamQueryResult::from_room_read(MamRoomReadOutcome::Missing),
            MamQueryResult::ItemNotFound
        );
        assert_eq!(
            MamQueryResult::from_room_read(MamRoomReadOutcome::Forbidden),
            MamQueryResult::Forbidden
        );
    }

    #[test]
    fn room_metadata_result_preserves_authorized_empty_boundaries() {
        let access = MamRoomAccess::new("room".to_owned(), vec![7; 32], false);
        assert_eq!(
            MamMetadataResult::from_room_read(MamRoomReadOutcome::Allowed {
                access: access.clone(),
                value: (None, None),
            }),
            MamMetadataResult::Boundaries {
                room: Some(access),
                start: None,
                end: None,
            }
        );
        assert_eq!(
            MamMetadataResult::from_room_read(MamRoomReadOutcome::Missing),
            MamMetadataResult::ItemNotFound
        );
        assert_eq!(
            MamMetadataResult::from_room_read(MamRoomReadOutcome::Forbidden),
            MamMetadataResult::Forbidden
        );
    }

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

        let mut excessive_max = cmd;
        excessive_max.query.max = MAX_MAM_PAGE_SIZE + 1;
        assert_eq!(
            validate_mam_query_command(&excessive_max),
            Err(MamQueryValidationError::ExcessiveMaxResults)
        );

        let mut invalid_index = excessive_max.clone();
        invalid_index.query.max = 20;
        invalid_index.query.page = MamRsmPage::Index(-1);
        assert_eq!(
            validate_mam_query_command(&invalid_index),
            Err(MamQueryValidationError::InvalidRsmIndex)
        );
        invalid_index.query.page =
            MamRsmPage::Index(northstar_xep_0313::MAX_MAM_RSM_INDEX as i64 + 1);
        assert_eq!(
            validate_mam_query_command(&invalid_index),
            Err(MamQueryValidationError::InvalidRsmIndex)
        );

        let mut too_many_ids = invalid_index;
        too_many_ids.query.page = MamRsmPage::First;
        too_many_ids.query.ids = vec![Uuid::nil(); northstar_xep_0313::MAX_MAM_IDS + 1];
        assert_eq!(
            validate_mam_query_command(&too_many_ids),
            Err(MamQueryValidationError::ExcessiveIdFilter)
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

        let mut excessive = valid_prefs;
        excessive.always = vec!["bob@example.test".to_string(); northstar_xep_0313::MAX_PREFS_JIDS];
        assert_eq!(
            validate_mam_preferences(&excessive),
            Err(MamQueryValidationError::ExcessivePreferences)
        );
    }
}
