//! Pure, capability-free occupant state transitions and policy update evaluations.

#![forbid(unsafe_code)]

use crate::address::OccupantNick;
use crate::affiliation::Affiliation;
use crate::form::RoomConfig;
use crate::role::Role;
use crate::status_code::StatusCode;

/// Pure snapshot of an occupant's state in a MUC room.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OccupantSnapshot {
    pub nick: String,
    pub full_jid: String,
    pub affiliation: Affiliation,
    pub role: Role,
    pub room_non_anonymous: bool,
}

/// The result of an occupant joining a room.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinOutcome {
    pub nick: String,
    pub affiliation: Affiliation,
    pub role: Role,
    pub status_codes: Vec<StatusCode>,
    pub created: bool,
}

/// Compute the initial state and status codes for a newly joining occupant.
pub fn compute_join_transition(
    nick: &OccupantNick,
    affiliation: Affiliation,
    room_config: &RoomConfig,
    created: bool,
) -> JoinOutcome {
    let role = Role::default_for(affiliation, room_config.moderated);
    let mut status_codes = Vec::new();

    if room_config.non_anonymous {
        status_codes.push(StatusCode::NonAnonymous); // 100
    }
    status_codes.push(StatusCode::SelfPresence); // 110
    if created {
        status_codes.push(StatusCode::RoomCreated); // 201
    }

    JoinOutcome {
        nick: nick.as_str().to_owned(),
        affiliation,
        role,
        status_codes,
        created,
    }
}

/// The result of an occupant changing their nickname.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NickChangeOutcome {
    pub old_nick: String,
    pub new_nick: String,
    pub status_codes: Vec<StatusCode>,
}

/// Compute the state transition and status codes for a nickname change.
pub fn compute_nick_change_transition(
    old_nick: &str,
    new_nick: &OccupantNick,
) -> NickChangeOutcome {
    NickChangeOutcome {
        old_nick: old_nick.to_owned(),
        new_nick: new_nick.as_str().to_owned(),
        status_codes: vec![StatusCode::NewNickname, StatusCode::SelfPresence], // 303, 110
    }
}

/// The result of an affiliation change on an occupant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffiliationChangeOutcome {
    pub new_affiliation: Affiliation,
    pub new_role: Role,
    pub evicted: bool,
    pub eviction_status_code: Option<StatusCode>,
}

/// Compute the state transition when an occupant's affiliation is modified.
pub fn compute_affiliation_change_transition(
    _current_affiliation: Affiliation,
    new_affiliation: Affiliation,
    current_role: Role,
    room_config: &RoomConfig,
) -> AffiliationChangeOutcome {
    if new_affiliation == Affiliation::Outcast {
        return AffiliationChangeOutcome {
            new_affiliation,
            new_role: Role::None,
            evicted: true,
            eviction_status_code: Some(StatusCode::Banned), // 301
        };
    }

    if room_config.members_only && new_affiliation == Affiliation::None {
        return AffiliationChangeOutcome {
            new_affiliation,
            new_role: Role::None,
            evicted: true,
            eviction_status_code: Some(StatusCode::AffiliationLost), // 321
        };
    }

    let new_role = if new_affiliation.is_privileged() {
        Role::Moderator
    } else if room_config.moderated && new_affiliation == Affiliation::None {
        Role::Visitor
    } else if current_role == Role::Visitor && new_affiliation.is_member_or_above() {
        Role::Participant
    } else {
        current_role
    };

    AffiliationChangeOutcome {
        new_affiliation,
        new_role,
        evicted: false,
        eviction_status_code: None,
    }
}

/// The result of a role change on an occupant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleChangeOutcome {
    pub new_role: Role,
    pub evicted: bool,
    pub eviction_status_code: Option<StatusCode>,
}

/// Compute the state transition when an occupant's role is modified.
pub fn compute_role_change_transition(new_role: Role) -> RoleChangeOutcome {
    if new_role == Role::None {
        RoleChangeOutcome {
            new_role,
            evicted: true,
            eviction_status_code: Some(StatusCode::Kicked), // 307
        }
    } else {
        RoleChangeOutcome {
            new_role,
            evicted: false,
            eviction_status_code: None,
        }
    }
}

/// Result of evaluating a batch of occupants when room configuration changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomPolicyUpdateDiff {
    pub evicted_occupants: Vec<(OccupantSnapshot, StatusCode)>,
    pub refreshed_occupants: Vec<OccupantSnapshot>,
}

/// Re-evaluate all room occupants when room configuration changes.
///
/// Handles:
/// - Making room members-only: occupants with `Affiliation::None` are evicted with status code 322.
/// - Moderation changes: unprivileged occupants toggle between `Visitor` and `Participant`.
/// - Anonymity changes: occupant `room_non_anonymous` flag updated.
pub fn evaluate_room_policy_update(
    occupants: &[OccupantSnapshot],
    old_config: &RoomConfig,
    new_config: &RoomConfig,
) -> RoomPolicyUpdateDiff {
    let mut evicted_occupants = Vec::new();
    let mut refreshed_occupants = Vec::new();

    for occupant in occupants {
        // Members-only eviction check
        if new_config.members_only
            && !old_config.members_only
            && occupant.affiliation == Affiliation::None
        {
            let mut evicted = occupant.clone();
            evicted.role = Role::None;
            evicted_occupants.push((evicted, StatusCode::MembersOnlyRemoval)); // 322
            continue;
        }

        let mut changed = false;
        let mut updated = occupant.clone();

        // Moderation role refresh
        if new_config.moderated != old_config.moderated {
            let next_role = if occupant.affiliation.is_privileged() {
                Role::Moderator
            } else if new_config.moderated && occupant.affiliation == Affiliation::None {
                Role::Visitor
            } else {
                Role::Participant
            };
            if updated.role != next_role {
                updated.role = next_role;
                changed = true;
            }
        }

        // Anonymity flag refresh
        if new_config.non_anonymous != old_config.non_anonymous {
            updated.room_non_anonymous = new_config.non_anonymous;
            changed = true;
        }

        if changed {
            refreshed_occupants.push(updated);
        }
    }

    RoomPolicyUpdateDiff {
        evicted_occupants,
        refreshed_occupants,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_join_transition() {
        let nick = OccupantNick::parse("Alice").unwrap();
        let config = RoomConfig {
            non_anonymous: true,
            moderated: false,
            ..Default::default()
        };

        let outcome = compute_join_transition(&nick, Affiliation::Owner, &config, true);
        assert_eq!(outcome.role, Role::Moderator);
        assert_eq!(outcome.affiliation, Affiliation::Owner);
        assert!(outcome.status_codes.contains(&StatusCode::NonAnonymous));
        assert!(outcome.status_codes.contains(&StatusCode::SelfPresence));
        assert!(outcome.status_codes.contains(&StatusCode::RoomCreated));

        let outcome2 = compute_join_transition(&nick, Affiliation::None, &config, false);
        assert_eq!(outcome2.role, Role::Participant);
        assert!(!outcome2.status_codes.contains(&StatusCode::RoomCreated));
    }

    #[test]
    fn test_nick_change_transition() {
        let new_nick = OccupantNick::parse("AliceNew").unwrap();
        let outcome = compute_nick_change_transition("AliceOld", &new_nick);
        assert_eq!(outcome.old_nick, "AliceOld");
        assert_eq!(outcome.new_nick, "AliceNew");
        assert_eq!(
            outcome.status_codes,
            vec![StatusCode::NewNickname, StatusCode::SelfPresence]
        );
    }

    #[test]
    fn test_affiliation_change_transition() {
        let config = RoomConfig::default();

        // Ban -> outcast + role none + status 301
        let outcome = compute_affiliation_change_transition(
            Affiliation::Member,
            Affiliation::Outcast,
            Role::Participant,
            &config,
        );
        assert_eq!(outcome.new_role, Role::None);
        assert!(outcome.evicted);
        assert_eq!(outcome.eviction_status_code, Some(StatusCode::Banned));

        // Member in members-only room reduced to None -> evicted with 321
        let members_only_config = RoomConfig {
            members_only: true,
            ..Default::default()
        };
        let outcome2 = compute_affiliation_change_transition(
            Affiliation::Member,
            Affiliation::None,
            Role::Participant,
            &members_only_config,
        );
        assert_eq!(outcome2.new_role, Role::None);
        assert!(outcome2.evicted);
        assert_eq!(
            outcome2.eviction_status_code,
            Some(StatusCode::AffiliationLost)
        );
    }

    #[test]
    fn test_policy_update_evaluation() {
        let old_config = RoomConfig {
            members_only: false,
            moderated: false,
            non_anonymous: true,
            ..Default::default()
        };

        let new_config = RoomConfig {
            members_only: true,
            moderated: true,
            ..old_config.clone()
        };

        let occupants = vec![
            OccupantSnapshot {
                nick: "OwnerUser".to_owned(),
                full_jid: "owner@example.org/res".to_owned(),
                affiliation: Affiliation::Owner,
                role: Role::Moderator,
                room_non_anonymous: true,
            },
            OccupantSnapshot {
                nick: "MemberUser".to_owned(),
                full_jid: "member@example.org/res".to_owned(),
                affiliation: Affiliation::Member,
                role: Role::Participant,
                room_non_anonymous: true,
            },
            OccupantSnapshot {
                nick: "NoneUser".to_owned(),
                full_jid: "none@example.org/res".to_owned(),
                affiliation: Affiliation::None,
                role: Role::Participant,
                room_non_anonymous: true,
            },
        ];

        let diff = evaluate_room_policy_update(&occupants, &old_config, &new_config);

        // NoneUser should be evicted with 322 because room became members-only
        assert_eq!(diff.evicted_occupants.len(), 1);
        assert_eq!(diff.evicted_occupants[0].0.nick, "NoneUser");
        assert_eq!(diff.evicted_occupants[0].1, StatusCode::MembersOnlyRemoval);

        // Owner and Member remain
        assert!(diff.refreshed_occupants.is_empty()); // Role for Owner (Moderator) and Member (Participant) didn't change
    }
}
