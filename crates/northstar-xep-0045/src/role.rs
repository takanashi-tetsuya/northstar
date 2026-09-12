//! XEP-0045 MUC Occupant Role definitions, ordering, default derivations, and transition rules.

#![forbid(unsafe_code)]

use crate::affiliation::Affiliation;
use std::fmt;
use thiserror::Error;

/// Error evaluating a role modification or kick request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RoleError {
    /// Requester is not a moderator.
    #[error("actor must be a moderator to modify occupant roles")]
    Forbidden,

    /// Action not allowed (e.g. moderator cannot change another moderator's role or kick an owner/admin without higher affiliation).
    #[error("role transition is not allowed")]
    NotAllowed,

    /// Role string is invalid or unmapped.
    #[error("invalid or unknown role value")]
    InvalidRole,
}

/// A transient, session-scoped role held by an occupant within a MUC room.
///
/// Ranked from lowest privilege (`None`) to highest (`Moderator`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Role {
    /// None (not an active occupant or kicked from the room).
    None,
    /// Visitor (can receive messages and presence, but cannot send messages in a moderated room).
    Visitor,
    /// Participant (has voice; can send and receive discussion messages).
    Participant,
    /// Moderator (can grant voice, kick visitors/participants, manage subject).
    Moderator,
}

impl Role {
    /// Parse a role from its wire name string.
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "moderator" => Some(Self::Moderator),
            "participant" => Some(Self::Participant),
            "visitor" => Some(Self::Visitor),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// Return the wire string name of this role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Moderator => "moderator",
            Self::Participant => "participant",
            Self::Visitor => "visitor",
            Self::None => "none",
        }
    }

    /// Numeric rank of the role (0 to 3).
    pub const fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Visitor => 1,
            Self::Participant => 2,
            Self::Moderator => 3,
        }
    }

    /// Returns `true` if this role allows speaking in a moderated room (`Moderator` or `Participant`).
    pub const fn is_voice(self) -> bool {
        matches!(self, Self::Moderator | Self::Participant)
    }

    /// Returns `true` if this role is `Moderator`.
    pub const fn is_moderator(self) -> bool {
        matches!(self, Self::Moderator)
    }

    /// Determine the default initial role for an occupant based on their affiliation and whether the room is moderated.
    ///
    /// Per XEP-0045 Section 5.1:
    /// - `Owner` or `Admin` always receives `Moderator`.
    /// - `Member` receives `Participant`.
    /// - `None` receives `Visitor` if room is moderated, otherwise `Participant`.
    /// - `Outcast` receives `None` (forbidden from entry).
    pub const fn default_for(affiliation: Affiliation, moderated_room: bool) -> Self {
        match affiliation {
            Affiliation::Owner | Affiliation::Admin => Self::Moderator,
            Affiliation::Member => Self::Participant,
            Affiliation::None => {
                if moderated_room {
                    Self::Visitor
                } else {
                    Self::Participant
                }
            }
            Affiliation::Outcast => Self::None,
        }
    }

    /// Pure validation of whether an actor can change a target's role.
    ///
    /// Per XEP-0045 Section 5.1 / Section 8.2:
    /// - The actor MUST hold the `Moderator` role.
    /// - A moderator cannot change the role of an `Owner` or `Admin` unless the actor holds higher/equal affiliation.
    /// - An admin cannot change the role of an `Owner` or another `Admin`.
    /// - A non-owner/non-admin moderator cannot grant or revoke `Moderator` role.
    /// - Kicking (setting role to `None`) follows the same hierarchy rules.
    pub fn can_modify_role(
        actor_role: Role,
        actor_affiliation: Affiliation,
        target_role: Role,
        target_affiliation: Affiliation,
        new_role: Role,
    ) -> Result<(), RoleError> {
        if actor_role != Self::Moderator {
            return Err(RoleError::Forbidden);
        }

        // Admin cannot modify Owner or Admin occupant
        if actor_affiliation == Affiliation::Admin
            && matches!(target_affiliation, Affiliation::Owner | Affiliation::Admin)
        {
            return Err(RoleError::NotAllowed);
        }

        // Non-admin/non-owner moderator cannot modify Owner or Admin occupant
        if !actor_affiliation.is_privileged()
            && matches!(target_affiliation, Affiliation::Owner | Affiliation::Admin)
        {
            return Err(RoleError::NotAllowed);
        }

        // Granting or revoking moderator role requires Owner or Admin affiliation
        if (new_role == Self::Moderator || target_role == Self::Moderator)
            && !actor_affiliation.is_privileged()
        {
            return Err(RoleError::NotAllowed);
        }

        Ok(())
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_parsing_and_display() {
        for (name, role) in [
            ("moderator", Role::Moderator),
            ("participant", Role::Participant),
            ("visitor", Role::Visitor),
            ("none", Role::None),
        ] {
            assert_eq!(Role::from_str_name(name), Some(role));
            assert_eq!(role.as_str(), name);
            assert_eq!(role.to_string(), name);
        }
        assert_eq!(Role::from_str_name("invalid"), None);
    }

    #[test]
    fn test_role_rank_and_ordering() {
        assert!(Role::Moderator > Role::Participant);
        assert!(Role::Participant > Role::Visitor);
        assert!(Role::Visitor > Role::None);

        assert_eq!(Role::Moderator.rank(), 3);
        assert_eq!(Role::Participant.rank(), 2);
        assert_eq!(Role::Visitor.rank(), 1);
        assert_eq!(Role::None.rank(), 0);
    }

    #[test]
    fn test_role_defaults() {
        assert_eq!(Role::default_for(Affiliation::Owner, true), Role::Moderator);
        assert_eq!(
            Role::default_for(Affiliation::Owner, false),
            Role::Moderator
        );
        assert_eq!(Role::default_for(Affiliation::Admin, true), Role::Moderator);
        assert_eq!(
            Role::default_for(Affiliation::Admin, false),
            Role::Moderator
        );

        assert_eq!(
            Role::default_for(Affiliation::Member, true),
            Role::Participant
        );
        assert_eq!(
            Role::default_for(Affiliation::Member, false),
            Role::Participant
        );

        assert_eq!(Role::default_for(Affiliation::None, true), Role::Visitor);
        assert_eq!(
            Role::default_for(Affiliation::None, false),
            Role::Participant
        );

        assert_eq!(Role::default_for(Affiliation::Outcast, true), Role::None);
        assert_eq!(Role::default_for(Affiliation::Outcast, false), Role::None);
    }

    #[test]
    fn test_role_permissions_matrix() {
        // Non-moderator cannot change roles
        assert_eq!(
            Role::can_modify_role(
                Role::Participant,
                Affiliation::Owner,
                Role::Visitor,
                Affiliation::None,
                Role::Participant
            ),
            Err(RoleError::Forbidden)
        );

        // Owner moderator can change anything
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Owner,
                Role::Visitor,
                Affiliation::None,
                Role::Participant
            ),
            Ok(())
        );
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Owner,
                Role::Participant,
                Affiliation::Member,
                Role::Moderator
            ),
            Ok(())
        );
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Owner,
                Role::Moderator,
                Affiliation::Admin,
                Role::None
            ),
            Ok(())
        );

        // Admin moderator cannot change owner or admin
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Admin,
                Role::Moderator,
                Affiliation::Owner,
                Role::None
            ),
            Err(RoleError::NotAllowed)
        );
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Admin,
                Role::Moderator,
                Affiliation::Admin,
                Role::None
            ),
            Err(RoleError::NotAllowed)
        );

        // Admin moderator can change member/none
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Admin,
                Role::Visitor,
                Affiliation::None,
                Role::Participant
            ),
            Ok(())
        );

        // Regular moderator (affiliation Member or None) cannot grant or revoke moderator role
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Member,
                Role::Participant,
                Affiliation::None,
                Role::Moderator
            ),
            Err(RoleError::NotAllowed)
        );
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Member,
                Role::Moderator,
                Affiliation::Member,
                Role::Participant
            ),
            Err(RoleError::NotAllowed)
        );

        // Regular moderator can kick/voice visitors and participants
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Member,
                Role::Visitor,
                Affiliation::None,
                Role::Participant
            ),
            Ok(())
        );
        assert_eq!(
            Role::can_modify_role(
                Role::Moderator,
                Affiliation::Member,
                Role::Participant,
                Affiliation::None,
                Role::None
            ),
            Ok(())
        );
    }
}
