//! XEP-0045 MUC Affiliation definitions, ordering, and transition rules.

#![forbid(unsafe_code)]

use std::fmt;
use thiserror::Error;

/// Error evaluating an affiliation change request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AffiliationError {
    /// Requester does not hold sufficient privileges (e.g. member/none/outcast attempting to change affiliations).
    #[error("insufficient privileges to modify affiliation")]
    Forbidden,

    /// Action not allowed by XEP-0045 affiliation rules (e.g. admin attempting to change owner/admin).
    #[error("affiliation transition is not allowed")]
    NotAllowed,

    /// Actor cannot ban themselves (self-outcast conflict).
    #[error("occupant cannot ban themselves")]
    SelfBanConflict,

    /// Target affiliation name is unmapped or invalid.
    #[error("invalid or unknown affiliation value")]
    InvalidAffiliation,
}

/// A long-lived, persistent association between a bare JID and a MUC room.
///
/// Ranked from lowest privilege (`Outcast`) to highest (`Owner`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Affiliation {
    /// Outcast (banned from entering or speaking in the room).
    Outcast,
    /// None (no persistent affiliation with the room).
    None,
    /// Member (granted admission in a members-only room, voice in moderated room).
    Member,
    /// Admin (can kick/ban visitors/participants/members, grant voice).
    Admin,
    /// Owner (full administrative control over room configuration, ownership, and destruction).
    Owner,
}

impl Affiliation {
    /// Parse an affiliation from its wire name string.
    pub fn from_str_name(name: &str) -> Option<Self> {
        match name {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            "none" => Some(Self::None),
            "outcast" => Some(Self::Outcast),
            _ => None,
        }
    }

    /// Return the wire string name of this affiliation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::None => "none",
            Self::Outcast => "outcast",
        }
    }

    /// Numeric rank of the affiliation (0 to 4).
    pub const fn rank(self) -> u8 {
        match self {
            Self::Outcast => 0,
            Self::None => 1,
            Self::Member => 2,
            Self::Admin => 3,
            Self::Owner => 4,
        }
    }

    /// Returns `true` if this affiliation is privileged (`Owner` or `Admin`).
    pub const fn is_privileged(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Returns `true` if this affiliation is at least `Member` (`Owner`, `Admin`, or `Member`).
    pub const fn is_member_or_above(self) -> bool {
        matches!(self, Self::Owner | Self::Admin | Self::Member)
    }

    /// Pure validation of whether `actor` can change the affiliation of a target from `target_current` to `target_new`.
    ///
    /// Rules per XEP-0045 Section 5.2 / Section 8:
    /// - An `Owner` can grant or revoke any affiliation (Owner, Admin, Member, None, Outcast).
    /// - An `Admin` can only grant `Member`, `None`, or `Outcast`.
    /// - An `Admin` cannot change the affiliation of an `Owner` or `Admin`.
    /// - An `Admin` cannot grant `Owner` or `Admin` affiliation.
    /// - `Member`, `None`, and `Outcast` have no permission to modify affiliations.
    pub fn can_modify_affiliation(
        actor: Affiliation,
        target_current: Affiliation,
        target_new: Affiliation,
    ) -> Result<(), AffiliationError> {
        match actor {
            Self::Owner => {
                // Owners can change anyone's affiliation to anything.
                Ok(())
            }
            Self::Admin => {
                // Admins cannot change owner or admin affiliations
                if matches!(target_current, Self::Owner | Self::Admin) {
                    return Err(AffiliationError::NotAllowed);
                }
                // Admins cannot grant owner or admin affiliations
                if matches!(target_new, Self::Owner | Self::Admin) {
                    return Err(AffiliationError::NotAllowed);
                }
                Ok(())
            }
            Self::Member | Self::None | Self::Outcast => Err(AffiliationError::Forbidden),
        }
    }
}

impl fmt::Display for Affiliation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_affiliation_parsing_and_display() {
        for (name, affil) in [
            ("owner", Affiliation::Owner),
            ("admin", Affiliation::Admin),
            ("member", Affiliation::Member),
            ("none", Affiliation::None),
            ("outcast", Affiliation::Outcast),
        ] {
            assert_eq!(Affiliation::from_str_name(name), Some(affil));
            assert_eq!(affil.as_str(), name);
            assert_eq!(affil.to_string(), name);
        }
        assert_eq!(Affiliation::from_str_name("invalid"), None);
    }

    #[test]
    fn test_affiliation_rank_and_ordering() {
        assert!(Affiliation::Owner > Affiliation::Admin);
        assert!(Affiliation::Admin > Affiliation::Member);
        assert!(Affiliation::Member > Affiliation::None);
        assert!(Affiliation::None > Affiliation::Outcast);

        assert_eq!(Affiliation::Owner.rank(), 4);
        assert_eq!(Affiliation::Admin.rank(), 3);
        assert_eq!(Affiliation::Member.rank(), 2);
        assert_eq!(Affiliation::None.rank(), 1);
        assert_eq!(Affiliation::Outcast.rank(), 0);
    }

    #[test]
    fn test_affiliation_permissions_matrix() {
        // Owner can do everything
        for current in [
            Affiliation::Owner,
            Affiliation::Admin,
            Affiliation::Member,
            Affiliation::None,
            Affiliation::Outcast,
        ] {
            for target in [
                Affiliation::Owner,
                Affiliation::Admin,
                Affiliation::Member,
                Affiliation::None,
                Affiliation::Outcast,
            ] {
                assert_eq!(
                    Affiliation::can_modify_affiliation(Affiliation::Owner, current, target),
                    Ok(())
                );
            }
        }

        // Admin cannot modify Owner or Admin
        assert_eq!(
            Affiliation::can_modify_affiliation(
                Affiliation::Admin,
                Affiliation::Owner,
                Affiliation::Member
            ),
            Err(AffiliationError::NotAllowed)
        );
        assert_eq!(
            Affiliation::can_modify_affiliation(
                Affiliation::Admin,
                Affiliation::Admin,
                Affiliation::None
            ),
            Err(AffiliationError::NotAllowed)
        );

        // Admin cannot grant Owner or Admin
        assert_eq!(
            Affiliation::can_modify_affiliation(
                Affiliation::Admin,
                Affiliation::Member,
                Affiliation::Admin
            ),
            Err(AffiliationError::NotAllowed)
        );
        assert_eq!(
            Affiliation::can_modify_affiliation(
                Affiliation::Admin,
                Affiliation::None,
                Affiliation::Owner
            ),
            Err(AffiliationError::NotAllowed)
        );

        // Admin can modify Member, None, Outcast to Member, None, Outcast
        for current in [Affiliation::Member, Affiliation::None, Affiliation::Outcast] {
            for target in [Affiliation::Member, Affiliation::None, Affiliation::Outcast] {
                assert_eq!(
                    Affiliation::can_modify_affiliation(Affiliation::Admin, current, target),
                    Ok(())
                );
            }
        }

        // Non-privileged cannot modify anything
        for actor in [Affiliation::Member, Affiliation::None, Affiliation::Outcast] {
            assert_eq!(
                Affiliation::can_modify_affiliation(actor, Affiliation::None, Affiliation::Member),
                Err(AffiliationError::Forbidden)
            );
        }
    }
}
