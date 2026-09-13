//! Pure, capability-free XEP-0045 permission and authorization evaluation functions.

#![forbid(unsafe_code)]

use crate::affiliation::Affiliation;
use crate::role::Role;
use std::fmt;

/// Standard XMPP error condition associated with a denied permission decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PermissionDeniedReason {
    /// `<forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` (auth error).
    Forbidden,
    /// `<registration-required xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` (auth error, e.g. members-only).
    RegistrationRequired,
    /// `<not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` (auth error, e.g. invalid room password).
    NotAuthorized,
    /// `<conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` (cancel error, e.g. nickname collision).
    Conflict,
    /// `<service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` (wait error, e.g. room full).
    ServiceUnavailable,
    /// `<item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` (cancel error, e.g. room expired or missing).
    ItemNotFound,
    /// `<not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` (cancel error, e.g. admin modifying owner).
    NotAllowed,
    /// `<bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` (modify error).
    BadRequest,
    /// `<not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>` (modify/cancel error).
    NotAcceptable,
}

impl PermissionDeniedReason {
    /// Return the standard XMPP stanza error condition name.
    pub const fn xmpp_condition(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::RegistrationRequired => "registration-required",
            Self::NotAuthorized => "not-authorized",
            Self::Conflict => "conflict",
            Self::ServiceUnavailable => "service-unavailable",
            Self::ItemNotFound => "item-not-found",
            Self::NotAllowed => "not-allowed",
            Self::BadRequest => "bad-request",
            Self::NotAcceptable => "not-acceptable",
        }
    }

    /// Return the standard XMPP stanza error type (`auth`, `cancel`, `modify`, `wait`).
    pub const fn xmpp_error_type(self) -> &'static str {
        match self {
            Self::Forbidden | Self::RegistrationRequired | Self::NotAuthorized => "auth",
            Self::Conflict | Self::ItemNotFound | Self::NotAllowed => "cancel",
            Self::ServiceUnavailable => "wait",
            Self::BadRequest | Self::NotAcceptable => "modify",
        }
    }
}

impl fmt::Display for PermissionDeniedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.xmpp_condition())
    }
}

/// The result of a pure permission evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PermissionDecision {
    /// Action is authorized.
    Allowed,
    /// Action is denied with the specified XMPP error condition reason.
    Denied(PermissionDeniedReason),
}

impl PermissionDecision {
    /// Returns `true` if the decision is `Allowed`.
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Returns `true` if the decision is `Denied`.
    pub const fn is_denied(self) -> bool {
        matches!(self, Self::Denied(_))
    }

    /// Convert to a standard `Result<(), PermissionDeniedReason>`.
    pub fn to_result(self) -> Result<(), PermissionDeniedReason> {
        match self {
            Self::Allowed => Ok(()),
            Self::Denied(reason) => Err(reason),
        }
    }
}

/// Evaluate whether an actor can view or submit room configuration.
///
/// Per XEP-0045 Section 10.1:
/// - If the room is newly created and locked:
///   - Only the designated configuration owner full JID can configure before expiration.
/// - The actor must hold the `Owner` affiliation.
pub fn evaluate_room_configuration_access(
    actor_affiliation: Affiliation,
    is_locked: bool,
    is_configuration_owner: bool,
    is_configuration_expired: bool,
) -> PermissionDecision {
    if is_locked {
        if is_configuration_expired {
            return PermissionDecision::Denied(PermissionDeniedReason::ItemNotFound);
        }
        if !is_configuration_owner {
            return PermissionDecision::Denied(PermissionDeniedReason::Forbidden);
        }
    }

    if actor_affiliation != Affiliation::Owner {
        return PermissionDecision::Denied(PermissionDeniedReason::Forbidden);
    }

    PermissionDecision::Allowed
}

/// Evaluate whether an actor is permitted to enter/join a MUC room.
///
/// Checks:
/// 1. Outcast affiliation -> `Denied(Forbidden)`.
/// 2. Members-only room without member/admin/owner affiliation -> `Denied(RegistrationRequired)`.
/// 3. Password-protected room with invalid/missing password -> `Denied(NotAuthorized)`.
/// 4. Room capacity (taking into account admin capacity reserve) -> `Denied(ServiceUnavailable)`.
pub fn evaluate_room_join(
    actor_affiliation: Affiliation,
    members_only: bool,
    password_protected: bool,
    password_valid: bool,
    current_occupants_count: usize,
    max_occupants: usize,
    admin_capacity_reserve: usize,
) -> PermissionDecision {
    if actor_affiliation == Affiliation::Outcast {
        return PermissionDecision::Denied(PermissionDeniedReason::Forbidden);
    }

    if members_only && !actor_affiliation.is_member_or_above() {
        return PermissionDecision::Denied(PermissionDeniedReason::RegistrationRequired);
    }

    if password_protected && !password_valid {
        return PermissionDecision::Denied(PermissionDeniedReason::NotAuthorized);
    }

    let privileged = actor_affiliation.is_privileged();
    let effective_capacity = if privileged {
        max_occupants.saturating_add(admin_capacity_reserve)
    } else {
        max_occupants
    };

    if current_occupants_count >= effective_capacity {
        return PermissionDecision::Denied(PermissionDeniedReason::ServiceUnavailable);
    }

    PermissionDecision::Allowed
}

/// Evaluate whether an occupant can send discussion messages to the room.
///
/// In a moderated room, only occupants with voice (`Moderator` or `Participant`) may speak.
/// Occupants with role `Visitor` or `None` cannot speak.
pub fn evaluate_discussion_message(actor_role: Role, room_moderated: bool) -> PermissionDecision {
    if actor_role == Role::None {
        return PermissionDecision::Denied(PermissionDeniedReason::Forbidden);
    }
    if room_moderated && actor_role == Role::Visitor {
        return PermissionDecision::Denied(PermissionDeniedReason::Forbidden);
    }
    PermissionDecision::Allowed
}

/// Evaluate whether an occupant can change the room subject.
///
/// Per XEP-0045 Section 7.2.16:
/// - Any occupant may change subject if `allow_subject_change` is enabled and occupant has voice.
/// - Moderators and Owners/Admins may change the subject regardless of `allow_subject_change`.
pub fn evaluate_subject_change(
    actor_role: Role,
    actor_affiliation: Affiliation,
    allow_subject_change: bool,
) -> PermissionDecision {
    if actor_role.is_moderator() || actor_affiliation.is_privileged() {
        return PermissionDecision::Allowed;
    }
    if allow_subject_change && actor_role.is_voice() {
        return PermissionDecision::Allowed;
    }
    PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
}

/// Evaluate whether an occupant is permitted to invite another entity.
///
/// Per XEP-0045 Section 7.8:
/// - Room owners and admins can always invite.
/// - Other occupants may invite if `allow_invites` is enabled and occupant is not a visitor.
pub fn evaluate_invitation(
    actor_role: Role,
    actor_affiliation: Affiliation,
    allow_invites: bool,
) -> PermissionDecision {
    if actor_affiliation.is_privileged() {
        return PermissionDecision::Allowed;
    }
    if allow_invites && actor_role != Role::Visitor && actor_role != Role::None {
        return PermissionDecision::Allowed;
    }
    PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
}

/// Evaluate whether a requester can query a specific affiliation list via MUC Admin IQ.
///
/// Per XEP-0045 Section 9.5:
/// - Owners and Admins can query any affiliation list (`owner`, `admin`, `member`, `outcast`).
/// - In members-only + non-anonymous rooms (adapted for OMEMO multi-recipient device discovery),
///   members may query `owner`, `admin`, and `member` lists.
/// - Otherwise, queries by non-privileged occupants are forbidden.
pub fn evaluate_affiliation_list_access(
    requester_affiliation: Affiliation,
    requested_affiliation: Affiliation,
    members_only: bool,
    non_anonymous: bool,
) -> PermissionDecision {
    if requester_affiliation.is_privileged() {
        return PermissionDecision::Allowed;
    }

    if requester_affiliation == Affiliation::Member
        && members_only
        && non_anonymous
        && requested_affiliation.is_member_or_above()
    {
        return PermissionDecision::Allowed;
    }

    PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
}

/// Evaluate whether a requester can query a specific role list via MUC Admin IQ.
///
/// Per XEP-0045 Section 9.6:
/// - Moderators, Admins, and Owners can query any role list (`moderator`, `participant`, `visitor`).
/// - Otherwise, querying role lists is forbidden.
pub fn evaluate_role_list_access(
    requester_role: Role,
    requester_affiliation: Affiliation,
) -> PermissionDecision {
    if requester_role.is_moderator() || requester_affiliation.is_privileged() {
        return PermissionDecision::Allowed;
    }
    PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
}

/// Determine whether an offline affiliation change notice should be broadcast.
///
/// XEP-0045 communicates an online affiliate's change with presence. When the affiliate
/// is offline, a room-origin normal message notice is sent to occupants in non-anonymous rooms.
/// Never broadcast offline notices in semi-anonymous rooms to avoid leaking bare JIDs.
pub fn should_broadcast_offline_affiliation_change(
    non_anonymous: bool,
    target_is_occupant: bool,
    previous_affiliation: Affiliation,
    new_affiliation: Affiliation,
) -> bool {
    non_anonymous && !target_is_occupant && previous_affiliation != new_affiliation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_room_config_access() {
        // Owner access on unlocked room
        assert_eq!(
            evaluate_room_configuration_access(Affiliation::Owner, false, false, false),
            PermissionDecision::Allowed
        );

        // Non-owner access denied
        assert_eq!(
            evaluate_room_configuration_access(Affiliation::Admin, false, false, false),
            PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
        );

        // Locked room configuration owner before expiry
        assert_eq!(
            evaluate_room_configuration_access(Affiliation::Owner, true, true, false),
            PermissionDecision::Allowed
        );

        // Locked room non-config-owner
        assert_eq!(
            evaluate_room_configuration_access(Affiliation::Owner, true, false, false),
            PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
        );

        // Expired locked room
        assert_eq!(
            evaluate_room_configuration_access(Affiliation::Owner, true, true, true),
            PermissionDecision::Denied(PermissionDeniedReason::ItemNotFound)
        );
    }

    #[test]
    fn test_join_evaluation() {
        // Normal open room join
        assert_eq!(
            evaluate_room_join(Affiliation::None, false, false, false, 5, 50, 10),
            PermissionDecision::Allowed
        );

        // Outcast rejected
        assert_eq!(
            evaluate_room_join(Affiliation::Outcast, false, false, false, 0, 50, 10),
            PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
        );

        // Members-only with no affiliation rejected
        assert_eq!(
            evaluate_room_join(Affiliation::None, true, false, false, 0, 50, 10),
            PermissionDecision::Denied(PermissionDeniedReason::RegistrationRequired)
        );

        // Members-only with Member allowed
        assert_eq!(
            evaluate_room_join(Affiliation::Member, true, false, false, 0, 50, 10),
            PermissionDecision::Allowed
        );

        // Password protected with valid password
        assert_eq!(
            evaluate_room_join(Affiliation::None, false, true, true, 0, 50, 10),
            PermissionDecision::Allowed
        );

        // Password protected with invalid password
        assert_eq!(
            evaluate_room_join(Affiliation::None, false, true, false, 0, 50, 10),
            PermissionDecision::Denied(PermissionDeniedReason::NotAuthorized)
        );

        // Room full for normal occupant
        assert_eq!(
            evaluate_room_join(Affiliation::None, false, false, false, 50, 50, 10),
            PermissionDecision::Denied(PermissionDeniedReason::ServiceUnavailable)
        );

        // Room full for admin with administrative reserve
        assert_eq!(
            evaluate_room_join(Affiliation::Admin, false, false, false, 50, 50, 10),
            PermissionDecision::Allowed
        );
        assert_eq!(
            evaluate_room_join(Affiliation::Admin, false, false, false, 60, 50, 10),
            PermissionDecision::Denied(PermissionDeniedReason::ServiceUnavailable)
        );
    }

    #[test]
    fn test_discussion_message_evaluation() {
        assert_eq!(
            evaluate_discussion_message(Role::Participant, false),
            PermissionDecision::Allowed
        );
        assert_eq!(
            evaluate_discussion_message(Role::Visitor, false),
            PermissionDecision::Allowed
        );
        assert_eq!(
            evaluate_discussion_message(Role::Visitor, true),
            PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
        );
        assert_eq!(
            evaluate_discussion_message(Role::Participant, true),
            PermissionDecision::Allowed
        );
        assert_eq!(
            evaluate_discussion_message(Role::Moderator, true),
            PermissionDecision::Allowed
        );
        assert_eq!(
            evaluate_discussion_message(Role::None, false),
            PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
        );
    }

    #[test]
    fn test_affiliation_list_access() {
        // Admin can query outcast list
        assert_eq!(
            evaluate_affiliation_list_access(
                Affiliation::Admin,
                Affiliation::Outcast,
                false,
                false
            ),
            PermissionDecision::Allowed
        );

        // Member in members-only + non-anonymous room can query member, admin, owner
        assert_eq!(
            evaluate_affiliation_list_access(Affiliation::Member, Affiliation::Member, true, true),
            PermissionDecision::Allowed
        );
        assert_eq!(
            evaluate_affiliation_list_access(Affiliation::Member, Affiliation::Admin, true, true),
            PermissionDecision::Allowed
        );
        assert_eq!(
            evaluate_affiliation_list_access(Affiliation::Member, Affiliation::Owner, true, true),
            PermissionDecision::Allowed
        );

        // Member cannot query outcast list
        assert_eq!(
            evaluate_affiliation_list_access(Affiliation::Member, Affiliation::Outcast, true, true),
            PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
        );

        // Member in semi-anonymous room cannot query admin/owner lists
        assert_eq!(
            evaluate_affiliation_list_access(Affiliation::Member, Affiliation::Admin, true, false),
            PermissionDecision::Denied(PermissionDeniedReason::Forbidden)
        );
    }
}
