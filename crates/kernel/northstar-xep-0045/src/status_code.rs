//! XEP-0045 MUC Status Codes and wire representations.

#![forbid(unsafe_code)]

use std::fmt;

/// Strongly-typed XEP-0045 status codes.
///
/// Status codes are returned within `<status code='...'/>` elements inside
/// `<x xmlns='http://jabber.org/protocol/muc#user'>`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StatusCode {
    /// 100: Inform user that any occupant is allowed to see the user's full JID.
    NonAnonymous,
    /// 104: Inform occupants that room configuration has changed.
    ConfigChanged,
    /// 110: Inform user that presence refers to oneself.
    SelfPresence,
    /// 170: Inform occupants that room logging is now enabled.
    LoggingEnabled,
    /// 171: Inform occupants that room logging is now disabled.
    LoggingDisabled,
    /// 172: Inform occupants that the room is now non-anonymous.
    NonAnonymousShow,
    /// 173: Inform occupants that the room is now semi-anonymous.
    SemiAnonymousShow,
    /// 174: Inform occupants that the room is now fully-anonymous.
    FullyAnonymousShow,
    /// 201: Inform user that a new room has been created and requires configuration.
    RoomCreated,
    /// 210: Inform user that service has assigned or modified occupant's nick.
    NickAssigned,
    /// 301: Inform user that they have been banned (outcast) from the room.
    Banned,
    /// 303: Inform occupants that occupant changed nickname (new nick is in item nick attribute).
    NewNickname,
    /// 307: Inform user that they have been kicked from the room.
    Kicked,
    /// 321: Inform user that they are removed due to affiliation change.
    AffiliationLost,
    /// 322: Inform user that they are removed because room is now members-only.
    MembersOnlyRemoval,
    /// 332: Inform user that they are removed due to system shutdown.
    SystemShutdown,
    /// 333: Inform user that they are removed being disconnected.
    Disconnected,
    /// Custom or unrecognized numeric status code.
    Custom(u16),
}

impl StatusCode {
    /// Create a `StatusCode` from a numeric u16 value.
    pub const fn from_u16(code: u16) -> Self {
        match code {
            100 => Self::NonAnonymous,
            104 => Self::ConfigChanged,
            110 => Self::SelfPresence,
            170 => Self::LoggingEnabled,
            171 => Self::LoggingDisabled,
            172 => Self::NonAnonymousShow,
            173 => Self::SemiAnonymousShow,
            174 => Self::FullyAnonymousShow,
            201 => Self::RoomCreated,
            210 => Self::NickAssigned,
            301 => Self::Banned,
            303 => Self::NewNickname,
            307 => Self::Kicked,
            321 => Self::AffiliationLost,
            322 => Self::MembersOnlyRemoval,
            332 => Self::SystemShutdown,
            333 => Self::Disconnected,
            other => Self::Custom(other),
        }
    }

    /// Return the numeric code value.
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::NonAnonymous => 100,
            Self::ConfigChanged => 104,
            Self::SelfPresence => 110,
            Self::LoggingEnabled => 170,
            Self::LoggingDisabled => 171,
            Self::NonAnonymousShow => 172,
            Self::SemiAnonymousShow => 173,
            Self::FullyAnonymousShow => 174,
            Self::RoomCreated => 201,
            Self::NickAssigned => 210,
            Self::Banned => 301,
            Self::NewNickname => 303,
            Self::Kicked => 307,
            Self::AffiliationLost => 321,
            Self::MembersOnlyRemoval => 322,
            Self::SystemShutdown => 332,
            Self::Disconnected => 333,
            Self::Custom(code) => code,
        }
    }

    /// Returns `true` if this status code represents occupant removal / eviction.
    pub const fn is_removal(self) -> bool {
        matches!(
            self,
            Self::Banned
                | Self::Kicked
                | Self::AffiliationLost
                | Self::MembersOnlyRemoval
                | Self::SystemShutdown
                | Self::Disconnected
        )
    }

    /// Returns `true` if this status code represents informational self-presence or configuration notices.
    pub const fn is_informational(self) -> bool {
        matches!(
            self,
            Self::NonAnonymous
                | Self::ConfigChanged
                | Self::SelfPresence
                | Self::LoggingEnabled
                | Self::LoggingDisabled
                | Self::NonAnonymousShow
                | Self::SemiAnonymousShow
                | Self::FullyAnonymousShow
                | Self::RoomCreated
                | Self::NickAssigned
        )
    }

    /// Human-readable explanation of the status code.
    pub const fn description(self) -> &'static str {
        match self {
            Self::NonAnonymous => "Room is non-anonymous; user full JID is publicly visible",
            Self::ConfigChanged => "Room configuration has been updated",
            Self::SelfPresence => "Self-presence notification",
            Self::LoggingEnabled => "Room discussion logging is now enabled",
            Self::LoggingDisabled => "Room discussion logging is now disabled",
            Self::NonAnonymousShow => "Room is now non-anonymous",
            Self::SemiAnonymousShow => "Room is now semi-anonymous",
            Self::FullyAnonymousShow => "Room is now fully anonymous",
            Self::RoomCreated => "Room has been newly created and requires configuration",
            Self::NickAssigned => "Service has modified or assigned occupant nickname",
            Self::Banned => "Occupant has been banned from the room",
            Self::NewNickname => "Occupant has changed nickname",
            Self::Kicked => "Occupant has been kicked from the room",
            Self::AffiliationLost => "Occupant removed due to an affiliation change",
            Self::MembersOnlyRemoval => "Occupant removed because room became members-only",
            Self::SystemShutdown => "Occupant removed due to system shutdown",
            Self::Disconnected => "Occupant removed because the connection was lost",
            Self::Custom(_) => "Custom or unmapped status code",
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.as_u16())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_roundtrip() {
        let codes = [
            (100, StatusCode::NonAnonymous),
            (104, StatusCode::ConfigChanged),
            (110, StatusCode::SelfPresence),
            (170, StatusCode::LoggingEnabled),
            (171, StatusCode::LoggingDisabled),
            (172, StatusCode::NonAnonymousShow),
            (173, StatusCode::SemiAnonymousShow),
            (174, StatusCode::FullyAnonymousShow),
            (201, StatusCode::RoomCreated),
            (210, StatusCode::NickAssigned),
            (301, StatusCode::Banned),
            (303, StatusCode::NewNickname),
            (307, StatusCode::Kicked),
            (321, StatusCode::AffiliationLost),
            (322, StatusCode::MembersOnlyRemoval),
            (332, StatusCode::SystemShutdown),
            (333, StatusCode::Disconnected),
            (999, StatusCode::Custom(999)),
        ];

        for (num, status) in codes {
            assert_eq!(StatusCode::from_u16(num), status);
            assert_eq!(status.as_u16(), num);
            assert_eq!(status.to_string(), num.to_string());
        }
    }

    #[test]
    fn test_status_code_classifications() {
        assert!(StatusCode::Kicked.is_removal());
        assert!(StatusCode::Banned.is_removal());
        assert!(StatusCode::MembersOnlyRemoval.is_removal());
        assert!(!StatusCode::SelfPresence.is_removal());
        assert!(StatusCode::SelfPresence.is_informational());
        assert!(StatusCode::RoomCreated.is_informational());
    }
}
