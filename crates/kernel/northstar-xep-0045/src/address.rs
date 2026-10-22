//! XEP-0045 Wire-level MUC Addresses, Room Names, and Occupant Nicknames.
//!
//! This module provides capability-free wire address models and PRECIS/RFC 7622
//! validation without replacing the server's canonical JID authority.

#![forbid(unsafe_code)]

use northstar_xmpp_types::{
    prepare_domainpart, prepare_localpart, prepare_resourcepart, CanonicalJid,
};
use std::fmt;
use thiserror::Error;

/// Maximum length of a MUC room name localpart in bytes.
pub const MAX_ROOM_NAME_BYTES: usize = 255;

/// Maximum length of a MUC occupant nickname in bytes.
pub const MAX_OCCUPANT_NICK_BYTES: usize = 128;

/// Errors arising during MUC address parsing or validation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AddressError {
    /// Room localpart is empty or exceeds length limits.
    #[error("room name must contain 1 to {MAX_ROOM_NAME_BYTES} bytes")]
    InvalidRoomLength,

    /// Room localpart contains disallowed characters (whitespace, quotes, control chars, delimiters).
    #[error("room name contains invalid characters")]
    InvalidRoomCharacters,

    /// Room localpart fails PRECIS UsernameCaseMapped preparation.
    #[error("room name failed RFC 7622 PRECIS preparation")]
    InvalidRoomPreparation,

    /// Occupant nickname is empty or exceeds length limits.
    #[error("occupant nick must contain 1 to {MAX_OCCUPANT_NICK_BYTES} bytes")]
    InvalidNickLength,

    /// Occupant nickname contains disallowed control characters or fails PRECIS OpaqueString profile.
    #[error("occupant nick contains invalid characters or failed PRECIS preparation")]
    InvalidNickCharacters,

    /// JID structure is malformed or missing required components.
    #[error("MUC JID is malformed")]
    MalformedJid,

    /// MUC occupant JID is missing resourcepart (nickname).
    #[error("MUC occupant JID must include a nickname resourcepart")]
    MissingNicknameResource,

    /// MUC domainpart does not match expected service domain.
    #[error("MUC JID domain does not match expected conference service")]
    DomainMismatch,
}

/// A validated, normalized MUC room name (localpart).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RoomName(String);

impl RoomName {
    /// Parse and validate a room name localpart.
    ///
    /// Validates length (1..=255 bytes), checks for disallowed characters
    /// (`"`, `&`, `'`, `/`, `:`, `<`, `>`, `@`, `\0`, whitespace), and verifies
    /// PRECIS localpart compliance.
    pub fn parse(value: &str) -> Result<Self, AddressError> {
        if value.is_empty() || value.len() > MAX_ROOM_NAME_BYTES {
            return Err(AddressError::InvalidRoomLength);
        }
        if value.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, '"' | '&' | '\'' | '/' | ':' | '<' | '>' | '@' | '\0')
        }) {
            return Err(AddressError::InvalidRoomCharacters);
        }
        let prepared =
            prepare_localpart(value).map_err(|_| AddressError::InvalidRoomPreparation)?;
        Ok(Self(prepared))
    }

    /// Return the room name string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RoomName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoomName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated, PRECIS-prepared MUC occupant nickname (resourcepart).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OccupantNick(String);

impl OccupantNick {
    /// Parse and prepare a MUC occupant nickname.
    ///
    /// MUC nicknames preserve case using the RFC 8265 PRECIS `OpaqueString`
    /// profile and must not contain ASCII control characters.
    pub fn parse(value: &str) -> Result<Self, AddressError> {
        if value.is_empty() || value.len() > MAX_OCCUPANT_NICK_BYTES {
            return Err(AddressError::InvalidNickLength);
        }
        if value.chars().any(char::is_control) {
            return Err(AddressError::InvalidNickCharacters);
        }
        let prepared =
            prepare_resourcepart(value).map_err(|_| AddressError::InvalidNickCharacters)?;
        Ok(Self(prepared))
    }

    /// Return the prepared nickname string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for OccupantNick {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OccupantNick {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A strictly validated bare MUC Room JID (`room@conference.example.org`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MucRoomJid {
    room: RoomName,
    domain: String,
    bare_jid: String,
}

impl MucRoomJid {
    /// Parse a bare MUC room JID from a string.
    pub fn parse(value: &str) -> Result<Self, AddressError> {
        let canonical = CanonicalJid::parse(value).map_err(|_| AddressError::MalformedJid)?;
        let local = canonical.localpart().ok_or(AddressError::MalformedJid)?;
        let room = RoomName::parse(local)?;
        let domain = canonical.domainpart().to_owned();
        let bare_jid = format!("{}@{}", room.as_str(), domain);
        Ok(Self {
            room,
            domain,
            bare_jid,
        })
    }

    /// Parse a room JID and verify that its domain matches an expected conference service domain.
    pub fn parse_for_service(value: &str, expected_domain: &str) -> Result<Self, AddressError> {
        let parsed = Self::parse(value)?;
        let expected_domain =
            prepare_domainpart(expected_domain).map_err(|_| AddressError::DomainMismatch)?;
        if parsed.domain != expected_domain {
            return Err(AddressError::DomainMismatch);
        }
        Ok(parsed)
    }

    /// Construct a room JID from an existing `RoomName` and prepared service domain.
    pub fn from_parts(room: RoomName, service_domain: &str) -> Result<Self, AddressError> {
        let domain =
            prepare_domainpart(service_domain).map_err(|_| AddressError::DomainMismatch)?;
        let bare_jid = format!("{}@{}", room.as_str(), domain);
        Ok(Self {
            room,
            domain,
            bare_jid,
        })
    }

    /// The room name (localpart).
    pub fn room_name(&self) -> &RoomName {
        &self.room
    }

    /// The conference service domain.
    pub fn service_domain(&self) -> &str {
        &self.domain
    }

    /// Canonical bare JID string (`room@domain`).
    pub fn as_str(&self) -> &str {
        &self.bare_jid
    }
}

impl AsRef<str> for MucRoomJid {
    fn as_ref(&self) -> &str {
        &self.bare_jid
    }
}

impl fmt::Display for MucRoomJid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bare_jid)
    }
}

/// A strictly validated full MUC Occupant JID (`room@conference.example.org/nickname`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MucOccupantJid {
    room: MucRoomJid,
    nick: OccupantNick,
    full_jid: String,
}

impl MucOccupantJid {
    /// Parse a full MUC occupant JID from a string.
    pub fn parse(value: &str) -> Result<Self, AddressError> {
        let canonical = CanonicalJid::parse(value).map_err(|_| AddressError::MalformedJid)?;
        let local = canonical.localpart().ok_or(AddressError::MalformedJid)?;
        let resource = canonical
            .resourcepart()
            .ok_or(AddressError::MissingNicknameResource)?;
        let room_name = RoomName::parse(local)?;
        let nick = OccupantNick::parse(resource)?;
        let room = MucRoomJid::from_parts(room_name, canonical.domainpart())?;
        let full_jid = format!("{}/{}", room.as_str(), nick.as_str());
        Ok(Self {
            room,
            nick,
            full_jid,
        })
    }

    /// Construct an occupant JID from a `MucRoomJid` and `OccupantNick`.
    pub fn from_parts(room: MucRoomJid, nick: OccupantNick) -> Self {
        let full_jid = format!("{}/{}", room.as_str(), nick.as_str());
        Self {
            room,
            nick,
            full_jid,
        }
    }

    /// The room JID of the occupant.
    pub fn room(&self) -> &MucRoomJid {
        &self.room
    }

    /// The occupant's nickname.
    pub fn nick(&self) -> &OccupantNick {
        &self.nick
    }

    /// Canonical full JID string (`room@domain/nick`).
    pub fn as_str(&self) -> &str {
        &self.full_jid
    }
}

impl AsRef<str> for MucOccupantJid {
    fn as_ref(&self) -> &str {
        &self.full_jid
    }
}

impl fmt::Display for MucOccupantJid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.full_jid)
    }
}

/// Compute the canonical occupant map key `room_jid/nick`.
pub fn occupant_key(room_jid: &str, nick: &str) -> Result<String, AddressError> {
    let canonical = CanonicalJid::parse(room_jid).map_err(|_| AddressError::MalformedJid)?;
    let room_bare = canonical.bare();
    let nick = OccupantNick::parse(nick)?;
    Ok(format!("{}/{}", room_bare, nick.as_str()))
}

/// Check if a string is a valid MUC room localpart.
pub fn is_valid_room_name(value: &str) -> bool {
    RoomName::parse(value).is_ok()
}

/// Check if a string is a valid MUC occupant nickname.
pub fn is_valid_occupant_nick(value: &str) -> bool {
    OccupantNick::parse(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_room_name() {
        assert!(is_valid_room_name("general"));
        assert!(is_valid_room_name("dev-team_2026"));
        assert!(is_valid_room_name("cafe"));

        // Invalid room names
        assert!(!is_valid_room_name(""));
        assert!(!is_valid_room_name("bad name"));
        assert!(!is_valid_room_name("bad@room"));
        assert!(!is_valid_room_name("bad/room"));
        assert!(!is_valid_room_name("bad:room"));
        assert!(!is_valid_room_name("bad<room>"));
        assert!(!is_valid_room_name("bad\"room"));
        assert!(!is_valid_room_name("bad\'room"));
        assert!(!is_valid_room_name("bad&room"));
        assert!(!is_valid_room_name(&"a".repeat(256)));
    }

    #[test]
    fn test_valid_occupant_nick() {
        assert!(is_valid_occupant_nick("Alice"));
        assert!(is_valid_occupant_nick("Bob Smith"));
        assert!(is_valid_occupant_nick("User/123"));
        assert!(is_valid_occupant_nick("user@somewhere"));

        // Invalid occupant nicks
        assert!(!is_valid_occupant_nick(""));
        assert!(!is_valid_occupant_nick("bad\u{0007}nick"));
        assert!(!is_valid_occupant_nick("bad\u{0000}nick"));
        assert!(!is_valid_occupant_nick(&"a".repeat(129)));
    }

    #[test]
    fn test_muc_room_jid() {
        let room_jid = MucRoomJid::parse("general@conference.example.org").unwrap();
        assert_eq!(room_jid.room_name().as_str(), "general");
        assert_eq!(room_jid.service_domain(), "conference.example.org");
        assert_eq!(room_jid.as_str(), "general@conference.example.org");
        assert_eq!(room_jid.to_string(), "general@conference.example.org");

        assert!(MucRoomJid::parse_for_service(
            "general@conference.example.org",
            "conference.example.org"
        )
        .is_ok());
        assert_eq!(
            MucRoomJid::parse_for_service("general@other.example.org", "conference.example.org"),
            Err(AddressError::DomainMismatch)
        );
    }

    #[test]
    fn test_muc_occupant_jid() {
        let occupant_jid = MucOccupantJid::parse("general@conference.example.org/Alice").unwrap();
        assert_eq!(
            occupant_jid.room().as_str(),
            "general@conference.example.org"
        );
        assert_eq!(occupant_jid.nick().as_str(), "Alice");
        assert_eq!(
            occupant_jid.as_str(),
            "general@conference.example.org/Alice"
        );

        // Missing resource fails
        assert_eq!(
            MucOccupantJid::parse("general@conference.example.org"),
            Err(AddressError::MissingNicknameResource)
        );
    }

    #[test]
    fn test_occupant_key() {
        assert_eq!(
            occupant_key("general@conference.example.org", "Alice").unwrap(),
            "general@conference.example.org/Alice"
        );
        assert_eq!(
            occupant_key("GENERAL@conference.example.org/resource", "Alice").unwrap(),
            "general@conference.example.org/Alice"
        );
    }
}
