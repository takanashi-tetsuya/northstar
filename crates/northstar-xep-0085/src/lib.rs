#![forbid(unsafe_code)]

//! Capability-free XEP-0085 Chat State Notifications wire support.
//!
//! This module validates, classifies, and serializes XEP-0085 Chat State
//! Notifications. It has no runtime, database, session, storage, or transport
//! dependencies and does not maintain global state.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt;

pub const XEP_ID: XepId = XepId::new(85);
pub const NAMESPACE: &str = "http://jabber.org/protocol/chatstates";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Chat State Notifications",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "active",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "composing",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "gone",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "inactive",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "paused",
        },
    ],
};

/// A typed chat state notification per XEP-0085 Section 5.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ChatState {
    /// User is actively participating in the chat session.
    Active,
    /// User is actively composing a message.
    Composing,
    /// User had been composing but has paused.
    Paused,
    /// User has not been active in the chat session for a brief period.
    Inactive,
    /// User has effectively ended their participation in the chat session.
    Gone,
}

impl ChatState {
    /// The XML local element name corresponding to this chat state.
    pub const fn local_name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Composing => "composing",
            Self::Paused => "paused",
            Self::Inactive => "inactive",
            Self::Gone => "gone",
        }
    }

    /// Parse a chat state from its local element name.
    pub fn from_local_name(name: &str) -> Option<Self> {
        match name {
            "active" => Some(Self::Active),
            "composing" => Some(Self::Composing),
            "paused" => Some(Self::Paused),
            "inactive" => Some(Self::Inactive),
            "gone" => Some(Self::Gone),
            _ => None,
        }
    }

    /// Routing policy classification for this chat state.
    pub const fn routing_policy(self) -> RoutingPolicy {
        RoutingPolicy::TransientCoalescing
    }

    /// Returns `true` since all chat state notifications are transient signaling.
    pub const fn is_transient(self) -> bool {
        true
    }

    /// Returns `true` since chat state notifications coalesce per conversation thread.
    pub const fn is_coalescing(self) -> bool {
        true
    }
}

impl fmt::Display for ChatState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.local_name())
    }
}

/// Routing policy classification for XEP-0085 chat states.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RoutingPolicy {
    /// Chat state notifications are transient signaling payloads that do not
    /// require durable storage on their own, and newer states coalesce or
    /// supersede older states in a conversation thread.
    TransientCoalescing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousChatState,
    ElementHasContent,
    InvalidChatStateAttributes,
    UnexpectedNamespace,
    UnexpectedTagName,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousChatState => {
                write!(formatter, "multiple chat state elements in message")
            }
            Self::ElementHasContent => {
                write!(
                    formatter,
                    "chat state element must not contain child elements or text"
                )
            }
            Self::InvalidChatStateAttributes => {
                write!(formatter, "chat state element must not contain attributes")
            }
            Self::UnexpectedNamespace => {
                write!(
                    formatter,
                    "element namespace does not match http://jabber.org/protocol/chatstates"
                )
            }
            Self::UnexpectedTagName => {
                write!(formatter, "unrecognized chat state element tag name")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Parse and validate a single direct chat state XML element.
pub fn parse_chat_state_element(node: Node<'_, '_>) -> Result<ChatState, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    let state = ChatState::from_local_name(node.tag_name().name())
        .ok_or(ValidationError::UnexpectedTagName)?;

    if node.attributes().len() != 0 {
        return Err(ValidationError::InvalidChatStateAttributes);
    }
    if node.children().any(|child| child.is_element())
        || node.text().is_some_and(|text| !text.trim().is_empty())
    {
        return Err(ValidationError::ElementHasContent);
    }

    Ok(state)
}

/// Parse and validate the direct XEP-0085 chat state child of an enclosing `<message>`.
///
/// Only direct children of the message are inspected; nested payloads (e.g., inside
/// forwarded messages or encrypted containers) are ignored.
///
/// At most one chat state element is permitted. If multiple chat state elements are found,
/// or if duplicate/mixed states are present, [`ValidationError::AmbiguousChatState`] is returned.
pub fn parse_message<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<ChatState>, ValidationError> {
    let states = root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
        .collect::<Vec<_>>();

    if states.len() > 1 {
        return Err(ValidationError::AmbiguousChatState);
    }
    let Some(state_node) = states.into_iter().next() else {
        return Ok(None);
    };

    parse_chat_state_element(state_node).map(Some)
}

/// Build an XML chat state element string for the given [`ChatState`].
pub const fn build_chat_state(state: ChatState) -> &'static str {
    match state {
        ChatState::Active => "<active xmlns='http://jabber.org/protocol/chatstates'/>",
        ChatState::Composing => "<composing xmlns='http://jabber.org/protocol/chatstates'/>",
        ChatState::Paused => "<paused xmlns='http://jabber.org/protocol/chatstates'/>",
        ChatState::Inactive => "<inactive xmlns='http://jabber.org/protocol/chatstates'/>",
        ChatState::Gone => "<gone xmlns='http://jabber.org/protocol/chatstates'/>",
    }
}

/// Build an XML string for the `<active/>` chat state.
pub const fn build_active() -> &'static str {
    build_chat_state(ChatState::Active)
}

/// Build an XML string for the `<composing/>` chat state.
pub const fn build_composing() -> &'static str {
    build_chat_state(ChatState::Composing)
}

/// Build an XML string for the `<paused/>` chat state.
pub const fn build_paused() -> &'static str {
    build_chat_state(ChatState::Paused)
}

/// Build an XML string for the `<inactive/>` chat state.
pub const fn build_inactive() -> &'static str {
    build_chat_state(ChatState::Inactive)
}

/// Build an XML string for the `<gone/>` chat state.
pub const fn build_gone() -> &'static str {
    build_chat_state(ChatState::Gone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse(xml: &str) -> Result<Option<ChatState>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_message(document.root_element())
    }

    fn parse_element(xml: &str) -> Result<ChatState, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_chat_state_element(document.root_element())
    }

    #[test]
    fn parses_all_valid_chat_states() {
        assert_eq!(
            parse("<message type='chat'><active xmlns='http://jabber.org/protocol/chatstates'/></message>"),
            Ok(Some(ChatState::Active))
        );
        assert_eq!(
            parse("<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>"),
            Ok(Some(ChatState::Composing))
        );
        assert_eq!(
            parse("<message type='chat'><paused xmlns='http://jabber.org/protocol/chatstates'/></message>"),
            Ok(Some(ChatState::Paused))
        );
        assert_eq!(
            parse("<message type='chat'><inactive xmlns='http://jabber.org/protocol/chatstates'/></message>"),
            Ok(Some(ChatState::Inactive))
        );
        assert_eq!(
            parse("<message type='chat'><gone xmlns='http://jabber.org/protocol/chatstates'/></message>"),
            Ok(Some(ChatState::Gone))
        );
    }

    #[test]
    fn allows_whitespace_content_within_element() {
        assert_eq!(
            parse_element("<active xmlns='http://jabber.org/protocol/chatstates'>  \n\t </active>"),
            Ok(ChatState::Active)
        );
    }

    #[test]
    fn returns_none_when_no_chat_state_present() {
        assert_eq!(
            parse("<message type='chat'><body>Hello world</body></message>"),
            Ok(None)
        );
    }

    #[test]
    fn ignores_nested_chat_states_in_forwarded_or_other_payloads() {
        let xml = "<message type='chat'>\
            <forwarded xmlns='urn:xmpp:forward:0'>\
                <message><composing xmlns='http://jabber.org/protocol/chatstates'/></message>\
            </forwarded>\
        </message>";
        assert_eq!(parse(xml), Ok(None));
    }

    #[test]
    fn rejects_ambiguous_duplicate_or_mixed_chat_states() {
        assert_eq!(
            parse(
                "<message type='chat'>\
                    <composing xmlns='http://jabber.org/protocol/chatstates'/>\
                    <paused xmlns='http://jabber.org/protocol/chatstates'/>\
                </message>"
            ),
            Err(ValidationError::AmbiguousChatState)
        );
        assert_eq!(
            parse(
                "<message type='chat'>\
                    <active xmlns='http://jabber.org/protocol/chatstates'/>\
                    <active xmlns='http://jabber.org/protocol/chatstates'/>\
                </message>"
            ),
            Err(ValidationError::AmbiguousChatState)
        );
    }

    #[test]
    fn rejects_attributes_on_chat_state_element() {
        assert_eq!(
            parse("<message><composing xmlns='http://jabber.org/protocol/chatstates' id='c1'/></message>"),
            Err(ValidationError::InvalidChatStateAttributes)
        );
        assert_eq!(
            parse("<message><active xmlns='http://jabber.org/protocol/chatstates' custom='val'/></message>"),
            Err(ValidationError::InvalidChatStateAttributes)
        );
    }

    #[test]
    fn rejects_child_elements_or_non_whitespace_content() {
        assert_eq!(
            parse("<message><composing xmlns='http://jabber.org/protocol/chatstates'><child/></composing></message>"),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse("<message><active xmlns='http://jabber.org/protocol/chatstates'>text content</active></message>"),
            Err(ValidationError::ElementHasContent)
        );
    }

    #[test]
    fn rejects_unrecognized_tag_or_namespace() {
        assert_eq!(
            parse_element("<unknown xmlns='http://jabber.org/protocol/chatstates'/>"),
            Err(ValidationError::UnexpectedTagName)
        );
        assert_eq!(
            parse_element("<active xmlns='urn:other:ns'/>"),
            Err(ValidationError::UnexpectedNamespace)
        );
    }

    #[test]
    fn builders_produce_exact_xml_and_round_trip() {
        for state in [
            ChatState::Active,
            ChatState::Composing,
            ChatState::Paused,
            ChatState::Inactive,
            ChatState::Gone,
        ] {
            let built = build_chat_state(state);
            let message_xml = format!("<message>{built}</message>");
            assert_eq!(parse(&message_xml), Ok(Some(state)));
            assert_eq!(parse_element(built), Ok(state));
        }

        assert_eq!(
            build_active(),
            "<active xmlns='http://jabber.org/protocol/chatstates'/>"
        );
        assert_eq!(
            build_composing(),
            "<composing xmlns='http://jabber.org/protocol/chatstates'/>"
        );
        assert_eq!(
            build_paused(),
            "<paused xmlns='http://jabber.org/protocol/chatstates'/>"
        );
        assert_eq!(
            build_inactive(),
            "<inactive xmlns='http://jabber.org/protocol/chatstates'/>"
        );
        assert_eq!(
            build_gone(),
            "<gone xmlns='http://jabber.org/protocol/chatstates'/>"
        );
    }

    #[test]
    fn classification_and_routing_policy() {
        for state in [
            ChatState::Active,
            ChatState::Composing,
            ChatState::Paused,
            ChatState::Inactive,
            ChatState::Gone,
        ] {
            assert!(state.is_transient());
            assert!(state.is_coalescing());
            assert_eq!(state.routing_policy(), RoutingPolicy::TransientCoalescing);
        }
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Chat State Notifications");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert!(DESCRIPTOR.conflicts.is_empty());
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 5);

        let mut route_names = DESCRIPTOR
            .routes
            .iter()
            .map(|route| {
                assert_eq!(route.stanza, StanzaKind::Message);
                assert_eq!(route.namespace, NAMESPACE);
                route.local_name
            })
            .collect::<Vec<_>>();
        route_names.sort();
        assert_eq!(
            route_names,
            vec!["active", "composing", "gone", "inactive", "paused"]
        );
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            ValidationError::AmbiguousChatState.to_string(),
            "multiple chat state elements in message"
        );
        assert_eq!(
            ValidationError::ElementHasContent.to_string(),
            "chat state element must not contain child elements or text"
        );
        assert_eq!(
            ValidationError::InvalidChatStateAttributes.to_string(),
            "chat state element must not contain attributes"
        );
        assert_eq!(
            ValidationError::UnexpectedNamespace.to_string(),
            "element namespace does not match http://jabber.org/protocol/chatstates"
        );
        assert_eq!(
            ValidationError::UnexpectedTagName.to_string(),
            "unrecognized chat state element tag name"
        );
    }
}
