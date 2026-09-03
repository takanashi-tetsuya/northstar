#![forbid(unsafe_code)]

//! Capability-free XEP-0333 Chat Markers wire support.
//!
//! This module validates, classifies, and serializes XEP-0333 Chat Markers
//! (`<markable/>`, `<received/>`, `<displayed/>`, `<acknowledged/>`). It has no
//! runtime, database, session, storage, or transport dependencies, does not maintain
//! global state, and never invents server read state.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt::{self, Write};

pub const XEP_ID: XepId = XepId::new(333);
pub const NAMESPACE: &str = "urn:xmpp:chat-markers:0";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Chat Markers",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "acknowledged",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "displayed",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "markable",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "received",
        },
    ],
};

/// A typed chat marker per XEP-0333.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChatMarker<'a> {
    /// Sender indicates that the message may be marked by the recipient.
    Markable,
    /// Recipient has received the message.
    Received { id: &'a str },
    /// Recipient has displayed the message / read marker.
    Displayed { id: &'a str },
    /// Recipient has acknowledged the message.
    Acknowledged { id: &'a str },
}

impl<'a> ChatMarker<'a> {
    /// The XML local element name corresponding to this marker.
    pub const fn local_name(self) -> &'static str {
        match self {
            Self::Markable => "markable",
            Self::Received { .. } => "received",
            Self::Displayed { .. } => "displayed",
            Self::Acknowledged { .. } => "acknowledged",
        }
    }

    /// The target message identifier being marked, if this is a marker signal.
    pub const fn id(self) -> Option<&'a str> {
        match self {
            Self::Markable => None,
            Self::Received { id } | Self::Displayed { id } | Self::Acknowledged { id } => Some(id),
        }
    }

    /// Returns `true` if this is a `<markable/>` request.
    pub const fn is_markable(self) -> bool {
        matches!(self, Self::Markable)
    }

    /// Returns `true` if this is a `<displayed/>` read-marker signal.
    pub const fn is_read_marker(self) -> bool {
        matches!(self, Self::Displayed { .. })
    }

    /// Returns `true` if this is an end-to-end transient signaling marker
    /// (`received`, `displayed`, or `acknowledged`).
    pub const fn is_transient_signal(self) -> bool {
        matches!(
            self,
            Self::Received { .. } | Self::Displayed { .. } | Self::Acknowledged { .. }
        )
    }

    /// Routing policy classification for this chat marker.
    pub const fn routing_policy(self) -> RoutingPolicy {
        match self {
            Self::Markable => RoutingPolicy::MarkableRequest,
            Self::Received { .. } => RoutingPolicy::TransientReceived,
            Self::Displayed { .. } => RoutingPolicy::TransientReadMarker,
            Self::Acknowledged { .. } => RoutingPolicy::TransientAcknowledged,
        }
    }
}

/// Routing policy classification for XEP-0333 chat markers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RoutingPolicy {
    /// A markable element requests chat markers from the recipient; it accompanies
    /// normal message routing and durability.
    MarkableRequest,
    /// A received marker confirms delivery to the client; it is transient end-to-end signaling.
    TransientReceived,
    /// A displayed marker signals the message was read/displayed; it is transient read-marker routing.
    TransientReadMarker,
    /// An acknowledged marker signals user acceptance/interaction; it is transient acknowledgement.
    TransientAcknowledged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousMarker,
    ElementHasContent,
    InvalidMarkableAttributes,
    MissingId,
    InvalidId,
    InvalidMarkerAttributes,
    UnexpectedNamespace,
    UnexpectedTagName,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousMarker => write!(formatter, "multiple chat marker elements in message"),
            Self::ElementHasContent => {
                write!(
                    formatter,
                    "chat marker element must not contain child elements or text"
                )
            }
            Self::InvalidMarkableAttributes => {
                write!(formatter, "markable element must not contain attributes")
            }
            Self::MissingId => write!(
                formatter,
                "marker element is missing required 'id' attribute"
            ),
            Self::InvalidId => {
                write!(
                    formatter,
                    "marker 'id' attribute is empty, oversized, or contains control characters"
                )
            }
            Self::InvalidMarkerAttributes => {
                write!(
                    formatter,
                    "marker element contains unrecognized or namespaced attributes"
                )
            }
            Self::UnexpectedNamespace => {
                write!(
                    formatter,
                    "element namespace does not match urn:xmpp:chat-markers:0"
                )
            }
            Self::UnexpectedTagName => {
                write!(formatter, "unrecognized chat marker element tag name")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

fn validate_identifier(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        Err(())
    } else {
        Ok(())
    }
}

/// Parse and validate a single direct chat marker XML element.
pub fn parse_chat_marker_element<'a, 'input>(
    node: Node<'a, 'input>,
) -> Result<ChatMarker<'a>, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.children().any(|child| child.is_element())
        || node.text().is_some_and(|text| !text.trim().is_empty())
    {
        return Err(ValidationError::ElementHasContent);
    }

    match node.tag_name().name() {
        "markable" => {
            if node.attributes().len() != 0 {
                return Err(ValidationError::InvalidMarkableAttributes);
            }
            Ok(ChatMarker::Markable)
        }
        "received" | "displayed" | "acknowledged" => {
            let id = node.attribute("id").ok_or(ValidationError::MissingId)?;
            validate_identifier(id).map_err(|()| ValidationError::InvalidId)?;

            if node.attributes().len() != 1
                || node
                    .attributes()
                    .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
            {
                return Err(ValidationError::InvalidMarkerAttributes);
            }

            match node.tag_name().name() {
                "received" => Ok(ChatMarker::Received { id }),
                "displayed" => Ok(ChatMarker::Displayed { id }),
                "acknowledged" => Ok(ChatMarker::Acknowledged { id }),
                _ => unreachable!(),
            }
        }
        _ => Err(ValidationError::UnexpectedTagName),
    }
}

/// Parse and validate the direct XEP-0333 chat marker child of an enclosing `<message>`.
///
/// Only direct children of the message are inspected; nested payloads (e.g., inside
/// forwarded messages or encrypted containers) are ignored.
///
/// At most one chat marker element is permitted per message.
pub fn parse_message<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<ChatMarker<'a>>, ValidationError> {
    let markers = root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
        .collect::<Vec<_>>();

    if markers.len() > 1 {
        return Err(ValidationError::AmbiguousMarker);
    }
    let Some(marker_node) = markers.into_iter().next() else {
        return Ok(None);
    };

    parse_chat_marker_element(marker_node).map(Some)
}

/// Build an XML string for the `<markable/>` element.
pub const fn build_markable() -> &'static str {
    "<markable xmlns='urn:xmpp:chat-markers:0'/>"
}

/// Build an XML string for the `<received/>` marker element.
pub fn build_received(id: &str) -> Result<String, ValidationError> {
    build_marker_with_id("received", id)
}

/// Build an XML string for the `<displayed/>` marker element.
pub fn build_displayed(id: &str) -> Result<String, ValidationError> {
    build_marker_with_id("displayed", id)
}

/// Build an XML string for the `<acknowledged/>` marker element.
pub fn build_acknowledged(id: &str) -> Result<String, ValidationError> {
    build_marker_with_id("acknowledged", id)
}

fn build_marker_with_id(tag: &str, id: &str) -> Result<String, ValidationError> {
    validate_identifier(id).map_err(|()| ValidationError::InvalidId)?;
    let mut xml = String::with_capacity(tag.len() * 2 + id.len() + 48);
    xml.push('<');
    xml.push_str(tag);
    xml.push_str(" xmlns='urn:xmpp:chat-markers:0' id='");
    escape_attribute(&mut xml, id);
    xml.push_str("'/>");
    Ok(xml)
}

fn escape_attribute(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            character => {
                let _ = output.write_char(character);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[derive(Debug, Eq, PartialEq)]
    enum OwnedMarker {
        Markable,
        Received { id: String },
        Displayed { id: String },
        Acknowledged { id: String },
    }

    fn to_owned(marker: ChatMarker<'_>) -> OwnedMarker {
        match marker {
            ChatMarker::Markable => OwnedMarker::Markable,
            ChatMarker::Received { id } => OwnedMarker::Received { id: id.to_owned() },
            ChatMarker::Displayed { id } => OwnedMarker::Displayed { id: id.to_owned() },
            ChatMarker::Acknowledged { id } => OwnedMarker::Acknowledged { id: id.to_owned() },
        }
    }

    fn parse(xml: &str) -> Result<Option<OwnedMarker>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_message(document.root_element()).map(|opt| opt.map(to_owned))
    }

    fn parse_element(xml: &str) -> Result<OwnedMarker, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_chat_marker_element(document.root_element()).map(to_owned)
    }

    #[test]
    fn parses_all_valid_chat_markers() {
        assert_eq!(
            parse("<message><markable xmlns='urn:xmpp:chat-markers:0'/></message>"),
            Ok(Some(OwnedMarker::Markable))
        );
        assert_eq!(
            parse("<message><received xmlns='urn:xmpp:chat-markers:0' id='msg-1'/></message>"),
            Ok(Some(OwnedMarker::Received {
                id: "msg-1".to_owned(),
            }))
        );
        assert_eq!(
            parse("<message><displayed xmlns='urn:xmpp:chat-markers:0' id='msg-2'/></message>"),
            Ok(Some(OwnedMarker::Displayed {
                id: "msg-2".to_owned(),
            }))
        );
        assert_eq!(
            parse("<message><acknowledged xmlns='urn:xmpp:chat-markers:0' id='msg-3'/></message>"),
            Ok(Some(OwnedMarker::Acknowledged {
                id: "msg-3".to_owned(),
            }))
        );
    }

    #[test]
    fn returns_none_when_no_marker_present() {
        assert_eq!(parse("<message><body>Just text</body></message>"), Ok(None));
    }

    #[test]
    fn ignores_nested_markers_in_forwarded_payloads() {
        let xml = "<message>\
            <forwarded xmlns='urn:xmpp:forward:0'>\
                <message><displayed xmlns='urn:xmpp:chat-markers:0' id='nested-1'/></message>\
            </forwarded>\
        </message>";
        assert_eq!(parse(xml), Ok(None));
    }

    #[test]
    fn rejects_ambiguous_multiple_markers() {
        assert_eq!(
            parse(
                "<message>\
                    <markable xmlns='urn:xmpp:chat-markers:0'/>\
                    <received xmlns='urn:xmpp:chat-markers:0' id='m1'/>\
                </message>"
            ),
            Err(ValidationError::AmbiguousMarker)
        );
        assert_eq!(
            parse(
                "<message>\
                    <received xmlns='urn:xmpp:chat-markers:0' id='m1'/>\
                    <displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/>\
                </message>"
            ),
            Err(ValidationError::AmbiguousMarker)
        );
    }

    #[test]
    fn rejects_attributes_on_markable() {
        assert_eq!(
            parse("<message><markable xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>"),
            Err(ValidationError::InvalidMarkableAttributes)
        );
        assert_eq!(
            parse("<message><markable xmlns='urn:xmpp:chat-markers:0' extra='val'/></message>"),
            Err(ValidationError::InvalidMarkableAttributes)
        );
    }

    #[test]
    fn rejects_missing_or_invalid_id_on_markers() {
        assert_eq!(
            parse("<message><received xmlns='urn:xmpp:chat-markers:0'/></message>"),
            Err(ValidationError::MissingId)
        );
        assert_eq!(
            parse("<message><displayed xmlns='urn:xmpp:chat-markers:0' id=''/></message>"),
            Err(ValidationError::InvalidId)
        );
        assert_eq!(
            parse(
                "<message><acknowledged xmlns='urn:xmpp:chat-markers:0' id='bad\x7fid'/></message>"
            ),
            Err(ValidationError::InvalidId)
        );
        let oversized_id = "a".repeat(1025);
        assert_eq!(
            parse(&format!("<message><received xmlns='urn:xmpp:chat-markers:0' id='{oversized_id}'/></message>")),
            Err(ValidationError::InvalidId)
        );
    }

    #[test]
    fn rejects_extra_or_namespaced_attributes() {
        assert_eq!(
            parse("<message><received xmlns='urn:xmpp:chat-markers:0' id='m1' thread='t1'/></message>"),
            Err(ValidationError::InvalidMarkerAttributes)
        );
        assert_eq!(
            parse("<message><received xmlns='urn:xmpp:chat-markers:0' id='m1' extra='val'/></message>"),
            Err(ValidationError::InvalidMarkerAttributes)
        );
        assert_eq!(
            parse("<message><received xmlns='urn:xmpp:chat-markers:0' id='m1' evil:id='m2' xmlns:evil='urn:evil'/></message>"),
            Err(ValidationError::InvalidMarkerAttributes)
        );
    }

    #[test]
    fn rejects_child_elements_or_non_whitespace_content() {
        assert_eq!(
            parse(
                "<message><markable xmlns='urn:xmpp:chat-markers:0'><child/></markable></message>"
            ),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse("<message><received xmlns='urn:xmpp:chat-markers:0' id='m1'>content</received></message>"),
            Err(ValidationError::ElementHasContent)
        );
    }

    #[test]
    fn rejects_unrecognized_tag_or_namespace() {
        assert_eq!(
            parse_element("<unknown xmlns='urn:xmpp:chat-markers:0'/>"),
            Err(ValidationError::UnexpectedTagName)
        );
        assert_eq!(
            parse_element("<markable xmlns='urn:other:ns'/>"),
            Err(ValidationError::UnexpectedNamespace)
        );
    }

    #[test]
    fn builders_escape_attributes_and_round_trip() {
        assert_eq!(
            build_markable(),
            "<markable xmlns='urn:xmpp:chat-markers:0'/>"
        );

        let id = "msg-1&<'\"";

        let received_xml = build_received(id).expect("build received");
        assert_eq!(
            received_xml,
            "<received xmlns='urn:xmpp:chat-markers:0' id='msg-1&amp;&lt;&apos;&quot;'/>"
        );
        let parsed = parse_element(&received_xml).expect("parse received");
        assert_eq!(parsed, OwnedMarker::Received { id: id.to_owned() });

        let displayed_xml = build_displayed(id).expect("build displayed");
        assert_eq!(
            displayed_xml,
            "<displayed xmlns='urn:xmpp:chat-markers:0' id='msg-1&amp;&lt;&apos;&quot;'/>"
        );
        let parsed = parse_element(&displayed_xml).expect("parse displayed");
        assert_eq!(parsed, OwnedMarker::Displayed { id: id.to_owned() });

        let ack_xml = build_acknowledged(id).expect("build acknowledged");
        assert_eq!(
            ack_xml,
            "<acknowledged xmlns='urn:xmpp:chat-markers:0' id='msg-1&amp;&lt;&apos;&quot;'/>"
        );
        let parsed = parse_element(&ack_xml).expect("parse acknowledged");
        assert_eq!(parsed, OwnedMarker::Acknowledged { id: id.to_owned() });
    }

    #[test]
    fn builder_rejects_invalid_inputs() {
        assert_eq!(build_received(""), Err(ValidationError::InvalidId));
        assert_eq!(build_displayed(""), Err(ValidationError::InvalidId));
        assert_eq!(
            build_acknowledged("valid\0id"),
            Err(ValidationError::InvalidId)
        );
    }

    #[test]
    fn marker_classification_and_routing_policy() {
        let markable = ChatMarker::Markable;
        assert!(markable.is_markable());
        assert!(!markable.is_read_marker());
        assert!(!markable.is_transient_signal());
        assert_eq!(markable.routing_policy(), RoutingPolicy::MarkableRequest);
        assert_eq!(markable.id(), None);

        let received = ChatMarker::Received { id: "m1" };
        assert!(!received.is_markable());
        assert!(!received.is_read_marker());
        assert!(received.is_transient_signal());
        assert_eq!(received.routing_policy(), RoutingPolicy::TransientReceived);
        assert_eq!(received.id(), Some("m1"));

        let displayed = ChatMarker::Displayed { id: "m1" };
        assert!(!displayed.is_markable());
        assert!(displayed.is_read_marker());
        assert!(displayed.is_transient_signal());
        assert_eq!(
            displayed.routing_policy(),
            RoutingPolicy::TransientReadMarker
        );
        assert_eq!(displayed.id(), Some("m1"));

        let ack = ChatMarker::Acknowledged { id: "m1" };
        assert!(!ack.is_markable());
        assert!(!ack.is_read_marker());
        assert!(ack.is_transient_signal());
        assert_eq!(ack.routing_policy(), RoutingPolicy::TransientAcknowledged);
        assert_eq!(ack.id(), Some("m1"));
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Chat Markers");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert!(DESCRIPTOR.conflicts.is_empty());
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 4);

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
            vec!["acknowledged", "displayed", "markable", "received"]
        );
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            ValidationError::AmbiguousMarker.to_string(),
            "multiple chat marker elements in message"
        );
        assert_eq!(
            ValidationError::ElementHasContent.to_string(),
            "chat marker element must not contain child elements or text"
        );
        assert_eq!(
            ValidationError::InvalidMarkableAttributes.to_string(),
            "markable element must not contain attributes"
        );
        assert_eq!(
            ValidationError::MissingId.to_string(),
            "marker element is missing required 'id' attribute"
        );
        assert_eq!(
            ValidationError::InvalidId.to_string(),
            "marker 'id' attribute is empty, oversized, or contains control characters"
        );
        assert_eq!(
            ValidationError::InvalidMarkerAttributes.to_string(),
            "marker element contains unrecognized or namespaced attributes"
        );
        assert_eq!(
            ValidationError::UnexpectedNamespace.to_string(),
            "element namespace does not match urn:xmpp:chat-markers:0"
        );
        assert_eq!(
            ValidationError::UnexpectedTagName.to_string(),
            "unrecognized chat marker element tag name"
        );
    }
}
