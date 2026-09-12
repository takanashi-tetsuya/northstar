#![forbid(unsafe_code)]

//! Capability-free XEP-0308 Last Message Correction wire support.
//!
//! This module validates, classifies, and serializes XEP-0308 `<replace/>`
//! elements. It has no runtime, database, session, storage, or transport
//! dependencies and does not maintain global state.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt::{self, Write};

pub const XEP_ID: XepId = XepId::new(308);
pub const NAMESPACE: &str = "urn:xmpp:message-correct:0";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Last Message Correction",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[StanzaRoute {
        stanza: StanzaKind::Message,
        namespace: NAMESPACE,
        local_name: "replace",
    }],
};

/// A typed XEP-0308 Last Message Correction reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageCorrection<'a> {
    /// The target message identifier being replaced.
    pub id: &'a str,
}

impl<'a> MessageCorrection<'a> {
    /// Construct a new [`MessageCorrection`] pointing to the target message ID.
    pub const fn new(id: &'a str) -> Self {
        Self { id }
    }

    /// The target message identifier being corrected.
    pub const fn id(self) -> &'a str {
        self.id
    }

    /// Routing policy classification for this message correction.
    pub const fn routing_policy(self) -> RoutingPolicy {
        RoutingPolicy::CorrectionMetadata
    }

    /// Returns `true` since this is a message correction payload.
    pub const fn is_correction(self) -> bool {
        true
    }
}

/// Routing policy classification for XEP-0308 message correction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RoutingPolicy {
    /// A correction replaces the logical content of an earlier message
    /// identified by its stanza ID; it accompanies message routing and durability.
    CorrectionMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousCorrection,
    ElementHasContent,
    MissingId,
    InvalidId,
    InvalidReplaceAttributes,
    UnexpectedNamespace,
    UnexpectedTagName,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousCorrection => {
                write!(formatter, "multiple replace elements in message")
            }
            Self::ElementHasContent => {
                write!(
                    formatter,
                    "replace element must not contain child elements or text"
                )
            }
            Self::MissingId => {
                write!(
                    formatter,
                    "replace element is missing required 'id' attribute"
                )
            }
            Self::InvalidId => {
                write!(
                    formatter,
                    "replace 'id' attribute is empty, oversized, or contains control characters"
                )
            }
            Self::InvalidReplaceAttributes => {
                write!(
                    formatter,
                    "replace element contains unrecognized or namespaced attributes"
                )
            }
            Self::UnexpectedNamespace => {
                write!(
                    formatter,
                    "element namespace does not match urn:xmpp:message-correct:0"
                )
            }
            Self::UnexpectedTagName => {
                write!(formatter, "expected <replace> element tag name")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

fn validate_identifier(id: &str) -> Result<(), ()> {
    if id.is_empty() || id.len() > 1_024 || id.chars().any(char::is_control) {
        Err(())
    } else {
        Ok(())
    }
}

/// Parse and validate a single direct `<replace xmlns='urn:xmpp:message-correct:0'/>` XML element.
pub fn parse_replace_element<'a, 'input>(
    node: Node<'a, 'input>,
) -> Result<MessageCorrection<'a>, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.tag_name().name() != "replace" {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.children().any(|child| child.is_element())
        || node.text().is_some_and(|text| !text.trim().is_empty())
    {
        return Err(ValidationError::ElementHasContent);
    }

    let id = node.attribute("id").ok_or(ValidationError::MissingId)?;
    validate_identifier(id).map_err(|()| ValidationError::InvalidId)?;

    for attribute in node.attributes() {
        if attribute.namespace().is_some() || attribute.name() != "id" {
            return Err(ValidationError::InvalidReplaceAttributes);
        }
    }

    Ok(MessageCorrection { id })
}

/// Parse and validate the direct XEP-0308 correction child of an enclosing `<message>`.
///
/// Only direct children of the message are inspected; nested payloads (e.g., inside
/// forwarded messages or encrypted containers) are ignored.
///
/// At most one `<replace/>` element is permitted per message.
pub fn parse_message<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<MessageCorrection<'a>>, ValidationError> {
    let replacements = root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
        .collect::<Vec<_>>();

    if replacements.len() > 1 {
        return Err(ValidationError::AmbiguousCorrection);
    }
    let Some(replace_node) = replacements.into_iter().next() else {
        return Ok(None);
    };

    parse_replace_element(replace_node).map(Some)
}

/// Build an XML string for the `<replace/>` element per XEP-0308.
///
/// The `id` attribute is required, non-empty, and bounded. All attribute values are XML-escaped.
pub fn build_replace(id: &str) -> Result<String, ValidationError> {
    validate_identifier(id).map_err(|()| ValidationError::InvalidId)?;
    let mut xml = String::with_capacity(id.len() + 64);
    xml.push_str("<replace xmlns='urn:xmpp:message-correct:0' id='");
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
    enum OwnedCorrection {
        Replace { id: String },
    }

    fn to_owned(correction: MessageCorrection<'_>) -> OwnedCorrection {
        OwnedCorrection::Replace {
            id: correction.id.to_owned(),
        }
    }

    fn parse(xml: &str) -> Result<Option<OwnedCorrection>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_message(document.root_element()).map(|opt| opt.map(to_owned))
    }

    fn parse_element(xml: &str) -> Result<OwnedCorrection, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_replace_element(document.root_element()).map(to_owned)
    }

    #[test]
    fn parses_valid_replace_element() {
        assert_eq!(
            parse("<message id='msg-2'><replace xmlns='urn:xmpp:message-correct:0' id='msg-1'/></message>"),
            Ok(Some(OwnedCorrection::Replace {
                id: "msg-1".to_owned()
            }))
        );
        assert_eq!(
            parse_element("<replace xmlns='urn:xmpp:message-correct:0' id='target-id'/>"),
            Ok(OwnedCorrection::Replace {
                id: "target-id".to_owned()
            })
        );
    }

    #[test]
    fn returns_none_when_no_replace_present() {
        assert_eq!(
            parse("<message><body>No correction here</body></message>"),
            Ok(None)
        );
    }

    #[test]
    fn ignores_nested_replace_in_forwarded_payloads() {
        let xml = "<message>\
            <forwarded xmlns='urn:xmpp:forward:0'>\
                <message><replace xmlns='urn:xmpp:message-correct:0' id='nested-id'/></message>\
            </forwarded>\
        </message>";
        assert_eq!(parse(xml), Ok(None));
    }

    #[test]
    fn rejects_ambiguous_multiple_replacements() {
        assert_eq!(
            parse(
                "<message>\
                    <replace xmlns='urn:xmpp:message-correct:0' id='m1'/>\
                    <replace xmlns='urn:xmpp:message-correct:0' id='m2'/>\
                </message>"
            ),
            Err(ValidationError::AmbiguousCorrection)
        );
    }

    #[test]
    fn rejects_missing_id_attribute() {
        assert_eq!(
            parse("<message><replace xmlns='urn:xmpp:message-correct:0'/></message>"),
            Err(ValidationError::MissingId)
        );
    }

    #[test]
    fn rejects_invalid_id() {
        assert_eq!(
            parse("<message><replace xmlns='urn:xmpp:message-correct:0' id=''/></message>"),
            Err(ValidationError::InvalidId)
        );
        assert_eq!(
            parse(
                "<message><replace xmlns='urn:xmpp:message-correct:0' id='bad\x7fid'/></message>"
            ),
            Err(ValidationError::InvalidId)
        );
        assert_eq!(
            parse(
                "<message><replace xmlns='urn:xmpp:message-correct:0' id='bad\u{85}id'/></message>"
            ),
            Err(ValidationError::InvalidId)
        );
        let oversized_id = "a".repeat(1025);
        assert_eq!(
            parse(&format!("<message><replace xmlns='urn:xmpp:message-correct:0' id='{oversized_id}'/></message>")),
            Err(ValidationError::InvalidId)
        );
    }

    #[test]
    fn rejects_unexpected_or_namespaced_attributes() {
        assert_eq!(
            parse("<message><replace xmlns='urn:xmpp:message-correct:0' id='m1' extra='val'/></message>"),
            Err(ValidationError::InvalidReplaceAttributes)
        );
        assert_eq!(
            parse("<message><replace xmlns='urn:xmpp:message-correct:0' id='m1' evil:id='m2' xmlns:evil='urn:evil'/></message>"),
            Err(ValidationError::InvalidReplaceAttributes)
        );
    }

    #[test]
    fn rejects_child_elements_or_non_whitespace_content() {
        assert_eq!(
            parse("<message><replace xmlns='urn:xmpp:message-correct:0' id='m1'><child/></replace></message>"),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse("<message><replace xmlns='urn:xmpp:message-correct:0' id='m1'>content</replace></message>"),
            Err(ValidationError::ElementHasContent)
        );
    }

    #[test]
    fn allows_whitespace_content_within_element() {
        assert_eq!(
            parse("<message><replace xmlns='urn:xmpp:message-correct:0' id='m1'>  \n\t  </replace></message>"),
            Ok(Some(OwnedCorrection::Replace {
                id: "m1".to_owned()
            }))
        );
    }

    #[test]
    fn rejects_unrecognized_tag_or_namespace() {
        assert_eq!(
            parse_element("<correct xmlns='urn:xmpp:message-correct:0' id='m1'/>"),
            Err(ValidationError::UnexpectedTagName)
        );
        assert_eq!(
            parse_element("<replace xmlns='urn:other:ns' id='m1'/>"),
            Err(ValidationError::UnexpectedNamespace)
        );
    }

    #[test]
    fn builder_escapes_attributes_and_round_trips() {
        let id = "msg-1&<'\"";
        let xml = build_replace(id).expect("build replace");
        assert_eq!(
            xml,
            "<replace xmlns='urn:xmpp:message-correct:0' id='msg-1&amp;&lt;&apos;&quot;'/>"
        );
        let parsed = parse_element(&xml).expect("parse replace");
        assert_eq!(parsed, OwnedCorrection::Replace { id: id.to_owned() });
    }

    #[test]
    fn builder_rejects_invalid_inputs() {
        assert_eq!(build_replace(""), Err(ValidationError::InvalidId));
        assert_eq!(build_replace("id\0null"), Err(ValidationError::InvalidId));
        let oversized_id = "x".repeat(1025);
        assert_eq!(
            build_replace(&oversized_id),
            Err(ValidationError::InvalidId)
        );
    }

    #[test]
    fn message_correction_classification_and_routing_policy() {
        let correction = MessageCorrection::new("msg-100");
        assert_eq!(correction.id(), "msg-100");
        assert!(correction.is_correction());
        assert_eq!(
            correction.routing_policy(),
            RoutingPolicy::CorrectionMetadata
        );
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Last Message Correction");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert!(DESCRIPTOR.conflicts.is_empty());
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 1);
        assert_eq!(DESCRIPTOR.routes[0].stanza, StanzaKind::Message);
        assert_eq!(DESCRIPTOR.routes[0].namespace, NAMESPACE);
        assert_eq!(DESCRIPTOR.routes[0].local_name, "replace");
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            ValidationError::AmbiguousCorrection.to_string(),
            "multiple replace elements in message"
        );
        assert_eq!(
            ValidationError::ElementHasContent.to_string(),
            "replace element must not contain child elements or text"
        );
        assert_eq!(
            ValidationError::MissingId.to_string(),
            "replace element is missing required 'id' attribute"
        );
        assert_eq!(
            ValidationError::InvalidId.to_string(),
            "replace 'id' attribute is empty, oversized, or contains control characters"
        );
        assert_eq!(
            ValidationError::InvalidReplaceAttributes.to_string(),
            "replace element contains unrecognized or namespaced attributes"
        );
        assert_eq!(
            ValidationError::UnexpectedNamespace.to_string(),
            "element namespace does not match urn:xmpp:message-correct:0"
        );
        assert_eq!(
            ValidationError::UnexpectedTagName.to_string(),
            "expected <replace> element tag name"
        );
    }
}
