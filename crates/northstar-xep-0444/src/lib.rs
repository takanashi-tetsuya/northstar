#![forbid(unsafe_code)]

//! Capability-free XEP-0444 Message Reactions wire support.
//!
//! This module validates, classifies, and serializes XEP-0444 `<reactions/>`
//! elements. It has no runtime, database, session, storage, or transport
//! dependencies, does not maintain global state, and does not invent reaction
//! aggregation or read state.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt::{self, Write};

pub const XEP_ID: XepId = XepId::new(444);
pub const NAMESPACE: &str = "urn:xmpp:reactions:0";

/// Maximum number of `<reaction>` elements permitted in a single `<reactions>` container.
pub const MAX_REACTIONS: usize = 1_024;

/// Maximum character/byte length permitted for a single reaction string.
pub const MAX_REACTION_LENGTH: usize = 4_096;

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Message Reactions",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[StanzaRoute {
        stanza: StanzaKind::Message,
        namespace: NAMESPACE,
        local_name: "reactions",
    }],
};

/// A typed XEP-0444 Message Reactions container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageReactions<'a> {
    /// The target message identifier being reacted to.
    pub id: &'a str,
    /// The ordered list of reaction strings.
    pub reactions: Vec<&'a str>,
}

impl<'a> MessageReactions<'a> {
    /// Construct a new [`MessageReactions`] container.
    pub const fn new(id: &'a str, reactions: Vec<&'a str>) -> Self {
        Self { id, reactions }
    }

    /// The target message identifier being reacted to.
    pub const fn id(&self) -> &'a str {
        self.id
    }

    /// The ordered slice of reactions.
    pub fn reactions(&self) -> &[&'a str] {
        &self.reactions
    }

    /// Returns `true` if this is an empty reaction set, which represents retraction
    /// of earlier reactions per XEP-0444 Section 3.3.
    pub fn is_retraction(&self) -> bool {
        self.reactions.is_empty()
    }

    /// Routing policy classification for this message reactions payload.
    pub const fn routing_policy(&self) -> RoutingPolicy {
        RoutingPolicy::TransientReactions
    }
}

/// Routing policy classification for XEP-0444 message reactions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RoutingPolicy {
    /// Message reactions are transient or standalone metadata signals targeting
    /// an earlier message identified by its stanza ID.
    TransientReactions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousReactions,
    ContainerHasNonWhitespaceText,
    MissingId,
    InvalidId,
    InvalidReactionsAttributes,
    UnexpectedNamespace,
    UnexpectedTagName,
    UnexpectedChildElement,
    InvalidReactionAttributes,
    ReactionHasChildElements,
    EmptyReaction,
    InvalidReactionContent,
    ExcessiveReactions,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousReactions => {
                write!(formatter, "multiple reactions containers in message")
            }
            Self::ContainerHasNonWhitespaceText => {
                write!(
                    formatter,
                    "reactions container must not contain direct text content"
                )
            }
            Self::MissingId => {
                write!(
                    formatter,
                    "reactions container is missing required 'id' attribute"
                )
            }
            Self::InvalidId => {
                write!(
                    formatter,
                    "reactions 'id' attribute is empty, oversized, or contains control characters"
                )
            }
            Self::InvalidReactionsAttributes => {
                write!(
                    formatter,
                    "reactions container contains unrecognized or namespaced attributes"
                )
            }
            Self::UnexpectedNamespace => {
                write!(
                    formatter,
                    "element namespace does not match urn:xmpp:reactions:0"
                )
            }
            Self::UnexpectedTagName => {
                write!(formatter, "expected <reactions> container tag name")
            }
            Self::UnexpectedChildElement => {
                write!(
                    formatter,
                    "reactions container contains unexpected child element"
                )
            }
            Self::InvalidReactionAttributes => {
                write!(formatter, "reaction element must not contain attributes")
            }
            Self::ReactionHasChildElements => {
                write!(
                    formatter,
                    "reaction element must not contain child elements"
                )
            }
            Self::EmptyReaction => {
                write!(formatter, "reaction element text content must not be empty")
            }
            Self::InvalidReactionContent => {
                write!(
                    formatter,
                    "reaction text content is oversized or contains control characters"
                )
            }
            Self::ExcessiveReactions => {
                write!(
                    formatter,
                    "reactions container exceeds maximum permitted reaction count"
                )
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

fn validate_reaction_str(reaction: &str) -> Result<(), ValidationError> {
    if reaction.is_empty() {
        return Err(ValidationError::EmptyReaction);
    }
    if reaction.len() > MAX_REACTION_LENGTH || reaction.chars().any(char::is_control) {
        return Err(ValidationError::InvalidReactionContent);
    }
    Ok(())
}

/// Parse and validate a single direct `<reactions xmlns='urn:xmpp:reactions:0'/>` XML element.
pub fn parse_reactions_element<'a, 'input>(
    node: Node<'a, 'input>,
) -> Result<MessageReactions<'a>, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.tag_name().name() != "reactions" {
        return Err(ValidationError::UnexpectedTagName);
    }

    let id = node.attribute("id").ok_or(ValidationError::MissingId)?;
    validate_identifier(id).map_err(|()| ValidationError::InvalidId)?;

    for attribute in node.attributes() {
        if attribute.namespace().is_some() || attribute.name() != "id" {
            return Err(ValidationError::InvalidReactionsAttributes);
        }
    }

    if node
        .children()
        .any(|child| child.is_text() && !child.text().unwrap_or_default().trim().is_empty())
    {
        return Err(ValidationError::ContainerHasNonWhitespaceText);
    }

    let mut reactions = Vec::new();
    for child in node.children().filter(|child| child.is_element()) {
        if child.tag_name().name() != "reaction" || child.tag_name().namespace() != Some(NAMESPACE)
        {
            return Err(ValidationError::UnexpectedChildElement);
        }

        if child.attributes().len() != 0 {
            return Err(ValidationError::InvalidReactionAttributes);
        }

        if child.children().any(|nested| nested.is_element()) {
            return Err(ValidationError::ReactionHasChildElements);
        }

        let reaction_text = child.text().unwrap_or("");
        validate_reaction_str(reaction_text)?;

        reactions.push(reaction_text);
        if reactions.len() > MAX_REACTIONS {
            return Err(ValidationError::ExcessiveReactions);
        }
    }

    Ok(MessageReactions { id, reactions })
}

/// Parse and validate the direct XEP-0444 reactions child of an enclosing `<message>`.
///
/// Only direct children of the message are inspected; nested payloads (e.g., inside
/// forwarded messages or encrypted containers) are ignored.
///
/// At most one `<reactions/>` container element is permitted per message.
pub fn parse_message<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<MessageReactions<'a>>, ValidationError> {
    let containers = root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
        .collect::<Vec<_>>();

    if containers.len() > 1 {
        return Err(ValidationError::AmbiguousReactions);
    }
    let Some(container_node) = containers.into_iter().next() else {
        return Ok(None);
    };

    parse_reactions_element(container_node).map(Some)
}

/// Build an XML string for the `<reactions/>` container per XEP-0444.
///
/// The `id` attribute is required, non-empty, and bounded. Reactions are preserved in order.
/// An empty reaction collection serializes to a self-closing `<reactions/>` element representing retraction.
/// All attribute and text values are XML-escaped.
pub fn build_reactions<I, S>(id: &str, reactions: I) -> Result<String, ValidationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    validate_identifier(id).map_err(|()| ValidationError::InvalidId)?;

    let mut count = 0usize;
    let mut body = String::new();
    for reaction in reactions {
        let r = reaction.as_ref();
        validate_reaction_str(r)?;
        count += 1;
        if count > MAX_REACTIONS {
            return Err(ValidationError::ExcessiveReactions);
        }
        body.push_str("<reaction>");
        escape_xml_text(&mut body, r);
        body.push_str("</reaction>");
    }

    if count == 0 {
        let mut xml = String::with_capacity(id.len() + 64);
        xml.push_str("<reactions xmlns='urn:xmpp:reactions:0' id='");
        escape_attribute(&mut xml, id);
        xml.push_str("'/>");
        return Ok(xml);
    }

    let mut xml = String::with_capacity(id.len() + body.len() + 64);
    xml.push_str("<reactions xmlns='urn:xmpp:reactions:0' id='");
    escape_attribute(&mut xml, id);
    xml.push_str("'>");
    xml.push_str(&body);
    xml.push_str("</reactions>");
    Ok(xml)
}

/// Build an XML string for a reaction retraction (`<reactions id='...'/>`) per XEP-0444 Section 3.3.
pub fn build_retraction(id: &str) -> Result<String, ValidationError> {
    build_reactions(id, std::iter::empty::<&str>())
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

fn escape_xml_text(output: &mut String, value: &str) {
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
    struct OwnedReactions {
        id: String,
        reactions: Vec<String>,
    }

    fn to_owned(reactions: MessageReactions<'_>) -> OwnedReactions {
        OwnedReactions {
            id: reactions.id.to_owned(),
            reactions: reactions.reactions.into_iter().map(str::to_owned).collect(),
        }
    }

    fn parse(xml: &str) -> Result<Option<OwnedReactions>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_message(document.root_element()).map(|opt| opt.map(to_owned))
    }

    fn parse_element(xml: &str) -> Result<OwnedReactions, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_reactions_element(document.root_element()).map(to_owned)
    }

    #[test]
    fn parses_valid_reactions_with_order_preserved() {
        let xml = "<message id='msg-2'>\
            <reactions xmlns='urn:xmpp:reactions:0' id='msg-1'>\
                <reaction>👍</reaction>\
                <reaction>❤️</reaction>\
                <reaction>🎉</reaction>\
            </reactions>\
        </message>";
        assert_eq!(
            parse(xml),
            Ok(Some(OwnedReactions {
                id: "msg-1".to_owned(),
                reactions: vec!["👍".to_owned(), "❤️".to_owned(), "🎉".to_owned()],
            }))
        );
    }

    #[test]
    fn parses_empty_reactions_set_as_retraction() {
        let self_closing =
            "<message><reactions xmlns='urn:xmpp:reactions:0' id='msg-1'/></message>";
        let parsed = parse(self_closing).expect("parse retraction");
        assert_eq!(
            parsed,
            Some(OwnedReactions {
                id: "msg-1".to_owned(),
                reactions: vec![],
            })
        );

        let explicit_empty =
            "<message><reactions xmlns='urn:xmpp:reactions:0' id='msg-1'></reactions></message>";
        let parsed_empty = parse(explicit_empty).expect("parse empty reactions");
        assert_eq!(
            parsed_empty,
            Some(OwnedReactions {
                id: "msg-1".to_owned(),
                reactions: vec![],
            })
        );
    }

    #[test]
    fn returns_none_when_no_reactions_present() {
        assert_eq!(
            parse("<message><body>Plain text</body></message>"),
            Ok(None)
        );
    }

    #[test]
    fn ignores_nested_reactions_in_forwarded_payloads() {
        let xml = "<message>\
            <forwarded xmlns='urn:xmpp:forward:0'>\
                <message><reactions xmlns='urn:xmpp:reactions:0' id='nested-id'><reaction>👍</reaction></reactions></message>\
            </forwarded>\
        </message>";
        assert_eq!(parse(xml), Ok(None));
    }

    #[test]
    fn rejects_ambiguous_multiple_reactions_containers() {
        let xml = "<message>\
            <reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>👍</reaction></reactions>\
            <reactions xmlns='urn:xmpp:reactions:0' id='m2'><reaction>❤️</reaction></reactions>\
        </message>";
        assert_eq!(parse(xml), Err(ValidationError::AmbiguousReactions));
    }

    #[test]
    fn rejects_missing_id_attribute() {
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0'><reaction>👍</reaction></reactions></message>"),
            Err(ValidationError::MissingId)
        );
    }

    #[test]
    fn rejects_invalid_id() {
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id=''><reaction>👍</reaction></reactions></message>"),
            Err(ValidationError::InvalidId)
        );
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='bad\x7fid'><reaction>👍</reaction></reactions></message>"),
            Err(ValidationError::InvalidId)
        );
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='bad\u{85}id'><reaction>👍</reaction></reactions></message>"),
            Err(ValidationError::InvalidId)
        );
        let oversized = "a".repeat(1025);
        assert_eq!(
            parse(&format!("<message><reactions xmlns='urn:xmpp:reactions:0' id='{oversized}'><reaction>👍</reaction></reactions></message>")),
            Err(ValidationError::InvalidId)
        );
    }

    #[test]
    fn rejects_unexpected_or_namespaced_attributes_on_container() {
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1' extra='val'><reaction>👍</reaction></reactions></message>"),
            Err(ValidationError::InvalidReactionsAttributes)
        );
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1' evil:attr='val' xmlns:evil='urn:evil'><reaction>👍</reaction></reactions></message>"),
            Err(ValidationError::InvalidReactionsAttributes)
        );
    }

    #[test]
    fn rejects_attributes_on_reaction_elements() {
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction custom='val'>👍</reaction></reactions></message>"),
            Err(ValidationError::InvalidReactionAttributes)
        );
    }

    #[test]
    fn rejects_unexpected_child_elements_in_container() {
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><invalid/></reactions></message>"),
            Err(ValidationError::UnexpectedChildElement)
        );
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><other xmlns='urn:other'/></reactions></message>"),
            Err(ValidationError::UnexpectedChildElement)
        );
    }

    #[test]
    fn rejects_child_elements_inside_reaction() {
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction><nested/></reaction></reactions></message>"),
            Err(ValidationError::ReactionHasChildElements)
        );
    }

    #[test]
    fn rejects_empty_or_invalid_reaction_text() {
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction></reaction></reactions></message>"),
            Err(ValidationError::EmptyReaction)
        );
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>bad\x7femoji</reaction></reactions></message>"),
            Err(ValidationError::InvalidReactionContent)
        );
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>bad\u{85}emoji</reaction></reactions></message>"),
            Err(ValidationError::InvalidReactionContent)
        );
        let oversized = "e".repeat(MAX_REACTION_LENGTH + 1);
        assert_eq!(
            parse(&format!("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>{oversized}</reaction></reactions></message>")),
            Err(ValidationError::InvalidReactionContent)
        );
    }

    #[test]
    fn rejects_container_with_non_whitespace_direct_text() {
        assert_eq!(
            parse("<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'>stray text<reaction>👍</reaction></reactions></message>"),
            Err(ValidationError::ContainerHasNonWhitespaceText)
        );
    }

    #[test]
    fn allows_container_with_whitespace_direct_text() {
        let xml = "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'>\n  <reaction>👍</reaction>\n</reactions></message>";
        assert_eq!(
            parse(xml),
            Ok(Some(OwnedReactions {
                id: "m1".to_owned(),
                reactions: vec!["👍".to_owned()],
            }))
        );
    }

    #[test]
    fn rejects_unrecognized_tag_or_namespace() {
        assert_eq!(
            parse_element("<other xmlns='urn:xmpp:reactions:0' id='m1'/>"),
            Err(ValidationError::UnexpectedTagName)
        );
        assert_eq!(
            parse_element("<reactions xmlns='urn:other:ns' id='m1'/>"),
            Err(ValidationError::UnexpectedNamespace)
        );
    }

    #[test]
    fn builders_escape_attributes_and_round_trip() {
        let id = "msg-1&<'\"";
        let reactions = ["👍&<", "rock'n'roll", "<3"];

        let xml = build_reactions(id, reactions).expect("build reactions");
        assert_eq!(
            xml,
            "<reactions xmlns='urn:xmpp:reactions:0' id='msg-1&amp;&lt;&apos;&quot;'><reaction>👍&amp;&lt;</reaction><reaction>rock&apos;n&apos;roll</reaction><reaction>&lt;3</reaction></reactions>"
        );

        let parsed = parse_element(&xml).expect("parse built reactions");
        assert_eq!(
            parsed,
            OwnedReactions {
                id: id.to_owned(),
                reactions: vec!["👍&<".to_owned(), "rock'n'roll".to_owned(), "<3".to_owned()],
            }
        );

        let retraction_xml = build_retraction(id).expect("build retraction");
        assert_eq!(
            retraction_xml,
            "<reactions xmlns='urn:xmpp:reactions:0' id='msg-1&amp;&lt;&apos;&quot;'/>"
        );
        let parsed_retraction = parse_element(&retraction_xml).expect("parse retraction");
        assert!(parsed_retraction.reactions.is_empty());
    }

    #[test]
    fn builders_reject_invalid_inputs() {
        assert_eq!(build_reactions("", ["👍"]), Err(ValidationError::InvalidId));
        assert_eq!(
            build_reactions("m1", [""]),
            Err(ValidationError::EmptyReaction)
        );
        assert_eq!(
            build_reactions("m1", ["bad\0emoji"]),
            Err(ValidationError::InvalidReactionContent)
        );

        let oversized_emoji = "a".repeat(MAX_REACTION_LENGTH + 1);
        assert_eq!(
            build_reactions("m1", [oversized_emoji.as_str()]),
            Err(ValidationError::InvalidReactionContent)
        );

        let excessive_reactions = vec!["👍"; MAX_REACTIONS + 1];
        assert_eq!(
            build_reactions("m1", &excessive_reactions),
            Err(ValidationError::ExcessiveReactions)
        );
    }

    #[test]
    fn message_reactions_classification_and_routing_policy() {
        let reactions = MessageReactions::new("msg-1", vec!["👍"]);
        assert_eq!(reactions.id(), "msg-1");
        assert_eq!(reactions.reactions(), &["👍"]);
        assert!(!reactions.is_retraction());
        assert_eq!(
            reactions.routing_policy(),
            RoutingPolicy::TransientReactions
        );

        let retraction = MessageReactions::new("msg-1", vec![]);
        assert!(retraction.is_retraction());
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Message Reactions");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert!(DESCRIPTOR.conflicts.is_empty());
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 1);
        assert_eq!(DESCRIPTOR.routes[0].stanza, StanzaKind::Message);
        assert_eq!(DESCRIPTOR.routes[0].namespace, NAMESPACE);
        assert_eq!(DESCRIPTOR.routes[0].local_name, "reactions");
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            ValidationError::AmbiguousReactions.to_string(),
            "multiple reactions containers in message"
        );
        assert_eq!(
            ValidationError::ContainerHasNonWhitespaceText.to_string(),
            "reactions container must not contain direct text content"
        );
        assert_eq!(
            ValidationError::MissingId.to_string(),
            "reactions container is missing required 'id' attribute"
        );
        assert_eq!(
            ValidationError::InvalidId.to_string(),
            "reactions 'id' attribute is empty, oversized, or contains control characters"
        );
        assert_eq!(
            ValidationError::InvalidReactionsAttributes.to_string(),
            "reactions container contains unrecognized or namespaced attributes"
        );
        assert_eq!(
            ValidationError::UnexpectedNamespace.to_string(),
            "element namespace does not match urn:xmpp:reactions:0"
        );
        assert_eq!(
            ValidationError::UnexpectedTagName.to_string(),
            "expected <reactions> container tag name"
        );
        assert_eq!(
            ValidationError::UnexpectedChildElement.to_string(),
            "reactions container contains unexpected child element"
        );
        assert_eq!(
            ValidationError::InvalidReactionAttributes.to_string(),
            "reaction element must not contain attributes"
        );
        assert_eq!(
            ValidationError::ReactionHasChildElements.to_string(),
            "reaction element must not contain child elements"
        );
        assert_eq!(
            ValidationError::EmptyReaction.to_string(),
            "reaction element text content must not be empty"
        );
        assert_eq!(
            ValidationError::InvalidReactionContent.to_string(),
            "reaction text content is oversized or contains control characters"
        );
        assert_eq!(
            ValidationError::ExcessiveReactions.to_string(),
            "reactions container exceeds maximum permitted reaction count"
        );
    }
}
