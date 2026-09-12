#![forbid(unsafe_code)]

//! Capability-free XEP-0461 Message Replies wire support.
//!
//! This module validates, classifies, and serializes XEP-0461 `<reply/>`
//! elements. It performs bounded lexical wire validation on attributes and
//! treats replies strictly as typed advisory references.
//!
//! # Architecture and Boundary Policy
//!
//! This wire crate deliberately does not invent a secondary JID parser or claim
//! RFC 7622 conformance. It validates only bounded lexical wire constraints
//! (required non-empty values, length limits, absence of Unicode whitespace and control
//! characters, and XML-legal scalar values).
//!
//! The server adapter MUST pass the returned `to` target string through its canonical
//! RFC 7622 JID parser and PRECIS profiles before making routing, authorization, or
//! storage decisions.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt::{self, Write};

pub const XEP_ID: XepId = XepId::new(461);
pub const NAMESPACE: &str = "urn:xmpp:reply:0";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Message Replies",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[StanzaRoute {
        stanza: StanzaKind::Message,
        namespace: NAMESPACE,
        local_name: "reply",
    }],
};

/// A typed XEP-0461 Message Reply advisory reference.
///
/// The `to` field contains the raw target address attribute extracted from the wire.
/// The server adapter MUST parse and validate this value with its canonical RFC 7622 JID
/// authority before routing or authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageReply<'a> {
    /// The target recipient or author address attribute being referenced.
    pub to: &'a str,
    /// The target message identifier being referenced.
    pub id: &'a str,
}

impl<'a> MessageReply<'a> {
    /// Construct a new [`MessageReply`] advisory reference.
    pub const fn new(to: &'a str, id: &'a str) -> Self {
        Self { to, id }
    }

    /// The target address being referenced.
    pub const fn to(self) -> &'a str {
        self.to
    }

    /// The target message identifier being referenced.
    pub const fn id(self) -> &'a str {
        self.id
    }

    /// Routing policy classification for this message reply reference.
    pub const fn routing_policy(self) -> RoutingPolicy {
        RoutingPolicy::AdvisoryReference
    }

    /// Returns `true` since a reply is an advisory reference.
    pub const fn is_advisory_reference(self) -> bool {
        true
    }
}

/// Routing policy classification for XEP-0461 message replies.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RoutingPolicy {
    /// A reply is an advisory reference linking a message to the author and ID
    /// of a referenced previous message.
    AdvisoryReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousReply,
    ElementHasContent,
    MissingId,
    InvalidId,
    MissingTo,
    InvalidTo,
    InvalidReplyAttributes,
    UnexpectedNamespace,
    UnexpectedTagName,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousReply => {
                write!(formatter, "multiple reply elements in message")
            }
            Self::ElementHasContent => {
                write!(
                    formatter,
                    "reply element must not contain child elements or text"
                )
            }
            Self::MissingId => {
                write!(
                    formatter,
                    "reply element is missing required 'id' attribute"
                )
            }
            Self::InvalidId => {
                write!(
                    formatter,
                    "reply 'id' attribute is empty, oversized, or contains control characters"
                )
            }
            Self::MissingTo => {
                write!(
                    formatter,
                    "reply element is missing required 'to' attribute"
                )
            }
            Self::InvalidTo => {
                write!(formatter, "reply 'to' attribute is empty, oversized, or contains whitespace/control characters")
            }
            Self::InvalidReplyAttributes => {
                write!(
                    formatter,
                    "reply element contains unrecognized or namespaced attributes"
                )
            }
            Self::UnexpectedNamespace => {
                write!(
                    formatter,
                    "element namespace does not match urn:xmpp:reply:0"
                )
            }
            Self::UnexpectedTagName => {
                write!(formatter, "expected <reply> element tag name")
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

/// Validate lexical wire constraints for the `to` address attribute.
///
/// Ensures the value is non-empty, byte-bounded, and free of Unicode whitespace,
/// control codes, and XML-illegal characters. Full JID validation and PRECIS
/// canonicalization belong to the server's canonical JID authority.
fn validate_to_attribute(to: &str) -> Result<(), ()> {
    if to.is_empty() || to.len() > 1_024 {
        return Err(());
    }
    for c in to.chars() {
        if c.is_control() || c.is_whitespace() || matches!(c, '\u{FFFE}' | '\u{FFFF}') {
            return Err(());
        }
    }
    Ok(())
}

/// Parse and validate a single direct `<reply xmlns='urn:xmpp:reply:0'/>` XML element.
pub fn parse_reply_element<'a, 'input>(
    node: Node<'a, 'input>,
) -> Result<MessageReply<'a>, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.tag_name().name() != "reply" {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.children().any(|child| child.is_element())
        || node.text().is_some_and(|text| !text.trim().is_empty())
    {
        return Err(ValidationError::ElementHasContent);
    }

    let to = node.attribute("to").ok_or(ValidationError::MissingTo)?;
    validate_to_attribute(to).map_err(|()| ValidationError::InvalidTo)?;

    let id = node.attribute("id").ok_or(ValidationError::MissingId)?;
    validate_identifier(id).map_err(|()| ValidationError::InvalidId)?;

    for attribute in node.attributes() {
        if attribute.namespace().is_some() || !matches!(attribute.name(), "to" | "id") {
            return Err(ValidationError::InvalidReplyAttributes);
        }
    }

    Ok(MessageReply { to, id })
}

/// Parse and validate the direct XEP-0461 reply child of an enclosing `<message>`.
///
/// Only direct children of the message are inspected; nested payloads (e.g., inside
/// forwarded messages or encrypted containers) are ignored.
///
/// At most one `<reply/>` element is permitted per message.
pub fn parse_message<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<MessageReply<'a>>, ValidationError> {
    let replies = root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
        .collect::<Vec<_>>();

    if replies.len() > 1 {
        return Err(ValidationError::AmbiguousReply);
    }
    let Some(reply_node) = replies.into_iter().next() else {
        return Ok(None);
    };

    parse_reply_element(reply_node).map(Some)
}

/// Build an XML string for the `<reply/>` element per XEP-0461.
///
/// Both `to` and `id` are required, non-empty, and bounded. All attribute values are XML-escaped.
pub fn build_reply(to: &str, id: &str) -> Result<String, ValidationError> {
    validate_to_attribute(to).map_err(|()| ValidationError::InvalidTo)?;
    validate_identifier(id).map_err(|()| ValidationError::InvalidId)?;

    let mut xml = String::with_capacity(to.len() + id.len() + 64);
    xml.push_str("<reply xmlns='urn:xmpp:reply:0' to='");
    escape_attribute(&mut xml, to);
    xml.push_str("' id='");
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
    enum OwnedReply {
        Reply { to: String, id: String },
    }

    fn to_owned(reply: MessageReply<'_>) -> OwnedReply {
        OwnedReply::Reply {
            to: reply.to.to_owned(),
            id: reply.id.to_owned(),
        }
    }

    fn parse(xml: &str) -> Result<Option<OwnedReply>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_message(document.root_element()).map(|opt| opt.map(to_owned))
    }

    fn parse_element(xml: &str) -> Result<OwnedReply, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_reply_element(document.root_element()).map(to_owned)
    }

    #[test]
    fn parses_valid_bare_and_full_jid_replies() {
        assert_eq!(
            parse("<message id='msg-2'><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='msg-1'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "juliet@capulet.lit".to_owned(),
                id: "msg-1".to_owned()
            }))
        );
        assert_eq!(
            parse("<message id='msg-3'><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit/balcony' id='msg-1'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "juliet@capulet.lit/balcony".to_owned(),
                id: "msg-1".to_owned()
            }))
        );
        assert_eq!(
            parse("<message id='msg-4'><reply xmlns='urn:xmpp:reply:0' to='conference.domain.lit' id='msg-1'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "conference.domain.lit".to_owned(),
                id: "msg-1".to_owned()
            }))
        );
    }

    #[test]
    fn accepts_internationalized_and_address_literal_to_forms() {
        // Non-ASCII internationalized JID-shaped values
        assert_eq!(
            parse(
                "<message><reply xmlns='urn:xmpp:reply:0' to='juliet@élan.lit' id='m1'/></message>"
            ),
            Ok(Some(OwnedReply::Reply {
                to: "juliet@élan.lit".to_owned(),
                id: "m1".to_owned()
            }))
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='user@тест.example.com' id='m2'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "user@тест.example.com".to_owned(),
                id: "m2".to_owned()
            }))
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='ユーザー@ドメイン.jp/リソース' id='m3'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "ユーザー@ドメイン.jp/リソース".to_owned(),
                id: "m3".to_owned()
            }))
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='عمر@مثال.إختبار/بوابة' id='m4'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "عمر@مثال.إختبار/بوابة".to_owned(),
                id: "m4".to_owned()
            }))
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='münchen@münchen.de' id='m5'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "münchen@münchen.de".to_owned(),
                id: "m5".to_owned()
            }))
        );

        // Address-literal and complex gateway forms
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='romeo@[127.0.0.1]' id='m6'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "romeo@[127.0.0.1]".to_owned(),
                id: "m6".to_owned()
            }))
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='romeo@[IPv6:::1]' id='m7'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "romeo@[IPv6:::1]".to_owned(),
                id: "m7".to_owned()
            }))
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='room%muc.example.com@gateway.domain.org/nick' id='m8'/></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "room%muc.example.com@gateway.domain.org/nick".to_owned(),
                id: "m8".to_owned()
            }))
        );
    }

    #[test]
    fn returns_none_when_no_reply_present() {
        assert_eq!(
            parse("<message><body>No reply here</body></message>"),
            Ok(None)
        );
    }

    #[test]
    fn ignores_nested_reply_in_forwarded_payloads() {
        let xml = "<message>\
            <forwarded xmlns='urn:xmpp:forward:0'>\
                <message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='nested-id'/></message>\
            </forwarded>\
        </message>";
        assert_eq!(parse(xml), Ok(None));
    }

    #[test]
    fn rejects_ambiguous_multiple_replies() {
        assert_eq!(
            parse(
                "<message>\
                    <reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='m1'/>\
                    <reply xmlns='urn:xmpp:reply:0' to='romeo@montague.lit' id='m2'/>\
                </message>"
            ),
            Err(ValidationError::AmbiguousReply)
        );
    }

    #[test]
    fn rejects_missing_to_or_id_attribute() {
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' id='m1'/></message>"),
            Err(ValidationError::MissingTo)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit'/></message>"),
            Err(ValidationError::MissingId)
        );
    }

    #[test]
    fn rejects_invalid_id() {
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id=''/></message>"),
            Err(ValidationError::InvalidId)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='bad\x7fid'/></message>"),
            Err(ValidationError::InvalidId)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='bad\u{85}id'/></message>"),
            Err(ValidationError::InvalidId)
        );
        let oversized_id = "a".repeat(1025);
        assert_eq!(
            parse(&format!("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='{oversized_id}'/></message>")),
            Err(ValidationError::InvalidId)
        );
    }

    #[test]
    fn rejects_invalid_to_attribute() {
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='' id='m1'/></message>"),
            Err(ValidationError::InvalidTo)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit/with space' id='m1'/></message>"),
            Err(ValidationError::InvalidTo)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to=' juliet@capulet.lit' id='m1'/></message>"),
            Err(ValidationError::InvalidTo)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit ' id='m1'/></message>"),
            Err(ValidationError::InvalidTo)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit/\x7fcontrol' id='m1'/></message>"),
            Err(ValidationError::InvalidTo)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit\u{85}' id='m1'/></message>"),
            Err(ValidationError::InvalidTo)
        );
        let oversized_to = "a".repeat(1025);
        assert_eq!(
            parse(&format!(
                "<message><reply xmlns='urn:xmpp:reply:0' to='{oversized_to}' id='m1'/></message>"
            )),
            Err(ValidationError::InvalidTo)
        );
    }

    #[test]
    fn rejects_unexpected_or_namespaced_attributes() {
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='m1' extra='val'/></message>"),
            Err(ValidationError::InvalidReplyAttributes)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='m1' evil:attr='val' xmlns:evil='urn:evil'/></message>"),
            Err(ValidationError::InvalidReplyAttributes)
        );
    }

    #[test]
    fn rejects_child_elements_or_non_whitespace_content() {
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='m1'><child/></reply></message>"),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='m1'>content</reply></message>"),
            Err(ValidationError::ElementHasContent)
        );
    }

    #[test]
    fn allows_whitespace_content_within_element() {
        assert_eq!(
            parse("<message><reply xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='m1'>  \n\t  </reply></message>"),
            Ok(Some(OwnedReply::Reply {
                to: "juliet@capulet.lit".to_owned(),
                id: "m1".to_owned()
            }))
        );
    }

    #[test]
    fn rejects_unrecognized_tag_or_namespace() {
        assert_eq!(
            parse_element("<answered xmlns='urn:xmpp:reply:0' to='juliet@capulet.lit' id='m1'/>"),
            Err(ValidationError::UnexpectedTagName)
        );
        assert_eq!(
            parse_element("<reply xmlns='urn:other:ns' to='juliet@capulet.lit' id='m1'/>"),
            Err(ValidationError::UnexpectedNamespace)
        );
    }

    #[test]
    fn builder_escapes_attributes_and_round_trips() {
        let to = "juliet&co@capulet.lit";
        let id = "msg-1&<'\"";

        let xml = build_reply(to, id).expect("build reply");
        assert_eq!(
            xml,
            "<reply xmlns='urn:xmpp:reply:0' to='juliet&amp;co@capulet.lit' id='msg-1&amp;&lt;&apos;&quot;'/>"
        );
        let parsed = parse_element(&xml).expect("parse reply");
        assert_eq!(
            parsed,
            OwnedReply::Reply {
                to: to.to_owned(),
                id: id.to_owned()
            }
        );
    }

    #[test]
    fn builder_accepts_internationalized_addresses() {
        let to = "ユーザー@ドメイン.jp";
        let id = "msg-123";
        let xml = build_reply(to, id).expect("build reply");
        let parsed = parse_element(&xml).expect("parse reply");
        assert_eq!(
            parsed,
            OwnedReply::Reply {
                to: to.to_owned(),
                id: id.to_owned(),
            }
        );
    }

    #[test]
    fn builder_rejects_invalid_inputs() {
        assert_eq!(build_reply("", "m1"), Err(ValidationError::InvalidTo));
        assert_eq!(
            build_reply("juliet capulet.lit", "m1"),
            Err(ValidationError::InvalidTo)
        );
        assert_eq!(
            build_reply("juliet\t@capulet.lit", "m1"),
            Err(ValidationError::InvalidTo)
        );
        assert_eq!(
            build_reply("juliet@capulet.lit\n", "m1"),
            Err(ValidationError::InvalidTo)
        );
        assert_eq!(
            build_reply("juliet@capulet.lit\u{FFFE}", "m1"),
            Err(ValidationError::InvalidTo)
        );
        assert_eq!(
            build_reply("juliet@capulet.lit", ""),
            Err(ValidationError::InvalidId)
        );
        assert_eq!(
            build_reply("juliet@capulet.lit", "id\0null"),
            Err(ValidationError::InvalidId)
        );
        assert_eq!(
            build_reply("juliet@capulet.lit\0", "m1"),
            Err(ValidationError::InvalidTo)
        );
        let oversized_to = "a".repeat(1025);
        assert_eq!(
            build_reply(&oversized_to, "m1"),
            Err(ValidationError::InvalidTo)
        );
    }

    #[test]
    fn message_reply_classification_and_routing_policy() {
        let reply = MessageReply::new("juliet@capulet.lit", "msg-100");
        assert_eq!(reply.to(), "juliet@capulet.lit");
        assert_eq!(reply.id(), "msg-100");
        assert!(reply.is_advisory_reference());
        assert_eq!(reply.routing_policy(), RoutingPolicy::AdvisoryReference);
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Message Replies");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert!(DESCRIPTOR.conflicts.is_empty());
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 1);
        assert_eq!(DESCRIPTOR.routes[0].stanza, StanzaKind::Message);
        assert_eq!(DESCRIPTOR.routes[0].namespace, NAMESPACE);
        assert_eq!(DESCRIPTOR.routes[0].local_name, "reply");
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            ValidationError::AmbiguousReply.to_string(),
            "multiple reply elements in message"
        );
        assert_eq!(
            ValidationError::ElementHasContent.to_string(),
            "reply element must not contain child elements or text"
        );
        assert_eq!(
            ValidationError::MissingId.to_string(),
            "reply element is missing required 'id' attribute"
        );
        assert_eq!(
            ValidationError::InvalidId.to_string(),
            "reply 'id' attribute is empty, oversized, or contains control characters"
        );
        assert_eq!(
            ValidationError::MissingTo.to_string(),
            "reply element is missing required 'to' attribute"
        );
        assert_eq!(
            ValidationError::InvalidTo.to_string(),
            "reply 'to' attribute is empty, oversized, or contains whitespace/control characters"
        );
        assert_eq!(
            ValidationError::InvalidReplyAttributes.to_string(),
            "reply element contains unrecognized or namespaced attributes"
        );
        assert_eq!(
            ValidationError::UnexpectedNamespace.to_string(),
            "element namespace does not match urn:xmpp:reply:0"
        );
        assert_eq!(
            ValidationError::UnexpectedTagName.to_string(),
            "expected <reply> element tag name"
        );
    }
}
