#![forbid(unsafe_code)]

//! Capability-free XEP-0199 XMPP Ping wire support.
//!
//! The module validates and describes XMPP Ping stanzas. It does not
//! gain access to accounts, sessions, timers, persistence, or transports.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt;

pub const XEP_ID: XepId = XepId::new(199);
pub const NAMESPACE: &str = "urn:xmpp:ping";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "XMPP Ping",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[StanzaRoute {
        stanza: StanzaKind::IqGet,
        namespace: NAMESPACE,
        local_name: "ping",
    }],
};

/// A validated XEP-0199 ping request payload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PingRequest;

/// A typed XEP-0199 ping response.
///
/// Per XEP-0199 Section 2, the IQ result contains an empty child payload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PingResponse;

/// Payload string for an IQ-result responding to an XEP-0199 ping.
pub const RESPONSE_PAYLOAD: &str = "";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousPing,
    ElementHasContent,
    InvalidPingAttributes,
    UnexpectedNamespace,
    UnexpectedTagName,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousPing => write!(formatter, "multiple ping elements in stanza"),
            Self::ElementHasContent => {
                write!(
                    formatter,
                    "ping element must not have child elements or text"
                )
            }
            Self::InvalidPingAttributes => {
                write!(formatter, "ping element must not contain custom attributes")
            }
            Self::UnexpectedNamespace => {
                write!(formatter, "element namespace does not match urn:xmpp:ping")
            }
            Self::UnexpectedTagName => write!(formatter, "expected <ping> element tag"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Parse and validate a single direct `<ping xmlns='urn:xmpp:ping'/>` element.
///
/// Per XEP-0199 Section 2, the `<ping/>` element possesses no attributes and contains no child nodes.
pub fn parse_ping_element(node: Node<'_, '_>) -> Result<PingRequest, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.tag_name().name() != "ping" {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.attributes().len() != 0 {
        return Err(ValidationError::InvalidPingAttributes);
    }
    if node.children().any(|child| {
        child.is_element()
            || (child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()))
    }) {
        return Err(ValidationError::ElementHasContent);
    }
    Ok(PingRequest)
}

/// Parse and validate the XEP-0199 ping child of an enclosing stanza (e.g. an `<iq type='get'>`).
///
/// Returns `Ok(Some(PingRequest))` if a single valid `<ping/>` element is present,
/// `Ok(None)` if no elements in the `urn:xmpp:ping` namespace exist,
/// or `Err(ValidationError)` if the ping payload is malformed or ambiguous.
pub fn parse_iq<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<PingRequest>, ValidationError> {
    let mut ping = None;
    for child in root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
    {
        if ping.replace(parse_ping_element(child)?).is_some() {
            return Err(ValidationError::AmbiguousPing);
        }
    }
    Ok(ping)
}

/// Build an XEP-0199 ping request XML payload string.
pub const fn build_request() -> &'static str {
    "<ping xmlns='urn:xmpp:ping'/>"
}

/// Alias for [`build_request`].
pub const fn build_ping() -> &'static str {
    build_request()
}

/// Build an XEP-0199 ping response payload (empty string for IQ-result).
pub const fn build_response() -> &'static str {
    RESPONSE_PAYLOAD
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse_doc(xml: &str) -> Result<Option<PingRequest>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_iq(document.root_element())
    }

    fn parse_raw_element(xml: &str) -> Result<PingRequest, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_ping_element(document.root_element())
    }

    #[test]
    fn parses_valid_ping_element() {
        assert_eq!(
            parse_raw_element("<ping xmlns='urn:xmpp:ping'/>"),
            Ok(PingRequest)
        );
        assert_eq!(
            parse_raw_element("<ping xmlns='urn:xmpp:ping'></ping>"),
            Ok(PingRequest)
        );
        assert_eq!(
            parse_raw_element("<ping xmlns='urn:xmpp:ping'>   \n\t </ping>"),
            Ok(PingRequest)
        );
    }

    #[test]
    fn parses_valid_iq_ping() {
        assert_eq!(
            parse_doc(
                "<iq from='capulet.lit' to='juliet@capulet.lit/balcony' id='ping1' type='get'>\
                    <ping xmlns='urn:xmpp:ping'/>\
                 </iq>"
            ),
            Ok(Some(PingRequest))
        );
        assert_eq!(
            parse_doc("<iq type='get' id='p1'><body>other</body></iq>"),
            Ok(None)
        );
    }

    #[test]
    fn rejects_ping_with_attributes() {
        assert_eq!(
            parse_raw_element("<ping xmlns='urn:xmpp:ping' foo='bar'/>"),
            Err(ValidationError::InvalidPingAttributes)
        );
        assert_eq!(
            parse_raw_element("<ping xmlns='urn:xmpp:ping' id='p1'/>"),
            Err(ValidationError::InvalidPingAttributes)
        );
    }

    #[test]
    fn rejects_ping_with_child_elements() {
        assert_eq!(
            parse_raw_element("<ping xmlns='urn:xmpp:ping'><child/></ping>"),
            Err(ValidationError::ElementHasContent)
        );
    }

    #[test]
    fn rejects_ping_with_non_whitespace_text() {
        assert_eq!(
            parse_raw_element("<ping xmlns='urn:xmpp:ping'>data</ping>"),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse_raw_element("<ping xmlns='urn:xmpp:ping'> <!--split--> data</ping>"),
            Err(ValidationError::ElementHasContent)
        );
    }

    #[test]
    fn rejects_ambiguous_multiple_pings() {
        assert_eq!(
            parse_doc(
                "<iq type='get' id='p1'>\
                    <ping xmlns='urn:xmpp:ping'/>\
                    <ping xmlns='urn:xmpp:ping'/>\
                 </iq>"
            ),
            Err(ValidationError::AmbiguousPing)
        );
    }

    #[test]
    fn rejects_unexpected_tag_or_namespace() {
        assert_eq!(
            parse_raw_element("<pong xmlns='urn:xmpp:ping'/>"),
            Err(ValidationError::UnexpectedTagName)
        );
        assert_eq!(
            parse_raw_element("<ping xmlns='urn:other:namespace'/>"),
            Err(ValidationError::UnexpectedNamespace)
        );
    }

    #[test]
    fn builders_produce_deterministic_output() {
        assert_eq!(build_request(), "<ping xmlns='urn:xmpp:ping'/>");
        assert_eq!(build_ping(), "<ping xmlns='urn:xmpp:ping'/>");
        assert_eq!(build_response(), "");
        assert_eq!(RESPONSE_PAYLOAD, "");

        // Verify that the built ping request parses successfully
        assert_eq!(parse_raw_element(build_request()), Ok(PingRequest));
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "XMPP Ping");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 1);
        assert_eq!(DESCRIPTOR.routes[0].stanza, StanzaKind::IqGet);
        assert_eq!(DESCRIPTOR.routes[0].namespace, NAMESPACE);
        assert_eq!(DESCRIPTOR.routes[0].local_name, "ping");
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            ValidationError::AmbiguousPing.to_string(),
            "multiple ping elements in stanza"
        );
        assert_eq!(
            ValidationError::ElementHasContent.to_string(),
            "ping element must not have child elements or text"
        );
        assert_eq!(
            ValidationError::InvalidPingAttributes.to_string(),
            "ping element must not contain custom attributes"
        );
        assert_eq!(
            ValidationError::UnexpectedNamespace.to_string(),
            "element namespace does not match urn:xmpp:ping"
        );
        assert_eq!(
            ValidationError::UnexpectedTagName.to_string(),
            "expected <ping> element tag"
        );
    }
}
