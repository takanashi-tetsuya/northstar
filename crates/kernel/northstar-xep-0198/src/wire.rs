#![forbid(unsafe_code)]

//! Wire protocol parsing, validation, and XML builders for XEP-0198 Stream Management elements.

use roxmltree::Node;
use std::fmt::Write;

use crate::counter::SmCounter;
use crate::error::{FailedReason, WireError};

/// Canonical XML namespace for XEP-0198 Stream Management.
pub const NAMESPACE: &str = "urn:xmpp:sm:3";

/// Canonical XML namespace for RFC 6120 stanza errors.
pub const STANZA_ERROR_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";

/// Canonical XML namespace for RFC 6120 stream errors.
pub const STREAM_ERROR_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-streams";

/// Canonical XML namespace for stream framing.
pub const STREAMS_NAMESPACE: &str = "http://etherx.jabber.org/streams";

/// Maximum allowed length in bytes for a `previd` or `id` resume token string.
pub const MAX_PREVID_BYTES: usize = 256;

/// Maximum allowed length in bytes for an SM `location` URI string.
pub const MAX_LOCATION_BYTES: usize = 1024;

/// A validated `<enable xmlns='urn:xmpp:sm:3'/>` element sent by the client.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EnableElement {
    /// Whether stream resumption is requested (`resume='true'`).
    pub resume: bool,
    /// Client's preferred maximum resumption timeout in seconds (`max='...'`).
    pub max: Option<u32>,
    /// Client's preferred reconnection location (`location='...'`).
    pub location: Option<String>,
}

/// A validated `<enabled xmlns='urn:xmpp:sm:3'/>` element sent by the server.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EnabledElement {
    /// The stream resumption identifier issued by the server (`id='...'`).
    pub id: Option<String>,
    /// Whether stream resumption was granted (`resume='true'`).
    pub resume: bool,
    /// The server's maximum resumption timeout in seconds (`max='...'`).
    pub max: Option<u32>,
    /// The server's preferred reconnection location (`location='...'`).
    pub location: Option<String>,
}

/// A validated `<resume xmlns='urn:xmpp:sm:3'/>` element sent by the client.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResumeElement {
    /// The previous stream identifier (`previd='...'`).
    pub previd: String,
    /// The client's handled inbound stanza count (`h='...'`).
    pub h: SmCounter,
}

/// A validated `<resumed xmlns='urn:xmpp:sm:3'/>` element sent by the server.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResumedElement {
    /// The previous stream identifier (`previd='...'`).
    pub previd: String,
    /// The server's handled inbound stanza count (`h='...'`).
    pub h: SmCounter,
    /// Optional alternate reconnection location (`location='...'`).
    pub location: Option<String>,
}

/// A validated `<failed xmlns='urn:xmpp:sm:3'/>` element.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FailedElement {
    /// Optional handled sequence count on failure (`h='...'`).
    pub h: Option<SmCounter>,
    /// Defined RFC 6120 error condition.
    pub reason: FailedReason,
    /// Custom condition name if not a standard RFC 6120 condition.
    pub custom_condition: Option<String>,
}

/// A validated `<r xmlns='urn:xmpp:sm:3'/>` acknowledgement request element.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AckRequestElement;

/// A validated `<a xmlns='urn:xmpp:sm:3'/>` acknowledgement answer element.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AckAnswerElement {
    /// Handled inbound stanza count (`h='...'`).
    pub h: SmCounter,
}

// ---------------------------------------------------------------------------
// Wire Parsers
// ---------------------------------------------------------------------------

/// Validates that an XML node belongs to `urn:xmpp:sm:3`, contains only allowed
/// unqualified attributes, and possesses no child elements or non-whitespace text.
pub fn is_valid_sm_control(node: Node<'_, '_>, allowed_attributes: &[&str]) -> bool {
    if !node.is_element() || node.tag_name().namespace() != Some(NAMESPACE) {
        return false;
    }
    for attribute in node.attributes() {
        if attribute.namespace().is_some() || !allowed_attributes.contains(&attribute.name()) {
            return false;
        }
    }
    for child in node.children() {
        if child.is_element() {
            return false;
        }
        if child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()) {
            return false;
        }
    }
    true
}

/// Validates a resume `previd` / `id` token: non-empty, bounded, no control characters.
pub fn is_valid_previd(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PREVID_BYTES
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Validates a location URI: non-empty, bounded, no control characters or whitespace.
pub fn is_valid_location(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LOCATION_BYTES
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Parses an XML boolean string ("true" | "1" -> true, "false" | "0" -> false).
fn parse_xml_bool(value: &str, attr_name: &'static str) -> Result<bool, WireError> {
    match value.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(WireError::InvalidAttribute {
            name: attr_name,
            reason: format!("expected boolean ('true'|'false'|'1'|'0'), got '{value}'"),
        }),
    }
}

/// Parses `<enable xmlns='urn:xmpp:sm:3' .../>`.
pub fn parse_enable(node: Node<'_, '_>) -> Result<EnableElement, WireError> {
    if !node.is_element() {
        return Err(WireError::UnexpectedTagName {
            expected: "enable",
            actual: "non-element node".into(),
        });
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(WireError::UnexpectedNamespace {
            expected: NAMESPACE,
            actual: node.tag_name().namespace().map(str::to_owned),
        });
    }
    if node.tag_name().name() != "enable" {
        return Err(WireError::UnexpectedTagName {
            expected: "enable",
            actual: node.tag_name().name().into(),
        });
    }

    // Check for unknown attributes
    for attr in node.attributes() {
        if attr.namespace().is_some() || !matches!(attr.name(), "resume" | "max" | "location") {
            return Err(WireError::DisallowedAttribute(attr.name().into()));
        }
    }

    // Check for child elements or text
    for child in node.children() {
        if child.is_element() {
            return Err(WireError::UnexpectedChildElements);
        }
        if child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()) {
            return Err(WireError::UnexpectedTextContent);
        }
    }

    let resume = match node.attribute("resume") {
        Some(val) => parse_xml_bool(val, "resume")?,
        None => false,
    };

    let max = match node.attribute("max") {
        Some(val) => {
            let parsed = val
                .parse::<u32>()
                .map_err(|_| WireError::InvalidMax(val.into()))?;
            if parsed == 0 {
                return Err(WireError::InvalidMax("max must be greater than 0".into()));
            }
            Some(parsed)
        }
        None => None,
    };

    let location = match node.attribute("location") {
        Some(val) => {
            if !is_valid_location(val) {
                return Err(WireError::InvalidLocation(val.into()));
            }
            Some(val.to_owned())
        }
        None => None,
    };

    Ok(EnableElement {
        resume,
        max,
        location,
    })
}

/// Parses `<enabled xmlns='urn:xmpp:sm:3' .../>`.
pub fn parse_enabled(node: Node<'_, '_>) -> Result<EnabledElement, WireError> {
    if !node.is_element() {
        return Err(WireError::UnexpectedTagName {
            expected: "enabled",
            actual: "non-element node".into(),
        });
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(WireError::UnexpectedNamespace {
            expected: NAMESPACE,
            actual: node.tag_name().namespace().map(str::to_owned),
        });
    }
    if node.tag_name().name() != "enabled" {
        return Err(WireError::UnexpectedTagName {
            expected: "enabled",
            actual: node.tag_name().name().into(),
        });
    }

    for attr in node.attributes() {
        if attr.namespace().is_some()
            || !matches!(attr.name(), "id" | "resume" | "max" | "location")
        {
            return Err(WireError::DisallowedAttribute(attr.name().into()));
        }
    }

    for child in node.children() {
        if child.is_element() {
            return Err(WireError::UnexpectedChildElements);
        }
        if child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()) {
            return Err(WireError::UnexpectedTextContent);
        }
    }

    let id = match node.attribute("id") {
        Some(val) => {
            if !is_valid_previd(val) {
                return Err(WireError::InvalidPrevid(val.into()));
            }
            Some(val.to_owned())
        }
        None => None,
    };

    let resume = match node.attribute("resume") {
        Some(val) => parse_xml_bool(val, "resume")?,
        None => false,
    };

    let max = match node.attribute("max") {
        Some(val) => {
            let parsed = val
                .parse::<u32>()
                .map_err(|_| WireError::InvalidMax(val.into()))?;
            if parsed == 0 {
                return Err(WireError::InvalidMax("max must be greater than 0".into()));
            }
            Some(parsed)
        }
        None => None,
    };

    let location = match node.attribute("location") {
        Some(val) => {
            if !is_valid_location(val) {
                return Err(WireError::InvalidLocation(val.into()));
            }
            Some(val.to_owned())
        }
        None => None,
    };

    Ok(EnabledElement {
        id,
        resume,
        max,
        location,
    })
}

/// Parses `<resume xmlns='urn:xmpp:sm:3' previd='...' h='...'/>`.
pub fn parse_resume(node: Node<'_, '_>) -> Result<ResumeElement, WireError> {
    if !node.is_element() {
        return Err(WireError::UnexpectedTagName {
            expected: "resume",
            actual: "non-element node".into(),
        });
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(WireError::UnexpectedNamespace {
            expected: NAMESPACE,
            actual: node.tag_name().namespace().map(str::to_owned),
        });
    }
    if node.tag_name().name() != "resume" {
        return Err(WireError::UnexpectedTagName {
            expected: "resume",
            actual: node.tag_name().name().into(),
        });
    }

    for attr in node.attributes() {
        if attr.namespace().is_some() || !matches!(attr.name(), "previd" | "h") {
            return Err(WireError::DisallowedAttribute(attr.name().into()));
        }
    }

    for child in node.children() {
        if child.is_element() {
            return Err(WireError::UnexpectedChildElements);
        }
        if child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()) {
            return Err(WireError::UnexpectedTextContent);
        }
    }

    let previd = match node.attribute("previd") {
        Some(val) if is_valid_previd(val) => val.to_owned(),
        Some(val) => return Err(WireError::InvalidPrevid(val.into())),
        None => return Err(WireError::MissingRequiredAttribute("previd")),
    };

    let h = match node.attribute("h") {
        Some(val) => val
            .parse::<u32>()
            .map(SmCounter::new)
            .map_err(|_| WireError::InvalidHandledCount(val.into()))?,
        None => return Err(WireError::MissingRequiredAttribute("h")),
    };

    Ok(ResumeElement { previd, h })
}

/// Parses `<resumed xmlns='urn:xmpp:sm:3' previd='...' h='...' location='...'/>`.
pub fn parse_resumed(node: Node<'_, '_>) -> Result<ResumedElement, WireError> {
    if !node.is_element() {
        return Err(WireError::UnexpectedTagName {
            expected: "resumed",
            actual: "non-element node".into(),
        });
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(WireError::UnexpectedNamespace {
            expected: NAMESPACE,
            actual: node.tag_name().namespace().map(str::to_owned),
        });
    }
    if node.tag_name().name() != "resumed" {
        return Err(WireError::UnexpectedTagName {
            expected: "resumed",
            actual: node.tag_name().name().into(),
        });
    }

    for attr in node.attributes() {
        if attr.namespace().is_some() || !matches!(attr.name(), "previd" | "h" | "location") {
            return Err(WireError::DisallowedAttribute(attr.name().into()));
        }
    }

    for child in node.children() {
        if child.is_element() {
            return Err(WireError::UnexpectedChildElements);
        }
        if child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()) {
            return Err(WireError::UnexpectedTextContent);
        }
    }

    let previd = match node.attribute("previd") {
        Some(val) if is_valid_previd(val) => val.to_owned(),
        Some(val) => return Err(WireError::InvalidPrevid(val.into())),
        None => return Err(WireError::MissingRequiredAttribute("previd")),
    };

    let h = match node.attribute("h") {
        Some(val) => val
            .parse::<u32>()
            .map(SmCounter::new)
            .map_err(|_| WireError::InvalidHandledCount(val.into()))?,
        None => return Err(WireError::MissingRequiredAttribute("h")),
    };

    let location = match node.attribute("location") {
        Some(val) => {
            if !is_valid_location(val) {
                return Err(WireError::InvalidLocation(val.into()));
            }
            Some(val.to_owned())
        }
        None => None,
    };

    Ok(ResumedElement {
        previd,
        h,
        location,
    })
}

/// Parses `<failed xmlns='urn:xmpp:sm:3' h='...'>...error...</failed>`.
pub fn parse_failed(node: Node<'_, '_>) -> Result<FailedElement, WireError> {
    if !node.is_element() {
        return Err(WireError::UnexpectedTagName {
            expected: "failed",
            actual: "non-element node".into(),
        });
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(WireError::UnexpectedNamespace {
            expected: NAMESPACE,
            actual: node.tag_name().namespace().map(str::to_owned),
        });
    }
    if node.tag_name().name() != "failed" {
        return Err(WireError::UnexpectedTagName {
            expected: "failed",
            actual: node.tag_name().name().into(),
        });
    }

    for attr in node.attributes() {
        if attr.namespace().is_some() || attr.name() != "h" {
            return Err(WireError::DisallowedAttribute(attr.name().into()));
        }
    }

    let h = match node.attribute("h") {
        Some(val) => Some(
            val.parse::<u32>()
                .map(SmCounter::new)
                .map_err(|_| WireError::InvalidHandledCount(val.into()))?,
        ),
        None => None,
    };

    let error_child = node
        .children()
        .find(|c| c.is_element())
        .ok_or(WireError::MissingFailedCondition)?;

    let (reason, custom_condition) =
        match FailedReason::from_str_name(error_child.tag_name().name()) {
            Some(reason) => (reason, None),
            None => (
                FailedReason::UndefinedCondition,
                Some(error_child.tag_name().name().to_owned()),
            ),
        };

    Ok(FailedElement {
        h,
        reason,
        custom_condition,
    })
}

/// Parses `<r xmlns='urn:xmpp:sm:3'/>`.
pub fn parse_r(node: Node<'_, '_>) -> Result<AckRequestElement, WireError> {
    if !is_valid_sm_control(node, &[]) {
        if !node.is_element() {
            return Err(WireError::UnexpectedTagName {
                expected: "r",
                actual: "non-element node".into(),
            });
        }
        if node.tag_name().namespace() != Some(NAMESPACE) {
            return Err(WireError::UnexpectedNamespace {
                expected: NAMESPACE,
                actual: node.tag_name().namespace().map(str::to_owned),
            });
        }
        if node.tag_name().name() != "r" {
            return Err(WireError::UnexpectedTagName {
                expected: "r",
                actual: node.tag_name().name().into(),
            });
        }
        if node.attributes().len() != 0 {
            return Err(WireError::DisallowedAttribute(
                node.attributes().next().unwrap().name().into(),
            ));
        }
        return Err(WireError::UnexpectedChildElements);
    }
    if node.tag_name().name() != "r" {
        return Err(WireError::UnexpectedTagName {
            expected: "r",
            actual: node.tag_name().name().into(),
        });
    }
    Ok(AckRequestElement)
}

/// Parses `<a xmlns='urn:xmpp:sm:3' h='...'/>`.
pub fn parse_a(node: Node<'_, '_>) -> Result<AckAnswerElement, WireError> {
    if !is_valid_sm_control(node, &["h"]) {
        if !node.is_element() {
            return Err(WireError::UnexpectedTagName {
                expected: "a",
                actual: "non-element node".into(),
            });
        }
        if node.tag_name().namespace() != Some(NAMESPACE) {
            return Err(WireError::UnexpectedNamespace {
                expected: NAMESPACE,
                actual: node.tag_name().namespace().map(str::to_owned),
            });
        }
        if node.tag_name().name() != "a" {
            return Err(WireError::UnexpectedTagName {
                expected: "a",
                actual: node.tag_name().name().into(),
            });
        }
        for attr in node.attributes() {
            if attr.name() != "h" || attr.namespace().is_some() {
                return Err(WireError::DisallowedAttribute(attr.name().into()));
            }
        }
        return Err(WireError::UnexpectedChildElements);
    }
    if node.tag_name().name() != "a" {
        return Err(WireError::UnexpectedTagName {
            expected: "a",
            actual: node.tag_name().name().into(),
        });
    }
    let h = match node.attribute("h") {
        Some(val) => val
            .parse::<u32>()
            .map(SmCounter::new)
            .map_err(|_| WireError::InvalidHandledCount(val.into()))?,
        None => return Err(WireError::MissingRequiredAttribute("h")),
    };
    Ok(AckAnswerElement { h })
}

// ---------------------------------------------------------------------------
// XML Builders
// ---------------------------------------------------------------------------

/// XML attribute escaping helper.
fn escape_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Builds an `<enable xmlns='urn:xmpp:sm:3'/>` string.
pub fn build_enable(resume: bool, max: Option<u32>, location: Option<&str>) -> String {
    let mut out = String::from("<enable xmlns='urn:xmpp:sm:3'");
    if resume {
        out.push_str(" resume='true'");
    }
    if let Some(max_secs) = max {
        let _ = write!(out, " max='{max_secs}'");
    }
    if let Some(loc) = location {
        let _ = write!(out, " location='{}'", escape_attr(loc));
    }
    out.push_str("/>");
    out
}

/// Builds an `<enabled xmlns='urn:xmpp:sm:3'/>` string.
pub fn build_enabled(
    id: Option<&str>,
    resume: bool,
    max: Option<u32>,
    location: Option<&str>,
) -> String {
    let mut out = String::from("<enabled xmlns='urn:xmpp:sm:3'");
    if let Some(id_str) = id {
        let _ = write!(out, " id='{}'", escape_attr(id_str));
    }
    if resume {
        out.push_str(" resume='true'");
    } else {
        out.push_str(" resume='false'");
    }
    if let Some(max_secs) = max {
        let _ = write!(out, " max='{max_secs}'");
    }
    if let Some(loc) = location {
        let _ = write!(out, " location='{}'", escape_attr(loc));
    }
    out.push_str("/>");
    out
}

/// Builds a `<resume xmlns='urn:xmpp:sm:3' previd='...' h='...'/>` string.
pub fn build_resume(previd: &str, h: u32) -> String {
    format!(
        "<resume xmlns='urn:xmpp:sm:3' previd='{}' h='{h}'/>",
        escape_attr(previd)
    )
}

/// Builds a `<resumed xmlns='urn:xmpp:sm:3' previd='...' h='...'/>` string.
pub fn build_resumed(previd: &str, h: u32, location: Option<&str>) -> String {
    match location {
        Some(loc) => format!(
            "<resumed xmlns='urn:xmpp:sm:3' previd='{}' h='{h}' location='{}'/>",
            escape_attr(previd),
            escape_attr(loc)
        ),
        None => format!(
            "<resumed xmlns='urn:xmpp:sm:3' previd='{}' h='{h}'/>",
            escape_attr(previd)
        ),
    }
}

/// Builds a `<failed xmlns='urn:xmpp:sm:3'>...error...</failed>` string.
pub fn build_failed(reason: FailedReason, h: Option<u32>) -> String {
    reason.build_failed_element(h)
}

/// Builds a `<failed xmlns='urn:xmpp:sm:3'>` string with a given stanza error condition name.
pub fn build_failed_str(condition_name: &str) -> String {
    FailedReason::from_str_name(condition_name)
        .unwrap_or(FailedReason::UndefinedCondition)
        .build_failed_element(None)
}

/// Builds an `<r xmlns='urn:xmpp:sm:3'/>` string.
pub const fn build_r() -> &'static str {
    "<r xmlns='urn:xmpp:sm:3'/>"
}

/// Builds an `<a xmlns='urn:xmpp:sm:3' h='...'/>` string.
pub fn build_a(h: u32) -> String {
    format!("<a xmlns='urn:xmpp:sm:3' h='{h}'/>")
}

/// Builds the standard terminal stream error `<stream:error>` for `handled-count-too-high`
/// per XEP-0198 Section 6.
pub fn build_handled_count_too_high_stream_error(received: u32, sent: u32) -> String {
    format!(
        "<stream:error xmlns:stream='http://etherx.jabber.org/streams'>\
            <undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>\
            <handled-count-too-high xmlns='urn:xmpp:sm:3' h='{received}' send-count='{sent}'/>\
        </stream:error>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn parse_valid_enable_variants() {
        let doc = Document::parse("<enable xmlns='urn:xmpp:sm:3'/>").unwrap();
        let enable = parse_enable(doc.root_element()).unwrap();
        assert_eq!(
            enable,
            EnableElement {
                resume: false,
                max: None,
                location: None,
            }
        );

        let doc =
            Document::parse("<enable xmlns='urn:xmpp:sm:3' resume='true' max='60'/>").unwrap();
        let enable = parse_enable(doc.root_element()).unwrap();
        assert_eq!(
            enable,
            EnableElement {
                resume: true,
                max: Some(60),
                location: None,
            }
        );

        let doc = Document::parse(
            "<enable xmlns='urn:xmpp:sm:3' resume='1' max='300' location='backup.example.com'/>",
        )
        .unwrap();
        let enable = parse_enable(doc.root_element()).unwrap();
        assert_eq!(
            enable,
            EnableElement {
                resume: true,
                max: Some(300),
                location: Some("backup.example.com".into()),
            }
        );
    }

    #[test]
    fn parse_enable_rejects_invalid() {
        // Disallowed attribute
        let doc = Document::parse("<enable xmlns='urn:xmpp:sm:3' foo='bar'/>").unwrap();
        assert!(matches!(
            parse_enable(doc.root_element()),
            Err(WireError::DisallowedAttribute(_))
        ));

        // Child element
        let doc = Document::parse("<enable xmlns='urn:xmpp:sm:3'><child/></enable>").unwrap();
        assert!(matches!(
            parse_enable(doc.root_element()),
            Err(WireError::UnexpectedChildElements)
        ));

        // Wrong namespace
        let doc = Document::parse("<enable xmlns='wrong:namespace'/>").unwrap();
        assert!(matches!(
            parse_enable(doc.root_element()),
            Err(WireError::UnexpectedNamespace { .. })
        ));

        // Max is zero
        let doc = Document::parse("<enable xmlns='urn:xmpp:sm:3' max='0'/>").unwrap();
        assert!(matches!(
            parse_enable(doc.root_element()),
            Err(WireError::InvalidMax(_))
        ));
    }

    #[test]
    fn parse_valid_resume_and_resumed() {
        let doc =
            Document::parse("<resume xmlns='urn:xmpp:sm:3' previd='tok123' h='42'/>").unwrap();
        let resume = parse_resume(doc.root_element()).unwrap();
        assert_eq!(
            resume,
            ResumeElement {
                previd: "tok123".into(),
                h: SmCounter::new(42),
            }
        );

        let doc = Document::parse(
            "<resumed xmlns='urn:xmpp:sm:3' previd='tok123' h='42' location='backup.lit'/>",
        )
        .unwrap();
        let resumed = parse_resumed(doc.root_element()).unwrap();
        assert_eq!(
            resumed,
            ResumedElement {
                previd: "tok123".into(),
                h: SmCounter::new(42),
                location: Some("backup.lit".into()),
            }
        );
    }

    #[test]
    fn parse_valid_ack_r_and_a() {
        let doc = Document::parse("<r xmlns='urn:xmpp:sm:3'/>").unwrap();
        assert_eq!(parse_r(doc.root_element()), Ok(AckRequestElement));

        let doc = Document::parse("<a xmlns='urn:xmpp:sm:3' h='12345'/>").unwrap();
        assert_eq!(
            parse_a(doc.root_element()),
            Ok(AckAnswerElement {
                h: SmCounter::new(12345)
            })
        );
    }

    #[test]
    fn parse_ack_rejects_malformed() {
        // <r> with attribute
        let doc = Document::parse("<r xmlns='urn:xmpp:sm:3' foo='bar'/>").unwrap();
        assert!(parse_r(doc.root_element()).is_err());

        // <a> without h
        let doc = Document::parse("<a xmlns='urn:xmpp:sm:3'/>").unwrap();
        assert!(parse_a(doc.root_element()).is_err());

        // <a> with child
        let doc = Document::parse("<a xmlns='urn:xmpp:sm:3' h='1'><child/></a>").unwrap();
        assert!(parse_a(doc.root_element()).is_err());
    }

    #[test]
    fn parse_failed_element() {
        let doc = Document::parse(
            "<failed xmlns='urn:xmpp:sm:3'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>",
        )
        .unwrap();
        let failed = parse_failed(doc.root_element()).unwrap();
        assert_eq!(
            failed,
            FailedElement {
                h: None,
                reason: FailedReason::ItemNotFound,
                custom_condition: None,
            }
        );

        let doc = Document::parse(
            "<failed xmlns='urn:xmpp:sm:3' h='10'><unexpected-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>",
        )
        .unwrap();
        let failed = parse_failed(doc.root_element()).unwrap();
        assert_eq!(
            failed,
            FailedElement {
                h: Some(SmCounter::new(10)),
                reason: FailedReason::UnexpectedRequest,
                custom_condition: None,
            }
        );
    }

    #[test]
    fn builders_roundtrip() {
        let enable_xml = build_enable(true, Some(300), Some("xmpp.example.org"));
        let doc = Document::parse(&enable_xml).unwrap();
        let parsed_enable = parse_enable(doc.root_element()).unwrap();
        assert!(parsed_enable.resume);
        assert_eq!(parsed_enable.max, Some(300));
        assert_eq!(parsed_enable.location.as_deref(), Some("xmpp.example.org"));

        let enabled_xml = build_enabled(Some("bearer123"), true, Some(60), None);
        let doc = Document::parse(&enabled_xml).unwrap();
        let parsed_enabled = parse_enabled(doc.root_element()).unwrap();
        assert_eq!(parsed_enabled.id.as_deref(), Some("bearer123"));
        assert!(parsed_enabled.resume);
        assert_eq!(parsed_enabled.max, Some(60));

        let resume_xml = build_resume("tok456", 77);
        let doc = Document::parse(&resume_xml).unwrap();
        let parsed_resume = parse_resume(doc.root_element()).unwrap();
        assert_eq!(parsed_resume.previd, "tok456");
        assert_eq!(parsed_resume.h.get(), 77);

        let resumed_xml = build_resumed("tok456", 77, Some("alt.host"));
        let doc = Document::parse(&resumed_xml).unwrap();
        let parsed_resumed = parse_resumed(doc.root_element()).unwrap();
        assert_eq!(parsed_resumed.previd, "tok456");
        assert_eq!(parsed_resumed.h.get(), 77);
        assert_eq!(parsed_resumed.location.as_deref(), Some("alt.host"));

        let r_xml = build_r();
        let doc = Document::parse(r_xml).unwrap();
        assert_eq!(parse_r(doc.root_element()), Ok(AckRequestElement));

        let a_xml = build_a(99);
        let doc = Document::parse(&a_xml).unwrap();
        assert_eq!(
            parse_a(doc.root_element()),
            Ok(AckAnswerElement {
                h: SmCounter::new(99)
            })
        );
    }

    #[test]
    fn handled_count_too_high_stream_error_format() {
        let err_xml = build_handled_count_too_high_stream_error(15, 10);
        let doc = Document::parse(&err_xml).unwrap();
        let root = doc.root_element();
        assert_eq!(root.tag_name().name(), "error");
        assert_eq!(
            root.tag_name().namespace(),
            Some("http://etherx.jabber.org/streams")
        );
        let handled_too_high = root
            .children()
            .find(|c| c.tag_name().name() == "handled-count-too-high")
            .unwrap();
        assert_eq!(handled_too_high.attribute("h"), Some("15"));
        assert_eq!(handled_too_high.attribute("send-count"), Some("10"));
    }
}
