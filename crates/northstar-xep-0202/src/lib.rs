#![forbid(unsafe_code)]

//! Capability-free XEP-0202 Entity Time wire support.
//!
//! The module validates and describes XEP-0202 Entity Time stanzas. It does not
//! gain access to system clocks, accounts, sessions, persistence, or transports.
//! All time and timezone offset values are provided explicitly by the caller.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt::{self, Write};

pub const XEP_ID: XepId = XepId::new(202);
pub const NAMESPACE: &str = "urn:xmpp:time";

/// Default time zone offset for UTC (+00:00).
pub const DEFAULT_TZO: &str = "+00:00";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Entity Time",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[StanzaRoute {
        stanza: StanzaKind::IqGet,
        namespace: NAMESPACE,
        local_name: "time",
    }],
};

/// A validated XEP-0202 entity time query request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimeRequest;

/// A typed, capability-free representation of entity time values.
///
/// Per XEP-0202:
/// - `tzo`: Time zone offset in the format `[+|-]HH:MM` (e.g. `+00:00` or `-05:00`). `Z` is forbidden.
/// - `utc`: UTC timestamp formatted according to the dateTime profile of RFC 3339 / XSD
///   (e.g. `CCYY-MM-DDThh:mm:ssZ` or `2026-09-02T15:25:08Z`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntityTime<'a> {
    pub tzo: &'a str,
    pub utc: &'a str,
}

impl<'a> EntityTime<'a> {
    /// Construct a new [`EntityTime`] with validation.
    pub fn new(tzo: &'a str, utc: &'a str) -> Result<Self, ValidationError> {
        validate_tzo(tzo)?;
        validate_utc(utc)?;
        Ok(Self { tzo, utc })
    }

    /// Construct a new [`EntityTime`] using the default UTC offset (`+00:00`).
    pub fn utc_only(utc: &'a str) -> Result<Self, ValidationError> {
        Self::new(DEFAULT_TZO, utc)
    }
}

/// An owned representation of entity time values parsed from an incoming response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedEntityTime {
    pub tzo: String,
    pub utc: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousTime,
    ElementHasContent,
    InvalidTimeAttributes,
    UnexpectedNamespace,
    UnexpectedTagName,
    MissingTzo,
    MissingUtc,
    DuplicateTzo,
    DuplicateUtc,
    InvalidTzoFormat,
    InvalidUtcFormat,
    UnexpectedChildElement,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousTime => write!(formatter, "multiple time elements in stanza"),
            Self::ElementHasContent => {
                write!(
                    formatter,
                    "time request must not have child elements or text"
                )
            }
            Self::InvalidTimeAttributes => {
                write!(formatter, "time element must not contain custom attributes")
            }
            Self::UnexpectedNamespace => {
                write!(formatter, "element namespace does not match urn:xmpp:time")
            }
            Self::UnexpectedTagName => write!(formatter, "expected <time> element tag"),
            Self::MissingTzo => write!(formatter, "missing required <tzo> child element"),
            Self::MissingUtc => write!(formatter, "missing required <utc> child element"),
            Self::DuplicateTzo => write!(formatter, "duplicate <tzo> element found in response"),
            Self::DuplicateUtc => write!(formatter, "duplicate <utc> element found in response"),
            Self::InvalidTzoFormat => write!(
                formatter,
                "invalid time zone offset format, expected [+|-]HH:MM"
            ),
            Self::InvalidUtcFormat => {
                write!(
                    formatter,
                    "invalid UTC timestamp format, expected RFC 3339 CCYY-MM-DDThh:mm:ssZ"
                )
            }
            Self::UnexpectedChildElement => {
                write!(formatter, "unexpected child element in <time> payload")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate the format of a time zone offset (`[+|-]HH:MM`).
pub fn validate_tzo(tzo: &str) -> Result<(), ValidationError> {
    let bytes = tzo.as_bytes();
    if bytes.len() != 6 {
        return Err(ValidationError::InvalidTzoFormat);
    }
    if bytes[0] != b'+' && bytes[0] != b'-' {
        return Err(ValidationError::InvalidTzoFormat);
    }
    if !bytes[1].is_ascii_digit() || !bytes[2].is_ascii_digit() {
        return Err(ValidationError::InvalidTzoFormat);
    }
    if bytes[3] != b':' {
        return Err(ValidationError::InvalidTzoFormat);
    }
    if !bytes[4].is_ascii_digit() || !bytes[5].is_ascii_digit() {
        return Err(ValidationError::InvalidTzoFormat);
    }

    let hours = (bytes[1] - b'0') * 10 + (bytes[2] - b'0');
    let minutes = (bytes[4] - b'0') * 10 + (bytes[5] - b'0');

    // XEP-0082 defers to XML Schema dateTime. Its timezone interval is
    // bounded to +/-14:00, and an offset at the boundary cannot carry minutes.
    if hours > 14 || minutes > 59 || (hours == 14 && minutes != 0) {
        return Err(ValidationError::InvalidTzoFormat);
    }

    Ok(())
}

/// Validate the format of an RFC 3339 / XSD dateTime UTC timestamp (`CCYY-MM-DDThh:mm:ssZ`).
pub fn validate_utc(utc: &str) -> Result<(), ValidationError> {
    let bytes = utc.as_bytes();
    // Minimum length for `YYYY-MM-DDTHH:MM:SSZ` is 20
    if bytes.len() < 20 || bytes.len() > 64 {
        return Err(ValidationError::InvalidUtcFormat);
    }
    if !utc.ends_with('Z') {
        return Err(ValidationError::InvalidUtcFormat);
    }
    // Year YYYY
    for &b in &bytes[0..4] {
        if !b.is_ascii_digit() {
            return Err(ValidationError::InvalidUtcFormat);
        }
    }
    let year = parse_two(bytes[0], bytes[1]) as u16 * 100 + parse_two(bytes[2], bytes[3]) as u16;
    if year == 0 {
        return Err(ValidationError::InvalidUtcFormat);
    }
    if bytes[4] != b'-' {
        return Err(ValidationError::InvalidUtcFormat);
    }
    // Month MM
    if !bytes[5].is_ascii_digit() || !bytes[6].is_ascii_digit() {
        return Err(ValidationError::InvalidUtcFormat);
    }
    let month = (bytes[5] - b'0') * 10 + (bytes[6] - b'0');
    if !(1..=12).contains(&month) {
        return Err(ValidationError::InvalidUtcFormat);
    }
    if bytes[7] != b'-' {
        return Err(ValidationError::InvalidUtcFormat);
    }
    // Day DD
    if !bytes[8].is_ascii_digit() || !bytes[9].is_ascii_digit() {
        return Err(ValidationError::InvalidUtcFormat);
    }
    let day = (bytes[8] - b'0') * 10 + (bytes[9] - b'0');
    let max_day = match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=max_day).contains(&day) {
        return Err(ValidationError::InvalidUtcFormat);
    }
    // Separator T
    if bytes[10] != b'T' {
        return Err(ValidationError::InvalidUtcFormat);
    }
    // Hour HH
    if !bytes[11].is_ascii_digit() || !bytes[12].is_ascii_digit() {
        return Err(ValidationError::InvalidUtcFormat);
    }
    let hour = (bytes[11] - b'0') * 10 + (bytes[12] - b'0');
    if hour > 23 {
        return Err(ValidationError::InvalidUtcFormat);
    }
    if bytes[13] != b':' {
        return Err(ValidationError::InvalidUtcFormat);
    }
    // Minute MM
    if !bytes[14].is_ascii_digit() || !bytes[15].is_ascii_digit() {
        return Err(ValidationError::InvalidUtcFormat);
    }
    let minute = (bytes[14] - b'0') * 10 + (bytes[15] - b'0');
    if minute > 59 {
        return Err(ValidationError::InvalidUtcFormat);
    }
    if bytes[16] != b':' {
        return Err(ValidationError::InvalidUtcFormat);
    }
    // Second SS
    if !bytes[17].is_ascii_digit() || !bytes[18].is_ascii_digit() {
        return Err(ValidationError::InvalidUtcFormat);
    }
    let second = (bytes[17] - b'0') * 10 + (bytes[18] - b'0');
    if second > 59 {
        return Err(ValidationError::InvalidUtcFormat);
    }

    // Optional fractional seconds: .sss
    if bytes.len() > 20 {
        if bytes[19] != b'.' || bytes.len() == 21 {
            return Err(ValidationError::InvalidUtcFormat);
        }
        for &b in &bytes[20..bytes.len() - 1] {
            if !b.is_ascii_digit() {
                return Err(ValidationError::InvalidUtcFormat);
            }
        }
    }

    Ok(())
}

const fn parse_two(tens: u8, ones: u8) -> u8 {
    (tens - b'0') * 10 + (ones - b'0')
}

const fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Parse and validate a single direct `<time xmlns='urn:xmpp:time'/>` request element.
pub fn parse_time_request_element(node: Node<'_, '_>) -> Result<TimeRequest, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.tag_name().name() != "time" {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.attributes().len() != 0 {
        return Err(ValidationError::InvalidTimeAttributes);
    }
    if node.children().any(|child| {
        child.is_element()
            || (child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()))
    }) {
        return Err(ValidationError::ElementHasContent);
    }
    Ok(TimeRequest)
}

/// Parse and validate the XEP-0202 time child of an enclosing stanza (e.g. an `<iq type='get'>`).
///
/// Returns `Ok(Some(TimeRequest))` if a single valid `<time/>` request element is present,
/// `Ok(None)` if no elements in the `urn:xmpp:time` namespace exist,
/// or `Err(ValidationError)` if the request is malformed or ambiguous.
pub fn parse_iq<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<TimeRequest>, ValidationError> {
    let mut time = None;
    for child in root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
    {
        if time.replace(parse_time_request_element(child)?).is_some() {
            return Err(ValidationError::AmbiguousTime);
        }
    }
    Ok(time)
}

/// Parse and validate an XEP-0202 `<time xmlns='urn:xmpp:time'>` response element.
pub fn parse_time_response_element<'a, 'input>(
    node: Node<'a, 'input>,
) -> Result<OwnedEntityTime, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.tag_name().name() != "time" {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.attributes().len() != 0 {
        return Err(ValidationError::InvalidTimeAttributes);
    }
    if node
        .children()
        .any(|child| child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err(ValidationError::UnexpectedChildElement);
    }

    let mut tzo: Option<String> = None;
    let mut utc: Option<String> = None;

    for child in node.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "tzo" => {
                if tzo.is_some() {
                    return Err(ValidationError::DuplicateTzo);
                }
                let text = field_text(child)?;
                validate_tzo(&text)?;
                tzo = Some(text);
            }
            "utc" => {
                if utc.is_some() {
                    return Err(ValidationError::DuplicateUtc);
                }
                let text = field_text(child)?;
                validate_utc(&text)?;
                utc = Some(text);
            }
            _ => return Err(ValidationError::UnexpectedChildElement),
        }
    }

    let tzo = tzo.ok_or(ValidationError::MissingTzo)?;
    let utc = utc.ok_or(ValidationError::MissingUtc)?;

    Ok(OwnedEntityTime { tzo, utc })
}

fn field_text(node: Node<'_, '_>) -> Result<String, ValidationError> {
    if node.tag_name().namespace() != Some(NAMESPACE)
        || node.attributes().len() != 0
        || node.children().any(|nested| nested.is_element())
    {
        return Err(ValidationError::UnexpectedChildElement);
    }
    Ok(node
        .children()
        .filter_map(|child| child.is_text().then(|| child.text()).flatten())
        .collect())
}

/// Build an XEP-0202 time query request XML payload string.
pub const fn build_request() -> &'static str {
    "<time xmlns='urn:xmpp:time'/>"
}

/// Build an XEP-0202 time response XML payload string from typed [`EntityTime`].
pub fn build_response(time: &EntityTime<'_>) -> Result<String, ValidationError> {
    validate_tzo(time.tzo)?;
    validate_utc(time.utc)?;

    let mut output = String::with_capacity(64 + time.tzo.len() + time.utc.len());
    output.push_str("<time xmlns='urn:xmpp:time'><tzo>");
    escape_xml_text(&mut output, time.tzo);
    output.push_str("</tzo><utc>");
    escape_xml_text(&mut output, time.utc);
    output.push_str("</utc></time>");
    Ok(output)
}

/// Build an XEP-0202 time response XML payload string from raw offset and timestamp strings.
pub fn build_response_from_parts(tzo: &str, utc: &str) -> Result<String, ValidationError> {
    let entity_time = EntityTime::new(tzo, utc)?;
    build_response(&entity_time)
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

    fn parse_doc(xml: &str) -> Result<Option<TimeRequest>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_iq(document.root_element())
    }

    fn parse_raw_element(xml: &str) -> Result<TimeRequest, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_time_request_element(document.root_element())
    }

    fn parse_response(xml: &str) -> Result<OwnedEntityTime, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_time_response_element(document.root_element())
    }

    #[test]
    fn parses_valid_time_request() {
        assert_eq!(
            parse_raw_element("<time xmlns='urn:xmpp:time'/>"),
            Ok(TimeRequest)
        );
        assert_eq!(
            parse_doc(
                "<iq type='get' id='time1' from='a@example.com' to='b@example.com'>\
                    <time xmlns='urn:xmpp:time'/>\
                 </iq>"
            ),
            Ok(Some(TimeRequest))
        );
        assert_eq!(
            parse_doc("<iq type='get' id='time1'><body>other</body></iq>"),
            Ok(None)
        );
    }

    #[test]
    fn rejects_malformed_time_requests() {
        assert_eq!(
            parse_raw_element("<time xmlns='urn:xmpp:time' attr='val'/>"),
            Err(ValidationError::InvalidTimeAttributes)
        );
        assert_eq!(
            parse_raw_element("<time xmlns='urn:xmpp:time'><sub/></time>"),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse_raw_element("<time xmlns='urn:xmpp:time'>text</time>"),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse_raw_element("<other xmlns='urn:xmpp:time'/>"),
            Err(ValidationError::UnexpectedTagName)
        );
        assert_eq!(
            parse_raw_element("<time xmlns='urn:wrong:ns'/>"),
            Err(ValidationError::UnexpectedNamespace)
        );
        assert_eq!(
            parse_doc(
                "<iq type='get' id='t1'>\
                    <time xmlns='urn:xmpp:time'/>\
                    <time xmlns='urn:xmpp:time'/>\
                 </iq>"
            ),
            Err(ValidationError::AmbiguousTime)
        );
    }

    #[test]
    fn validates_tzo_formats() {
        assert_eq!(validate_tzo("+00:00"), Ok(()));
        assert_eq!(validate_tzo("-05:00"), Ok(()));
        assert_eq!(validate_tzo("+05:30"), Ok(()));
        assert_eq!(validate_tzo("-11:00"), Ok(()));
        assert_eq!(validate_tzo("+14:00"), Ok(()));

        // Invalid cases
        assert_eq!(validate_tzo("Z"), Err(ValidationError::InvalidTzoFormat));
        assert_eq!(
            validate_tzo("00:00"),
            Err(ValidationError::InvalidTzoFormat)
        );
        assert_eq!(
            validate_tzo("+0:00"),
            Err(ValidationError::InvalidTzoFormat)
        );
        assert_eq!(
            validate_tzo("+00:0"),
            Err(ValidationError::InvalidTzoFormat)
        );
        assert_eq!(
            validate_tzo("+24:00"),
            Err(ValidationError::InvalidTzoFormat)
        );
        assert_eq!(
            validate_tzo("+14:01"),
            Err(ValidationError::InvalidTzoFormat)
        );
        assert_eq!(
            validate_tzo("-15:00"),
            Err(ValidationError::InvalidTzoFormat)
        );
        assert_eq!(
            validate_tzo("+00:60"),
            Err(ValidationError::InvalidTzoFormat)
        );
        assert_eq!(
            validate_tzo("invalid"),
            Err(ValidationError::InvalidTzoFormat)
        );
    }

    #[test]
    fn validates_utc_formats() {
        assert_eq!(validate_utc("2026-09-02T15:25:08Z"), Ok(()));
        assert_eq!(validate_utc("2006-12-19T17:58:35Z"), Ok(()));
        assert_eq!(validate_utc("2026-09-02T15:25:08.123Z"), Ok(()));
        assert_eq!(validate_utc("2026-09-02T15:25:08.123456Z"), Ok(()));

        // Invalid cases
        assert_eq!(
            validate_utc("2026-09-02"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-09-02T15:25:08"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-13-01T00:00:00Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-00-01T00:00:00Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-01-32T00:00:00Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-02-29T00:00:00Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(validate_utc("2024-02-29T00:00:00Z"), Ok(()));
        assert_eq!(
            validate_utc("2026-04-31T00:00:00Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("0000-01-01T00:00:00Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-01-01t00:00:00Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-01-01T00:00:00z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-01-01T00:00:00.Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-01-01T24:00:00Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-01-01T00:60:00Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("2026-01-01T00:00:61Z"),
            Err(ValidationError::InvalidUtcFormat)
        );
        assert_eq!(
            validate_utc("not-a-date"),
            Err(ValidationError::InvalidUtcFormat)
        );
    }

    #[test]
    fn builds_and_parses_response_round_trip() {
        let tzo = "+00:00";
        let utc = "2026-09-02T15:25:08Z";
        let time = EntityTime::new(tzo, utc).expect("valid entity time");
        let xml = build_response(&time).expect("build response succeeds");

        assert_eq!(
            xml,
            "<time xmlns='urn:xmpp:time'><tzo>+00:00</tzo><utc>2026-09-02T15:25:08Z</utc></time>"
        );

        let parsed = parse_response(&xml).expect("parse response succeeds");
        assert_eq!(parsed.tzo, "+00:00");
        assert_eq!(parsed.utc, "2026-09-02T15:25:08Z");
    }

    #[test]
    fn rejects_malformed_responses() {
        // Missing <tzo>
        assert_eq!(
            parse_response("<time xmlns='urn:xmpp:time'><utc>2026-09-02T15:25:08Z</utc></time>"),
            Err(ValidationError::MissingTzo)
        );
        // Missing <utc>
        assert_eq!(
            parse_response("<time xmlns='urn:xmpp:time'><tzo>+00:00</tzo></time>"),
            Err(ValidationError::MissingUtc)
        );
        // Duplicate <tzo>
        assert_eq!(
            parse_response(
                "<time xmlns='urn:xmpp:time'>\
                    <tzo>+00:00</tzo>\
                    <tzo>-05:00</tzo>\
                    <utc>2026-09-02T15:25:08Z</utc>\
                 </time>"
            ),
            Err(ValidationError::DuplicateTzo)
        );
        // Duplicate <utc>
        assert_eq!(
            parse_response(
                "<time xmlns='urn:xmpp:time'>\
                    <tzo>+00:00</tzo>\
                    <utc>2026-09-02T15:25:08Z</utc>\
                    <utc>2026-09-02T15:25:09Z</utc>\
                 </time>"
            ),
            Err(ValidationError::DuplicateUtc)
        );
        // Unexpected child
        assert_eq!(
            parse_response(
                "<time xmlns='urn:xmpp:time'>\
                    <tzo>+00:00</tzo>\
                    <utc>2026-09-02T15:25:08Z</utc>\
                    <extra>unknown</extra>\
                 </time>"
            ),
            Err(ValidationError::UnexpectedChildElement)
        );
        for malformed in [
            "<time xmlns='urn:xmpp:time' extra='1'><tzo>+00:00</tzo><utc>2026-09-02T15:25:08Z</utc></time>",
            "<time xmlns='urn:xmpp:time'><tzo xmlns=''>+00:00</tzo><utc>2026-09-02T15:25:08Z</utc></time>",
            "<time xmlns='urn:xmpp:time'><tzo><nested/>+00:00</tzo><utc>2026-09-02T15:25:08Z</utc></time>",
            "<time xmlns='urn:xmpp:time'>unexpected<tzo>+00:00</tzo><utc>2026-09-02T15:25:08Z</utc></time>",
        ] {
            assert!(parse_response(malformed).is_err(), "{malformed}");
        }
    }

    #[test]
    fn response_text_split_by_comments_is_not_truncated() {
        let parsed = parse_response(
            "<time xmlns='urn:xmpp:time'><tzo>+00<!--split-->:00</tzo><utc>2026-09-02T15:25:<!--split-->08Z</utc></time>",
        )
        .unwrap();
        assert_eq!(parsed.tzo, "+00:00");
        assert_eq!(parsed.utc, "2026-09-02T15:25:08Z");
    }

    #[test]
    fn builder_deterministic_and_escapes() {
        let xml = build_response_from_parts("+00:00", "2026-09-02T15:25:08Z").unwrap();
        assert_eq!(
            xml,
            "<time xmlns='urn:xmpp:time'><tzo>+00:00</tzo><utc>2026-09-02T15:25:08Z</utc></time>"
        );
        assert_eq!(build_request(), "<time xmlns='urn:xmpp:time'/>");
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Entity Time");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 1);
        assert_eq!(DESCRIPTOR.routes[0].stanza, StanzaKind::IqGet);
        assert_eq!(DESCRIPTOR.routes[0].namespace, NAMESPACE);
        assert_eq!(DESCRIPTOR.routes[0].local_name, "time");
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            ValidationError::AmbiguousTime.to_string(),
            "multiple time elements in stanza"
        );
        assert_eq!(
            ValidationError::ElementHasContent.to_string(),
            "time request must not have child elements or text"
        );
        assert_eq!(
            ValidationError::MissingTzo.to_string(),
            "missing required <tzo> child element"
        );
        assert_eq!(
            ValidationError::MissingUtc.to_string(),
            "missing required <utc> child element"
        );
        assert_eq!(
            ValidationError::InvalidTzoFormat.to_string(),
            "invalid time zone offset format, expected [+|-]HH:MM"
        );
        assert_eq!(
            ValidationError::InvalidUtcFormat.to_string(),
            "invalid UTC timestamp format, expected RFC 3339 CCYY-MM-DDThh:mm:ssZ"
        );
    }
}
