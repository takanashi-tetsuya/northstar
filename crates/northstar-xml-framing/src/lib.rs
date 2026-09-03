#![forbid(unsafe_code)]

//! Transport-neutral incremental XML entity framing, depth tracking, and
//! character validation for Northstar.
//!
//! This crate implements incremental XML streaming and framing for XMPP
//! transports (RFC 6120, RFC 7395 WebSocket, BOSH, etc.). It parses XML streams
//! into discrete stanzas and stream root tags while enforcing XML 1.0 character
//! validity, depth limits, element limits, attribute ceilings, and restricted
//! XML policies (forbidding DTDs, comments, processing instructions, and
//! non-predefined entities).
//!
//! It has no runtime, async, socket, filesystem, logging, or transport dependencies.

use anyhow::{bail, Result};

pub const MAX_XML_DEPTH: usize = 256;
// A byte ceiling alone does not bound parser work: a one MiB stanza can hold
// hundreds of thousands of `<x/>` nodes or tens of thousands of tiny
// attributes. Enforce structural ceilings before any transport hands the
// frame to roxmltree. The values are deliberately far above ordinary XMPP
// traffic (including PubSub/OMEMO bundles) while keeping one hostile stanza
// from creating an unbounded DOM or attribute table.
pub const MAX_XML_ELEMENTS: usize = 16_384;
pub const MAX_XML_ATTRIBUTES_PER_ELEMENT: usize = 128;
pub const MAX_XML_START_TAG_BYTES: usize = 64 * 1024;
pub const MAX_XML_DECLARATION_BYTES: usize = 1_024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum XmlFramingError {
    #[error("restricted XML feature: {0}")]
    Restricted(&'static str),
    #[error("XMPP XML entities must use UTF-8 encoding")]
    UnsupportedEncoding,
    #[error("XMPP XML resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
}

pub fn stream_error_condition(error: &anyhow::Error) -> &'static str {
    match error.downcast_ref::<XmlFramingError>() {
        Some(XmlFramingError::Restricted(_)) => "restricted-xml",
        Some(XmlFramingError::UnsupportedEncoding) => "unsupported-encoding",
        Some(XmlFramingError::ResourceLimit(_)) => "policy-violation",
        None => "not-well-formed",
    }
}

pub fn restricted(feature: &'static str) -> anyhow::Error {
    XmlFramingError::Restricted(feature).into()
}

pub fn resource_limit(limit: &'static str) -> anyhow::Error {
    XmlFramingError::ResourceLimit(limit).into()
}

pub fn unsupported_encoding() -> anyhow::Error {
    XmlFramingError::UnsupportedEncoding.into()
}

pub fn reject_forbidden_xml_10_chars(xml: &str) -> Result<()> {
    if let Some(character) = xml.chars().find(|character| !is_xml_10_char(*character)) {
        bail!(
            "character U+{:04X} is forbidden by XML 1.0",
            character as u32
        );
    }
    Ok(())
}

pub fn is_xml_10_char(character: char) -> bool {
    matches!(
        character as u32,
        0x09 | 0x0A | 0x0D | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

/// XML 1.0 defines whitespace as exactly space, tab, carriage return and line
/// feed. Rust's Unicode-aware `trim*` helpers accept additional characters
/// (for example NBSP) which are valid XML text but are not legal padding
/// outside the document element.
pub fn is_xml_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

/// Removes and returns one complete top-level XML element from an XMPP stream.
///
/// XMPP is an XML stream rather than a sequence of complete XML documents. The
/// opening `stream:stream` tag therefore has to be emitted on its own, while
/// normal stanzas are delimited by balanced XML elements. This scanner tracks
/// element depth and quoted markup instead of looking for the first textual
/// closing tag, which is unsafe for forwarded, carbon-copied and MAM stanzas
/// that can contain another `<message>` element.
pub fn take_frame(buffer: &mut String) -> Result<Option<String>> {
    XmlEntityFramer::default().take_frame(buffer)
}

/// Per-XML-entity framing state. RFC 6120 stream restarts after TLS and SASL
/// create new XML entities, so declaration placement cannot be validated from
/// the current socket buffer alone: a second declaration can arrive in a
/// later read after the opening declaration was already drained.
#[derive(Debug, Default)]
pub struct XmlEntityFramer {
    declaration_seen: bool,
    declaration_forbidden: bool,
    stream_qname: Option<String>,
    scan: FrameScanState,
}

#[derive(Debug, Default)]
struct FrameScanState {
    /// First byte which has not yet been inspected. Offsets remain valid while
    /// an incomplete frame stays at the front of the caller-owned buffer.
    cursor: usize,
    elements: Vec<String>,
    element_count: usize,
    root_started: bool,
    mode: ScanMode,
}

impl FrameScanState {
    fn reset(&mut self) {
        self.cursor = 0;
        self.elements.clear();
        self.element_count = 0;
        self.root_started = false;
        self.mode = ScanMode::Text;
    }

    /// Incremental offsets are byte indexes into the caller-owned UTF-8
    /// buffer. The public contract remains retain-and-append; this check is a
    /// totality guard which prevents stale or corrupted offsets from reaching
    /// a `str` slice. Adapters which replace a buffer must still call
    /// `reset_pending_frame` explicitly.
    fn offsets_are_safe_for(&self, buffer: &str) -> bool {
        let is_boundary = |offset: usize| offset <= buffer.len() && buffer.is_char_boundary(offset);
        if !is_boundary(self.cursor) {
            return false;
        }
        if self.root_started && buffer.as_bytes().first() != Some(&b'<') {
            return false;
        }

        match self.mode {
            ScanMode::Text => true,
            ScanMode::Markup { start } => {
                self.cursor == start
                    && is_boundary(start)
                    && buffer.as_bytes().get(start) == Some(&b'<')
            }
            ScanMode::Tag(tag) => {
                let Some(name_start) = tag.start.checked_add(if tag.closing { 2 } else { 1 })
                else {
                    return false;
                };
                let closing_prefix =
                    buffer.as_bytes().get(tag.start.saturating_add(1)) == Some(&b'/');
                self.cursor == tag.cursor
                    && tag.start < buffer.len()
                    && tag.start < tag.cursor
                    && name_start <= tag.cursor
                    && is_boundary(tag.start)
                    && is_boundary(name_start)
                    && is_boundary(tag.cursor)
                    && buffer.as_bytes().get(tag.start) == Some(&b'<')
                    && closing_prefix == tag.closing
                    && tag.name_end.is_none_or(|name_end| {
                        name_start <= name_end && name_end <= tag.cursor && is_boundary(name_end)
                    })
            }
            ScanMode::Cdata(cdata) => self.cursor == cdata.cursor && is_boundary(cdata.cursor),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
enum ScanMode {
    #[default]
    Text,
    Markup {
        start: usize,
    },
    Tag(TagScanState),
    Cdata(CdataScanState),
}

#[derive(Clone, Copy, Debug)]
struct TagScanState {
    start: usize,
    cursor: usize,
    closing: bool,
    quote: Option<char>,
    name_end: Option<usize>,
    attribute_count: usize,
}

#[derive(Clone, Copy, Debug)]
struct CdataScanState {
    cursor: usize,
    closing_brackets: u8,
}

impl XmlEntityFramer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset_entity(&mut self) {
        self.declaration_seen = false;
        self.declaration_forbidden = false;
        self.stream_qname = None;
        self.scan.reset();
    }

    pub fn take_frame(&mut self, buffer: &mut String) -> Result<Option<String>> {
        take_frame_in_entity(buffer, self)
    }

    /// Forget only an incomplete top-level frame while preserving XML-entity
    /// state such as declaration placement. RFC 7395 uses one complete XML
    /// frame per WebSocket text message, so partial scan state must never flow
    /// from a rejected message into the next standalone message.
    pub fn reset_pending_frame(&mut self) {
        self.scan.reset();
    }
}

fn take_frame_in_entity(
    buffer: &mut String,
    entity: &mut XmlEntityFramer,
) -> Result<Option<String>> {
    // A frame is only drained after it is complete, so an in-progress scan
    // must always refer to offsets within the retained buffer. Resetting on a
    // shorter/replaced buffer makes the type defensive for test and adapter
    // callers which clear their buffer without starting a new XML entity.
    if !entity.scan.offsets_are_safe_for(buffer) {
        entity.scan.reset();
    }

    loop {
        let trimmed = buffer.trim_start_matches(is_xml_whitespace);
        let leading_whitespace = trimmed.len() != buffer.len();
        if trimmed.len() != buffer.len() {
            // Leading whitespace can only be removed between frames. Once a
            // root has started, the buffer begins with its opening '<'.
            debug_assert!(!entity.scan.root_started);
            let leading_len = buffer.len() - trimmed.len();
            reject_forbidden_xml_10_chars(&buffer[..leading_len])?;
            buffer.drain(..leading_len);
            entity.scan.reset();
            if !entity.declaration_seen {
                entity.declaration_forbidden = true;
            }
        }
        if buffer.is_empty() {
            return Ok(None);
        }
        // A TCP/WebSocket read may stop at any byte boundary.  `<?` and
        // `<?x` are therefore not yet enough information to distinguish the
        // one permitted XML declaration from a forbidden processing
        // instruction.  Wait until the declaration prefix is complete before
        // classifying it; once a byte differs from `<?xml`, the normal
        // restricted-XML path below rejects it.
        if "<?xml".starts_with(buffer.as_str()) {
            reject_forbidden_xml_10_chars(buffer)?;
            return Ok(None);
        }
        if buffer.starts_with("<?xml") {
            if entity.declaration_seen || entity.declaration_forbidden || leading_whitespace {
                bail!("XML declaration must occur exactly once at the start of an XML entity");
            }
            // A forbidden character is malformed XML, even when it also makes
            // the declaration look like another processing instruction.
            let declaration_end = buffer.find("?>").map(|end| end + 2);
            let declaration_bytes = declaration_end.unwrap_or(buffer.len());
            if declaration_bytes > MAX_XML_DECLARATION_BYTES {
                return Err(resource_limit("XML declaration bytes"));
            }
            reject_forbidden_xml_10_chars(&buffer[..declaration_bytes])?;
            let Some(boundary) = buffer.as_bytes().get(5).copied() else {
                return Ok(None);
            };
            if !boundary.is_ascii_whitespace() {
                return Err(restricted("processing instruction"));
            }
            let Some(end) = declaration_end.map(|end| end - 2) else {
                return Ok(None);
            };
            validate_xml_declaration(&buffer[..end + 2])?;
            buffer.drain(..end + 2);
            entity.scan.reset();
            entity.declaration_seen = true;
            continue;
        }
        break;
    }

    if !buffer.starts_with('<') {
        bail!("unexpected non-XML data before XMPP frame");
    }

    loop {
        match entity.scan.mode {
            ScanMode::Text => {
                let cursor = entity.scan.cursor;
                let Some(relative) = buffer.as_bytes()[cursor..]
                    .iter()
                    .position(|byte| *byte == b'<')
                else {
                    reject_forbidden_xml_10_chars(&buffer[cursor..])?;
                    if !entity.scan.root_started && !buffer[cursor..].chars().all(is_xml_whitespace)
                    {
                        bail!("unexpected text before XMPP stanza");
                    }
                    entity.scan.cursor = buffer.len();
                    return Ok(None);
                };
                let start = cursor + relative;
                reject_forbidden_xml_10_chars(&buffer[cursor..start])?;
                if !entity.scan.root_started
                    && !buffer[cursor..start].chars().all(is_xml_whitespace)
                {
                    bail!("unexpected text before XMPP stanza");
                }
                entity.scan.cursor = start;
                entity.scan.mode = ScanMode::Markup { start };
            }
            ScanMode::Markup { start } => {
                let remainder = &buffer[start..];
                if remainder == "<" {
                    reject_forbidden_xml_10_chars(remainder)?;
                    return Ok(None);
                }
                if remainder.starts_with("<!--") {
                    reject_forbidden_xml_10_chars(&remainder[..4])?;
                    return Err(restricted("comment"));
                }
                if remainder.starts_with("<![CDATA[") {
                    if !entity.scan.root_started {
                        bail!("CDATA is not allowed outside an XMPP stanza");
                    }
                    let cursor = start + "<![CDATA[".len();
                    reject_forbidden_xml_10_chars(&buffer[start..cursor])?;
                    entity.scan.cursor = cursor;
                    entity.scan.mode = ScanMode::Cdata(CdataScanState {
                        cursor,
                        closing_brackets: 0,
                    });
                    continue;
                }
                if "<!--".starts_with(remainder) || "<![CDATA[".starts_with(remainder) {
                    reject_forbidden_xml_10_chars(remainder)?;
                    return Ok(None);
                }
                if remainder.starts_with("<?") {
                    reject_forbidden_xml_10_chars(&remainder[..2])?;
                    return Err(restricted("processing instruction"));
                }
                if remainder.starts_with("<!") {
                    reject_forbidden_xml_10_chars(remainder)?;
                    return Err(restricted("DTD or declaration"));
                }

                let closing = remainder.starts_with("</");
                let name_start = start + if closing { 2 } else { 1 };
                if name_start == buffer.len() {
                    return Ok(None);
                }
                entity.scan.cursor = name_start;
                entity.scan.mode = ScanMode::Tag(TagScanState {
                    start,
                    cursor: name_start,
                    closing,
                    quote: None,
                    name_end: None,
                    attribute_count: 0,
                });
            }
            ScanMode::Tag(mut tag) => {
                let mut completed = None;
                while tag.cursor < buffer.len() {
                    let Some(character) = buffer
                        .get(tag.cursor..)
                        .and_then(|remainder| remainder.chars().next())
                    else {
                        bail!("invalid incremental XML tag cursor");
                    };
                    if !is_xml_10_char(character) {
                        bail!(
                            "character U+{:04X} is forbidden by XML 1.0",
                            character as u32
                        );
                    }
                    let next = tag.cursor + character.len_utf8();
                    if !tag.closing && next.saturating_sub(tag.start) > MAX_XML_START_TAG_BYTES {
                        return Err(resource_limit("start-tag bytes"));
                    }
                    match tag.quote {
                        Some(delimiter) if character == delimiter => tag.quote = None,
                        Some(_) => {}
                        None if matches!(character, '\'' | '"') => tag.quote = Some(character),
                        None if character == '>' => {
                            completed = Some(tag.cursor);
                            tag.cursor = next;
                            break;
                        }
                        None if character == '<' => bail!("unexpected '<' inside XML tag"),
                        None => {
                            if tag.name_end.is_none()
                                && (character.is_ascii_whitespace() || character == '/')
                            {
                                tag.name_end = Some(tag.cursor);
                            } else if !tag.closing && tag.name_end.is_some() && character == '=' {
                                tag.attribute_count = tag
                                    .attribute_count
                                    .checked_add(1)
                                    .ok_or_else(|| resource_limit("attributes per element"))?;
                                if tag.attribute_count > MAX_XML_ATTRIBUTES_PER_ELEMENT {
                                    return Err(resource_limit("attributes per element"));
                                }
                            }
                        }
                    }
                    tag.cursor = next;
                }

                let Some(end) = completed else {
                    entity.scan.cursor = tag.cursor;
                    entity.scan.mode = ScanMode::Tag(tag);
                    return Ok(None);
                };
                entity.scan.cursor = end + 1;
                entity.scan.mode = ScanMode::Text;
                if let Some(frame) = finish_tag(buffer, entity, tag, end)? {
                    return Ok(Some(frame));
                }
            }
            ScanMode::Cdata(mut cdata) => {
                let mut completed = false;
                while cdata.cursor < buffer.len() {
                    let Some(character) = buffer
                        .get(cdata.cursor..)
                        .and_then(|remainder| remainder.chars().next())
                    else {
                        bail!("invalid incremental XML CDATA cursor");
                    };
                    if !is_xml_10_char(character) {
                        bail!(
                            "character U+{:04X} is forbidden by XML 1.0",
                            character as u32
                        );
                    }
                    cdata.cursor += character.len_utf8();
                    match character {
                        ']' => cdata.closing_brackets = (cdata.closing_brackets + 1).min(2),
                        '>' if cdata.closing_brackets == 2 => {
                            cdata.closing_brackets = 0;
                            completed = true;
                            break;
                        }
                        _ => cdata.closing_brackets = 0,
                    }
                }
                entity.scan.cursor = cdata.cursor;
                if completed {
                    entity.scan.mode = ScanMode::Text;
                } else {
                    entity.scan.mode = ScanMode::Cdata(cdata);
                    return Ok(None);
                }
            }
        }
    }
}

fn finish_tag(
    buffer: &mut String,
    entity: &mut XmlEntityFramer,
    tag: TagScanState,
    end: usize,
) -> Result<Option<String>> {
    let name_start = tag.start + if tag.closing { 2 } else { 1 };
    let name = element_name(buffer, name_start, end)?.to_owned();

    if tag.closing {
        let stream_qname = entity.stream_qname.as_deref().unwrap_or("stream:stream");
        if !entity.scan.root_started
            && entity.scan.elements.is_empty()
            && tag.start == 0
            && name == stream_qname
        {
            let trailing = &buffer[name_start + name.len()..end];
            if !trailing.chars().all(is_xml_whitespace) {
                bail!("XMPP stream closing tag must not contain attributes");
            }
            entity.declaration_forbidden = true;
            return drain_entity_frame(buffer, entity, end + 1);
        }

        let Some(expected) = entity.scan.elements.pop() else {
            bail!("unexpected XML closing tag");
        };
        if name != expected {
            bail!("mismatched XML closing tag: expected </{expected}>, found </{name}>");
        }
        if entity.scan.elements.is_empty() {
            entity.declaration_forbidden = true;
            return drain_entity_frame(buffer, entity, end + 1);
        }
        return Ok(None);
    }

    if !entity.scan.root_started
        && entity.scan.elements.is_empty()
        && tag.start == 0
        && name
            .rsplit_once(':')
            .map_or(name.as_str(), |(_, local)| local)
            == "stream"
    {
        if is_self_closing(buffer, end) {
            bail!("XMPP stream opening tag must not be self-closing");
        }
        entity.declaration_forbidden = true;
        entity.stream_qname = Some(name);
        return drain_entity_frame(buffer, entity, end + 1);
    }

    entity.scan.element_count = entity
        .scan
        .element_count
        .checked_add(1)
        .ok_or_else(|| resource_limit("element count"))?;
    if entity.scan.element_count > MAX_XML_ELEMENTS {
        return Err(resource_limit("element count"));
    }
    entity.scan.root_started = true;
    if is_self_closing(buffer, end) {
        if entity.scan.elements.is_empty() {
            entity.declaration_forbidden = true;
            return drain_entity_frame(buffer, entity, end + 1);
        }
    } else {
        // Most extension-heavy payloads use self-closing leaf nodes. Do not
        // allocate and immediately discard a QName for every leaf; only open
        // elements need ownership in the balancing stack.
        entity.scan.elements.push(name);
        if entity.scan.elements.len() > MAX_XML_DEPTH {
            return Err(resource_limit("nesting depth"));
        }
    }
    Ok(None)
}

fn drain_entity_frame(
    buffer: &mut String,
    entity: &mut XmlEntityFramer,
    end: usize,
) -> Result<Option<String>> {
    let frame = drain_frame(buffer, end)?;
    entity.scan.reset();
    Ok(frame)
}

fn validate_xml_declaration(declaration: &str) -> Result<()> {
    let content = declaration
        .strip_prefix("<?xml")
        .and_then(|value| value.strip_suffix("?>"))
        .ok_or_else(|| anyhow::anyhow!("malformed XML declaration"))?;

    let attributes = parse_xml_declaration_attributes(content)?;

    let ordered_names: Vec<&str> = attributes.iter().map(|(k, _)| k.as_str()).collect();
    if !matches!(
        ordered_names.as_slice(),
        ["version"]
            | ["version", "encoding"]
            | ["version", "standalone"]
            | ["version", "encoding", "standalone"]
    ) || attributes[0].1 != "1.0"
        || attributes.iter().any(|(name, value)| {
            !matches!(name.as_str(), "version" | "encoding" | "standalone")
                || (name == "standalone" && !matches!(value.as_str(), "yes" | "no"))
        })
    {
        bail!("unsupported or malformed XML declaration");
    }

    if attributes
        .iter()
        .any(|(name, value)| name == "encoding" && !value.eq_ignore_ascii_case("UTF-8"))
    {
        return Err(unsupported_encoding());
    }

    Ok(())
}

fn parse_xml_declaration_attributes(content: &str) -> Result<Vec<(String, String)>> {
    let mut attributes = Vec::new();
    let bytes = content.as_bytes();
    let mut i = 0;

    // XMLDecl requires S (whitespace) immediately following <?xml
    if bytes.is_empty() || !is_xml_whitespace(bytes[0] as char) {
        bail!("malformed XML declaration");
    }

    while i < bytes.len() {
        let ws_start = i;
        while i < bytes.len() && is_xml_whitespace(bytes[i] as char) {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if i == ws_start && !attributes.is_empty() {
            bail!("malformed XML declaration");
        }

        let name_start = i;
        while i < bytes.len()
            && !is_xml_whitespace(bytes[i] as char)
            && bytes[i] != b'='
            && bytes[i] != b'\''
            && bytes[i] != b'"'
            && bytes[i] != b'>'
            && bytes[i] != b'<'
        {
            i += 1;
        }
        if i == name_start {
            bail!("malformed XML declaration");
        }
        let name = &content[name_start..i];

        while i < bytes.len() && is_xml_whitespace(bytes[i] as char) {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            bail!("malformed XML declaration");
        }
        i += 1; // skip '='

        while i < bytes.len() && is_xml_whitespace(bytes[i] as char) {
            i += 1;
        }
        if i >= bytes.len() || (bytes[i] != b'"' && bytes[i] != b'\'') {
            bail!("malformed XML declaration");
        }
        let quote = bytes[i];
        i += 1; // skip opening quote

        let val_start = i;
        while i < bytes.len() && bytes[i] != quote {
            if bytes[i] == b'<' {
                bail!("malformed XML declaration");
            }
            i += 1;
        }
        if i >= bytes.len() {
            bail!("malformed XML declaration");
        }
        let val = &content[val_start..i];
        i += 1; // skip closing quote

        attributes.push((name.to_string(), val.to_string()));
    }

    Ok(attributes)
}

fn drain_frame(buffer: &mut String, end: usize) -> Result<Option<String>> {
    reject_forbidden_xml_10_chars(&buffer[..end])?;
    reject_non_predefined_entities(&buffer[..end])?;
    Ok(Some(buffer.drain(..end).collect()))
}

fn reject_non_predefined_entities(xml: &str) -> Result<()> {
    let bytes = xml.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"<![CDATA[") {
            let Some(end) = bytes[cursor + 9..]
                .windows(3)
                .position(|window| window == b"]]>")
            else {
                // Incomplete CDATA is handled by the framing loop.
                return Ok(());
            };
            cursor += 9 + end + 3;
            continue;
        }
        if bytes[cursor] != b'&' {
            cursor += 1;
            continue;
        }
        let Some(relative_end) = bytes[cursor + 1..].iter().position(|byte| *byte == b';') else {
            // Let the XML parser report the malformed reference.
            cursor += 1;
            continue;
        };
        let end = cursor + 1 + relative_end;
        let name = &xml[cursor + 1..end];
        let numeric = name.strip_prefix("#x").is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) || name.strip_prefix('#').is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        });
        if !numeric && !matches!(name, "amp" | "lt" | "gt" | "apos" | "quot") {
            return Err(restricted("entity reference"));
        }
        cursor = end + 1;
    }
    Ok(())
}

fn element_name(xml: &str, start: usize, tag_end: usize) -> Result<&str> {
    let end = xml.as_bytes()[start..tag_end]
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'>'))
        .map(|offset| start + offset)
        .unwrap_or(tag_end);
    if start == end {
        bail!("XML element name is empty");
    }
    Ok(&xml[start..end])
}

fn is_self_closing(xml: &str, tag_end: usize) -> bool {
    xml.as_bytes()[..tag_end]
        .iter()
        .rev()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(&b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_stream_and_stanzas() {
        let mut data =
            "<stream:stream to='localhost'><message to='a@localhost'><body>hi</body></message>"
                .to_owned();
        assert!(take_frame(&mut data)
            .unwrap()
            .unwrap()
            .starts_with("<stream:stream"));
        assert_eq!(
            take_frame(&mut data).unwrap().unwrap(),
            "<message to='a@localhost'><body>hi</body></message>"
        );
    }

    #[test]
    fn keeps_nested_stanzas_in_the_outer_frame() {
        let outer = "<message id='outer'><result xmlns='urn:xmpp:mam:2'><forwarded xmlns='urn:xmpp:forward:0'><message id='inner'><body>stored</body></message></forwarded></result></message>";
        let mut data = format!("{outer}<presence/>");
        assert_eq!(take_frame(&mut data).unwrap().unwrap(), outer);
        assert_eq!(take_frame(&mut data).unwrap().unwrap(), "<presence/>");
    }

    #[test]
    fn accepts_one_leading_declaration_but_rejects_misplaced_or_repeated_ones() {
        let mut valid = "<?xml version='1.0' encoding='UTF-8'?>\n<message/>".to_owned();
        assert_eq!(take_frame(&mut valid).unwrap().unwrap(), "<message/>");
        for invalid in [
            " <?xml version='1.0'?><message/>",
            "<?xml version='1.0'?><?xml version='1.0'?><message/>",
            "<?xml version='1.0'?> \n <?xml version='1.0'?><message/>",
        ] {
            assert!(take_frame(&mut invalid.to_owned()).is_err(), "{invalid}");
        }
    }

    #[test]
    fn declaration_state_spans_reads_and_resets_only_for_a_new_xml_entity() {
        let mut framer = XmlEntityFramer::default();
        let mut opening = "<?xml version='1.0'?><stream:stream to='localhost'>".to_owned();
        assert!(framer
            .take_frame(&mut opening)
            .unwrap()
            .unwrap()
            .starts_with("<stream:stream"));

        let mut repeated = "<?xml version='1.0'?><message/>".to_owned();
        assert!(framer.take_frame(&mut repeated).is_err());

        framer.reset_entity();
        let mut restarted = "<?xml version='1.0'?><stream:stream to='localhost'>".to_owned();
        assert!(framer.take_frame(&mut restarted).unwrap().is_some());
    }

    #[test]
    fn whitespace_in_an_earlier_read_still_forbids_a_late_declaration() {
        let mut framer = XmlEntityFramer::default();
        let mut whitespace = " \r\n".to_owned();
        assert!(framer.take_frame(&mut whitespace).unwrap().is_none());
        let mut declaration = "<?xml version='1.0'?><message/>".to_owned();
        assert!(framer.take_frame(&mut declaration).is_err());
    }

    #[test]
    fn waits_at_every_xml_declaration_fragment_boundary() {
        let entity = "<?xml version='1.0' encoding='UTF-8'?><message/>";
        for split in 1..entity.len() {
            let mut buffer = entity[..split].to_owned();
            assert!(
                take_frame(&mut buffer).unwrap().is_none(),
                "declaration fragment was classified before byte {split}"
            );
            buffer.push_str(&entity[split..]);
            assert_eq!(
                take_frame(&mut buffer).unwrap().as_deref(),
                Some("<message/>")
            );
            assert!(buffer.is_empty());
        }
    }

    #[test]
    fn ignores_markup_in_attributes_and_cdata() {
        let stanza =
            "<message data='</message> and >'><body><![CDATA[</message>]]></body></message>";
        let mut data = stanza.to_owned();
        assert_eq!(take_frame(&mut data).unwrap().unwrap(), stanza);
    }

    #[test]
    fn waits_for_fragmented_tags_and_utf8_text() {
        let mut data = "<message><body>消".to_owned();
        assert!(take_frame(&mut data).unwrap().is_none());
        data.push_str("息</body></message>");
        assert_eq!(
            take_frame(&mut data).unwrap().unwrap(),
            "<message><body>消息</body></message>"
        );
    }

    #[test]
    fn stateful_scan_keeps_cursor_stack_quotes_and_cdata_progress() {
        let mut framer = XmlEntityFramer::default();
        let mut data = "<message data='a>b'><body>hel".to_owned();
        assert!(framer.take_frame(&mut data).unwrap().is_none());
        assert_eq!(framer.scan.cursor, data.len());
        assert_eq!(framer.scan.elements, ["message", "body"]);
        assert!(matches!(framer.scan.mode, ScanMode::Text));

        data.push_str("lo<![CDA");
        assert!(framer.take_frame(&mut data).unwrap().is_none());
        assert!(matches!(framer.scan.mode, ScanMode::Markup { .. }));

        data.push_str("TA[part ]");
        assert!(framer.take_frame(&mut data).unwrap().is_none());
        assert!(matches!(
            framer.scan.mode,
            ScanMode::Cdata(CdataScanState {
                closing_brackets: 1,
                ..
            })
        ));
        assert_eq!(framer.scan.cursor, data.len());

        data.push_str("]></body></message><presence/>");
        assert_eq!(
            framer.take_frame(&mut data).unwrap().as_deref(),
            Some("<message data='a>b'><body>hello<![CDATA[part ]]></body></message>")
        );
        assert_eq!(data, "<presence/>");
        assert_eq!(framer.scan.cursor, 0);
        assert!(framer.scan.elements.is_empty());
        assert_eq!(
            framer.take_frame(&mut data).unwrap().as_deref(),
            Some("<presence/>")
        );
    }

    #[test]
    fn fragmented_stream_tags_use_the_same_incremental_tag_state() {
        let mut framer = XmlEntityFramer::default();
        let mut opening = "<stream:str".to_owned();
        assert!(framer.take_frame(&mut opening).unwrap().is_none());
        assert!(matches!(framer.scan.mode, ScanMode::Tag(_)));
        opening.push_str("eam to='localhost'>");
        assert_eq!(
            framer.take_frame(&mut opening).unwrap().as_deref(),
            Some("<stream:stream to='localhost'>")
        );

        let mut closing = "</stream:str".to_owned();
        assert!(framer.take_frame(&mut closing).unwrap().is_none());
        closing.push_str("eam>");
        assert_eq!(
            framer.take_frame(&mut closing).unwrap().as_deref(),
            Some("</stream:stream>")
        );
    }

    #[test]
    fn reset_entity_discards_an_incomplete_incremental_scan() {
        let mut framer = XmlEntityFramer::default();
        let mut data = "<message><body><![CDATA[pending".to_owned();
        assert!(framer.take_frame(&mut data).unwrap().is_none());
        assert!(matches!(framer.scan.mode, ScanMode::Cdata(_)));

        data.clear();
        framer.reset_entity();
        data.push_str("<?xml version='1.0'?><stream:stream to='localhost'>");
        assert_eq!(
            framer.take_frame(&mut data).unwrap().as_deref(),
            Some("<stream:stream to='localhost'>")
        );
        assert!(framer.scan.elements.is_empty());
    }

    #[test]
    fn replacement_buffer_with_stale_utf8_cursor_is_reset_defensively() {
        let mut framer = XmlEntityFramer::default();
        let mut first = "<--".to_owned();
        assert!(framer.take_frame(&mut first).unwrap().is_none());

        let mut replacement = "<\nƞ\n/a2<\n<".to_owned();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            framer.take_frame(&mut replacement)
        }));
        assert!(
            result.is_ok(),
            "stale byte offsets must not reach a str slice"
        );
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn tag_end_respects_quoted_greater_than_characters() {
        let mut data = "<stream:stream to='a>b'><iq id=\"one>two\"/>".to_owned();
        assert_eq!(
            take_frame(&mut data).unwrap().unwrap(),
            "<stream:stream to='a>b'>"
        );
        assert_eq!(
            take_frame(&mut data).unwrap().unwrap(),
            "<iq id=\"one>two\"/>"
        );
    }

    #[test]
    fn rejects_dtds_and_mismatched_elements() {
        let mut dtd = "<!DOCTYPE message><message/>".to_owned();
        assert!(take_frame(&mut dtd)
            .unwrap_err()
            .to_string()
            .contains("restricted XML"));

        let mut mismatched = "<message><body></message></body>".to_owned();
        assert!(take_frame(&mut mismatched)
            .unwrap_err()
            .to_string()
            .contains("mismatched"));
    }

    #[test]
    fn rejects_restricted_comments_processing_instructions_and_entities() {
        for xml in [
            "<message><!-- forbidden --><body>hello</body></message>",
            "<message><?target data?><body>hello</body></message>",
            "<message><body>&custom;</body></message>",
        ] {
            let mut buffer = xml.to_owned();
            let error = take_frame(&mut buffer).unwrap_err();
            assert_eq!(stream_error_condition(&error), "restricted-xml");
        }

        let mut allowed =
            "<message a='&quot;&amp;&#65;&#x41;'><body>&lt;&gt;&apos;</body><![CDATA[&custom;]]></message>"
                .to_owned();
        assert!(take_frame(&mut allowed).unwrap().is_some());
    }

    #[test]
    fn accepts_only_a_real_utf8_xml_10_declaration() {
        let mut valid =
            "<?xml version='1.0' encoding='UTF-8'?><stream:stream to='localhost'>".to_owned();
        assert_eq!(
            take_frame(&mut valid).unwrap().unwrap(),
            "<stream:stream to='localhost'>"
        );

        for xml in [
            "<?xml-stylesheet href='evil'?><stream:stream>",
            "<?xml encoding='UTF-8'?><stream:stream>",
            "<?xml version='1.1'?><stream:stream>",
            "<?xml version='1.0' encoding='UTF-16'?><stream:stream>",
            "<?xml version='1.0' extra='true'?><stream:stream>",
        ] {
            let mut buffer = xml.to_owned();
            assert!(take_frame(&mut buffer).is_err(), "accepted {xml}");
        }

        let mut unfinished = format!(
            "<?xml version='1.0' {}",
            " ".repeat(MAX_XML_DECLARATION_BYTES)
        );
        let error = take_frame(&mut unfinished).unwrap_err();
        assert_eq!(stream_error_condition(&error), "policy-violation");
        assert!(error.to_string().contains("XML declaration bytes"));
    }

    #[test]
    fn rejects_excessive_nesting_and_malformed_stream_close() {
        let mut nested = "<x>".repeat(MAX_XML_DEPTH + 1);
        nested.push_str(&"</x>".repeat(MAX_XML_DEPTH + 1));
        let error = take_frame(&mut nested).unwrap_err();
        assert_eq!(stream_error_condition(&error), "policy-violation");
        assert!(error.to_string().contains("nesting"));

        let mut close = "</stream:stream bogus='true'>".to_owned();
        assert!(take_frame(&mut close)
            .unwrap_err()
            .to_string()
            .contains("must not contain attributes"));
    }

    #[test]
    fn structural_resource_limits_are_transport_level_policy_violations() {
        let mut too_many_elements = String::from("<message>");
        too_many_elements.push_str(&"<x/>".repeat(MAX_XML_ELEMENTS));
        too_many_elements.push_str("</message>");
        let error = take_frame(&mut too_many_elements).unwrap_err();
        assert_eq!(stream_error_condition(&error), "policy-violation");
        assert!(error.to_string().contains("element count"));

        let mut too_many_attributes = String::from("<message");
        for index in 0..=MAX_XML_ATTRIBUTES_PER_ELEMENT {
            too_many_attributes.push_str(&format!(" a{index}='x'"));
        }
        too_many_attributes.push_str("/>");
        let error = take_frame(&mut too_many_attributes).unwrap_err();
        assert_eq!(stream_error_condition(&error), "policy-violation");
        assert!(error.to_string().contains("attributes per element"));

        let mut oversized_start_tag =
            format!("<message value='{}'/>", "x".repeat(MAX_XML_START_TAG_BYTES));
        let error = take_frame(&mut oversized_start_tag).unwrap_err();
        assert_eq!(stream_error_condition(&error), "policy-violation");
        assert!(error.to_string().contains("start-tag bytes"));
    }

    #[test]
    fn incomplete_start_tag_is_rejected_immediately_after_the_byte_ceiling() {
        let prefix = "<x value='";
        let mut at_limit = prefix.to_owned();
        at_limit.push_str(&"x".repeat(MAX_XML_START_TAG_BYTES - prefix.len()));
        assert_eq!(at_limit.len(), MAX_XML_START_TAG_BYTES);

        let mut framer = XmlEntityFramer::default();
        assert!(framer.take_frame(&mut at_limit).unwrap().is_none());
        at_limit.push('x');
        let error = framer.take_frame(&mut at_limit).unwrap_err();
        assert_eq!(stream_error_condition(&error), "policy-violation");
        assert!(error.to_string().contains("start-tag bytes"));

        let suffix = "'/>";
        let mut exactly_at_limit = prefix.to_owned();
        exactly_at_limit
            .push_str(&"x".repeat(MAX_XML_START_TAG_BYTES - prefix.len() - suffix.len()));
        exactly_at_limit.push_str(suffix);
        assert_eq!(exactly_at_limit.len(), MAX_XML_START_TAG_BYTES);
        assert!(take_frame(&mut exactly_at_limit).unwrap().is_some());
    }

    #[test]
    fn fragmented_valid_attributes_still_map_resource_limits_to_policy_violation() {
        let mut stanza = String::from("<x");
        for index in 0..=MAX_XML_ATTRIBUTES_PER_ELEMENT {
            stanza.push_str(&format!(" a{index}='x'"));
        }
        stanza.push_str("/>");
        let split = 60;
        let mut buffer = stanza[..split].to_owned();
        let mut framer = XmlEntityFramer::default();
        assert!(framer.take_frame(&mut buffer).unwrap().is_none());

        buffer.push_str(&stanza[split..]);
        let error = framer.take_frame(&mut buffer).unwrap_err();
        assert_eq!(stream_error_condition(&error), "policy-violation");
        assert!(error.to_string().contains("attributes per element"));
    }

    #[test]
    fn forbidden_xml_10_characters_are_not_well_formed_across_fragment_boundaries() {
        let mut forbidden = (0_u32..=0x1F)
            .filter(|value| !matches!(*value, 0x09 | 0x0A | 0x0D))
            .filter_map(char::from_u32)
            .collect::<Vec<_>>();
        forbidden.extend(['\u{FFFE}', '\u{FFFF}']);

        let prefix = "<message><body>";
        for character in forbidden {
            let stanza = format!("{prefix}{character}</body></message>");
            for split in [prefix.len(), prefix.len() + character.len_utf8()] {
                let mut framer = XmlEntityFramer::default();
                let mut buffer = stanza[..split].to_owned();
                let first = framer.take_frame(&mut buffer);
                if split == prefix.len() {
                    assert!(first.unwrap().is_none(), "U+{:04X}", character as u32);
                    buffer.push_str(&stanza[split..]);
                    let error = framer.take_frame(&mut buffer).unwrap_err();
                    assert_eq!(stream_error_condition(&error), "not-well-formed");
                } else {
                    let error = first.unwrap_err();
                    assert_eq!(stream_error_condition(&error), "not-well-formed");
                }
            }
        }

        let mut allowed = "<message><body>\t\n\r</body></message>".to_owned();
        assert!(take_frame(&mut allowed).unwrap().is_some());
    }

    #[test]
    fn forbidden_character_preempts_resource_policy_for_fuzz_artifact_shape() {
        // Deterministic regression for
        // crash-c07c6c348b38cedd14d3bf9a9905e76b94ad4b7f: its malformed start
        // tag contains NUL/control characters before enough unquoted `=`
        // bytes to hit the attribute ceiling. Malformed XML takes precedence.
        let mut artifact_shape = String::from("<x?(lm\0\u{2}\r");
        artifact_shape.push_str(&"=".repeat(MAX_XML_ATTRIBUTES_PER_ELEMENT + 1));
        artifact_shape.push_str("/>");
        let error = take_frame(&mut artifact_shape).unwrap_err();
        assert_eq!(stream_error_condition(&error), "not-well-formed");
        assert!(error.to_string().contains("U+0000"));
    }

    #[test]
    fn structural_limits_leave_large_normal_payload_text_untouched() {
        let body = "x".repeat(MAX_XML_START_TAG_BYTES * 2);
        let stanza = format!("<message><body>{body}</body></message>");
        let mut buffer = stanza.clone();
        assert_eq!(
            take_frame(&mut buffer).unwrap().as_deref(),
            Some(stanza.as_str())
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn compatibility_corpus_survives_every_utf8_fragment_boundary() {
        let corpus = [
            "<message xmlns='jabber:client' id='carbon'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' id='inner'><body>carbon</body></message></forwarded></sent></message>",
            "<message xmlns='jabber:client' id='mam'><result xmlns='urn:xmpp:mam:2'><forwarded xmlns='urn:xmpp:forward:0'><delay xmlns='urn:xmpp:delay' stamp='2026-08-22T00:00:00Z'/><message xmlns='jabber:client'><encrypted xmlns='urn:xmpp:omemo:2'><payload>密文</payload></encrypted></message></forwarded></result></message>",
            "<iq xmlns='jabber:client' type='set' id='pep'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:omemo:2:bundles'><item id='42'><bundle xmlns='urn:xmpp:omemo:2'><prekeys><pk id='1'>AA==</pk></prekeys></bundle></item></publish></pubsub></iq>",
            "<presence xmlns='jabber:client' data='a>b'><x xmlns='http://jabber.org/protocol/muc#user'><item jid='用户@example.test/device'/></x></presence>",
        ];
        for stanza in corpus {
            for split in stanza
                .char_indices()
                .map(|(index, _)| index)
                .chain(std::iter::once(stanza.len()))
            {
                let mut buffer = stanza[..split].to_owned();
                let first = take_frame(&mut buffer).unwrap();
                if split == stanza.len() {
                    assert_eq!(first.as_deref(), Some(stanza));
                    continue;
                }
                assert!(
                    first.is_none(),
                    "frame completed before split {split}: {stanza}"
                );
                buffer.push_str(&stanza[split..]);
                assert_eq!(take_frame(&mut buffer).unwrap().as_deref(), Some(stanza));
                assert!(buffer.is_empty());
            }
        }
    }

    #[test]
    fn reset_pending_frame_preserves_declaration_state() {
        let mut framer = XmlEntityFramer::new();
        let mut declaration = "<?xml version='1.0' encoding='UTF-8'?><open xmlns='urn:ietf:params:xml:ns:xmpp-framing'".to_owned();
        assert!(framer.take_frame(&mut declaration).unwrap().is_none());
        assert_eq!(
            declaration,
            "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'"
        );

        framer.reset_pending_frame();
        // Declaration is already seen; repeated declaration in the same XML entity must fail.
        let mut repeated =
            "<?xml version='1.0'?><open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>".to_owned();
        assert!(framer.take_frame(&mut repeated).is_err());
    }

    #[test]
    fn error_types_and_conditions() {
        let restricted_err = restricted("processing instruction");
        assert_eq!(stream_error_condition(&restricted_err), "restricted-xml");

        let encoding_err = unsupported_encoding();
        assert_eq!(
            stream_error_condition(&encoding_err),
            "unsupported-encoding"
        );

        let limit_err = resource_limit("element count");
        assert_eq!(stream_error_condition(&limit_err), "policy-violation");

        let generic_err = anyhow::anyhow!("syntax error");
        assert_eq!(stream_error_condition(&generic_err), "not-well-formed");
    }

    #[test]
    fn declaration_standalone_and_ordering() {
        let mut valid_standalone = "<?xml version='1.0' standalone='yes'?><message/>".to_owned();
        assert_eq!(
            take_frame(&mut valid_standalone).unwrap().unwrap(),
            "<message/>"
        );

        let mut valid_all =
            "<?xml version='1.0' encoding='UTF-8' standalone='no'?><message/>".to_owned();
        assert_eq!(take_frame(&mut valid_all).unwrap().unwrap(), "<message/>");

        let mut invalid_standalone_val =
            "<?xml version='1.0' standalone='maybe'?><message/>".to_owned();
        assert!(take_frame(&mut invalid_standalone_val).is_err());

        let mut invalid_order =
            "<?xml version='1.0' standalone='yes' encoding='UTF-8'?><message/>".to_owned();
        assert!(take_frame(&mut invalid_order).is_err());
    }
}
