//! Preserves serialized XML while rewriting a stanza's root attributes and namespace or appending children.

use crate::escape::attr_escape;
use crate::{ValidatedXmlFragment, XmlElement};
use roxmltree::Document;

pub fn remove_root_attribute(raw: &str, name: &str) -> String {
    if Document::parse(raw).is_err() {
        return raw.to_owned();
    }
    let Some(opening) = parse_root_opening(raw) else {
        return raw.to_owned();
    };
    let mut rewritten = raw.to_owned();
    let mut removals = opening
        .attributes
        .iter()
        .filter(|attribute| attribute.name == name)
        .map(|attribute| attribute.removal_start..attribute.end)
        .collect::<Vec<_>>();
    removals.sort_by_key(|range| std::cmp::Reverse(range.start));
    for range in removals {
        rewritten.replace_range(range, "");
    }
    rewritten
}

pub fn set_from(raw: &str, from: &str) -> String {
    rewrite_root_attribute(raw, "from", from, true)
}

pub fn set_to(raw: &str, to: &str) -> String {
    rewrite_root_attribute(raw, "to", to, false)
}

/// Rebinds the root element's namespace prefix (or default namespace) to the
/// client stanza namespace while preserving the serialized payload. This is
/// used at the authenticated S2S-to-C2S boundary, where forwarding an
/// explicit `jabber:server` root would make the stanza foreign to clients.
pub fn set_client_namespace(raw: &str) -> String {
    let Ok(document) = Document::parse(raw) else {
        return raw.to_owned();
    };
    let root = document.root_element();
    if root.tag_name().namespace() == Some("jabber:client") {
        return raw.to_owned();
    }
    let Some(opening) = parse_root_opening(raw) else {
        return raw.to_owned();
    };
    let namespace_attribute = opening.element_name.split_once(':').map_or_else(
        || "xmlns".to_owned(),
        |(prefix, _)| format!("xmlns:{prefix}"),
    );
    let mut rewritten = raw.to_owned();
    let mut removals = opening
        .attributes
        .iter()
        .filter(|attribute| attribute.name == namespace_attribute)
        .map(|attribute| attribute.removal_start..attribute.end)
        .collect::<Vec<_>>();
    removals.sort_by_key(|range| std::cmp::Reverse(range.start));
    for range in removals {
        rewritten.replace_range(range, "");
    }
    let Some(opening) = parse_root_opening(&rewritten) else {
        return raw.to_owned();
    };
    rewritten.insert_str(
        opening.insertion,
        &format!(" {namespace_attribute}='jabber:client'"),
    );
    rewritten
}

#[derive(Debug)]
pub struct RootOpeningAttribute {
    pub name: String,
    pub value: String,
    /// Includes the XML whitespace immediately preceding this attribute so
    /// removing it cannot concatenate the neighbouring attributes.
    pub removal_start: usize,
    pub end: usize,
}

#[derive(Debug)]
pub struct RootOpening {
    pub element_name: String,
    pub insertion: usize,
    pub attributes: Vec<RootOpeningAttribute>,
}

pub fn rewrite_root_attribute(
    raw: &str,
    name: &str,
    value: &str,
    ensure_client_namespace: bool,
) -> String {
    let Ok(document) = Document::parse(raw) else {
        return raw.to_owned();
    };
    let root = document.root_element();
    let Some(opening) = parse_root_opening(raw) else {
        return raw.to_owned();
    };

    let mut rewritten = raw.to_owned();
    let mut removals = opening
        .attributes
        .iter()
        .filter(|attribute| attribute.name == name)
        .map(|attribute| attribute.removal_start..attribute.end)
        .collect::<Vec<_>>();
    removals.sort_by_key(|range| std::cmp::Reverse(range.start));
    for range in removals {
        rewritten.replace_range(range, "");
    }

    // Attribute removal changes byte offsets, so locate the safe insertion
    // point again. The document was already validated and only complete
    // attributes were removed above.
    let Some(opening) = parse_root_opening(&rewritten) else {
        return raw.to_owned();
    };
    let namespace = if ensure_client_namespace && root.lookup_namespace_uri(None).is_none() {
        " xmlns='jabber:client'"
    } else {
        ""
    };
    rewritten.insert_str(
        opening.insertion,
        &format!("{namespace} {name}='{}'", attr_escape(value)),
    );
    rewritten
}

pub fn set_root_attribute(raw: &str, name: &str, value: &str) -> String {
    rewrite_root_attribute(raw, name, value, false)
}

pub fn append_root_element(raw: &str, child: &XmlElement) -> Option<String> {
    append_root_validated_fragment(raw, &child.finish())
}

pub fn append_root_validated_fragment(raw: &str, child: &str) -> Option<String> {
    // `raw` is commonly a stanza restored from durable storage. Validate it
    // under the same size/depth/node/attribute and restricted-XML policy as
    // the child before performing the lexical-preservation splice.
    ValidatedXmlFragment::parse(raw).ok()?;
    let child = ValidatedXmlFragment::parse(child).ok()?;
    let document = Document::parse(raw).ok()?;
    append_validated_child_to_range(raw, document.root_element().range(), child.as_str())
}

pub fn append_element_child(
    raw: &str,
    element_range: std::ops::Range<usize>,
    child: &XmlElement,
) -> Option<String> {
    ValidatedXmlFragment::parse(raw).ok()?;
    let child = ValidatedXmlFragment::parse(&child.finish()).ok()?;
    append_validated_child_to_range(raw, element_range, child.as_str())
}

pub fn append_validated_child_to_range(
    raw: &str,
    element_range: std::ops::Range<usize>,
    child: &str,
) -> Option<String> {
    let element = raw.get(element_range.clone())?;
    let opening = parse_root_opening(element)?;
    let mut rewritten = raw.to_owned();
    if element.as_bytes().get(opening.insertion) == Some(&b'/') {
        let closing = XmlElement::dynamic(&opening.element_name).ok()?.close();
        let insertion = element_range.start.checked_add(opening.insertion)?;
        rewritten.replace_range(insertion..insertion + 2, &format!(">{child}{closing}"));
        return Some(rewritten);
    }
    let closing = element.rfind("</")?;
    rewritten.insert_str(element_range.start.checked_add(closing)?, child);
    Some(rewritten)
}

/// Locate only attributes on the document's root start tag. This is a lexical
/// preservation pass performed after a real XML parse; it deliberately never
/// searches payload text or nested elements.
pub fn parse_root_opening(raw: &str) -> Option<RootOpening> {
    let bytes = raw.as_bytes();
    let mut cursor = raw.len() - raw.trim_start().len();
    if bytes.get(cursor) != Some(&b'<') {
        return None;
    }
    cursor += 1;
    if matches!(bytes.get(cursor), Some(b'!' | b'?' | b'/')) {
        return None;
    }
    let element_start = cursor;
    while let Some(byte) = bytes.get(cursor) {
        if byte.is_ascii_whitespace() || matches!(byte, b'>' | b'/') {
            break;
        }
        cursor += 1;
    }
    let element_name = raw.get(element_start..cursor)?.to_owned();

    let mut attributes = Vec::new();
    loop {
        let whitespace_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        match bytes.get(cursor) {
            Some(b'>') => {
                return Some(RootOpening {
                    element_name,
                    insertion: cursor,
                    attributes,
                });
            }
            Some(b'/') if bytes.get(cursor + 1) == Some(&b'>') => {
                return Some(RootOpening {
                    element_name,
                    insertion: cursor,
                    attributes,
                });
            }
            None => return None,
            _ => {}
        }

        let name_start = cursor;
        while let Some(byte) = bytes.get(cursor) {
            if byte.is_ascii_whitespace() || matches!(byte, b'=' | b'>' | b'/') {
                break;
            }
            cursor += 1;
        }
        let attribute_name = raw.get(name_start..cursor)?.to_owned();
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            return None;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let quote = *bytes.get(cursor)?;
        if quote != b'\'' && quote != b'"' {
            return None;
        }
        cursor += 1;
        let value_start = cursor;
        while bytes.get(cursor).copied() != Some(quote) {
            cursor += 1;
            if cursor >= bytes.len() {
                return None;
            }
        }
        cursor += 1;
        attributes.push(RootOpeningAttribute {
            name: attribute_name,
            value: raw.get(value_start..cursor - 1)?.to_owned(),
            removal_start: whitespace_start,
            end: cursor,
        });
    }
}

/// A TCP stanza with no namespace declaration inherits `jabber:client` from
/// the surrounding stream. An explicit empty default namespace is different:
/// it resets that inherited namespace and therefore cannot be a core stanza.
pub fn root_resets_default_namespace(raw: &str) -> bool {
    parse_root_opening(raw).is_some_and(|opening| {
        opening
            .attributes
            .iter()
            .any(|attribute| attribute.name == "xmlns" && attribute.value.is_empty())
    })
}
