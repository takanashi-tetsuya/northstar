//! Strict wire parsing for XEP-0059 Result Set Management XML elements.

use crate::bounds::RsmBounds;
use crate::constants::NAMESPACE;
use crate::error::RsmError;
use crate::models::{BeforeCursor, RsmFirstItem, RsmRequest, RsmResponse};
use roxmltree::{Document, Node};
use std::collections::BTreeSet;

/// Parse an <set xmlns='http://jabber.org/protocol/rsm'> request element using default bounds.
pub fn parse_rsm_element(set: Node<'_, '_>) -> Result<RsmRequest, RsmError> {
    parse_rsm_element_with_bounds(set, &RsmBounds::DEFAULT)
}

/// Parse an <set xmlns='http://jabber.org/protocol/rsm'> request element with custom bounds.
pub fn parse_rsm_element_with_bounds(
    set: Node<'_, '_>,
    bounds: &RsmBounds,
) -> Result<RsmRequest, RsmError> {
    if !set.is_element() {
        return Err(RsmError::UnexpectedTagName(
            set.tag_name().name().to_owned(),
        ));
    }
    if set.tag_name().name() != "set" {
        return Err(RsmError::UnexpectedTagName(
            set.tag_name().name().to_owned(),
        ));
    }
    if set.tag_name().namespace() != Some(NAMESPACE) {
        return Err(RsmError::UnexpectedNamespace {
            expected: NAMESPACE,
            actual: set.tag_name().namespace().map(str::to_owned),
        });
    }
    if let Some(attr) = set.attributes().next() {
        return Err(RsmError::UnexpectedAttribute(attr.name().to_owned()));
    }

    // Reject non-whitespace text in container
    if set
        .children()
        .filter(|c| c.is_text())
        .any(|c| c.text().is_some_and(|t| !t.trim().is_empty()))
    {
        return Err(RsmError::UnexpectedText);
    }

    let mut request = RsmRequest::default();
    let mut seen = BTreeSet::new();

    for child in set.children().filter(|c| c.is_element()) {
        if child.tag_name().namespace() != Some(NAMESPACE) {
            return Err(RsmError::UnexpectedNamespace {
                expected: NAMESPACE,
                actual: child.tag_name().namespace().map(str::to_owned),
            });
        }
        if let Some(attr) = child.attributes().next() {
            return Err(RsmError::UnexpectedAttribute(attr.name().to_owned()));
        }
        if child.children().any(|nested| nested.is_element()) {
            return Err(RsmError::UnexpectedChildElement(
                child
                    .children()
                    .find(|nested| nested.is_element())
                    .map(|n| n.tag_name().name().to_owned())
                    .unwrap_or_default(),
            ));
        }

        let name = child.tag_name().name();
        let static_name: &'static str = match name {
            "max" => "max",
            "after" => "after",
            "before" => "before",
            "index" => "index",
            other => return Err(RsmError::UnexpectedChildElement(other.to_owned())),
        };

        if !seen.insert(static_name) {
            return Err(RsmError::DuplicateElement(static_name));
        }

        let text: String = child
            .children()
            .filter(|c| c.is_text())
            .filter_map(|c| c.text())
            .collect();

        match static_name {
            "max" => {
                let parsed = text
                    .parse::<usize>()
                    .map_err(|_| RsmError::InvalidMax(text.clone()))?;
                bounds.validate_max(parsed)?;
                request.max = Some(parsed);
            }
            "after" => {
                bounds.validate_cursor(&text, "after")?;
                request.after = Some(text);
            }
            "before" => {
                if text.is_empty() {
                    request.before = Some(BeforeCursor::LastPage);
                } else {
                    bounds.validate_cursor(&text, "before")?;
                    request.before = Some(BeforeCursor::Item(text));
                }
            }
            "index" => {
                let parsed = text
                    .parse::<u64>()
                    .map_err(|_| RsmError::InvalidIndex(text.clone()))?;
                bounds.validate_index(parsed)?;
                request.index = Some(parsed);
            }
            _ => unreachable!(),
        }
    }

    let mut cursor_count = 0;
    if request.after.is_some() {
        cursor_count += 1;
    }
    if request.before.is_some() {
        cursor_count += 1;
    }
    if request.index.is_some() {
        cursor_count += 1;
    }
    if cursor_count > 1 {
        return Err(RsmError::MutuallyExclusiveCursors(
            "cannot combine after, before, or index in a single request",
        ));
    }

    Ok(request)
}

/// Find and parse an <set xmlns='http://jabber.org/protocol/rsm'> element from the children of a parent node.
///
/// Returns Ok(Some(request)) if exactly one RSM element is found,
/// Ok(None) if no RSM element is present,
/// or Err(RsmError) if duplicate RSM elements or malformed elements exist.
pub fn parse_rsm_from_parent<'a, 'input>(
    parent: Node<'a, 'input>,
) -> Result<Option<RsmRequest>, RsmError> {
    parse_rsm_from_parent_with_bounds(parent, &RsmBounds::DEFAULT)
}

/// Find and parse an <set xmlns='http://jabber.org/protocol/rsm'> element from parent with custom bounds.
pub fn parse_rsm_from_parent_with_bounds<'a, 'input>(
    parent: Node<'a, 'input>,
    bounds: &RsmBounds,
) -> Result<Option<RsmRequest>, RsmError> {
    let mut found = None;
    for child in parent
        .children()
        .filter(|c| c.is_element() && c.tag_name().namespace() == Some(NAMESPACE))
    {
        if child.tag_name().name() == "set" {
            if found.is_some() {
                return Err(RsmError::DuplicateElement("set"));
            }
            found = Some(parse_rsm_element_with_bounds(child, bounds)?);
        }
    }
    Ok(found)
}

/// Parse an <set xmlns='http://jabber.org/protocol/rsm'> response element.
pub fn parse_rsm_response_element(set: Node<'_, '_>) -> Result<RsmResponse, RsmError> {
    parse_rsm_response_element_with_bounds(set, &RsmBounds::DEFAULT)
}

/// Parse an <set xmlns='http://jabber.org/protocol/rsm'> response element with custom bounds.
pub fn parse_rsm_response_element_with_bounds(
    set: Node<'_, '_>,
    bounds: &RsmBounds,
) -> Result<RsmResponse, RsmError> {
    if !set.is_element() {
        return Err(RsmError::UnexpectedTagName(
            set.tag_name().name().to_owned(),
        ));
    }
    if set.tag_name().name() != "set" {
        return Err(RsmError::UnexpectedTagName(
            set.tag_name().name().to_owned(),
        ));
    }
    if set.tag_name().namespace() != Some(NAMESPACE) {
        return Err(RsmError::UnexpectedNamespace {
            expected: NAMESPACE,
            actual: set.tag_name().namespace().map(str::to_owned),
        });
    }
    if let Some(attr) = set.attributes().next() {
        return Err(RsmError::UnexpectedAttribute(attr.name().to_owned()));
    }
    if set
        .children()
        .filter(|c| c.is_text())
        .any(|c| c.text().is_some_and(|t| !t.trim().is_empty()))
    {
        return Err(RsmError::UnexpectedText);
    }

    let mut response = RsmResponse::default();
    let mut seen = BTreeSet::new();

    for child in set.children().filter(|c| c.is_element()) {
        if child.tag_name().namespace() != Some(NAMESPACE) {
            return Err(RsmError::UnexpectedNamespace {
                expected: NAMESPACE,
                actual: child.tag_name().namespace().map(str::to_owned),
            });
        }
        if child.children().any(|nested| nested.is_element()) {
            return Err(RsmError::UnexpectedChildElement(
                child
                    .children()
                    .find(|nested| nested.is_element())
                    .map(|n| n.tag_name().name().to_owned())
                    .unwrap_or_default(),
            ));
        }

        let name = child.tag_name().name();
        let static_name: &'static str = match name {
            "first" => "first",
            "last" => "last",
            "count" => "count",
            "index" => "index",
            other => return Err(RsmError::UnexpectedChildElement(other.to_owned())),
        };

        if !seen.insert(static_name) {
            return Err(RsmError::DuplicateElement(static_name));
        }

        let text: String = child
            .children()
            .filter(|c| c.is_text())
            .filter_map(|c| c.text())
            .collect();

        match static_name {
            "first" => {
                let index_attr = child.attribute("index");
                for attr in child.attributes() {
                    if attr.name() != "index" {
                        return Err(RsmError::UnexpectedAttribute(attr.name().to_owned()));
                    }
                }
                let index = if let Some(idx_str) = index_attr {
                    let parsed = idx_str
                        .parse::<u64>()
                        .map_err(|_| RsmError::InvalidIndex(idx_str.to_owned()))?;
                    bounds.validate_index(parsed)?;
                    Some(parsed)
                } else {
                    None
                };
                bounds.validate_cursor(&text, "first")?;
                response.first = Some(RsmFirstItem { value: text, index });
            }
            "last" => {
                if let Some(attr) = child.attributes().next() {
                    return Err(RsmError::UnexpectedAttribute(attr.name().to_owned()));
                }
                bounds.validate_cursor(&text, "last")?;
                response.last = Some(text);
            }
            "count" => {
                if let Some(attr) = child.attributes().next() {
                    return Err(RsmError::UnexpectedAttribute(attr.name().to_owned()));
                }
                let parsed = text
                    .parse::<u64>()
                    .map_err(|_| RsmError::InvalidCount(text.clone()))?;
                response.count = Some(parsed);
            }
            "index" => {
                if let Some(attr) = child.attributes().next() {
                    return Err(RsmError::UnexpectedAttribute(attr.name().to_owned()));
                }
                let parsed = text
                    .parse::<u64>()
                    .map_err(|_| RsmError::InvalidIndex(text.clone()))?;
                bounds.validate_index(parsed)?;
                response.index = Some(parsed);
            }
            _ => unreachable!(),
        }
    }

    Ok(response)
}

/// Parse an RSM request from an XML string snippet.
pub fn parse_rsm_str(xml: &str) -> Result<RsmRequest, RsmError> {
    parse_rsm_str_with_bounds(xml, &RsmBounds::DEFAULT)
}

/// Parse an RSM request from an XML string snippet with custom bounds.
pub fn parse_rsm_str_with_bounds(xml: &str, bounds: &RsmBounds) -> Result<RsmRequest, RsmError> {
    let doc = Document::parse(xml).map_err(|e| RsmError::MalformedXml(e.to_string()))?;
    parse_rsm_element_with_bounds(doc.root_element(), bounds)
}

/// Parse an RSM response from an XML string snippet.
pub fn parse_rsm_response_str(xml: &str) -> Result<RsmResponse, RsmError> {
    parse_rsm_response_str_with_bounds(xml, &RsmBounds::DEFAULT)
}

/// Parse an RSM response from an XML string snippet with custom bounds.
pub fn parse_rsm_response_str_with_bounds(
    xml: &str,
    bounds: &RsmBounds,
) -> Result<RsmResponse, RsmError> {
    let doc = Document::parse(xml).map_err(|e| RsmError::MalformedXml(e.to_string()))?;
    parse_rsm_response_element_with_bounds(doc.root_element(), bounds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_response_element_direct() {
        let doc = Document::parse(
            "<set xmlns='http://jabber.org/protocol/rsm'><first>f</first><last>l</last><count>2</count></set>",
        )
        .unwrap();
        let resp = parse_rsm_response_element(doc.root_element()).unwrap();
        assert_eq!(resp.first_value(), Some("f"));
        assert_eq!(resp.last_value(), Some("l"));
        assert_eq!(resp.count, Some(2));
    }

    #[test]
    fn response_rejects_invalid_first_attributes() {
        let doc = Document::parse(
            "<set xmlns='http://jabber.org/protocol/rsm'><first bad='1'>f</first></set>",
        )
        .unwrap();
        assert!(matches!(
            parse_rsm_response_element(doc.root_element()),
            Err(RsmError::UnexpectedAttribute(_))
        ));
    }
}
