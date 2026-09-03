//! Capability-free Result Set Management (XEP-0059) models, parsing, validation, and paging helper for XEP-0060.

use crate::constants::{MAX_RSM_PAGE_SIZE, NS_RSM};
use crate::error::PubSubError;
use crate::models::valid_item_id;
use crate::xml::XmlElement;
use roxmltree::Node;
use std::collections::BTreeSet;

/// A validated XEP-0059 Result Set Management request payload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RsmRequest {
    pub max: Option<usize>,
    pub after: Option<String>,
    /// `Some(None)` denotes an empty `<before/>` tag requesting the last page of results.
    /// `Some(Some(id))` denotes `<before>id</before>` requesting the page prior to `id`.
    pub before: Option<Option<String>>,
    pub index: Option<usize>,
}

/// Metadata describing a returned page of results.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RsmResponse {
    pub first: Option<(usize, String)>,
    pub last: Option<String>,
    pub count: usize,
}

/// Parse and validate an RSM `<set xmlns='http://jabber.org/protocol/rsm'>` element.
pub fn parse_rsm_element(set: Node<'_, '_>) -> Result<RsmRequest, PubSubError> {
    if set.tag_name().name() != "set"
        || set.tag_name().namespace() != Some(NS_RSM)
        || set.attributes().len() != 0
        || set
            .children()
            .filter(|c| c.is_text())
            .any(|c| c.text().is_some_and(|t| !t.trim().is_empty()))
    {
        return Err(PubSubError::bad_request());
    }

    let mut result = RsmRequest::default();
    let mut seen = BTreeSet::new();

    for child in set.children().filter(|c| c.is_element()) {
        if child.tag_name().namespace() != Some(NS_RSM)
            || child.attributes().len() != 0
            || child.children().any(|nested| nested.is_element())
            || !seen.insert(child.tag_name().name())
        {
            return Err(PubSubError::bad_request());
        }

        let text = child
            .children()
            .filter(|c| c.is_text())
            .filter_map(|c| c.text())
            .collect::<String>();

        match child.tag_name().name() {
            "max" => {
                let parsed = text
                    .parse::<usize>()
                    .map_err(|_| PubSubError::bad_request())?;
                if parsed > MAX_RSM_PAGE_SIZE {
                    return Err(PubSubError::bad_request());
                }
                result.max = Some(parsed);
            }
            "after" => {
                if !valid_item_id(&text) {
                    return Err(PubSubError::bad_request());
                }
                result.after = Some(text);
            }
            "before" => {
                if text.is_empty() {
                    result.before = Some(None);
                } else {
                    if !valid_item_id(&text) {
                        return Err(PubSubError::bad_request());
                    }
                    result.before = Some(Some(text));
                }
            }
            "index" => {
                let idx = text
                    .parse::<usize>()
                    .map_err(|_| PubSubError::bad_request())?;
                result.index = Some(idx);
            }
            _ => return Err(PubSubError::bad_request()),
        }
    }

    if result.after.is_some() && result.before.is_some() {
        return Err(PubSubError::bad_request());
    }

    Ok(result)
}

/// Build an `<set xmlns='http://jabber.org/protocol/rsm'>` XML element for an RSM response.
pub fn build_rsm_set_element(
    first: Option<(usize, &str)>,
    last: Option<&str>,
    total: usize,
) -> XmlElement {
    let mut set = XmlElement::namespaced("set", NS_RSM);
    if let Some((index, value)) = first {
        set.push_child(
            XmlElement::new("first")
                .attr("index", index)
                .text(value.to_owned()),
        );
    }
    if let Some(value) = last {
        set.push_child(XmlElement::new("last").text(value.to_owned()));
    }
    set.push_child(XmlElement::new("count").text(total.to_string()));
    set
}

/// Render an `<set xmlns='http://jabber.org/protocol/rsm'>` XML string.
pub fn build_rsm_set(first: Option<(usize, &str)>, last: Option<&str>, total: usize) -> String {
    build_rsm_set_element(first, last, total).finish()
}

/// Pure deterministic pagination helper for in-memory item / disco lists.
pub fn paginate_items<T, FId>(
    items: &[T],
    request: &RsmRequest,
    fallback_max: usize,
    get_id: FId,
) -> Result<(Vec<T>, RsmResponse), PubSubError>
where
    T: Clone,
    FId: Fn(&T) -> &str,
{
    let total = items.len();
    let max = request.max.unwrap_or(fallback_max).min(MAX_RSM_PAGE_SIZE);

    let cursor_index = |cursor: &str| {
        items
            .iter()
            .position(|item| get_id(item) == cursor)
            .ok_or_else(PubSubError::item_not_found)
    };

    let (start, end) = if let Some(ref after) = request.after {
        let start = cursor_index(after)?.saturating_add(1).min(total);
        (start, start.saturating_add(max).min(total))
    } else if let Some(ref before) = request.before {
        let end = match before {
            Some(cursor) => cursor_index(cursor)?,
            None => total,
        };
        (end.saturating_sub(max), end)
    } else if let Some(index) = request.index {
        let start = index.min(total);
        (start, start.saturating_add(max).min(total))
    } else {
        (0, max.min(total))
    };

    let page: Vec<T> = items[start..end].to_vec();

    let first = page.first().map(|item| (start, get_id(item).to_owned()));
    let last = page.last().map(|item| get_id(item).to_owned());

    Ok((
        page,
        RsmResponse {
            first,
            last,
            count: total,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn parses_valid_rsm_elements() {
        let doc = Document::parse(
            "<set xmlns='http://jabber.org/protocol/rsm'><max>20</max><after>item-1</after></set>",
        )
        .unwrap();
        let rsm = parse_rsm_element(doc.root_element()).unwrap();
        assert_eq!(rsm.max, Some(20));
        assert_eq!(rsm.after.as_deref(), Some("item-1"));
        assert_eq!(rsm.before, None);

        let doc2 =
            Document::parse("<set xmlns='http://jabber.org/protocol/rsm'><before/></set>").unwrap();
        let rsm2 = parse_rsm_element(doc2.root_element()).unwrap();
        assert_eq!(rsm2.before, Some(None));
    }

    #[test]
    fn rejects_conflicting_or_overflow_rsm() {
        let doc =
            Document::parse("<set xmlns='http://jabber.org/protocol/rsm'><max>1001</max></set>")
                .unwrap();
        assert!(parse_rsm_element(doc.root_element()).is_err());

        let doc2 = Document::parse(
            "<set xmlns='http://jabber.org/protocol/rsm'><after>a</after><before>b</before></set>",
        )
        .unwrap();
        assert!(parse_rsm_element(doc2.root_element()).is_err());
    }

    #[test]
    fn paginates_items_forward_and_backward() {
        let items = vec!["item-1", "item-2", "item-3", "item-4", "item-5"];

        // First page of 2
        let req = RsmRequest {
            max: Some(2),
            ..Default::default()
        };
        let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
        assert_eq!(page, vec!["item-1", "item-2"]);
        assert_eq!(resp.first, Some((0, "item-1".to_string())));
        assert_eq!(resp.last, Some("item-2".to_string()));
        assert_eq!(resp.count, 5);

        // After item-2
        let req = RsmRequest {
            max: Some(2),
            after: Some("item-2".to_string()),
            ..Default::default()
        };
        let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
        assert_eq!(page, vec!["item-3", "item-4"]);
        assert_eq!(resp.first, Some((2, "item-3".to_string())));

        // Last page (before empty)
        let req = RsmRequest {
            max: Some(2),
            before: Some(None),
            ..Default::default()
        };
        let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
        assert_eq!(page, vec!["item-4", "item-5"]);
        assert_eq!(resp.first, Some((3, "item-4".to_string())));
    }
}
