//! XEP-0030 item queries paged by XEP-0059.

use crate::XmlElement;

const RSM_NS: &str = "http://jabber.org/protocol/rsm";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoItemsRequest {
    pub node: Option<String>,
    pub max: i64,
    pub after: Option<String>,
    /// `Some(None)` represents an empty `<before/>`, i.e. the last page.
    pub before: Option<Option<String>>,
}

pub fn parse_disco_items_query(
    request: roxmltree::Node<'_, '_>,
) -> std::result::Result<DiscoItemsRequest, &'static str> {
    if !request
        .attributes()
        .all(|attribute| attribute.namespace().is_none() && attribute.name() == "node")
        || request
            .attribute("node")
            .is_some_and(|node| node.is_empty() || node.len() > 1_024)
        || request
            .children()
            .filter(|child| child.is_text())
            .any(|child| !child.text().unwrap_or_default().trim().is_empty())
    {
        return Err("bad-request");
    }
    let elements = request
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if elements.len() > 1 {
        return Err("bad-request");
    }
    let mut parsed = DiscoItemsRequest {
        node: request.attribute("node").map(str::to_owned),
        max: 100,
        after: None,
        before: None,
    };
    let Some(set) = elements.first().copied() else {
        return Ok(parsed);
    };
    if set.tag_name().name() != "set"
        || set.tag_name().namespace() != Some("http://jabber.org/protocol/rsm")
        || set.attributes().len() != 0
        || set
            .children()
            .filter(|child| child.is_text())
            .any(|child| !child.text().unwrap_or_default().trim().is_empty())
    {
        return Err("bad-request");
    }
    let mut seen = std::collections::HashSet::new();
    for child in set.children().filter(|child| child.is_element()) {
        if child.tag_name().namespace() != Some("http://jabber.org/protocol/rsm")
            || !matches!(child.tag_name().name(), "max" | "after" | "before")
            || !seen.insert(child.tag_name().name())
            || child.attributes().len() != 0
            || child.children().any(|nested| nested.is_element())
        {
            return Err("bad-request");
        }
        let value = child.text().unwrap_or_default();
        match child.tag_name().name() {
            "max" => {
                let max = value.parse::<i64>().map_err(|_| "bad-request")?;
                if max < 0 {
                    return Err("bad-request");
                }
                parsed.max = max.min(100);
            }
            "after" => {
                if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
                    return Err("bad-request");
                }
                parsed.after = Some(value.to_owned());
            }
            "before" => {
                if value.len() > 1_024 || value.chars().any(char::is_control) {
                    return Err("bad-request");
                }
                parsed.before = Some((!value.is_empty()).then(|| value.to_owned()));
            }
            _ => unreachable!(),
        }
    }
    if parsed.after.is_some() && parsed.before.is_some() {
        return Err("bad-request");
    }
    Ok(parsed)
}

pub fn disco_rsm_result(
    first: Option<&str>,
    last: Option<&str>,
    first_index: i64,
    total: i64,
) -> String {
    disco_rsm_result_element(first, last, first_index, total).finish()
}

pub fn disco_rsm_result_element(
    first: Option<&str>,
    last: Option<&str>,
    first_index: i64,
    total: i64,
) -> XmlElement {
    let mut set = XmlElement::namespaced("set", RSM_NS);
    if let (Some(first), Some(last)) = (first, last) {
        set.push_child(
            XmlElement::new("first")
                .attr("index", first_index)
                .text(first.to_owned()),
        );
        set.push_child(XmlElement::new("last").text(last.to_owned()));
    }
    set.push_child(XmlElement::new("count").text(total.to_string()));
    set
}
