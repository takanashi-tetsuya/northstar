use super::PRIVACY_NS;
use anyhow::Result;
use northstar_xep_0016::{
    PrivacyAction, PrivacyItem, PrivacyListName, PrivacyMatcher, MAX_PRIVACY_ITEMS,
};
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use std::collections::HashSet;

pub(super) fn valid_query_shell(query: Node<'_, '_>) -> bool {
    query.tag_name().name() == "query"
        && query.tag_name().namespace() == Some(PRIVACY_NS)
        && query.attributes().len() == 0
        && !has_non_whitespace_text(query)
        && query
            .children()
            .filter(Node::is_element)
            .all(|child| child.tag_name().namespace() == Some(PRIVACY_NS))
}

pub(super) fn element_children<'a, 'input>(node: Node<'a, 'input>) -> Vec<Node<'a, 'input>> {
    node.children().filter(Node::is_element).collect()
}

fn has_non_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(Node::is_text)
        .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
}

pub(super) fn parse_optional_name_control(
    node: Node<'_, '_>,
    expected: &str,
) -> Result<Option<String>, ()> {
    parse_name_control(node, expected).map(|name| name.map(PrivacyListName::into_inner))
}

pub(super) fn parse_name_control(
    node: Node<'_, '_>,
    expected: &str,
) -> Result<Option<PrivacyListName>, ()> {
    if node.tag_name().name() != expected
        || node.tag_name().namespace() != Some(PRIVACY_NS)
        || node.attributes().len() > 1
        || !element_children(node).is_empty()
        || has_non_whitespace_text(node)
    {
        return Err(());
    }
    match node.attribute("name") {
        Some(name) => PrivacyListName::parse(name).map(Some).ok_or(()),
        None => Ok(None),
    }
}

pub(super) fn parse_list(node: Node<'_, '_>) -> Result<(PrivacyListName, Vec<PrivacyItem>), ()> {
    if node.tag_name().name() != "list"
        || node.tag_name().namespace() != Some(PRIVACY_NS)
        || node.attributes().len() != 1
        || has_non_whitespace_text(node)
    {
        return Err(());
    }
    let name = node
        .attribute("name")
        .and_then(PrivacyListName::parse)
        .ok_or(())?;
    let children = element_children(node);
    if children.len() > MAX_PRIVACY_ITEMS {
        return Err(());
    }
    let mut orders = HashSet::with_capacity(children.len());
    let mut items = Vec::with_capacity(children.len());
    for item in children {
        if item.tag_name().name() != "item" || item.tag_name().namespace() != Some(PRIVACY_NS) {
            return Err(());
        }
        let allowed_attribute = |name: &str| matches!(name, "type" | "value" | "action" | "order");
        if item
            .attributes()
            .any(|attribute| !allowed_attribute(attribute.name()))
            || has_non_whitespace_text(item)
        {
            return Err(());
        }
        let order = item
            .attribute("order")
            .ok_or(())?
            .parse::<u32>()
            .map_err(|_| ())?;
        if !orders.insert(order) {
            return Err(());
        }
        let action = match item.attribute("action") {
            Some("allow") => PrivacyAction::Allow,
            Some("deny") => PrivacyAction::Deny,
            _ => return Err(()),
        };
        let matcher = match (item.attribute("type"), item.attribute("value")) {
            (None, None) => PrivacyMatcher::Everyone,
            (Some("jid"), Some(value)) => {
                let value = northstar_xmpp_types::jid::canonicalize(value).map_err(|_| ())?;
                PrivacyMatcher::Jid(value)
            }
            (Some("group"), Some(value)) if !value.is_empty() && value.len() <= 1023 => {
                PrivacyMatcher::Group(value.to_owned())
            }
            (Some("subscription"), Some(value))
                if matches!(value, "none" | "to" | "from" | "both") =>
            {
                PrivacyMatcher::Subscription(value.to_owned())
            }
            _ => return Err(()),
        };
        let mut message = false;
        let mut iq = false;
        let mut presence_in = false;
        let mut presence_out = false;
        let mut filters = HashSet::new();
        for filter in element_children(item) {
            if filter.tag_name().namespace() != Some(PRIVACY_NS)
                || filter.attributes().len() != 0
                || !element_children(filter).is_empty()
                || has_non_whitespace_text(filter)
                || !filters.insert(filter.tag_name().name())
            {
                return Err(());
            }
            match filter.tag_name().name() {
                "message" => message = true,
                "iq" => iq = true,
                "presence-in" => presence_in = true,
                "presence-out" => presence_out = true,
                _ => return Err(()),
            }
        }
        let (match_type, match_value) = matcher.matcher_parts();
        items.push(PrivacyItem {
            order,
            action,
            match_type,
            match_value,
            message,
            iq,
            presence_in,
            presence_out,
        });
    }
    items.sort_by_key(|item| item.order);
    Ok((name, items))
}

pub(super) fn render_list(name: &str, items: &[PrivacyItem]) -> String {
    let mut rendered_list = XmlElement::new("list").attr("name", name);
    for item in items {
        let mut rendered_item = XmlElement::new("item")
            .attr("action", item.action.as_str())
            .attr("order", item.order);
        if let (Some(kind), Some(value)) = (item.match_type, item.match_value.as_deref()) {
            rendered_item = rendered_item
                .attr("type", kind.as_str())
                .attr("value", value);
        }
        if item.message {
            rendered_item.push_child(XmlElement::new("message"));
        }
        if item.iq {
            rendered_item.push_child(XmlElement::new("iq"));
        }
        if item.presence_in {
            rendered_item.push_child(XmlElement::new("presence-in"));
        }
        if item.presence_out {
            rendered_item.push_child(XmlElement::new("presence-out"));
        }
        rendered_list.push_child(rendered_item);
    }
    XmlElement::namespaced("query", PRIVACY_NS)
        .child(rendered_list)
        .finish()
}
