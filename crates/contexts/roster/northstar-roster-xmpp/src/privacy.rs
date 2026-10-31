//! XEP-0016 privacy lists.

use anyhow::Result;
use northstar_roster_application::privacy::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyListMutationOutcome, PrivacyMatchType,
    PrivacyRepository, PrivacySelectionOutcome, PrivacyService, MAX_PRIVACY_ITEMS,
};
use northstar_xml_builder::{
    stanza::{iq_error, iq_result},
    XmlElement,
};
use roxmltree::Node;
use std::collections::HashSet;

const PRIVACY_NS: &str = northstar_xep_0016::NAMESPACE;
const MAX_PRIVACY_QUERY_BYTES: usize = 64 * 1024;

/// What a client session provides to the XEP-0016 handlers.
pub trait PrivacySession: crate::SessionIdentity {
    /// The session's bound full JID, or `None` before resource binding.
    fn privacy_full_jid(&self) -> Option<&str>;
    /// The id of the session's connection.
    fn privacy_connection_id(&self) -> uuid::Uuid;
    /// The privacy service, over the repository the composition root binds.
    fn privacy_service(&self) -> &PrivacyService<impl PrivacyRepository>;
    /// Records that this session asked for privacy lists, which makes it a target of later pushes.
    fn privacy_mark_requested(&self);
    /// The name of the session's active list.
    fn privacy_active_list(&self) -> Option<String>;
    /// Replaces the name of the session's active list.
    fn privacy_set_active_list(&self, name: Option<String>);
    /// How many resources of `account` are connected to this node.
    fn privacy_local_resources(&self, account: &str) -> usize;
    /// Whether a resource of `account` is connected to another node.
    fn privacy_has_remote_resources(
        &self,
        account: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    /// Whether a resource of `account` on this node has the list `name` active.
    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool;
    /// Delivers the push `base`, addressed to `account`, to every other resource of the account
    /// that asked for privacy lists, on this node and on the others. Returns the push for this
    /// session when it asked for them, for the caller to send after its reply.
    fn privacy_push_change(
        &self,
        account: &str,
        name: &str,
        base: &str,
    ) -> impl std::future::Future<Output = Option<String>> + Send;
}

/// Handles a privacy-list query IQ get request, returning the reply stanza.
pub async fn privacy_get<S: PrivacySession>(
    session: &S,
    id: &str,
    root: Node<'_, '_>,
    query: Node<'_, '_>,
) -> Result<String> {
    let Some(user) = session.session_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    if !privacy_iq_addressed_to_account(root, session.privacy_full_jid())
        || !valid_query_shell(query)
    {
        return Ok(iq_error(id, "bad-request"));
    }
    session.privacy_mark_requested();
    let children = element_children(query);
    if children.len() > 1 {
        return Ok(iq_error(id, "bad-request"));
    }
    let payload = if let Some(list) = children.first().copied() {
        if !valid_named_empty_control(list, "list") {
            return Ok(iq_error(id, "bad-request"));
        }
        let name = list.attribute("name").unwrap_or_default();
        let Some(list) = session.privacy_service().list(user.id, name).await? else {
            return Ok(iq_error(id, "item-not-found"));
        };
        render_list(&list)
    } else {
        let overview = session.privacy_service().overview(user.id).await?;
        let active = session.privacy_active_list();
        let mut payload = XmlElement::namespaced("query", PRIVACY_NS);
        if let Some(name) = active {
            payload.push_child(XmlElement::new("active").attr("name", name));
        }
        if let Some(name) = overview.default {
            payload.push_child(XmlElement::new("default").attr("name", name));
        }
        for name in overview.names {
            payload.push_child(XmlElement::new("list").attr("name", name));
        }
        payload.finish()
    };
    Ok(iq_result(id, &payload))
}

/// Handles a privacy-list query IQ set request, returning the reply and an optional push.
pub async fn privacy_set<S: PrivacySession>(
    session: &S,
    id: &str,
    root: Node<'_, '_>,
    query: Node<'_, '_>,
) -> Result<(String, Option<String>)> {
    let Some(user) = session.session_account() else {
        return Ok((iq_error(id, "not-authorized"), None));
    };
    if !privacy_iq_addressed_to_account(root, session.privacy_full_jid())
        || !valid_query_shell(query)
        || query.document().input_text().len() > MAX_PRIVACY_QUERY_BYTES
    {
        return Ok((iq_error(id, "bad-request"), None));
    }
    let children = element_children(query);
    if children.len() != 1 {
        return Ok((iq_error(id, "bad-request"), None));
    }
    let control = children[0];
    let mut changed_list = None;
    let result = match control.tag_name().name() {
        "active" => {
            let Ok(name) = parse_optional_name_control(control, "active") else {
                return Ok((iq_error(id, "bad-request"), None));
            };
            match session
                .privacy_service()
                .select_active(user.id, session.privacy_connection_id(), name.as_deref())
                .await?
            {
                PrivacySelectionOutcome::Updated => {}
                PrivacySelectionOutcome::Missing => {
                    return Ok((iq_error(id, "item-not-found"), None));
                }
                PrivacySelectionOutcome::Conflict => {
                    unreachable!("active-list selection has no resource conflict")
                }
            }
            session.privacy_set_active_list(name);
            Ok(())
        }
        "default" => {
            let Ok(name) = parse_optional_name_control(control, "default") else {
                return Ok((iq_error(id, "bad-request"), None));
            };
            let account = format!("{}@{}", user.username, session.session_local_domain());
            let remote_resource_exists = session.privacy_has_remote_resources(&account).await?;
            match session
                .privacy_service()
                .select_default(
                    user.id,
                    name.as_deref(),
                    session.privacy_local_resources(&account),
                    remote_resource_exists,
                )
                .await?
            {
                PrivacySelectionOutcome::Updated => Ok(()),
                PrivacySelectionOutcome::Missing => Err("item-not-found"),
                PrivacySelectionOutcome::Conflict => Err("conflict"),
            }
        }
        "list" => {
            let Ok(list) = parse_list(control) else {
                return Ok((iq_error(id, "bad-request"), None));
            };
            if list.items.is_empty() {
                let active_somewhere = session.privacy_list_active_locally(
                    &format!("{}@{}", user.username, session.session_local_domain()),
                    &list.name,
                );
                match session
                    .privacy_service()
                    .remove_list(user.id, &list.name, active_somewhere)
                    .await?
                {
                    PrivacyListMutationOutcome::Removed => {
                        changed_list = Some(list.name.clone());
                        Ok(())
                    }
                    PrivacyListMutationOutcome::Missing => Err("item-not-found"),
                    PrivacyListMutationOutcome::Conflict => Err("conflict"),
                    PrivacyListMutationOutcome::Stored
                    | PrivacyListMutationOutcome::QuotaExceeded => {
                        unreachable!("remove-list returned a replace outcome")
                    }
                }
            } else {
                match session
                    .privacy_service()
                    .replace_list(user.id, &list)
                    .await?
                {
                    PrivacyListMutationOutcome::Stored => {
                        changed_list = Some(list.name.clone());
                        Ok(())
                    }
                    PrivacyListMutationOutcome::QuotaExceeded => Err("resource-constraint"),
                    PrivacyListMutationOutcome::Removed
                    | PrivacyListMutationOutcome::Missing
                    | PrivacyListMutationOutcome::Conflict => {
                        unreachable!("replace-list returned a remove outcome")
                    }
                }
            }
        }
        _ => return Ok((iq_error(id, "bad-request"), None)),
    };
    let response = match result {
        Ok(()) => iq_result(id, ""),
        Err(condition) => return Ok((iq_error(id, condition), None)),
    };
    let Some(name) = changed_list else {
        return Ok((response, None));
    };
    let current_push = push_privacy_list_change(session, &user.username, &name).await?;
    Ok((response, current_push))
}

async fn push_privacy_list_change<S: PrivacySession>(
    session: &S,
    username: &str,
    name: &str,
) -> Result<Option<String>> {
    let account = format!("{}@{}", username, session.session_local_domain());
    let push_id = format!("privacy-{}", uuid::Uuid::new_v4());
    let payload = XmlElement::namespaced("query", PRIVACY_NS)
        .child(XmlElement::new("list").attr("name", name))
        .finish();
    let base = privacy_push_stanza(&account, &account, &push_id, &payload)?;
    Ok(session.privacy_push_change(&account, name, &base).await)
}

fn privacy_push_stanza(from: &str, to: &str, id: &str, payload: &str) -> Result<String> {
    Ok(XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "set")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .validated_fragment(payload)?
        .finish())
}

fn privacy_iq_addressed_to_account(root: Node<'_, '_>, full_jid: Option<&str>) -> bool {
    match root.attribute("to") {
        None => true,
        Some(to) => full_jid
            .and_then(|jid| northstar_xmpp_types::jid::canonical_bare_key(jid).ok())
            .is_some_and(|owner| {
                northstar_xmpp_types::jid::canonical_bare_key(to).is_ok_and(|to| to == owner)
            }),
    }
}

fn valid_query_shell(query: Node<'_, '_>) -> bool {
    query.tag_name().name() == "query"
        && query.tag_name().namespace() == Some(PRIVACY_NS)
        && query.attributes().len() == 0
        && !has_non_whitespace_text(query)
        && query
            .children()
            .filter(Node::is_element)
            .all(|child| child.tag_name().namespace() == Some(PRIVACY_NS))
}

fn element_children<'a, 'input>(node: Node<'a, 'input>) -> Vec<Node<'a, 'input>> {
    node.children().filter(Node::is_element).collect()
}

fn has_non_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(Node::is_text)
        .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
}

fn valid_named_empty_control(node: Node<'_, '_>, expected: &str) -> bool {
    node.tag_name().name() == expected
        && node.tag_name().namespace() == Some(PRIVACY_NS)
        && node.attributes().len() == 1
        && node.attribute("name").is_some_and(valid_name)
        && element_children(node).is_empty()
        && !has_non_whitespace_text(node)
}

fn parse_optional_name_control(node: Node<'_, '_>, expected: &str) -> Result<Option<String>, ()> {
    if node.tag_name().name() != expected
        || node.tag_name().namespace() != Some(PRIVACY_NS)
        || node.attributes().len() > 1
        || !element_children(node).is_empty()
        || has_non_whitespace_text(node)
    {
        return Err(());
    }
    match node.attribute("name") {
        Some(name) if valid_name(name) => Ok(Some(name.to_owned())),
        Some(_) => Err(()),
        None => Ok(None),
    }
}

fn parse_list(node: Node<'_, '_>) -> Result<PrivacyList, ()> {
    if node.tag_name().name() != "list"
        || node.tag_name().namespace() != Some(PRIVACY_NS)
        || node.attributes().len() != 1
        || has_non_whitespace_text(node)
    {
        return Err(());
    }
    let name = node
        .attribute("name")
        .filter(|name| valid_name(name))
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
        let (match_type, match_value) = match (item.attribute("type"), item.attribute("value")) {
            (None, None) => (None, None),
            (Some("jid"), Some(value)) => {
                let value = northstar_xmpp_types::jid::canonicalize(value).map_err(|_| ())?;
                (Some(PrivacyMatchType::Jid), Some(value))
            }
            (Some("group"), Some(value)) if !value.is_empty() && value.len() <= 1023 => {
                (Some(PrivacyMatchType::Group), Some(value.to_owned()))
            }
            (Some("subscription"), Some(value))
                if matches!(value, "none" | "to" | "from" | "both") =>
            {
                (Some(PrivacyMatchType::Subscription), Some(value.to_owned()))
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
    Ok(PrivacyList {
        name: name.to_owned(),
        items,
    })
}

fn render_list(list: &PrivacyList) -> String {
    let mut rendered_list = XmlElement::new("list").attr("name", &list.name);
    for item in &list.items {
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

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse(xml: &str) -> PrivacyList {
        let document = Document::parse(xml).unwrap();
        parse_list(document.root_element()).unwrap()
    }

    #[test]
    fn parses_canonical_bounded_ordered_rules() {
        let list = parse(
            "<list xmlns='jabber:iq:privacy' name='work'>\
             <item type='jid' value='ALICE@Example.test/Phone' action='deny' order='20'><message/><presence-in/></item>\
             <item action='allow' order='30'/></list>",
        );
        assert_eq!(
            list.items[0].match_value.as_deref(),
            Some("alice@example.test/Phone")
        );
        assert!(list.items[0].message && list.items[0].presence_in);
        assert_eq!(list.items[1].match_type, None);
    }

    #[test]
    fn rejects_ambiguous_duplicate_and_unknown_controls() {
        for xml in [
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='1'/><item action='allow' order='1'/></list>",
            "<list xmlns='jabber:iq:privacy' name='x'><item type='jid' action='deny' order='1'/></list>",
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='1'><message/><message/></item></list>",
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='1'><unknown/></item></list>",
            "<list xmlns='jabber:iq:privacy' name='x'><foreign/></list>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(
                parse_list(document.root_element()).is_err(),
                "accepted {xml}"
            );
        }
    }

    #[test]
    fn rendering_is_stable_and_escapes_values() {
        let list = PrivacyList {
            name: "a'b".to_owned(),
            items: vec![PrivacyItem {
                order: 1,
                action: PrivacyAction::Deny,
                match_type: Some(PrivacyMatchType::Group),
                match_value: Some("R&D".to_owned()),
                message: true,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        };
        let xml = render_list(&list);
        assert!(Document::parse(&xml).is_ok());
        assert!(xml.contains("a&apos;b") && xml.contains("R&amp;D"));
    }

    #[test]
    fn accepts_full_xs_unsigned_int_order_range() {
        let list = parse(
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='4294967295'/></list>",
        );
        assert_eq!(list.items[0].order, u32::MAX);
        let document = Document::parse(
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='4294967296'/></list>",
        )
        .unwrap();
        assert!(parse_list(document.root_element()).is_err());
    }

    #[test]
    fn privacy_push_is_a_strict_addressed_iq_set() {
        let push = privacy_push_stanza(
            "alice@example.test",
            "alice@example.test/Phone",
            "privacy-1",
            "<query xmlns='jabber:iq:privacy'><list name='work'/></query>",
        )
        .unwrap();
        let document = Document::parse(&push).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("type"), Some("set"));
        assert_eq!(root.attribute("from"), Some("alice@example.test"));
        assert_eq!(root.attribute("to"), Some("alice@example.test/Phone"));
        assert_eq!(
            root.children()
                .find(Node::is_element)
                .unwrap()
                .tag_name()
                .namespace(),
            Some(PRIVACY_NS)
        );
    }

    #[test]
    fn default_change_conflicts_with_any_other_connected_resource() {
        assert!(!northstar_roster_application::privacy::default_change_conflicts(1, false));
        assert!(northstar_roster_application::privacy::default_change_conflicts(2, false));
        assert!(northstar_roster_application::privacy::default_change_conflicts(1, true));
    }
}
