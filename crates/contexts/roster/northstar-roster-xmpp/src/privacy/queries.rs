use super::codec::{element_children, render_list, valid_named_empty_control, valid_query_shell};
use super::{privacy_iq_addressed_to_account, PrivacySession, PRIVACY_NS};
use anyhow::Result;
use northstar_xml_builder::{
    stanza::{iq_error, iq_result},
    XmlElement,
};
use roxmltree::Node;

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
