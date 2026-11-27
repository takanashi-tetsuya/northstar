use super::codec::{element_children, parse_name_control, render_list, valid_query_shell};
use super::{privacy_iq_addressed_to_account, PrivacySession, PRIVACY_NS};
use anyhow::Result;
use northstar_roster_application::privacy::commands::{ActorOutcome, PolicyCommandRepository};
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
    let Some(actor) = session.roster_actor() else {
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
        let Ok(Some(name)) = parse_name_control(list, "list") else {
            return Ok(iq_error(id, "bad-request"));
        };
        match session
            .privacy_commands()
            .read_privacy_list(&actor, &name)
            .await?
        {
            ActorOutcome::Current(Some(items)) => render_list(name.as_str(), &items),
            ActorOutcome::Current(None) => return Ok(iq_error(id, "item-not-found")),
            ActorOutcome::Stale => return Ok(iq_error(id, "not-authorized")),
        }
    } else {
        let ActorOutcome::Current(overview) = session
            .privacy_commands()
            .read_privacy_overview(&actor)
            .await?
        else {
            return Ok(iq_error(id, "not-authorized"));
        };
        let mut payload = XmlElement::namespaced("query", PRIVACY_NS);
        if let Some(name) = overview.active {
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
