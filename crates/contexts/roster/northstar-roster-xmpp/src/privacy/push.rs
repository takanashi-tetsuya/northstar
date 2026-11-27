use super::{PrivacySession, PRIVACY_NS};
use anyhow::Result;
use northstar_xml_builder::XmlElement;
use uuid::Uuid;

pub(super) async fn push_privacy_list_change<S: PrivacySession>(
    session: &S,
    name: &str,
) -> Result<Option<String>> {
    let Some(actor) = session.roster_actor() else {
        return Ok(None);
    };
    let account = actor.bare_jid();
    let base = privacy_push_base(account, name, || session.roster_events().new_protocol_id())?;
    Ok(session.privacy_push_change(&actor, name, &base).await)
}

fn privacy_push_base(account: &str, name: &str, new_id: impl FnOnce() -> Uuid) -> Result<String> {
    let push_id = format!("privacy-{}", new_id());
    let payload = XmlElement::namespaced("query", PRIVACY_NS)
        .child(XmlElement::new("list").attr("name", name))
        .finish();
    privacy_push_stanza(account, account, &push_id, &payload)
}

pub(super) fn privacy_push_stanza(from: &str, to: &str, id: &str, payload: &str) -> Result<String> {
    Ok(XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "set")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .validated_fragment(payload)?
        .finish())
}

#[cfg(test)]
mod tests;
