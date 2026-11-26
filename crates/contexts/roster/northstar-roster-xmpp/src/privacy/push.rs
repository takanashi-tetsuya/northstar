use super::{PrivacySession, PRIVACY_NS};
use anyhow::Result;
use northstar_xml_builder::XmlElement;

pub(super) async fn push_privacy_list_change<S: PrivacySession>(
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

pub(super) fn privacy_push_stanza(from: &str, to: &str, id: &str, payload: &str) -> Result<String> {
    Ok(XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "set")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .validated_fragment(payload)?
        .finish())
}
