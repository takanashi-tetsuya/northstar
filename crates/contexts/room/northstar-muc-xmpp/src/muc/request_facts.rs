use northstar_room_core::MucRequestFacts;
use northstar_xml_builder::{message_policy::add_delay_from, XmlElement};
use uuid::Uuid;

pub(crate) fn offline_delay(stanza: &str, room_jid: &str, facts: MucRequestFacts) -> String {
    add_delay_from(stanza, facts.at, Some(room_jid))
}

pub(crate) fn moderated_retraction(
    facts: MucRequestFacts,
    action_id: Option<Uuid>,
    moderated: XmlElement,
) -> XmlElement {
    XmlElement::namespaced("retracted", "urn:xmpp:message-retract:1")
        .optional_attr("id", action_id)
        .attr("stamp", facts.at.format("%Y-%m-%dT%H:%M:%SZ"))
        .child(moderated)
}

#[cfg(test)]
mod tests;
