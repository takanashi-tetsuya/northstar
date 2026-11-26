use super::MIX_ROSTER_NS;
use northstar_roster_core::RosterChange;
use northstar_xml_builder::XmlElement;
use uuid::Uuid;

/// Renders an RFC 6121 roster item or deletion element from a committed change.
pub fn roster_change_item_element(
    change: &RosterChange,
    participant_id: Option<&str>,
) -> XmlElement {
    if change.removed {
        return removed_roster_item_element(&change.contact_jid);
    }
    roster_item_element(
        &change.contact_jid,
        change.display_name.as_deref(),
        change.subscription.as_deref().unwrap_or("none"),
        change.ask.as_deref(),
        change.approved,
        &change.groups,
        participant_id,
    )
}

/// Renders an RFC 6121 roster push IQ stanza.
pub fn roster_push_xml(from: &str, to: &str, version: i64, item: XmlElement, id: Uuid) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "set")
        .attr("from", from)
        .attr("to", to)
        .attr("id", format!("roster-{}", id.as_u128()))
        .child(
            XmlElement::namespaced("query", "jabber:iq:roster")
                .attr("ver", version)
                .child(item),
        )
        .finish()
}

#[cfg(test)]
pub(crate) fn roster_item_xml(
    jid: &str,
    name: Option<&str>,
    subscription: &str,
    ask: Option<&str>,
    approved: bool,
    groups: &[String],
    participant_id: Option<&str>,
) -> String {
    roster_item_element(
        jid,
        name,
        subscription,
        ask,
        approved,
        groups,
        participant_id,
    )
    .finish()
}

pub(super) fn roster_item_element(
    jid: &str,
    name: Option<&str>,
    subscription: &str,
    ask: Option<&str>,
    approved: bool,
    groups: &[String],
    participant_id: Option<&str>,
) -> XmlElement {
    let mut item = XmlElement::new("item")
        .attr("jid", jid)
        .attr("subscription", subscription)
        .optional_attr("name", name)
        .optional_attr("ask", ask);
    if approved {
        item = item.attr("approved", "true");
    }
    for group in groups {
        item.push_child(XmlElement::new("group").text(group.clone()));
    }
    if let Some(participant_id) = participant_id {
        item.push_child(
            XmlElement::namespaced("channel", MIX_ROSTER_NS).attr("participant-id", participant_id),
        );
    }
    item
}

fn removed_roster_item_element(jid: &str) -> XmlElement {
    XmlElement::new("item")
        .attr("jid", jid)
        .attr("subscription", "remove")
}

pub(super) fn roster_removal_presence(from: &str, to: &str, kind: &str, id: Uuid) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", from)
        .attr("to", to)
        .attr("type", kind)
        .attr("id", id)
        .finish()
}

#[cfg(test)]
mod tests;
