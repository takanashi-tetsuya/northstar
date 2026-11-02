//! The XEP-0045 message a room sends its occupants when the affiliation of a user who is not in the
//! room changes.

use northstar_xml_builder::XmlElement;

/// A `normal` message from `room_jid` carrying the target's new `affiliation`, its registered `nick` and the
/// change's `reason`, with role `none` since the target is absent. The caller addresses it to each occupant.
pub fn offline_affiliation_change_notice(
    room_jid: &str,
    target_bare_jid: &str,
    affiliation: &str,
    nick: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut item = XmlElement::new("item")
        .attr("affiliation", affiliation)
        .attr("jid", target_bare_jid)
        .attr("role", "none")
        .optional_attr("nick", nick);
    if let Some(reason) = reason {
        item.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    XmlElement::namespaced("message", "jabber:client")
        .attr("from", room_jid)
        .attr("type", "normal")
        .child(XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user").child(item))
        .finish()
}
