use northstar_xml_builder::XmlElement;

pub(super) fn offline_affiliation_notice(
    room_jid: &str,
    bare_jid: &str,
    affiliation: &str,
    nick: Option<&str>,
    reason: Option<&str>,
    disclose: bool,
) -> String {
    if disclose {
        return northstar_xep_0045::notice::offline_affiliation_change_notice(
            room_jid,
            bare_jid,
            affiliation,
            nick,
            reason,
        );
    }
    let mut item = XmlElement::new("item")
        .attr("affiliation", affiliation)
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
