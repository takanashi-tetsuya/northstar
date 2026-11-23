use super::*;
use northstar_room_application::mix_service::RemotePamJoinOptions;
use northstar_room_core::mix::{MixChannelAddress, MixRealJid};

pub(crate) fn remote_pam_join_stanza(
    actor: &MixRealJid,
    channel: &MixChannelAddress,
    request_id: &str,
    join: &JoinData,
    options: &RemotePamJoinOptions,
) -> String {
    let namespace = if join.anonymous_profile {
        ANON_NS
    } else {
        CORE_NS
    };
    let mut element = XmlElement::namespaced("join", namespace);
    for node in &join.nodes {
        element.push_child(XmlElement::new("subscribe").attr("node", node));
    }
    if let Some(nick) = &join.nick {
        element.push_child(XmlElement::new("nick").text(nick.as_str()));
    }
    if let Some(invite) = &join.invitation {
        let invitation = XmlElement::namespaced("invitation", MISC_NS)
            .child(XmlElement::new("inviter").text(invite.inviter_jid.as_str()))
            .child(XmlElement::new("invitee").text(invite.invitee_jid.as_str()))
            .child(XmlElement::new("channel").text(invite.channel_jid.as_str()))
            .child(XmlElement::new("token").text(invite.token.as_str()));
        element.push_child(invitation);
    }
    if let Some(form) = options.submission_form() {
        element.push_child(form);
    }
    XmlElement::namespaced("iq", "jabber:server")
        .attr("type", "set")
        .attr("from", actor.as_str())
        .attr("to", channel.as_str())
        .attr("id", request_id)
        .child(element)
        .finish()
}
