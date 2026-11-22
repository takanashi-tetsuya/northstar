//! Session and stanza validation before changing room presence.

use super::*;

pub(super) struct JoinAddress<'a> {
    pub(super) user: MucSessionUser<'a>,
    pub(super) full_jid: String,
    pub(super) to_jid: CanonicalJid,
    pub(super) room_jid: String,
}

pub(super) fn validate_address<'a, S: MucSession>(
    session: &'a S,
    root: Node<'_, '_>,
) -> JoinStep<JoinAddress<'a>> {
    let Some(user) = session.user() else {
        return JoinStep::Done(MucAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        )));
    };
    let Some(full_jid) = session.full_jid().map(str::to_owned) else {
        return JoinStep::Done(MucAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        )));
    };
    if !session
        .host()
        .xmpp_extension_enabled(northstar_xep_0045::XEP_ID)
    {
        return JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            &full_jid,
            "cancel",
            "service-unavailable",
        )));
    }
    let Some(to) = root.attribute("to") else {
        return JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            &full_jid,
            "modify",
            "jid-malformed",
        )));
    };
    let Ok(to_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
        return JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            &full_jid,
            "modify",
            "jid-malformed",
        )));
    };
    if to_jid.domainpart() != muc_domain(session) || to_jid.localpart().is_none() {
        return JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            &full_jid,
            "modify",
            "jid-malformed",
        )));
    }
    let room_jid = to_jid.bare();
    JoinStep::Next(JoinAddress {
        user,
        full_jid,
        to_jid,
        room_jid,
    })
}

pub(super) async fn validate_presence<'a, S: MucSession>(
    session: &S,
    root: Node<'_, '_>,
    full_jid: String,
    to_jid: &'a CanonicalJid,
    room_jid: String,
) -> Result<JoinStep<(String, String, &'a str)>> {
    let nick = to_jid.resourcepart().unwrap_or_default();
    if !valid_muc_room(localpart(&room_jid)) || !valid_muc_nick(nick) {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            &full_jid,
            "modify",
            "jid-malformed",
        ))));
    }
    if root.attribute("type") == Some("unavailable") {
        return handle_muc_unavailable_presence(session, root, full_jid, room_jid)
            .await
            .map(JoinStep::Done);
    }
    if root.attribute("type").is_some() {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            &full_jid,
            "modify",
            "bad-request",
        ))));
    }
    Ok(JoinStep::Next((full_jid, room_jid, nick)))
}
