//! Provides MUC identity helpers, presence and error rendering, and MUC archive projections.

use super::*;

pub(crate) fn valid_muc_room(value: &str) -> bool {
    northstar_xep_0045::is_valid_room_name(value)
}

pub(crate) fn valid_muc_nick(value: &str) -> bool {
    northstar_xep_0045::is_valid_occupant_nick(value)
}

/// MUC occupants use the room JID resourcepart as their nickname. RFC 7622
/// therefore requires the case-preserving PRECIS OpaqueString profile; a
/// nickname must never pass through UsernameCaseMapped or ASCII lowercase.
pub(crate) fn prepare_muc_nick(value: &str) -> anyhow::Result<String> {
    northstar_xep_0045::OccupantNick::parse(value)
        .map(|nick| nick.to_string())
        .map_err(anyhow::Error::from)
}

pub(crate) fn muc_occupant_key(room_jid: &str, nick: &str) -> String {
    northstar_xep_0045::occupant_key(room_jid, nick).unwrap_or_else(|_| {
        let room_jid =
            crate::jid::canonicalize_bare(room_jid).unwrap_or_else(|_| room_jid.to_owned());
        let nick = prepare_muc_nick(nick).unwrap_or_else(|_| nick.to_owned());
        format!("{room_jid}/{nick}")
    })
}

pub(crate) fn muc_presence_stanza(
    occupant: &crate::state::SerializableMucOccupant,
    to: &str,
    unavailable: bool,
    self_presence: bool,
    created: bool,
    id: Option<&str>,
    disclose_real_jid: bool,
) -> String {
    muc_presence_stanza_with_status(
        occupant,
        to,
        unavailable,
        self_presence,
        created,
        id,
        disclose_real_jid,
        None,
        None,
        None,
    )
}

pub(crate) fn muc_nickname_change_presence(
    occupant: &crate::state::SerializableMucOccupant,
    recipient: &crate::state::SerializableMucOccupant,
    new_nick: &str,
    id: Option<&str>,
) -> String {
    let self_presence = occupant.full_jid == recipient.full_jid;
    let disclose_real_jid =
        occupant.room_non_anonymous || self_presence || recipient.role == "moderator";
    let item = XmlElement::new("item")
        .attr("affiliation", &occupant.affiliation)
        .attr("role", &occupant.role)
        .attr("nick", new_nick)
        .optional_attr(
            "jid",
            disclose_real_jid.then_some(occupant.full_jid.as_str()),
        );
    let mut muc_user = XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
        .child(item)
        .child(XmlElement::new("status").attr("code", 303));
    if self_presence {
        muc_user.push_child(XmlElement::new("status").attr("code", 110));
    }
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", format!("{}/{}", occupant.room_jid, occupant.nick))
        .attr("to", &recipient.full_jid)
        .attr("type", "unavailable")
        .optional_attr("id", id)
        .child(muc_user)
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &occupant.occupant_id),
        )
        .finish()
}

pub(crate) fn add_muc_user_status(stanza: &str, code: u16) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let Some(extension) = document.root_element().children().find(|node| {
        node.is_element()
            && node.tag_name().name() == "x"
            && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
    }) else {
        return stanza.to_owned();
    };
    let status = if extension.default_namespace() == Some("http://jabber.org/protocol/muc#user") {
        XmlElement::new("status")
    } else {
        // A prefixed MUC extension does not establish a default namespace for
        // an unprefixed child inserted into it.
        XmlElement::namespaced("status", "http://jabber.org/protocol/muc#user")
    }
    .attr("code", code);
    append_element_child(stanza, extension.range(), &status).unwrap_or_else(|| stanza.to_owned())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn muc_presence_stanza_with_status(
    occupant: &crate::state::SerializableMucOccupant,
    to: &str,
    unavailable: bool,
    self_presence: bool,
    created: bool,
    id: Option<&str>,
    disclose_real_jid: bool,
    removal_status: Option<u16>,
    actor_nick: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut muc_user = XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user");
    let mut item = XmlElement::new("item")
        .attr("affiliation", &occupant.affiliation)
        .attr("role", if unavailable { "none" } else { &occupant.role })
        .optional_attr(
            "jid",
            disclose_real_jid.then_some(occupant.full_jid.as_str()),
        );
    if let Some(actor_nick) = actor_nick {
        item.push_child(XmlElement::new("actor").attr("nick", actor_nick));
    }
    if let Some(reason) = reason {
        item.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    muc_user.push_child(item);
    if self_presence && occupant.room_non_anonymous {
        muc_user.push_child(XmlElement::new("status").attr("code", 100));
    }
    if self_presence {
        muc_user.push_child(XmlElement::new("status").attr("code", 110));
    }
    if created {
        muc_user.push_child(XmlElement::new("status").attr("code", 201));
    }
    if let Some(code) = removal_status {
        muc_user.push_child(XmlElement::new("status").attr("code", code));
    }
    let mut presence = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", format!("{}/{}", occupant.room_jid, occupant.nick))
        .attr("to", to)
        .optional_attr("id", id)
        .optional_attr("type", unavailable.then_some("unavailable"))
        .child(muc_user)
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &occupant.occupant_id),
        );
    if !unavailable && !occupant.payload.is_empty() {
        if let Err(error) = presence.push_validated_fragment(&occupant.payload) {
            tracing::warn!(
                ?error,
                room = %occupant.room_jid,
                "discarded invalid stored MUC presence payload"
            );
        }
    }
    let res = presence.finish();
    tracing::debug!(room=%occupant.room_jid, to=%to, "MUC routing presence");
    res
}

pub(crate) fn muc_destroy_presence(
    occupant: &crate::state::SerializableMucOccupant,
    alternate: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut destroy = XmlElement::new("destroy").optional_attr("jid", alternate);
    if let Some(reason) = reason {
        destroy.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    let muc_user = XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
        .child(
            XmlElement::new("item")
                .attr("affiliation", "none")
                .attr("role", "none"),
        )
        .child(destroy);
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", format!("{}/{}", occupant.room_jid, occupant.nick))
        .attr("to", &occupant.full_jid)
        .attr("type", "unavailable")
        .child(muc_user)
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &occupant.occupant_id),
        )
        .finish()
}

/// XEP-0421 pseudonym scoped to one room. HMAC-SHA-256 provides a stable,
/// non-guessable value without correlating the same account across rooms.
pub(crate) fn muc_occupant_id(room_secret: &[u8], user_bare_jid: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(room_secret)
        .expect("HMAC accepts XEP-0421 room secrets of any length");
    let user_bare_jid = crate::jid::canonical_bare_key(user_bare_jid)
        .unwrap_or_else(|_| bare_jid(user_bare_jid).to_owned());
    mac.update(user_bare_jid.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Replace any client-supplied occupant-id with the authoritative room value.
pub(crate) fn set_muc_occupant_id(stanza: &str, occupant_id: &str) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "occupant-id"
                && node.tag_name().namespace() == Some("urn:xmpp:occupant-id:0")
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut authoritative = stanza.to_owned();
    for range in ranges {
        authoritative.replace_range(range, "");
    }
    append_root_element(
        &authoritative,
        &XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0").attr("id", occupant_id),
    )
    .unwrap_or(authoritative)
}

pub(crate) fn muc_stanza_error(
    root: Node<'_, '_>,
    recipient: &str,
    error_type: &str,
    condition: &str,
) -> String {
    let from = root.attribute("to").unwrap_or_default();
    let stanza_name = match root.tag_name().name() {
        "iq" => "iq",
        "message" => "message",
        "presence" => "presence",
        _ => "message",
    };
    let mut reply = XmlElement::new(stanza_name)
        .attr("xmlns", "jabber:client")
        .attr("from", from)
        .attr("to", recipient)
        .attr("type", "error")
        .attr("id", root.attribute("id").unwrap_or_default());
    if stanza_name == "presence" {
        reply.push_child(XmlElement::namespaced(
            "x",
            "http://jabber.org/protocol/muc",
        ));
    }
    reply
        .child(
            XmlElement::new("error")
                .attr("by", bare_jid(from))
                .attr("type", error_type)
                .child(stanza_condition_element(condition)),
        )
        .finish()
}

pub(crate) fn add_muc_sender(stanza: &str, sender_jid: &str) -> String {
    append_root_element(
        stanza,
        &XmlElement::namespaced("x", "urn:northstar:muc:sender:0")
            .attr("jid", bare_jid(sender_jid)),
    )
    .unwrap_or_else(|| stanza.to_owned())
}

/// Produce the message payload embedded in a MUC MAM result. XEP-0313
/// requires no `to`, requires the occupant JID in `from`, and forbids trusting
/// a pre-existing MUC user extension. Real JIDs are added only when room
/// anonymity policy permits the querying user to see them.
pub(crate) fn mam_muc_stanza(stanza: &str, sender_jid: &str, reveal_real_jid: bool) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && matches!(
                    node.tag_name().namespace(),
                    Some("http://jabber.org/protocol/muc#user" | "urn:northstar:muc:sender:0")
                )
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut result = stanza.to_owned();
    for range in ranges {
        result.replace_range(range, "");
    }
    result = remove_root_attribute(&result, "to");
    if reveal_real_jid {
        let extension = XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
            .child(XmlElement::new("item").attr("jid", sender_jid));
        result = append_root_element(&result, &extension).unwrap_or(result);
    }
    result
}
