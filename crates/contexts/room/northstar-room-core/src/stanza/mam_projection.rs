use super::muc_occupant_id;
use northstar_xml_builder::message_policy::encrypted_archive_stanza;
use northstar_xml_builder::rewrite::{append_root_validated_fragment, parse_root_opening};
use northstar_xml_builder::stanza::is_encrypted;
use northstar_xml_builder::{ValidatedXmlFragment, XmlElement};
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::{Document, Node};
use std::fmt;
use uuid::Uuid;

const CLIENT: &str = "jabber:client";
const MUC_USER: &str = "http://jabber.org/protocol/muc#user";
const OCCUPANT: &str = "urn:xmpp:occupant-id:0";
const SID: &str = "urn:xmpp:sid:0";
const RETRACT: &str = "urn:xmpp:message-retract:1";
const MODERATE: &str = "urn:xmpp:message-moderate:1";

pub struct MucMamStoredRow<'a> {
    pub id: Uuid,
    pub stanza: &'a str,
    pub sender_jid: &'a str,
    pub nick: &'a str,
    pub message_kind: &'a str,
    pub encrypted: bool,
    pub retracted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucMamProjectionError {
    Xml,
    Envelope,
    Identity,
    Payload,
}

impl fmt::Display for MucMamProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Xml => "invalid MUC MAM XML",
            Self::Envelope => "invalid MUC MAM envelope",
            Self::Identity => "invalid MUC MAM identity metadata",
            Self::Payload => "invalid MUC MAM control or encrypted payload",
        })
    }
}

impl std::error::Error for MucMamProjectionError {}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Payload {
    Live,
    Tombstone,
    Retraction,
    Moderation,
}

pub fn project_muc_mam_message(
    room_bare_jid: &str,
    room_secret: &[u8],
    reveal_real_jid: bool,
    row: MucMamStoredRow<'_>,
) -> Result<String, MucMamProjectionError> {
    use MucMamProjectionError::{Envelope, Identity, Xml};

    ValidatedXmlFragment::parse(row.stanza).map_err(|_| Xml)?;
    let document = Document::parse(row.stanza).map_err(|_| Xml)?;
    let root = document.root_element();
    if root.tag_name().name() != "message"
        || !matches!(
            root.tag_name().namespace(),
            None | Some(CLIENT | "jabber:server")
        )
    {
        return Err(Envelope);
    }
    let kind = match (row.message_kind, row.retracted) {
        ("discussion" | "subject", false) => Payload::Live,
        ("discussion", true) => Payload::Tombstone,
        ("retraction", false) => Payload::Retraction,
        ("moderation", false) => Payload::Moderation,
        _ => return Err(MucMamProjectionError::Payload),
    };
    let room = CanonicalJid::parse_bare(room_bare_jid).map_err(|_| Identity)?;
    let sender = CanonicalJid::parse(row.sender_jid).map_err(|_| Identity)?;
    if room.localpart().is_none() || room_secret.len() != 32 {
        return Err(Identity);
    }
    let room = room.bare();
    let occupant = northstar_xep_0045::occupant_key(&room, row.nick).map_err(|_| Identity)?;
    let from = if kind == Payload::Moderation {
        &room
    } else {
        &occupant
    };
    let envelope = XmlElement::namespaced("message", CLIENT)
        .attr("from", from)
        .attr("type", "groupchat")
        .optional_attr("id", root.attribute("id"))
        .optional_attr(
            "xml:lang",
            root.attribute(("http://www.w3.org/XML/1998/namespace", "lang")),
        );

    let message = if kind == Payload::Live {
        live_payload(row.stanza, root, &envelope, row.encrypted)?
    } else {
        envelope.child(project_control(root, &room, kind)?).finish()
    };
    let mut metadata = XmlElement::new("metadata")
        .child(
            XmlElement::namespaced("stanza-id", SID)
                .attr("id", row.id)
                .attr("by", room),
        )
        .child(
            XmlElement::namespaced("occupant-id", OCCUPANT)
                .attr("id", muc_occupant_id(room_secret, &sender.bare())),
        );
    if reveal_real_jid {
        metadata.push_child(
            XmlElement::namespaced("x", MUC_USER)
                .child(XmlElement::new("item").attr("jid", sender)),
        );
    }
    let projected =
        append_root_validated_fragment(&message, &metadata.finish_children()).ok_or(Xml)?;
    ValidatedXmlFragment::parse(&projected).map_err(|_| Xml)?;
    Ok(projected)
}

fn live_payload(
    raw: &str,
    root: Node<'_, '_>,
    envelope: &XmlElement,
    encrypted: bool,
) -> Result<String, MucMamProjectionError> {
    let recognized = is_encrypted(root);
    if encrypted && !recognized {
        return Err(MucMamProjectionError::Payload);
    }
    let root_raw = &raw[root.range()];
    let opening = parse_root_opening(root_raw).ok_or(MucMamProjectionError::Xml)?;
    let mut projected = envelope.open();
    projected.truncate(projected.len() - 1);
    for attr in opening
        .attributes
        .iter()
        .filter(|attr| attr.name.starts_with("xmlns:"))
    {
        projected.push_str(&root_raw[attr.removal_start..attr.end]);
    }
    projected.push('>');
    let inherited_default =
        if opening.element_name.contains(':') && root.lookup_namespace_uri(None) != Some(CLIENT) {
            Some(
                opening
                    .attributes
                    .iter()
                    .find(|attr| attr.name == "xmlns")
                    .map_or(" xmlns=''", |attr| &root_raw[attr.removal_start..attr.end]),
            )
        } else {
            None
        };
    for child in root.children().filter(Node::is_element) {
        if reserved(child) {
            continue;
        }
        let range = child.range();
        let mut cursor = range.start;
        if let Some(default) = inherited_default {
            let opening =
                parse_root_opening(&raw[range.clone()]).ok_or(MucMamProjectionError::Xml)?;
            if !opening.attributes.iter().any(|attr| attr.name == "xmlns") {
                cursor += opening.insertion;
                projected.push_str(&raw[range.start..cursor]);
                projected.push_str(default);
            }
        }
        for removal in child
            .descendants()
            .filter(|node| node.is_element() && reserved(*node))
        {
            let range = removal.range();
            if range.start >= cursor {
                projected.push_str(&raw[cursor..range.start]);
                cursor = range.end;
            }
        }
        projected.push_str(&raw[cursor..range.end]);
    }
    projected.push_str(&envelope.close());
    ValidatedXmlFragment::parse(&projected).map_err(|_| MucMamProjectionError::Xml)?;
    Ok(if recognized {
        encrypted_archive_stanza(&projected)
    } else {
        projected
    })
}

fn reserved(node: Node<'_, '_>) -> bool {
    matches!(
        (node.tag_name().namespace(), node.tag_name().name()),
        (Some(SID), "stanza-id")
            | (
                Some(MUC_USER | "urn:northstar:muc:sender:0" | OCCUPANT | RETRACT | MODERATE),
                _
            )
    )
}

fn project_control(
    root: Node<'_, '_>,
    room: &str,
    kind: Payload,
) -> Result<XmlElement, MucMamProjectionError> {
    use MucMamProjectionError::Payload as Invalid;

    let name = if kind == Payload::Tombstone {
        "retracted"
    } else {
        "retract"
    };
    let field = unique_child(root, RETRACT, name)?.ok_or(Invalid)?;
    let mut control =
        XmlElement::namespaced(name, RETRACT).optional_attr("id", field.attribute("id"));
    if kind == Payload::Tombstone {
        let stamp = field.attribute("stamp").ok_or(Invalid)?;
        northstar_time::DateTime::parse_from_rfc3339(stamp).map_err(|_| Invalid)?;
        control = control.attr("stamp", stamp);
    } else {
        Uuid::parse_str(field.attribute("id").ok_or(Invalid)?).map_err(|_| Invalid)?;
    }
    if matches!(kind, Payload::Tombstone | Payload::Moderation) {
        match unique_child(field, MODERATE, "moderated")? {
            Some(moderated) => control.push_child(project_moderated(moderated, room)?),
            None if kind == Payload::Moderation => return Err(Invalid),
            None => {}
        }
    }
    if let Some(reason) = unique_child(field, RETRACT, "reason")? {
        let text: String = reason
            .children()
            .filter(Node::is_text)
            .filter_map(|node| node.text())
            .collect();
        control.push_child(XmlElement::new("reason").text(text));
    }
    Ok(control)
}

fn project_moderated(node: Node<'_, '_>, room: &str) -> Result<XmlElement, MucMamProjectionError> {
    use MucMamProjectionError::Payload as Invalid;

    let by = CanonicalJid::parse(node.attribute("by").ok_or(Invalid)?).map_err(|_| Invalid)?;
    let nick = by.resourcepart().ok_or(Invalid)?;
    if by.bare() != room {
        return Err(Invalid);
    }
    let occupant = northstar_xep_0045::occupant_key(room, nick).map_err(|_| Invalid)?;
    let mut result = XmlElement::namespaced("moderated", MODERATE).attr("by", occupant);
    if let Some(id) = unique_child(node, OCCUPANT, "occupant-id")?
        .and_then(|child| child.attribute("id"))
        .filter(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
    {
        result.push_child(XmlElement::namespaced("occupant-id", OCCUPANT).attr("id", id));
    }
    Ok(result)
}

fn unique_child<'a, 'input>(
    parent: Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> Result<Option<Node<'a, 'input>>, MucMamProjectionError> {
    let mut matches = parent
        .children()
        .filter(|node| node.has_tag_name((namespace, name)));
    let child = matches.next();
    if matches.next().is_some() {
        return Err(MucMamProjectionError::Payload);
    }
    Ok(child)
}

#[cfg(test)]
mod tests;
