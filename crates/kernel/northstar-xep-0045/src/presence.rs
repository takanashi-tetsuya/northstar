//! XEP-0045 Presence Payloads: Join Requests, User Presence Items, Status Codes, Nickname Changes, and Destruction.

#![forbid(unsafe_code)]

use crate::address::AddressError;
use crate::affiliation::Affiliation;
use crate::message::{parse_history_request, MucHistoryRequest, XMLNS_MUC, XMLNS_MUC_USER};
use crate::role::Role;
use crate::status_code::StatusCode;
use crate::xml::XmlElement;
use northstar_xmpp_types::CanonicalJid;
use roxmltree::Node;
use thiserror::Error;

/// Errors in parsing MUC presence extensions.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PresenceError {
    /// Presence XML node or attributes are malformed.
    #[error("presence XML syntax or attributes are invalid")]
    InvalidXml,

    /// Multiple conflicting or duplicate elements found.
    #[error("multiple duplicate or conflicting presence elements found")]
    DuplicateElement,

    /// Item affiliation or role attribute is invalid or missing.
    #[error("item missing valid affiliation or role attribute")]
    InvalidItem,

    /// JID attribute in item or destroy element is malformed.
    #[error("contained JID is malformed: {0}")]
    Address(#[from] AddressError),
}

/// A request to enter/join a MUC room parsed from an initial presence stanza.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MucJoinRequest {
    /// Room password supplied in `<password>...</password>`.
    pub password: Option<String>,
    /// Discussion history parameters requested in `<history .../>`.
    pub history: MucHistoryRequest,
}

/// An `<item .../>` element inside `<x xmlns='http://jabber.org/protocol/muc#user'>`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MucUserItem {
    pub affiliation: Affiliation,
    pub role: Role,
    pub jid: Option<String>,
    pub nick: Option<String>,
    pub actor_nick: Option<String>,
    pub reason: Option<String>,
}

/// A room destruction payload inside `<destroy .../>` in `<x xmlns='http://jabber.org/protocol/muc#user'>`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MucDestroyPayload {
    pub alternate_jid: Option<String>,
    pub reason: Option<String>,
    pub password: Option<String>,
}

/// Full parsed contents of an `<x xmlns='http://jabber.org/protocol/muc#user'>` extension.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MucUserPresencePayload {
    pub item: Option<MucUserItem>,
    pub status_codes: Vec<StatusCode>,
    pub destroy: Option<MucDestroyPayload>,
}

/// Returns `true` if a child XML namespace is allowed inside stored/reflected MUC presence stanzas.
///
/// Strips protocol-control extensions (MUC namespaces, Occupant ID, Delays, Stream management).
pub fn is_allowed_muc_presence_payload_namespace(namespace: &str) -> bool {
    !matches!(
        namespace,
        "http://jabber.org/protocol/muc"
            | "http://jabber.org/protocol/muc#user"
            | "http://jabber.org/protocol/muc#admin"
            | "http://jabber.org/protocol/muc#owner"
            | "urn:xmpp:occupant-id:0"
            | "urn:xmpp:sid:0"
            | "urn:xmpp:delay"
            | "jabber:x:delay"
    )
}

/// Parse an initial MUC join request from `<x xmlns='http://jabber.org/protocol/muc'>`.
pub fn parse_muc_join_request(root: Node<'_, '_>) -> Result<Option<MucJoinRequest>, PresenceError> {
    let muc_nodes = root
        .children()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "x"
                && n.tag_name().namespace() == Some(XMLNS_MUC)
        })
        .collect::<Vec<_>>();

    if muc_nodes.is_empty() {
        return Ok(None);
    }
    if muc_nodes.len() > 1 {
        return Err(PresenceError::DuplicateElement);
    }

    let x = muc_nodes[0];
    let password = x
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "password")
        .and_then(|n| n.text())
        .filter(|t| !t.trim().is_empty())
        .map(|t| t.trim().to_owned());

    let history = parse_history_request(root).map_err(|_| PresenceError::InvalidXml)?;

    Ok(Some(MucJoinRequest { password, history }))
}

/// Parse `<x xmlns='http://jabber.org/protocol/muc#user'>` from a presence stanza.
pub fn parse_muc_user_presence(
    root: Node<'_, '_>,
) -> Result<Option<MucUserPresencePayload>, PresenceError> {
    let user_nodes = root
        .children()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "x"
                && n.tag_name().namespace() == Some(XMLNS_MUC_USER)
        })
        .collect::<Vec<_>>();

    if user_nodes.is_empty() {
        return Ok(None);
    }
    if user_nodes.len() > 1 {
        return Err(PresenceError::DuplicateElement);
    }

    let x = user_nodes[0];

    // Parse items
    let item_nodes = x
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "item")
        .collect::<Vec<_>>();

    let item = if let Some(item_node) = item_nodes.first().copied() {
        let affil_str = item_node
            .attribute("affiliation")
            .ok_or(PresenceError::InvalidItem)?;
        let role_str = item_node
            .attribute("role")
            .ok_or(PresenceError::InvalidItem)?;

        let affiliation =
            Affiliation::from_str_name(affil_str).ok_or(PresenceError::InvalidItem)?;
        let role = Role::from_str_name(role_str).ok_or(PresenceError::InvalidItem)?;

        let jid = item_node
            .attribute("jid")
            .map(|j| CanonicalJid::parse(j).map(|c| c.to_string()))
            .transpose()
            .map_err(|_| AddressError::MalformedJid)?;

        let nick = item_node.attribute("nick").map(str::to_owned);

        let actor_nick = item_node
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "actor")
            .and_then(|n| n.attribute("nick"))
            .map(str::to_owned);

        let reason = item_node
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "reason")
            .and_then(|n| n.text())
            .filter(|t| !t.trim().is_empty())
            .map(|t| t.trim().to_owned());

        Some(MucUserItem {
            affiliation,
            role,
            jid,
            nick,
            actor_nick,
            reason,
        })
    } else {
        None
    };

    // Parse status codes
    let mut status_codes = Vec::new();
    for status_node in x
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "status")
    {
        if let Some(code_str) = status_node.attribute("code") {
            if let Ok(code_u16) = code_str.parse::<u16>() {
                status_codes.push(StatusCode::from_u16(code_u16));
            }
        }
    }

    // Parse destroy payload
    let destroy = if let Some(destroy_node) = x
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "destroy")
    {
        let alternate_jid = destroy_node
            .attribute("jid")
            .map(|j| CanonicalJid::parse_bare(j).map(|c| c.to_string()))
            .transpose()
            .map_err(|_| AddressError::MalformedJid)?;

        let reason = destroy_node
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "reason")
            .and_then(|n| n.text())
            .filter(|t| !t.trim().is_empty())
            .map(|t| t.trim().to_owned());

        let password = destroy_node
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "password")
            .and_then(|n| n.text())
            .filter(|t| !t.trim().is_empty())
            .map(|t| t.trim().to_owned());

        Some(MucDestroyPayload {
            alternate_jid,
            reason,
            password,
        })
    } else {
        None
    };

    Ok(Some(MucUserPresencePayload {
        item,
        status_codes,
        destroy,
    }))
}

/// Build a standard MUC presence stanza.
#[allow(clippy::too_many_arguments)]
pub fn build_muc_presence(
    from_occupant_jid: &str,
    to_jid: &str,
    unavailable: bool,
    item: &MucUserItem,
    status_codes: &[StatusCode],
    occupant_id: Option<&str>,
    payload_xml: Option<&str>,
    id: Option<&str>,
) -> String {
    let mut item_elem = XmlElement::new("item")
        .attr("affiliation", item.affiliation.as_str())
        .attr(
            "role",
            if unavailable {
                "none"
            } else {
                item.role.as_str()
            },
        )
        .optional_attr("jid", item.jid.as_deref())
        .optional_attr("nick", item.nick.as_deref());

    if let Some(actor) = &item.actor_nick {
        item_elem.push_child(XmlElement::new("actor").attr("nick", actor).finish());
    }
    if let Some(reason) = &item.reason {
        item_elem.push_child(XmlElement::new("reason").text(reason).finish());
    }

    let mut muc_user = XmlElement::namespaced("x", XMLNS_MUC_USER).child(item_elem.finish());

    for code in status_codes {
        muc_user.push_child(
            XmlElement::new("status")
                .attr("code", code.as_u16())
                .finish(),
        );
    }

    let mut presence = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", from_occupant_jid)
        .attr("to", to_jid)
        .optional_attr("type", unavailable.then_some("unavailable"))
        .optional_attr("id", id)
        .child(muc_user.finish());

    if let Some(occ_id) = occupant_id {
        presence.push_child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", occ_id)
                .finish(),
        );
    }

    if !unavailable {
        if let Some(extra) = payload_xml {
            if !extra.trim().is_empty() {
                presence.push_child(extra);
            }
        }
    }

    presence.finish()
}

/// Build a nickname change unavailable presence notification (status code 303).
#[allow(clippy::too_many_arguments)]
pub fn build_nick_change_presence(
    room_jid: &str,
    old_nick: &str,
    new_nick: &str,
    recipient_jid: &str,
    affiliation: Affiliation,
    role: Role,
    real_jid: Option<&str>,
    self_presence: bool,
    occupant_id: Option<&str>,
    id: Option<&str>,
) -> String {
    let from = format!("{room_jid}/{old_nick}");
    let item = MucUserItem {
        affiliation,
        role,
        jid: real_jid.map(str::to_owned),
        nick: Some(new_nick.to_owned()),
        actor_nick: None,
        reason: None,
    };

    let mut statuses = vec![StatusCode::NewNickname]; // 303
    if self_presence {
        statuses.push(StatusCode::SelfPresence); // 110
    }

    build_muc_presence(
        &from,
        recipient_jid,
        true,
        &item,
        &statuses,
        occupant_id,
        None,
        id,
    )
}

/// Build a room destruction unavailable presence stanza.
pub fn build_destroy_presence(
    room_jid: &str,
    occupant_nick: &str,
    recipient_jid: &str,
    alternate_jid: Option<&str>,
    reason: Option<&str>,
    occupant_id: Option<&str>,
) -> String {
    let mut destroy_elem = XmlElement::new("destroy").optional_attr("jid", alternate_jid);
    if let Some(r) = reason {
        destroy_elem.push_child(XmlElement::new("reason").text(r).finish());
    }

    let item_elem = XmlElement::new("item")
        .attr("affiliation", "none")
        .attr("role", "none")
        .finish();

    let muc_user = XmlElement::namespaced("x", XMLNS_MUC_USER)
        .child(item_elem)
        .child(destroy_elem.finish())
        .finish();

    let from = format!("{room_jid}/{occupant_nick}");
    let mut presence = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", from)
        .attr("to", recipient_jid)
        .attr("type", "unavailable")
        .child(muc_user);

    if let Some(occ_id) = occupant_id {
        presence.push_child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", occ_id)
                .finish(),
        );
    }

    presence.finish()
}

/// Build an offline affiliation change notice message.
pub fn build_offline_affiliation_notice(
    room_jid: &str,
    target_bare_jid: &str,
    affiliation: Affiliation,
    nick: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut item = XmlElement::new("item")
        .attr("affiliation", affiliation.as_str())
        .attr("jid", target_bare_jid)
        .attr("role", "none")
        .optional_attr("nick", nick);

    if let Some(r) = reason {
        item.push_child(XmlElement::new("reason").text(r).finish());
    }

    XmlElement::namespaced("message", "jabber:client")
        .attr("from", room_jid)
        .attr("type", "normal")
        .child(
            XmlElement::namespaced("x", XMLNS_MUC_USER)
                .child(item.finish())
                .finish(),
        )
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn test_parse_muc_join_request() {
        let xml = "<presence to='room@conf/nick'>\
            <x xmlns='http://jabber.org/protocol/muc'>\
                <password>secret</password>\
                <history maxstanzas='30'/>\
            </x>\
        </presence>";
        let doc = Document::parse(xml).unwrap();
        let join = parse_muc_join_request(doc.root_element()).unwrap().unwrap();
        assert_eq!(join.password, Some("secret".to_owned()));
        assert_eq!(join.history.max_stanzas, 30);
    }

    #[test]
    fn test_parse_muc_user_presence_with_item_and_statuses() {
        let xml = "<presence from='room@conf/nick' to='user@example.org'>\
            <x xmlns='http://jabber.org/protocol/muc#user'>\
                <item affiliation='owner' role='moderator' jid='real@example.org/res'>\
                    <actor nick='AdminNick'/>\
                    <reason>Promoted</reason>\
                </item>\
                <status code='100'/>\
                <status code='110'/>\
                <status code='201'/>\
            </x>\
        </presence>";
        let doc = Document::parse(xml).unwrap();
        let payload = parse_muc_user_presence(doc.root_element())
            .unwrap()
            .unwrap();

        let item = payload.item.unwrap();
        assert_eq!(item.affiliation, Affiliation::Owner);
        assert_eq!(item.role, Role::Moderator);
        assert_eq!(item.jid, Some("real@example.org/res".to_owned()));
        assert_eq!(item.actor_nick, Some("AdminNick".to_owned()));
        assert_eq!(item.reason, Some("Promoted".to_owned()));

        assert_eq!(
            payload.status_codes,
            vec![
                StatusCode::NonAnonymous,
                StatusCode::SelfPresence,
                StatusCode::RoomCreated
            ]
        );
    }

    #[test]
    fn test_build_and_parse_destroy_presence() {
        let presence_xml = build_destroy_presence(
            "room@conf",
            "Alice",
            "alice@example.org/home",
            Some("alt@conf"),
            Some("Room closed"),
            Some("occ-12345"),
        );
        let doc = Document::parse(&presence_xml).unwrap();
        let payload = parse_muc_user_presence(doc.root_element())
            .unwrap()
            .unwrap();

        let destroy = payload.destroy.unwrap();
        assert_eq!(destroy.alternate_jid, Some("alt@conf".to_owned()));
        assert_eq!(destroy.reason, Some("Room closed".to_owned()));
    }

    #[test]
    fn test_build_offline_affiliation_notice() {
        let notice = build_offline_affiliation_notice(
            "room@conf",
            "bob@example.org",
            Affiliation::Member,
            Some("Bob"),
            Some("Invited to member list"),
        );
        assert!(notice.contains("affiliation=\"member\""));
        assert!(notice.contains("jid=\"bob@example.org\""));
        assert!(notice.contains("<reason>Invited to member list</reason>"));
    }
}
