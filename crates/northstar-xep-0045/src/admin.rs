//! XEP-0045 MUC Admin, Owner, and Voice Request/Approval IQ Payloads.

#![forbid(unsafe_code)]

use crate::address::{AddressError, OccupantNick};
use crate::affiliation::Affiliation;
use crate::role::Role;
use crate::xml::XmlElement;
use northstar_xmpp_types::CanonicalJid;
use roxmltree::Node;
use thiserror::Error;

pub const XMLNS_MUC_ADMIN: &str = "http://jabber.org/protocol/muc#admin";
pub const XMLNS_MUC_OWNER: &str = "http://jabber.org/protocol/muc#owner";
pub const XMLNS_MUC_REQUEST: &str = "http://jabber.org/protocol/muc#request";

/// Errors encountered while parsing MUC Admin, Owner, or Voice IQ payloads.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdminError {
    /// XML query node is malformed or has unexpected namespace.
    #[error("admin or owner query XML is malformed")]
    InvalidXml,

    /// An item contains both or neither of `affiliation` and `role`.
    #[error("admin item must specify exactly one of affiliation or role")]
    AmbiguousItemKind,

    /// An affiliation item is missing the mandatory `jid` attribute.
    #[error("affiliation item requires a jid attribute")]
    MissingJidAttribute,

    /// A role item is missing the mandatory `nick` attribute.
    #[error("role item requires a nick attribute")]
    MissingNickAttribute,

    /// Item contains an invalid or unmapped affiliation/role string.
    #[error("invalid affiliation or role attribute value")]
    InvalidValue,

    /// A JID attribute is malformed.
    #[error("contained JID is malformed: {0}")]
    Address(#[from] AddressError),

    /// Voice form fields are malformed or missing required variables.
    #[error("voice request/approval data form is invalid")]
    InvalidVoiceForm,
}

/// An `<item .../>` element in a MUC Admin query.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AdminItem {
    pub affiliation: Option<Affiliation>,
    pub role: Option<Role>,
    pub jid: Option<String>,
    pub nick: Option<String>,
    pub actor_nick: Option<String>,
    pub reason: Option<String>,
}

/// A parsed `<query xmlns='http://jabber.org/protocol/muc#admin'>`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AdminQuery {
    pub items: Vec<AdminItem>,
}

/// Parse an incoming MUC Admin query `<query xmlns='http://jabber.org/protocol/muc#admin'>`.
pub fn parse_admin_query(query: Node<'_, '_>) -> Result<AdminQuery, AdminError> {
    if query.tag_name().name() != "query" || query.tag_name().namespace() != Some(XMLNS_MUC_ADMIN) {
        return Err(AdminError::InvalidXml);
    }

    let mut items = Vec::new();

    for child in query.children().filter(|n| n.is_element()) {
        if child.tag_name().name() != "item" {
            return Err(AdminError::InvalidXml);
        }

        let affil_attr = child.attribute("affiliation");
        let role_attr = child.attribute("role");

        // An item must specify either affiliation OR role, not both or neither
        if affil_attr.is_some() == role_attr.is_some() {
            return Err(AdminError::AmbiguousItemKind);
        }

        let affiliation = affil_attr
            .map(|s| Affiliation::from_str_name(s).ok_or(AdminError::InvalidValue))
            .transpose()?;

        let role = role_attr
            .map(|s| Role::from_str_name(s).ok_or(AdminError::InvalidValue))
            .transpose()?;

        let jid = child
            .attribute("jid")
            .map(|j| CanonicalJid::parse(j).map(|c| c.to_string()))
            .transpose()
            .map_err(|_| AddressError::MalformedJid)?;

        let nick = if let Some(n) = child.attribute("nick") {
            let prepared = OccupantNick::parse(n)?;
            Some(prepared.as_str().to_owned())
        } else {
            None
        };

        let actor_nick = child
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "actor")
            .and_then(|n| n.attribute("nick"))
            .map(str::to_owned);

        let reason = child
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "reason")
            .and_then(|n| n.text())
            .filter(|t| !t.trim().is_empty())
            .map(|t| t.trim().to_owned());

        items.push(AdminItem {
            affiliation,
            role,
            jid,
            nick,
            actor_nick,
            reason,
        });
    }

    if items.is_empty() {
        return Err(AdminError::InvalidXml);
    }

    Ok(AdminQuery { items })
}

/// Build an Admin query result payload `<query xmlns='http://jabber.org/protocol/muc#admin'>...</query>`.
pub fn build_admin_query_result(items: &[AdminItem]) -> String {
    let mut query = XmlElement::namespaced("query", XMLNS_MUC_ADMIN);

    for item in items {
        let mut item_elem = XmlElement::new("item")
            .optional_attr("affiliation", item.affiliation.map(|a| a.as_str()))
            .optional_attr("role", item.role.map(|r| r.as_str()))
            .optional_attr("jid", item.jid.as_deref())
            .optional_attr("nick", item.nick.as_deref());

        if let Some(actor) = &item.actor_nick {
            item_elem.push_child(XmlElement::new("actor").attr("nick", actor).finish());
        }
        if let Some(reason) = &item.reason {
            item_elem.push_child(XmlElement::new("reason").text(reason).finish());
        }

        query.push_child(item_elem.finish());
    }

    query.finish()
}

/// A parsed `<destroy jid='...'><reason>...</reason></destroy>` inside `<query xmlns='http://jabber.org/protocol/muc#owner'>`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OwnerDestroy {
    pub alternate_jid: Option<String>,
    pub reason: Option<String>,
    pub password: Option<String>,
}

/// Parse a `<destroy .../>` element inside `<query xmlns='http://jabber.org/protocol/muc#owner'>`.
pub fn parse_owner_destroy(destroy: Node<'_, '_>) -> Result<OwnerDestroy, AdminError> {
    if destroy.tag_name().name() != "destroy"
        || destroy.tag_name().namespace() != Some(XMLNS_MUC_OWNER)
    {
        return Err(AdminError::InvalidXml);
    }

    let alternate_jid = destroy
        .attribute("jid")
        .map(|j| CanonicalJid::parse_bare(j).map(|c| c.to_string()))
        .transpose()
        .map_err(|_| AddressError::MalformedJid)?;

    let reason = destroy
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "reason")
        .and_then(|n| n.text())
        .filter(|t| !t.trim().is_empty())
        .map(|t| t.trim().to_owned());

    let password = destroy
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "password")
        .and_then(|n| n.text())
        .filter(|t| !t.trim().is_empty())
        .map(|t| t.trim().to_owned());

    Ok(OwnerDestroy {
        alternate_jid,
        reason,
        password,
    })
}

/// Build an Owner room destroy element `<destroy jid='...'><reason>...</reason></destroy>`.
pub fn build_owner_destroy(
    alternate_jid: Option<&str>,
    reason: Option<&str>,
    password: Option<&str>,
) -> String {
    let mut destroy = XmlElement::new("destroy").optional_attr("jid", alternate_jid);
    if let Some(r) = reason {
        destroy.push_child(XmlElement::new("reason").text(r).finish());
    }
    if let Some(pwd) = password {
        destroy.push_child(XmlElement::new("password").text(pwd).finish());
    }
    destroy.finish()
}

/// A parsed voice request or approval form (XEP-0045 Section 7.12).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VoiceForm {
    /// A voice request from an occupant without voice.
    Request,
    /// A moderator's approval or rejection of a voice request.
    Approval {
        jid: String,
        nick: String,
        allow: bool,
    },
}

/// Parse a Voice Request or Voice Approval Data Form from `<x xmlns='jabber:x:data' type='submit'>` or an enclosing element.
pub fn parse_voice_form(root: Node<'_, '_>) -> Result<Option<VoiceForm>, AdminError> {
    let form_node = if root.is_element()
        && root.tag_name().name() == "x"
        && root.tag_name().namespace() == Some("jabber:x:data")
    {
        Some(root)
    } else {
        let forms = root
            .children()
            .filter(|n| {
                n.is_element()
                    && n.tag_name().name() == "x"
                    && n.tag_name().namespace() == Some("jabber:x:data")
            })
            .collect::<Vec<_>>();
        if forms.is_empty() {
            return Ok(None);
        }
        if forms.len() > 1 {
            return Err(AdminError::InvalidVoiceForm);
        }
        Some(forms[0])
    };

    let Some(form) = form_node else {
        return Ok(None);
    };

    if form.attribute("type") != Some("submit") {
        return Err(AdminError::InvalidVoiceForm);
    }

    let mut fields = std::collections::HashMap::new();
    let mut names = std::collections::HashSet::new();

    for field in form
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "field")
    {
        let Some(var) = field.attribute("var") else {
            return Err(AdminError::InvalidVoiceForm);
        };
        if !names.insert(var) {
            return Err(AdminError::InvalidVoiceForm);
        }
        let val = field
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "value")
            .and_then(|n| n.text())
            .unwrap_or_default();
        fields.insert(var, val);
    }

    if fields.get("FORM_TYPE").copied() != Some(XMLNS_MUC_REQUEST) {
        return Ok(None);
    }
    if fields.get("muc#role").copied() != Some("participant") {
        return Err(AdminError::InvalidVoiceForm);
    }

    let has_approval_fields = ["muc#jid", "muc#roomnick", "muc#request_allow"]
        .iter()
        .any(|name| names.contains(name));

    if !has_approval_fields {
        if names.len() != 2 {
            return Err(AdminError::InvalidVoiceForm);
        }
        return Ok(Some(VoiceForm::Request));
    }

    if names.len() != 5
        || ![
            "FORM_TYPE",
            "muc#role",
            "muc#jid",
            "muc#roomnick",
            "muc#request_allow",
        ]
        .iter()
        .all(|name| names.contains(name))
    {
        return Err(AdminError::InvalidVoiceForm);
    }

    let jid_raw = fields.get("muc#jid").ok_or(AdminError::InvalidVoiceForm)?;
    let jid = CanonicalJid::parse(jid_raw).map_err(|_| AddressError::MalformedJid)?;
    if jid.localpart().is_none() || jid.resourcepart().is_none() {
        return Err(AdminError::InvalidVoiceForm);
    }

    let nick_raw = fields
        .get("muc#roomnick")
        .ok_or(AdminError::InvalidVoiceForm)?;
    let nick = OccupantNick::parse(nick_raw)?;

    let allow_raw = fields
        .get("muc#request_allow")
        .ok_or(AdminError::InvalidVoiceForm)?;
    let allow = match *allow_raw {
        "1" | "true" => true,
        "0" | "false" => false,
        _ => return Err(AdminError::InvalidVoiceForm),
    };

    Ok(Some(VoiceForm::Approval {
        jid: jid.to_string(),
        nick: nick.as_str().to_owned(),
        allow,
    }))
}

/// Build a Voice Request Data Form submitted by an occupant requesting voice.
pub fn build_voice_request_form() -> String {
    XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "submit")
        .child(
            XmlElement::new("field")
                .attr("var", "FORM_TYPE")
                .child(XmlElement::new("value").text(XMLNS_MUC_REQUEST).finish())
                .finish(),
        )
        .child(
            XmlElement::new("field")
                .attr("var", "muc#role")
                .child(XmlElement::new("value").text("participant").finish())
                .finish(),
        )
        .finish()
}

/// Build a Voice Approval Data Form submitted by a moderator to grant or deny voice.
pub fn build_voice_approval_form(
    occupant_full_jid: &str,
    occupant_nick: &str,
    allow: bool,
) -> String {
    XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "submit")
        .child(
            XmlElement::new("field")
                .attr("var", "FORM_TYPE")
                .child(XmlElement::new("value").text(XMLNS_MUC_REQUEST).finish())
                .finish(),
        )
        .child(
            XmlElement::new("field")
                .attr("var", "muc#role")
                .child(XmlElement::new("value").text("participant").finish())
                .finish(),
        )
        .child(
            XmlElement::new("field")
                .attr("var", "muc#jid")
                .child(XmlElement::new("value").text(occupant_full_jid).finish())
                .finish(),
        )
        .child(
            XmlElement::new("field")
                .attr("var", "muc#roomnick")
                .child(XmlElement::new("value").text(occupant_nick).finish())
                .finish(),
        )
        .child(
            XmlElement::new("field")
                .attr("var", "muc#request_allow")
                .child(
                    XmlElement::new("value")
                        .text(if allow { "1" } else { "0" })
                        .finish(),
                )
                .finish(),
        )
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn test_parse_admin_query_affiliation() {
        let xml = "<query xmlns='http://jabber.org/protocol/muc#admin'>\
            <item affiliation='member' jid='alice@example.org'>\
                <reason>Invited</reason>\
            </item>\
            <item affiliation='outcast' jid='spammer@example.org'>\
                <actor nick='AdminNick'/>\
                <reason>Spamming</reason>\
            </item>\
        </query>";
        let doc = Document::parse(xml).unwrap();
        let query = parse_admin_query(doc.root_element()).unwrap();
        assert_eq!(query.items.len(), 2);
        assert_eq!(query.items[0].affiliation, Some(Affiliation::Member));
        assert_eq!(query.items[0].jid, Some("alice@example.org".to_owned()));
        assert_eq!(query.items[0].reason, Some("Invited".to_owned()));
        assert_eq!(query.items[1].affiliation, Some(Affiliation::Outcast));
        assert_eq!(query.items[1].actor_nick, Some("AdminNick".to_owned()));
    }

    #[test]
    fn test_parse_admin_query_role() {
        let xml = "<query xmlns='http://jabber.org/protocol/muc#admin'>\
            <item role='moderator' nick='Alice'/>\
        </query>";
        let doc = Document::parse(xml).unwrap();
        let query = parse_admin_query(doc.root_element()).unwrap();
        assert_eq!(query.items.len(), 1);
        assert_eq!(query.items[0].role, Some(Role::Moderator));
        assert_eq!(query.items[0].nick, Some("Alice".to_owned()));
    }

    #[test]
    fn test_parse_owner_destroy() {
        let xml = "<destroy xmlns='http://jabber.org/protocol/muc#owner' jid='alternate@conf'>\
            <reason>Renamed</reason>\
            <password>pass123</password>\
        </destroy>";
        let doc = Document::parse(xml).unwrap();
        let destroy = parse_owner_destroy(doc.root_element()).unwrap();
        assert_eq!(destroy.alternate_jid, Some("alternate@conf".to_owned()));
        assert_eq!(destroy.reason, Some("Renamed".to_owned()));
        assert_eq!(destroy.password, Some("pass123".to_owned()));
    }

    #[test]
    fn test_voice_forms_roundtrip() {
        // Request form
        let req_xml = build_voice_request_form();
        let req_doc = Document::parse(&req_xml).unwrap();
        let parsed_req = parse_voice_form(req_doc.root_element()).unwrap().unwrap();
        assert_eq!(parsed_req, VoiceForm::Request);

        // Approval form
        let app_xml = build_voice_approval_form("user@example.org/mobile", "UserNick", true);
        let app_doc = Document::parse(&app_xml).unwrap();
        let parsed_app = parse_voice_form(app_doc.root_element()).unwrap().unwrap();
        assert_eq!(
            parsed_app,
            VoiceForm::Approval {
                jid: "user@example.org/mobile".to_owned(),
                nick: "UserNick".to_owned(),
                allow: true,
            }
        );
    }
}
