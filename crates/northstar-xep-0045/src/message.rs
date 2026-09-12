//! XEP-0045 Message Payloads: Mediated Invitations, Declines, Subject Commands, and History Requests.

#![forbid(unsafe_code)]

use crate::address::AddressError;
use crate::xml::XmlElement;
use northstar_xmpp_types::CanonicalJid;
use roxmltree::Node;
use thiserror::Error;

pub const XMLNS_MUC_USER: &str = "http://jabber.org/protocol/muc#user";
pub const XMLNS_MUC: &str = "http://jabber.org/protocol/muc";
pub const DEFAULT_HISTORY_MAX_STANZAS: usize = 20;
pub const MAX_HISTORY_STANZA_BOUND: usize = 100;
pub const MAX_HISTORY_CHARS_BOUND: usize = 4 * 1024 * 1024; // 4 MB

/// Errors in parsing MUC message extensions.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MessageError {
    /// XML node is malformed or has invalid attributes.
    #[error("message extension syntax or attributes are invalid")]
    InvalidXml,

    /// Multiple conflicting or duplicate elements found where at most one is allowed.
    #[error("multiple duplicate or conflicting message elements found")]
    DuplicateElement,

    /// Address contained in invite or decline is invalid.
    #[error("contained JID is malformed: {0}")]
    Address(#[from] AddressError),

    /// History request attributes contain invalid numerical values or illegal format.
    #[error("invalid history request parameters")]
    InvalidHistoryParameters,
}

/// A mediated room invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MediatedInvite {
    /// JID of the invited user (`to` attribute).
    pub to: String,
    /// Optional invitation reason text.
    pub reason: Option<String>,
}

/// A mediated invitation decline.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InvitationDecline {
    /// Target user bare or full JID (`to` attribute).
    pub to: String,
    /// Optional decline reason text.
    pub reason: Option<String>,
}

/// Parameters requested for initial discussion message history.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MucHistoryRequest {
    /// Maximum number of stanzas to return (default 20, capped at 100).
    pub max_stanzas: usize,
    /// Maximum character count to return (capped at 4MB).
    pub max_chars: Option<usize>,
    /// Number of seconds in the past from which to retrieve history.
    pub seconds: Option<u64>,
    /// Timestamp string (RFC 3339 / ISO 8601) from which to retrieve history.
    pub since: Option<String>,
}

impl Default for MucHistoryRequest {
    fn default() -> Self {
        Self {
            max_stanzas: DEFAULT_HISTORY_MAX_STANZAS,
            max_chars: None,
            seconds: None,
            since: None,
        }
    }
}

/// Parse mediated invitation elements `<invite to='...'>` inside `<x xmlns='http://jabber.org/protocol/muc#user'>`.
pub fn parse_mediated_invites(root: Node<'_, '_>) -> Result<Vec<MediatedInvite>, MessageError> {
    let mut invites = Vec::new();

    let extensions = root.children().filter(|n| {
        n.is_element()
            && n.tag_name().name() == "x"
            && n.tag_name().namespace() == Some(XMLNS_MUC_USER)
    });

    for ext in extensions {
        for invite in ext
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "invite")
        {
            let Some(to_raw) = invite.attribute("to") else {
                return Err(MessageError::InvalidXml);
            };
            let canonical = CanonicalJid::parse(to_raw).map_err(|_| AddressError::MalformedJid)?;
            let reason = invite
                .children()
                .find(|n| n.is_element() && n.tag_name().name() == "reason")
                .and_then(|n| n.text())
                .filter(|t| !t.trim().is_empty())
                .map(|t| t.trim().to_owned());

            invites.push(MediatedInvite {
                to: canonical.to_string(),
                reason,
            });
        }
    }

    Ok(invites)
}

/// Build a mediated invitation XML message from room to invitee.
pub fn build_mediated_invite_message(
    room_jid: &str,
    invitee_jid: &str,
    inviter_jid: &str,
    reason: Option<&str>,
    password: Option<&str>,
) -> String {
    let mut invite_elem = XmlElement::new("invite").attr("from", inviter_jid);
    if let Some(r) = reason {
        invite_elem.push_child(XmlElement::new("reason").text(r).finish());
    }

    let mut muc_user = XmlElement::namespaced("x", XMLNS_MUC_USER).child(invite_elem.finish());
    if let Some(pwd) = password {
        muc_user.push_child(XmlElement::new("password").text(pwd).finish());
    }

    XmlElement::namespaced("message", "jabber:client")
        .attr("from", room_jid)
        .attr("to", invitee_jid)
        .child(muc_user.finish())
        .finish()
}

/// Parse an invitation decline `<decline to='...'>` inside `<x xmlns='http://jabber.org/protocol/muc#user'>`.
pub fn parse_invitation_decline(
    root: Node<'_, '_>,
) -> Result<Option<InvitationDecline>, MessageError> {
    let declines = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some(XMLNS_MUC_USER)
        })
        .flat_map(|extension| {
            extension.children().filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "decline"
                    && node.tag_name().namespace() == Some(XMLNS_MUC_USER)
            })
        })
        .collect::<Vec<_>>();

    if declines.is_empty() {
        return Ok(None);
    }
    if declines.len() != 1 {
        return Err(MessageError::DuplicateElement);
    }

    let decline = declines[0];
    if decline.attributes().any(|attr| attr.name() != "to") {
        return Err(MessageError::InvalidXml);
    }

    let to_attr = decline.attribute("to").ok_or(MessageError::InvalidXml)?;
    let canonical = CanonicalJid::parse(to_attr).map_err(|_| AddressError::MalformedJid)?;

    let reason = decline
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "reason")
        .and_then(|n| n.text())
        .filter(|t| !t.trim().is_empty())
        .map(|t| t.trim().to_owned());

    Ok(Some(InvitationDecline {
        to: canonical.to_string(),
        reason,
    }))
}

/// Build an invitation decline XML message from room to the original inviter.
pub fn build_invitation_decline_message(
    room_jid: &str,
    inviter_jid: &str,
    decliner_jid: &str,
    reason: Option<&str>,
) -> String {
    let mut decline_elem = XmlElement::new("decline").attr("from", decliner_jid);
    if let Some(r) = reason {
        decline_elem.push_child(XmlElement::new("reason").text(r).finish());
    }

    let muc_user = XmlElement::namespaced("x", XMLNS_MUC_USER).child(decline_elem.finish());

    XmlElement::namespaced("message", "jabber:client")
        .attr("from", room_jid)
        .attr("to", inviter_jid)
        .child(muc_user.finish())
        .finish()
}

/// Parse a room subject mutation command from an incoming groupchat message.
///
/// Per XEP-0045 Section 7.2.16:
/// A subject mutation is a subject-only groupchat message. A message that also contains
/// `<body/>` or `<thread/>` is treated as ordinary discussion and returns `Ok(None)`.
pub fn parse_subject_command(root: Node<'_, '_>) -> Result<Option<String>, MessageError> {
    let has_discussion_content = root.children().any(|node| {
        node.is_element()
            && matches!(node.tag_name().name(), "body" | "thread")
            && node
                .tag_name()
                .namespace()
                .is_none_or(|namespace| namespace == "jabber:client")
    });
    if has_discussion_content {
        return Ok(None);
    }

    let subjects = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "subject"
                && node
                    .tag_name()
                    .namespace()
                    .is_none_or(|namespace| namespace == "jabber:client")
        })
        .collect::<Vec<_>>();

    if subjects.is_empty() {
        return Ok(None);
    }
    if subjects.len() != 1
        || subjects[0].attributes().len() != 0
        || subjects[0].children().any(|node| node.is_element())
    {
        return Err(MessageError::InvalidXml);
    }

    Ok(Some(subjects[0].text().unwrap_or_default().to_owned()))
}

/// Build a current MUC subject groupchat message stanza.
pub fn build_subject_message(
    room_jid: &str,
    recipient_jid: &str,
    subject: &str,
    changed_at_rfc3339: Option<&str>,
) -> String {
    let mut message = XmlElement::namespaced("message", "jabber:client")
        .attr("from", room_jid)
        .attr("to", recipient_jid)
        .attr("type", "groupchat");

    if let Some(stamp) = changed_at_rfc3339 {
        message.push_child(
            XmlElement::namespaced("delay", "urn:xmpp:delay")
                .attr("from", room_jid)
                .attr("stamp", stamp)
                .finish(),
        );
    }

    message
        .child(XmlElement::new("subject").text(subject).finish())
        .finish()
}

/// Parse the `<history .../>` element inside `<x xmlns='http://jabber.org/protocol/muc'>`.
pub fn parse_history_request(root: Node<'_, '_>) -> Result<MucHistoryRequest, MessageError> {
    let muc_extensions = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some(XMLNS_MUC)
        })
        .collect::<Vec<_>>();

    if muc_extensions.len() > 1 {
        return Err(MessageError::DuplicateElement);
    }
    let Some(extension) = muc_extensions.first().copied() else {
        return Ok(MucHistoryRequest::default());
    };

    let histories = extension
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "history")
        .collect::<Vec<_>>();

    if histories.is_empty() {
        return Ok(MucHistoryRequest::default());
    }
    if histories.len() != 1 {
        return Err(MessageError::DuplicateElement);
    }

    let history = histories[0];
    if history.children().any(|node| node.is_element())
        || history.text().is_some_and(|text| !text.trim().is_empty())
        || history.attributes().any(|attribute| {
            !matches!(
                attribute.name(),
                "maxchars" | "maxstanzas" | "seconds" | "since"
            )
        })
    {
        return Err(MessageError::InvalidHistoryParameters);
    }

    let parse_nonnegative = |name: &str| -> Result<Option<u64>, MessageError> {
        history
            .attribute(name)
            .map(|value| {
                if value.is_empty() || value.starts_with('+') {
                    return Err(MessageError::InvalidHistoryParameters);
                }
                value
                    .parse::<u64>()
                    .map_err(|_| MessageError::InvalidHistoryParameters)
            })
            .transpose()
    };

    let max_stanzas = parse_nonnegative("maxstanzas")?
        .map(|v| (v as usize).min(MAX_HISTORY_STANZA_BOUND))
        .unwrap_or(DEFAULT_HISTORY_MAX_STANZAS);

    let max_chars =
        parse_nonnegative("maxchars")?.map(|v| (v as usize).min(MAX_HISTORY_CHARS_BOUND));

    let seconds = parse_nonnegative("seconds")?;
    let since = history.attribute("since").map(str::to_owned);

    Ok(MucHistoryRequest {
        max_stanzas,
        max_chars,
        seconds,
        since,
    })
}

/// Apply character and stanza bounds to historical message stanzas.
pub fn apply_history_bounds(mut stanzas: Vec<String>, request: MucHistoryRequest) -> Vec<String> {
    if stanzas.len() > request.max_stanzas {
        stanzas.drain(..stanzas.len() - request.max_stanzas);
    }
    if let Some(max_chars) = request.max_chars {
        let mut used = 0usize;
        let mut keep_from = stanzas.len();
        for (index, stanza) in stanzas.iter().enumerate().rev() {
            let next = used.saturating_add(stanza.chars().count());
            if next > max_chars {
                break;
            }
            used = next;
            keep_from = index;
        }
        stanzas.drain(..keep_from);
    }
    stanzas
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn test_parse_mediated_invites() {
        let xml = "<message to='room@conference.example.org'>\
            <x xmlns='http://jabber.org/protocol/muc#user'>\
                <invite to='alice@example.org'>\
                    <reason>Please join our discussion</reason>\
                </invite>\
                <invite to='bob@example.org'/>\
            </x>\
        </message>";
        let doc = Document::parse(xml).unwrap();
        let invites = parse_mediated_invites(doc.root_element()).unwrap();
        assert_eq!(invites.len(), 2);
        assert_eq!(invites[0].to, "alice@example.org");
        assert_eq!(
            invites[0].reason,
            Some("Please join our discussion".to_owned())
        );
        assert_eq!(invites[1].to, "bob@example.org");
        assert_eq!(invites[1].reason, None);
    }

    #[test]
    fn test_parse_invitation_decline() {
        let xml = "<message to='room@conference.example.org'>\
            <x xmlns='http://jabber.org/protocol/muc#user'>\
                <decline to='inviter@example.org'>\
                    <reason>Busy today</reason>\
                </decline>\
            </x>\
        </message>";
        let doc = Document::parse(xml).unwrap();
        let decline = parse_invitation_decline(doc.root_element())
            .unwrap()
            .unwrap();
        assert_eq!(decline.to, "inviter@example.org");
        assert_eq!(decline.reason, Some("Busy today".to_owned()));
    }

    #[test]
    fn test_parse_subject_command() {
        // Pure subject message -> accepted
        let xml = "<message type='groupchat'><subject>New Topic</subject></message>";
        let doc = Document::parse(xml).unwrap();
        assert_eq!(
            parse_subject_command(doc.root_element()),
            Ok(Some("New Topic".to_owned()))
        );

        // Message with body and subject -> treated as discussion, subject mutation returns None
        let xml2 = "<message type='groupchat'><body>Hey</body><subject>Topic</subject></message>";
        let doc2 = Document::parse(xml2).unwrap();
        assert_eq!(parse_subject_command(doc2.root_element()), Ok(None));
    }

    #[test]
    fn test_parse_history_request() {
        let xml = "<presence to='room@conf/nick'>\
            <x xmlns='http://jabber.org/protocol/muc'>\
                <history maxstanzas='50' maxchars='2000' seconds='3600'/>\
            </x>\
        </presence>";
        let doc = Document::parse(xml).unwrap();
        let req = parse_history_request(doc.root_element()).unwrap();
        assert_eq!(req.max_stanzas, 50);
        assert_eq!(req.max_chars, Some(2000));
        assert_eq!(req.seconds, Some(3600));
    }

    #[test]
    fn test_apply_history_bounds() {
        let stanzas = vec![
            "stanza 1".to_owned(),
            "stanza 2".to_owned(),
            "stanza 3".to_owned(),
            "stanza 4".to_owned(),
            "stanza 5".to_owned(),
        ];
        let req = MucHistoryRequest {
            max_stanzas: 3,
            max_chars: None,
            seconds: None,
            since: None,
        };
        let bounded = apply_history_bounds(stanzas, req);
        assert_eq!(bounded.len(), 3);
        assert_eq!(bounded, vec!["stanza 3", "stanza 4", "stanza 5"]);
    }
}
