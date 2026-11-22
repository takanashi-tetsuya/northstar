//! The personal XEP-0424 retraction a message carries.

use northstar_xml_builder::XmlElement;
use roxmltree::Node;

const NS_RETRACT: &str = "urn:xmpp:message-retract:1";

pub struct RetractionEnvelope<'a> {
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub id: Option<&'a str>,
}

pub fn render_retraction_tombstone<'a>(
    envelope: RetractionEnvelope<'_>,
    stanza_ids: impl IntoIterator<Item = (&'a str, &'a str)>,
    action_id: &str,
    stamp: &str,
) -> String {
    let mut message = XmlElement::namespaced("message", "jabber:client");
    for (name, value) in [
        ("from", envelope.from),
        ("to", envelope.to),
        ("type", envelope.kind),
        ("id", envelope.id),
    ] {
        if let Some(value) = value {
            message = message.attr(name, value);
        }
    }
    for (id, by) in stanza_ids {
        message.push_child(
            XmlElement::namespaced("stanza-id", "urn:xmpp:sid:0")
                .attr("id", id)
                .attr("by", by),
        );
    }
    message
        .child(
            XmlElement::namespaced("retracted", NS_RETRACT)
                .attr("stamp", stamp)
                .attr("id", action_id),
        )
        .finish()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalRetractionCommand {
    pub target_id: String,
    pub action_id: String,
    pub semantic_payload: String,
}

/// A message whose retraction cannot be applied, which is answered as a bad request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPersonalRetraction;

pub fn personal_retraction_command(
    root: Node<'_, '_>,
) -> Result<Option<PersonalRetractionCommand>, InvalidPersonalRetraction> {
    let mut retracts = root.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "retract"
            && node.tag_name().namespace() == Some(NS_RETRACT)
    });
    let Some(retract) = retracts.next() else {
        return Ok(None);
    };
    if retracts.next().is_some()
        || retract.children().any(|node| node.is_element())
        || retract.text().is_some_and(|text| !text.trim().is_empty())
        || retract
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
    {
        return Err(InvalidPersonalRetraction);
    }
    let target_id = retract.attribute("id").ok_or(InvalidPersonalRetraction)?;
    let action_id = root.attribute("id").ok_or(InvalidPersonalRetraction)?;
    if [target_id, action_id]
        .into_iter()
        .any(|id| id.is_empty() || id.len() > 1_024 || id.chars().any(char::is_control))
    {
        return Err(InvalidPersonalRetraction);
    }
    if root.children().any(|node| {
        node.is_element()
            && matches!(
                (node.tag_name().namespace(), node.tag_name().name()),
                (Some("urn:xmpp:message-correct:0"), "replace")
                    | (Some("urn:xmpp:reactions:0"), "reactions")
                    | (Some("urn:xmpp:reply:0"), "reply")
                    | (Some("urn:xmpp:chat-markers:0"), _)
                    | (Some("urn:xmpp:receipts"), _)
                    | (Some("http://jabber.org/protocol/chatstates"), _)
                    | (Some("urn:xmpp:jingle-message:0"), _)
                    | (Some("urn:xmpp:call-invites:0"), _)
                    | (Some("urn:xmpp:sfs:0"), "file-sharing")
                    | (Some("http://jabber.org/protocol/pubsub#event"), "event")
                    | (Some("jabber:x:roster"), "x")
                    | (Some("jabber:x:conference"), "x")
            )
    }) {
        return Err(InvalidPersonalRetraction);
    }
    Ok(Some(PersonalRetractionCommand {
        target_id: target_id.to_owned(),
        action_id: action_id.to_owned(),
        semantic_payload: root
            .document()
            .input_text()
            .get(root.range())
            .ok_or(InvalidPersonalRetraction)?
            .to_owned(),
    }))
}

pub fn retraction_target(root: Node<'_, '_>) -> Result<Option<String>, InvalidPersonalRetraction> {
    personal_retraction_command(root).map(|command| command.map(|command| command.target_id))
}
