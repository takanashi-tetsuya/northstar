//! MIX result payloads: disco#info, join and PAM results, participant JID encoding and remote result parsing.

use super::*;

pub(crate) fn mix_service_disco_info_payload(server_name: &str, mirror: &str) -> Result<String> {
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info").child(
        XmlElement::new("identity")
            .attr("category", "conference")
            .attr("type", "mix")
            .attr("name", format!("{server_name} MIX Service")),
    );
    for feature in [
        "http://jabber.org/protocol/disco#info",
        "http://jabber.org/protocol/disco#items",
        "urn:xmpp:mix:core:1",
        "urn:xmpp:mix:core:1#searchable",
        "urn:xmpp:mix:core:1#create-channel",
        "urn:xmpp:mix:misc:0#nick-register",
    ] {
        query.push_child(XmlElement::new("feature").attr("var", feature));
    }
    query.push_validated_fragment(mirror)?;
    Ok(query.finish())
}

pub(crate) fn mix_channel_disco_info_payload(
    name: &str,
    supports_retraction: bool,
    supports_private_messages: bool,
    supports_mam: bool,
    mirror: &str,
) -> Result<String> {
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info").child(
        XmlElement::new("identity")
            .attr("category", "conference")
            .attr("type", "mix")
            .attr("name", name),
    );
    for feature in [
        "http://jabber.org/protocol/disco#info",
        "http://jabber.org/protocol/disco#items",
        "http://jabber.org/protocol/pubsub",
        "http://jabber.org/protocol/rsm",
        "urn:xmpp:mix:core:1",
        "urn:xmpp:mix:admin:0",
        "urn:xmpp:mix:presence:0",
        "urn:xmpp:mix:anon:0",
        "urn:xmpp:mix:misc:0",
        "urn:xmpp:avatar:data",
        "urn:xmpp:avatar:metadata",
        "urn:xmpp:sid:0",
    ] {
        query.push_child(XmlElement::new("feature").attr("var", feature));
    }
    if supports_mam {
        query.push_child(
            XmlElement::new("feature").attr("var", northstar_xep_0313::DISCO_FEATURE_MAM),
        );
        query.push_child(
            XmlElement::new("feature").attr("var", northstar_xep_0313::DISCO_FEATURE_MAM_EXTENDED),
        );
    }
    if supports_retraction {
        query.push_child(
            XmlElement::new("feature").attr("var", "urn:xmpp:mix:misc:0#message-retract"),
        );
    }
    if supports_private_messages {
        query.push_child(
            XmlElement::new("feature").attr("var", "urn:xmpp:mix:anon:0#private-messages"),
        );
    }
    query.push_validated_fragment(mirror)?;
    Ok(query.finish())
}

pub(super) fn join_body(
    participant: &MixParticipant,
    subscriptions: &[String],
    preference: Option<&MixParticipantPreference>,
) -> Result<String> {
    let mut body = XmlElement::new("mix-join-body");
    for node in subscriptions {
        body.push_child(XmlElement::new("subscribe").attr("node", node));
    }
    if let Some(nick) = participant.nick.as_deref() {
        body.push_child(XmlElement::new("nick").text(nick.to_owned()));
    }
    if let Some(preference) = preference {
        body.push_validated_fragment(&preference_result_form(preference))?;
    }
    Ok(body.finish_children())
}

/// XEP-0369 identifies the participant with the Stable Participant ID in an
/// `id` attribute on the channel's direct join result.
pub(super) fn core_join_payload(
    participant: &MixParticipant,
    subscriptions: &[String],
    preference: Option<&MixParticipantPreference>,
    anonymous_profile: bool,
) -> Result<String> {
    let namespace = if anonymous_profile { ANON_NS } else { CORE_NS };
    XmlElement::namespaced("join", namespace)
        .attr("id", participant.participant_id)
        .validated_fragment(&join_body(participant, subscriptions, preference)?)
        .map(|element| element.finish())
}

/// XEP-0405 exposes the stable participant reference to a client as an
/// encoded bare JID: `stable-id#channel@mix-service`.  Ensure that embedding
/// the opaque ID in an RFC 7622 localpart does not change it under PRECIS.
pub(super) fn encoded_participant_jid(channel_jid: &str, participant_id: &str) -> Result<String> {
    anyhow::ensure!(
        crate::services::mix::valid_stable_participant_id(participant_id),
        "invalid MIX stable participant id"
    );
    let channel = northstar_xmpp_types::jid::CanonicalJid::parse_bare(channel_jid)?;
    let channel_localpart = channel
        .localpart()
        .context("MIX channel JID requires a localpart")?;
    let encoded_localpart = format!("{participant_id}#{channel_localpart}");
    let encoded = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
        "{encoded_localpart}@{}",
        channel.domainpart()
    ))?;
    anyhow::ensure!(
        encoded.localpart() == Some(encoded_localpart.as_str()),
        "MIX stable participant id is not a canonical JID localpart prefix"
    );
    Ok(encoded.to_string())
}

pub(super) fn decode_participant_jid(value: &str) -> Result<(String, String)> {
    let raw_localpart = value
        .split_once('@')
        .map(|(localpart, _)| localpart)
        .context("encoded MIX participant JID requires a localpart")?;
    let encoded = northstar_xmpp_types::jid::CanonicalJid::parse_bare(value)?;
    anyhow::ensure!(
        encoded.localpart() == Some(raw_localpart),
        "encoded MIX participant JID is not in canonical localpart form"
    );
    let (participant_id, channel_localpart) = encoded
        .localpart()
        .and_then(|localpart| localpart.split_once('#'))
        .context("encoded MIX participant JID is missing its channel")?;
    anyhow::ensure!(
        crate::services::mix::valid_stable_participant_id(participant_id),
        "invalid MIX stable participant id"
    );
    let channel = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!(
        "{channel_localpart}@{}",
        encoded.domainpart()
    ))?;
    Ok((participant_id.to_owned(), channel.to_string()))
}

pub(super) fn participant_id_from_encoded_jid(value: &str, channel_jid: &str) -> Result<String> {
    let (participant_id, encoded_channel) = decode_participant_jid(value)?;
    let channel = northstar_xmpp_types::jid::CanonicalJid::parse_bare(channel_jid)?;
    anyhow::ensure!(
        encoded_channel == channel.to_string(),
        "encoded MIX participant JID has the wrong channel"
    );
    Ok(participant_id)
}

pub(super) fn pam_join_payload(
    channel_jid: &str,
    participant: &MixParticipant,
    subscriptions: &[String],
    preference: Option<&MixParticipantPreference>,
    anonymous_profile: bool,
) -> Result<String> {
    let participant_jid =
        encoded_participant_jid(channel_jid, &participant.participant_id.to_string())?;
    let namespace = if anonymous_profile { ANON_NS } else { CORE_NS };
    Ok(XmlElement::namespaced("join", namespace)
        .attr("jid", &participant_jid)
        .validated_fragment(&join_body(participant, subscriptions, preference)?)?
        .finish())
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct RemoteJoinResult {
    pub(super) participant_id: String,
    pub(super) participant_jid: String,
    pub(super) subscriptions: Vec<String>,
    pub(super) nick: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct RemoteIqError {
    pub(super) error_type: String,
    pub(super) condition: String,
}

pub(super) fn parse_remote_iq_error(raw: &str) -> Result<RemoteIqError> {
    const STANZA_ERRORS_NS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
    const CONDITIONS: [&str; 22] = [
        "bad-request",
        "conflict",
        "feature-not-implemented",
        "forbidden",
        "gone",
        "internal-server-error",
        "item-not-found",
        "jid-malformed",
        "not-acceptable",
        "not-allowed",
        "not-authorized",
        "policy-violation",
        "recipient-unavailable",
        "redirect",
        "registration-required",
        "remote-server-not-found",
        "remote-server-timeout",
        "resource-constraint",
        "service-unavailable",
        "subscription-required",
        "undefined-condition",
        "unexpected-request",
    ];
    let document = Document::parse(raw).context("malformed federated MIX error")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "iq" && root.attribute("type") == Some("error"),
        "not an IQ error"
    );
    let error = root
        .children()
        .filter(Node::is_element)
        .find(|node| node.tag_name().name() == "error")
        .context("missing IQ error payload")?;
    let error_type = error.attribute("type").unwrap_or_default();
    anyhow::ensure!(
        matches!(
            error_type,
            "auth" | "cancel" | "continue" | "modify" | "wait"
        ),
        "invalid IQ error type"
    );
    let conditions = error
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(STANZA_ERRORS_NS)
                && node.tag_name().name() != "text"
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(conditions.len() == 1, "invalid IQ error condition count");
    let condition = conditions[0].tag_name().name();
    anyhow::ensure!(
        CONDITIONS.contains(&condition),
        "unknown IQ error condition"
    );
    Ok(RemoteIqError {
        error_type: error_type.to_owned(),
        condition: condition.to_owned(),
    })
}

pub(super) fn parse_remote_join_result(raw: &str, channel_jid: &str) -> Result<RemoteJoinResult> {
    let document = Document::parse(raw).context("malformed federated MIX join result")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "iq" && root.attribute("type") == Some("result"),
        "not a MIX join result"
    );
    let elements = root.children().filter(Node::is_element).collect::<Vec<_>>();
    anyhow::ensure!(elements.len() == 1, "invalid MIX join result payload count");
    let join = elements[0];
    anyhow::ensure!(
        join.tag_name().name() == "join"
            && matches!(join.tag_name().namespace(), Some(CORE_NS | ANON_NS)),
        "invalid MIX join result payload element name={:?} namespace={:?}",
        join.tag_name().name(),
        join.tag_name().namespace()
    );
    let participant_id = match (join.attribute("id"), join.attribute("jid")) {
        (Some(participant_id), None) => {
            anyhow::ensure!(
                crate::services::mix::valid_stable_participant_id(participant_id),
                "invalid MIX stable participant id"
            );
            participant_id.to_owned()
        }
        // XEP-0405 examples use the encoded JID form in the channel response,
        // while the current XEP-0369 text uses `id`. Accept both documented
        // forms but never accept an ambiguous response containing both.
        (None, Some(participant_jid)) => {
            participant_id_from_encoded_jid(participant_jid, channel_jid)?
        }
        _ => anyhow::bail!("MIX join result requires exactly one participant identifier"),
    };
    let participant_jid = encoded_participant_jid(channel_jid, &participant_id)?;
    let join = parse_join(join)?;
    Ok(RemoteJoinResult {
        participant_id,
        participant_jid,
        subscriptions: join.nodes,
        nick: join.nick,
    })
}

pub(super) fn parse_remote_pam_success(
    raw: &str,
    channel_jid: &str,
) -> Result<Option<RemoteJoinResult>> {
    let document = Document::parse(raw).context("malformed federated MIX result")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "iq" && root.attribute("type") == Some("result"),
        "not a MIX result"
    );
    let payloads = root.children().filter(Node::is_element).collect::<Vec<_>>();
    match payloads.as_slice() {
        [leave]
            if leave.tag_name().name() == "leave"
                && leave.tag_name().namespace() == Some(CORE_NS) =>
        {
            anyhow::ensure!(
                leave.attributes().len() == 0
                    && !leave.children().any(|node| node.is_element())
                    && leave
                        .children()
                        .filter(Node::is_text)
                        .all(|node| node.text().is_none_or(|text| text.trim().is_empty())),
                "invalid MIX leave result payload"
            );
            Ok(None)
        }
        [] => Ok(None),
        [_] => parse_remote_join_result(raw, channel_jid).map(Some),
        _ => anyhow::bail!("invalid MIX result payload count"),
    }
}

pub(super) fn mix_pubsub_publish_ack(node: &str, item_id: &str) -> String {
    XmlElement::namespaced("pubsub", PUBSUB_NS)
        .child(
            XmlElement::new("publish")
                .attr("node", node)
                .child(XmlElement::new("item").attr("id", item_id)),
        )
        .finish()
}

pub(super) fn mix_empty_pubsub() -> String {
    XmlElement::namespaced("pubsub", PUBSUB_NS).finish()
}
