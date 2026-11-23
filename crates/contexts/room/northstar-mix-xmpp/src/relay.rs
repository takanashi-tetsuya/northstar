//! MIX IQ relay: relay parsing, correlation, expiry and the channel relay request handler.

use super::*;
pub use northstar_room_application::mix_service::MixRelayProfileKind as RelayPayload;
use northstar_room_application::mix_service::{
    MixRelayProfileDenial, MixRelayProfileQuery, MixRelayProfileRequester, MixRelayProfileResult,
};

#[derive(Clone, Debug)]
pub struct RelayIq {
    pub id: String,
    pub kind: String,
    pub from: String,
    pub to: String,
    pub payload_xml: String,
    pub request: Option<RelayPayload>,
}

pub fn parse_relay_iq(raw: &str) -> Result<Option<RelayIq>> {
    if raw.len() > 1_048_576 {
        anyhow::bail!("MIX IQ relay stanza is too large");
    }
    let document = Document::parse(raw).context("malformed MIX IQ relay stanza")?;
    let root = document.root_element();
    if root.tag_name().name() != "iq" {
        return Ok(None);
    }
    let id = root.attribute("id").unwrap_or_default();
    let kind = root.attribute("type").unwrap_or_default();
    let from = root.attribute("from").unwrap_or_default();
    let to = root.attribute("to").unwrap_or_default();
    if id.is_empty()
        || id.len() > 1_024
        || to.is_empty()
        || !matches!(kind, "get" | "result" | "error")
    {
        return Ok(None);
    }
    let elements = root.children().filter(Node::is_element).collect::<Vec<_>>();
    let request = if kind == "get" {
        if elements.len() != 1 {
            return Ok(None);
        }
        let child = elements[0];
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("vCard", Some("vcard-temp")) => {
                if child.attributes().len() != 0
                    || child.children().any(|node| node.is_element())
                    || child.text().is_some_and(|text| !text.trim().is_empty())
                {
                    return Ok(None);
                }
                Some(RelayPayload::VCardTemp)
            }
            ("pubsub", Some(PUBSUB_NS)) => {
                if child.attributes().len() != 0 {
                    return Ok(None);
                }
                let actions = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                if actions.len() != 1
                    || actions[0].tag_name().name() != "items"
                    || actions[0].tag_name().namespace() != Some(PUBSUB_NS)
                    || actions[0].attribute("node") != Some("urn:xmpp:vcard4")
                    || actions[0].attributes().len() != 1
                {
                    return Ok(None);
                }
                let items = actions[0]
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                let item_id = match items.as_slice() {
                    [] => None,
                    [item]
                        if item.tag_name().name() == "item"
                            && item.tag_name().namespace() == Some(PUBSUB_NS)
                            && item.attributes().len() == 1
                            && !item.children().any(|node| node.is_element()) =>
                    {
                        let id = item.attribute("id").unwrap_or_default();
                        if id.is_empty() || id.len() > 1_024 {
                            return Ok(None);
                        }
                        Some(id.to_owned())
                    }
                    _ => return Ok(None),
                };
                Some(RelayPayload::VCard4 { item_id })
            }
            _ => return Ok(None),
        }
    } else {
        if elements.len() > 2
            || (kind == "error"
                && elements
                    .iter()
                    .filter(|node| node.tag_name().name() == "error")
                    .count()
                    != 1)
        {
            return Ok(None);
        }
        None
    };
    let payload_xml = elements
        .iter()
        .map(|element| &raw[element.range()])
        .collect::<String>();
    Ok(Some(RelayIq {
        id: id.to_owned(),
        kind: kind.to_owned(),
        from: if from.is_empty() {
            String::new()
        } else {
            northstar_xmpp_types::jid::canonicalize(from)?
        },
        to: northstar_xmpp_types::jid::canonicalize(to)?,
        payload_xml,
        request,
    }))
}

pub fn relay_iq_xml(iq: &RelayIq, id: &str, from: &str, to: &str) -> String {
    let mut reply = XmlElement::namespaced("iq", "jabber:client")
        .attr("type", &iq.kind)
        .attr("from", from)
        .attr("to", to)
        .attr("id", id);
    if reply.push_validated_fragment(&iq.payload_xml).is_err() {
        return iq_error_to(id, from, to, "modify", "bad-request");
    }
    reply.finish()
}

pub fn relay_error(id: &str, from: &str, to: &str, kind: &str, condition: &str) -> String {
    iq_error_to(id, from, to, kind, condition)
}

pub fn register_mix_iq_relay(
    state: &Arc<impl MixHost>,
    id: String,
    stage: MixIqRelayStage,
) -> bool {
    state.pending_mix_iq().admit(id, stage, Instant::now())
}

pub async fn expire_mix_iq_relay(route: &impl MixIqRelayRoutePort, pending: PendingMixIqRelay) {
    let (requester, stanza) = match pending.stage {
        MixIqRelayStage::Participant {
            requester_full_jid,
            original_id,
            expected_from,
            ..
        } => {
            let stanza = relay_error(
                &original_id,
                &expected_from,
                &requester_full_jid,
                "wait",
                "remote-server-timeout",
            );
            (requester_full_jid, stanza)
        }
        MixIqRelayStage::Channel {
            requester_full_jid,
            original_id,
            target_encoded_jid,
            ..
        } => {
            let stanza = relay_error(
                &original_id,
                &target_encoded_jid,
                &requester_full_jid,
                "wait",
                "remote-server-timeout",
            );
            (requester_full_jid, stanza)
        }
    };
    route.deliver(&requester, stanza).await;
}

pub async fn deliver_mix_relay_stanza(state: &Arc<impl MixHost>, recipient: &str, stanza: String) {
    state.mix_iq_relay_route().deliver(recipient, stanza).await;
}

pub(super) fn relay_profile_reply(
    id: &str,
    from: &str,
    to: &str,
    result: MixRelayProfileResult,
) -> Result<String> {
    use MixRelayProfileResult as Profile;
    let payload = match result {
        Profile::Denied(MixRelayProfileDenial::Forbidden) => {
            return Ok(relay_error(id, from, to, "auth", "forbidden"));
        }
        Profile::Denied(MixRelayProfileDenial::JidMalformed) => {
            return Ok(relay_error(id, from, to, "modify", "jid-malformed"));
        }
        Profile::TargetMissing | Profile::VCard4Missing => {
            return Ok(relay_error(id, from, to, "cancel", "item-not-found"));
        }
        Profile::EmptyCard => XmlElement::namespaced("vCard", "vcard-temp").finish(),
        Profile::VCardTemp(payload) => payload,
        Profile::VCard4(item) => {
            let mut items = XmlElement::new("items").attr("node", "urn:xmpp:vcard4");
            items.push_validated_fragment(&item)?;
            XmlElement::namespaced("pubsub", PUBSUB_NS)
                .child(items)
                .finish()
        }
        Profile::RemoteRoute { .. } => anyhow::bail!("MIX profile requires a remote relay"),
    };
    Ok(iq_result_to(id, from, to, &payload))
}

pub fn encoded_participant_full_jid(
    channel_jid: &str,
    participant_id: &str,
    resource: &str,
) -> Result<String> {
    northstar_room_core::mix::MixRelayAddress::encode(channel_jid, participant_id, Some(resource))
        .map(|address| address.to_string())
}

pub async fn handle_channel_relay_request(
    state: &Arc<impl MixHost>,
    request: &RelayIq,
    actor_full: &str,
) -> Result<String> {
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse(actor_full)?;
    let actor_resource = actor
        .resourcepart()
        .context("MIX IQ relay requires a full participant JID")?;
    let target = northstar_xmpp_types::jid::CanonicalJid::parse(&request.to)?;
    let (_, channel_jid) = decode_participant_jid(&target.bare())?;
    let channel = CanonicalJid::parse_bare(&channel_jid)?;
    let local_mix = local_mix_domain(state.local_domain());
    anyhow::ensure!(
        channel.domainpart() == local_mix,
        "MIX relay channel is not hosted locally"
    );
    let result = state
        .mix_service()
        .relay_profile_snapshot(MixRelayProfileQuery {
            channel,
            requester: MixRelayProfileRequester::ChannelParticipant {
                actor: actor.clone(),
                local_domain: state.local_domain().to_owned(),
            },
            target,
            kind: request.request.clone().context("missing relay request")?,
        })
        .await?;
    let MixRelayProfileResult::RemoteRoute {
        requester_participant_id,
        target_domain,
        target_jid,
    } = result
    else {
        return relay_profile_reply(&request.id, &request.to, actor_full, result);
    };
    let requester_encoded = encoded_participant_full_jid(
        &channel_jid,
        &requester_participant_id.to_string(),
        actor_resource,
    )?;
    if !state.federation_domain_allowed(&target_domain) {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "cancel",
            "remote-server-not-found",
        ));
    }
    let relay_id = Uuid::new_v4().to_string();
    if !register_mix_iq_relay(
        state,
        relay_id.clone(),
        MixIqRelayStage::Channel {
            requester_full_jid: actor_full.to_owned(),
            requester_encoded_jid: requester_encoded.clone(),
            original_id: request.id.clone(),
            target_real_jid: target_jid.clone(),
            target_encoded_jid: request.to.clone(),
            channel_jid: channel_jid.clone(),
        },
    ) {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "wait",
            "resource-constraint",
        ));
    }
    let outbound = relay_iq_xml(request, &relay_id, &requester_encoded, &target_jid);
    if !state
        .federation_outbox()
        .send(&target_domain, outbound, Some(channel_jid))
        .await
    {
        state.pending_mix_iq().remove(&relay_id);
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "wait",
            "remote-server-timeout",
        ));
    }
    Ok(String::new())
}
