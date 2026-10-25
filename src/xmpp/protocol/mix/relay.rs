//! MIX IQ relay: relay parsing, correlation, expiry and the channel relay request handler.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RelayPayload {
    VCardTemp,
    VCard4 { item_id: Option<String> },
}

#[derive(Clone, Debug)]
pub(super) struct RelayIq {
    pub(super) id: String,
    pub(super) kind: String,
    pub(super) from: String,
    pub(super) to: String,
    pub(super) payload_xml: String,
    pub(super) request: Option<RelayPayload>,
}

pub(super) fn parse_relay_iq(raw: &str) -> Result<Option<RelayIq>> {
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

pub(super) fn relay_iq_xml(iq: &RelayIq, id: &str, from: &str, to: &str) -> String {
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

pub(super) fn relay_error(id: &str, from: &str, to: &str, kind: &str, condition: &str) -> String {
    iq_error_to(id, from, to, kind, condition)
}

pub(super) fn register_mix_iq_relay(
    state: &Arc<AppState>,
    id: String,
    stage: MixIqRelayStage,
) -> bool {
    state.pending_mix_iq().admit(id, stage, Instant::now())
}

pub(super) async fn expire_mix_iq_relay(route: &MixIqRelayRoute, pending: PendingMixIqRelay) {
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

pub(super) async fn deliver_mix_relay_stanza(
    state: &Arc<AppState>,
    recipient: &str,
    stanza: String,
) {
    state.mix_iq_relay_route().deliver(recipient, stanza).await;
}

pub(super) async fn relay_vcard_payload(
    state: &Arc<AppState>,
    user: &crate::services::mix::MixAccount,
    request: &RelayPayload,
) -> Result<std::result::Result<String, &'static str>> {
    match request {
        RelayPayload::VCardTemp => Ok(Ok(state
            .mix_service()
            .get_vcard(user.id)
            .await?
            .payload_vcard_temp
            .unwrap_or_else(|| XmlElement::namespaced("vCard", "vcard-temp").finish()))),
        RelayPayload::VCard4 { item_id } => {
            if state
                .mix_service()
                .pep_node(user.id, "urn:xmpp:vcard4")
                .await?
                .is_none()
            {
                return Ok(Err("item-not-found"));
            }
            let items = state
                .mix_service()
                .pep_items(user.id, "urn:xmpp:vcard4", item_id.as_deref(), 1)
                .await?;
            if items.is_empty() {
                return Ok(Err("item-not-found"));
            }
            let mut item_elements = XmlElement::new("items").attr("node", "urn:xmpp:vcard4");
            for (_, payload) in items {
                item_elements.push_validated_fragment(&payload)?;
            }
            Ok(Ok(XmlElement::namespaced("pubsub", PUBSUB_NS)
                .child(item_elements)
                .finish()))
        }
    }
}

pub(super) fn encoded_participant_full_jid(
    channel_jid: &str,
    participant_id: &str,
    resource: &str,
) -> Result<String> {
    let bare = encoded_participant_jid(channel_jid, participant_id)?;
    northstar_xmpp_types::jid::canonicalize(&format!("{bare}/{resource}"))
}

pub(super) async fn handle_channel_relay_request(
    state: &Arc<AppState>,
    request: &RelayIq,
    actor_full: &str,
) -> Result<String> {
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse(actor_full)?;
    let actor_resource = actor
        .resourcepart()
        .context("MIX IQ relay requires a full participant JID")?;
    let target = northstar_xmpp_types::jid::CanonicalJid::parse(&request.to)?;
    let (target_id, channel_jid) = decode_participant_jid(&target.bare())?;
    let channel = CanonicalJid::parse_bare(&channel_jid)?;
    let channel_domain = channel.domainpart();
    let local_mix = local_mix_domain(state);
    anyhow::ensure!(
        channel_domain == local_mix,
        "MIX relay channel is not hosted locally"
    );
    let channel_localpart = channel
        .localpart()
        .context("MIX channel lacks a localpart")?;
    let Some(channel) = state
        .mix_service()
        .mix_channel(channel_domain, channel_localpart)
        .await?
    else {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "cancel",
            "item-not-found",
        ));
    };
    let Some(requester) = state
        .mix_service()
        .mix_participant(channel.id, &actor.bare())
        .await?
    else {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "auth",
            "forbidden",
        ));
    };
    let target_id = match Uuid::parse_str(&target_id) {
        Ok(target_id) => target_id,
        Err(_) => {
            return Ok(relay_error(
                &request.id,
                &request.to,
                actor_full,
                "modify",
                "jid-malformed",
            ));
        }
    };
    let Some(target_participant) = state
        .mix_service()
        .mix_participant_by_id(channel.id, target_id)
        .await?
    else {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "cancel",
            "item-not-found",
        ));
    };
    let target_preference = state
        .mix_service()
        .mix_participant_preference(channel.id, &target_participant.jid)
        .await?
        .unwrap_or_default();
    if target_preference.vcard != "allow" {
        return Ok(relay_error(
            &request.id,
            &request.to,
            actor_full,
            "auth",
            "forbidden",
        ));
    }
    let expected_target_bare = encoded_participant_jid(
        &channel.jid(),
        &target_participant.participant_id.to_string(),
    )?;
    anyhow::ensure!(
        target.bare() == expected_target_bare,
        "MIX encoded target does not belong to this channel"
    );
    let mapped_target = if target.resourcepart().is_some() {
        match state
            .mix_service()
            .mix_presence_source_jid(channel.id, &request.to)
            .await?
        {
            Some(source) => Some(source),
            None => {
                return Ok(relay_error(
                    &request.id,
                    &request.to,
                    actor_full,
                    "cancel",
                    "item-not-found",
                ));
            }
        }
    } else {
        None
    };
    let requester_encoded = encoded_participant_full_jid(
        &channel.jid(),
        &requester.participant_id.to_string(),
        actor_resource,
    )?;
    let target_real_jid = mapped_target.unwrap_or_else(|| target_participant.jid.clone());

    let requester_jid = CanonicalJid::parse_bare(&requester.jid)?;
    if same_jid_domain(requester_jid.domainpart(), state.local_domain()) {
        if let Some(username) = requester_jid.localpart() {
            if let Some(user) = state.mix_service().find_enabled_user(username).await? {
                if state
                    .mix_service()
                    .is_blocked(user.id, &channel.jid())
                    .await?
                    || state
                        .mix_service()
                        .is_blocked(user.id, &target_participant.jid)
                        .await?
                {
                    return Ok(relay_error(
                        &request.id,
                        &request.to,
                        actor_full,
                        "auth",
                        "forbidden",
                    ));
                }
            }
        }
    }
    let target_participant_jid = CanonicalJid::parse_bare(&target_participant.jid)?;
    let target_domain = target_participant_jid.domainpart();
    if same_jid_domain(target_domain, state.local_domain()) {
        let Some(target_username) = target_participant_jid.localpart() else {
            return Ok(relay_error(
                &request.id,
                &request.to,
                actor_full,
                "modify",
                "jid-malformed",
            ));
        };
        let Some(target_user) = state
            .mix_service()
            .find_enabled_user(target_username)
            .await?
        else {
            return Ok(relay_error(
                &request.id,
                &request.to,
                actor_full,
                "cancel",
                "item-not-found",
            ));
        };
        if state
            .mix_service()
            .is_blocked(target_user.id, &channel.jid())
            .await?
            || state
                .mix_service()
                .is_blocked(target_user.id, &requester.jid)
                .await?
        {
            return Ok(relay_error(
                &request.id,
                &request.to,
                actor_full,
                "auth",
                "forbidden",
            ));
        }
        let payload = relay_vcard_payload(
            state,
            &target_user,
            request.request.as_ref().context("missing relay request")?,
        )
        .await?;
        return Ok(match payload {
            Ok(payload) => iq_result_to(&request.id, &request.to, actor_full, &payload),
            Err(condition) => {
                relay_error(&request.id, &request.to, actor_full, "cancel", condition)
            }
        });
    }
    if !state.federation_domain_allowed(target_domain) {
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
            target_real_jid: target_real_jid.clone(),
            target_encoded_jid: request.to.clone(),
            channel_jid: channel.jid(),
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
    let outbound = relay_iq_xml(request, &relay_id, &requester_encoded, &target_real_jid);
    if !state
        .federation_outbox()
        .send(target_domain, outbound, Some(channel.jid()))
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
