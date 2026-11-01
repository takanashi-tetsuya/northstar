//! ProtocolSession entry points for MIX IQs, messages and presence.

use super::*;

fn mix_domain(session: &impl MixSession) -> String {
    local_mix_domain(session.host().local_domain())
}

/// Deliver the latest persisted roster change between `user` and the MIX
/// channel (XEP-0405). The stored change decides whether the item is removed,
/// so `_removed` is unused; a joined membership adds its participant id.
pub async fn push_mix_roster_update(
    state: &Arc<impl MixHost>,
    user: &northstar_room_application::mix_service::MixAccount,
    channel_jid: &str,
    _removed: bool,
) -> Result<()> {
    let Some(change) = state
        .mix_service()
        .latest_roster_change_for_contact(user.id, channel_jid)
        .await?
    else {
        return Ok(());
    };
    let participant_id = if change.removed {
        None
    } else {
        let participant_id = state
            .mix_service()
            .pam_membership(user.id, channel_jid)
            .await?
            .filter(|membership| membership.state == "joined")
            .and_then(|membership| membership.participant_id);
        participant_id
    };
    state
        .deliver_roster_change(user.id, &user.username, &change, participant_id.as_deref())
        .await
}

/// Intercept MIX/PAM IQs before ordinary entity and PubSub routing.
pub async fn try_mix_iq(session: &impl MixSession, raw: &str) -> Result<Option<MixAction>> {
    if let Some(action) = try_mix_iq_relay(session, raw).await? {
        return Ok(Some(action));
    }
    if !mix_iq_route_candidate(raw, &mix_domain(session)) {
        return Ok(None);
    }
    let Some(request) = parse_iq(raw)? else {
        return Ok(None);
    };
    let Some(user) = session.user() else {
        return Ok(Some(MixAction::Send(iq_error_to(
            &request.id,
            request
                .to
                .as_deref()
                .unwrap_or(session.host().local_domain()),
            request.from.as_deref().unwrap_or_default(),
            "auth",
            "not-authorized",
        ))));
    };
    let Some(full_jid) = session.full_jid() else {
        return Ok(Some(MixAction::Send(iq_error_to(
            &request.id,
            session.host().local_domain(),
            "",
            "auth",
            "not-authorized",
        ))));
    };
    let actor_bare = format!("{}@{}", user.username, session.host().local_domain());
    if let Some(asserted) = request.from.as_deref() {
        let asserted = northstar_xmpp_types::jid::canonicalize(asserted).ok();
        if asserted.as_deref() != Some(full_jid) && asserted.as_deref() != Some(actor_bare.as_str())
        {
            return Ok(Some(MixAction::Send(iq_error_to(
                &request.id,
                request
                    .to
                    .as_deref()
                    .unwrap_or(session.host().local_domain()),
                full_jid,
                "auth",
                "not-authorized",
            ))));
        }
    }
    let own_target = request.to.as_deref().is_some_and(|to| {
        CanonicalJid::parse_bare(to).is_ok_and(|target| target.to_string() == actor_bare)
    });
    if matches!(
        request.operation,
        IqOperation::PamJoin { .. } | IqOperation::PamLeave { .. }
    ) {
        if !own_target || request.kind != "set" {
            return Ok(Some(MixAction::Send(iq_error_to(
                &request.id,
                &actor_bare,
                full_jid,
                "modify",
                "bad-request",
            ))));
        }
        return handle_pam_request(
            session,
            request,
            user.id,
            user.username,
            &actor_bare,
            full_jid,
            Sha256::digest(raw.as_bytes()).into(),
        )
        .await
        .map(Some);
    }
    let to = request.to.as_deref().unwrap_or_default();
    if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == mix_domain(session)) {
        return Ok(None);
    }
    handle_local_mix_iq(session, request, &actor_bare, full_jid)
        .await
        .map(Some)
}

pub async fn try_mix_iq_relay(session: &impl MixSession, raw: &str) -> Result<Option<MixAction>> {
    let Some(request) = parse_relay_iq(raw)? else {
        return Ok(None);
    };
    if request.kind != "get" || request.request.is_none() {
        return Ok(None);
    }
    let target = match northstar_xmpp_types::jid::CanonicalJid::parse(&request.to) {
        Ok(target) if target.localpart().is_some() => target,
        _ => return Ok(None),
    };
    let (_target_id, channel_jid) = match decode_participant_jid(&target.bare()) {
        Ok(decoded) => decoded,
        Err(_) => return Ok(None),
    };
    let Some(user) = session.user() else {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            &request.from,
            "auth",
            "not-authorized",
        ))));
    };
    let Some(full_jid) = session.full_jid() else {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            &request.from,
            "auth",
            "not-authorized",
        ))));
    };
    if !request.from.is_empty() && request.from != full_jid {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            full_jid,
            "auth",
            "not-authorized",
        ))));
    }
    let channel_address = CanonicalJid::parse_bare(&channel_jid)?;
    let channel_domain = channel_address.domainpart();
    if channel_domain == mix_domain(session) {
        let response = handle_channel_relay_request(session.host(), &request, full_jid).await?;
        return Ok(Some(if response.is_empty() {
            MixAction::None
        } else {
            MixAction::Send(response)
        }));
    }
    let membership = session
        .host()
        .mix_service()
        .pam_membership(user.id, &channel_jid)
        .await?;
    if !membership.is_some_and(|membership| membership.state == "joined")
        || session
            .host()
            .mix_service()
            .is_blocked(user.id, &channel_jid)
            .await?
        || !session.host().federation_domain_allowed(channel_domain)
    {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            full_jid,
            "auth",
            "forbidden",
        ))));
    }
    let relay_id = Uuid::new_v4().to_string();
    if !register_mix_iq_relay(
        session.host(),
        relay_id.clone(),
        MixIqRelayStage::Participant {
            requester_full_jid: full_jid.to_owned(),
            original_id: request.id.clone(),
            expected_from: request.to.clone(),
            channel_jid: channel_jid.clone(),
        },
    ) {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            full_jid,
            "wait",
            "resource-constraint",
        ))));
    }
    let outbound = relay_iq_xml(&request, &relay_id, full_jid, &request.to);
    if !session
        .host()
        .federation_outbox()
        .send(
            channel_domain,
            outbound,
            Some(CanonicalJid::parse(full_jid)?.bare()),
        )
        .await
    {
        session.host().pending_mix_iq().remove(&relay_id);
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            full_jid,
            "wait",
            "remote-server-timeout",
        ))));
    }
    Ok(Some(MixAction::None))
}

pub async fn handle_pam_request(
    session: &impl MixSession,
    request: OwnedIq,
    user_id: Uuid,
    username: &str,
    actor_bare: &str,
    full_jid: &str,
    request_digest: [u8; 32],
) -> Result<MixAction> {
    match request.operation {
        IqOperation::PamJoin { channel, join } => {
            let channel_address = match CanonicalJid::parse_bare(&channel) {
                Ok(channel) if channel.localpart().is_some() => channel,
                _ => {
                    return Ok(MixAction::Send(iq_error_to(
                        &request.id,
                        actor_bare,
                        full_jid,
                        "modify",
                        "jid-malformed",
                    )));
                }
            };
            let channel = channel_address.to_string();
            let domain = channel_address.domainpart();
            if domain == mix_domain(session) {
                let channel_localpart = channel_address
                    .localpart()
                    .expect("MIX channel localpart was checked above");
                let Some(mix_channel) = session
                    .host()
                    .mix_service()
                    .mix_channel(domain, channel_localpart)
                    .await?
                else {
                    return Ok(MixAction::Send(iq_error_to(
                        &request.id,
                        actor_bare,
                        full_jid,
                        "cancel",
                        "item-not-found",
                    )));
                };
                match session
                    .host()
                    .mix_service()
                    .join_mix_channel(
                        mix_channel.id,
                        JoinMixRequest {
                            actor_jid: actor_bare.to_owned(),
                            nick: join.nick.clone(),
                            nodes: join.nodes.clone(),
                            pam_user_id: Some(user_id),
                            invitation: join.invitation.clone(),
                            preference: join.preference.clone(),
                            anonymous_profile: join.anonymous_profile,
                        },
                        None,
                    )
                    .await?
                {
                    JoinChannelOutcome::Joined {
                        participant,
                        preference,
                        subscriptions,
                        newly_joined: _,
                        roster_change,
                    } => {
                        if let Some(change) = roster_change.as_ref() {
                            let participant_id = participant.participant_id.to_string();
                            session
                                .host()
                                .deliver_roster_change(
                                    user_id,
                                    username,
                                    change,
                                    Some(&participant_id),
                                )
                                .await?;
                        }
                        let payload = XmlElement::namespaced("client-join", PAM_NS)
                            .validated_fragment(&pam_join_payload(
                                &channel,
                                &participant,
                                &subscriptions,
                                join.preference.as_ref().map(|_| &preference),
                                join.anonymous_profile,
                            )?)?
                            .finish();
                        Ok(MixAction::Send(iq_result_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            &payload,
                        )))
                    }
                    outcome => Ok(MixAction::Send(join_error(
                        &request.id,
                        actor_bare,
                        full_jid,
                        outcome,
                    ))),
                }
            } else {
                match session
                    .host()
                    .mix_service()
                    .lookup_remote_pam_operation(user_id, full_jid, &request.id, &request_digest)
                    .await?
                {
                    PamOperationReplay::Replay(response) => return Ok(MixAction::Send(response)),
                    PamOperationReplay::Pending => {
                        session.host().federation_outbox().wake_outbox();
                        return Ok(MixAction::None);
                    }
                    PamOperationReplay::Conflict => {
                        return Ok(MixAction::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "conflict",
                        )));
                    }
                    PamOperationReplay::Miss => {}
                }
                // Exact retries are journal reads, not new federation
                // attempts. A later policy change must not replace the
                // original byte-stable result or strand a pending request.
                if !session.host().federation_domain_allowed(domain) {
                    return Ok(MixAction::Send(iq_error_to(
                        &request.id,
                        actor_bare,
                        full_jid,
                        "cancel",
                        "remote-server-not-found",
                    )));
                }
                let federation_id = Uuid::new_v4().to_string();
                let mut join_element = XmlElement::namespaced("join", CORE_NS);
                for node in &join.nodes {
                    join_element.push_child(XmlElement::new("subscribe").attr("node", node));
                }
                if let Some(nick) = join.nick.as_deref() {
                    join_element.push_child(XmlElement::new("nick").text(nick.to_owned()));
                }
                let outbound = XmlElement::namespaced("iq", "jabber:server")
                    .attr("type", "set")
                    .attr("from", actor_bare)
                    .attr("to", &channel)
                    .attr("id", &federation_id)
                    .child(join_element)
                    .finish();
                let admitted = session
                    .host()
                    .mix_service()
                    .begin_remote_pam_join(BeginRemotePamJoin {
                        user_id,
                        actor_jid: actor_bare.to_owned(),
                        channel_jid: channel.clone(),
                        nick: join.nick.clone(),
                        nodes: join.nodes.clone(),
                        request_id: federation_id,
                        client_request_id: request.id.clone(),
                        requester_full_jid: full_jid.to_owned(),
                        request_digest,
                        remote_domain: domain.to_owned(),
                        outbound_stanza: outbound,
                        policy: session.host().federation_outbox().outbox_policy(),
                    })
                    .await?;
                match admitted {
                    PamOperationReplay::Replay(response) => return Ok(MixAction::Send(response)),
                    PamOperationReplay::Conflict => {
                        return Ok(MixAction::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "conflict",
                        )));
                    }
                    PamOperationReplay::Pending => {
                        session.host().federation_outbox().wake_outbox();
                    }
                    PamOperationReplay::Miss => {
                        return Ok(MixAction::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "wait",
                            "resource-constraint",
                        )));
                    }
                }
                Ok(MixAction::None)
            }
        }
        IqOperation::PamLeave { channel } => {
            let channel_address = match CanonicalJid::parse_bare(&channel) {
                Ok(channel) if channel.localpart().is_some() => channel,
                _ => {
                    return Ok(MixAction::Send(iq_error_to(
                        &request.id,
                        actor_bare,
                        full_jid,
                        "modify",
                        "jid-malformed",
                    )));
                }
            };
            let channel = channel_address.to_string();
            let domain = channel_address.domainpart();
            if domain == mix_domain(session) {
                let channel_localpart = channel_address
                    .localpart()
                    .expect("MIX channel localpart was checked above");
                let Some(mix_channel) = session
                    .host()
                    .mix_service()
                    .mix_channel(domain, channel_localpart)
                    .await?
                else {
                    return Ok(MixAction::Send(iq_error_to(
                        &request.id,
                        actor_bare,
                        full_jid,
                        "cancel",
                        "item-not-found",
                    )));
                };
                let Some(left) = session
                    .host()
                    .mix_service()
                    .leave_mix_channel(mix_channel.id, actor_bare, Some(user_id), None)
                    .await?
                else {
                    return Ok(MixAction::Send(iq_error_to(
                        &request.id,
                        actor_bare,
                        full_jid,
                        "cancel",
                        "item-not-found",
                    )));
                };
                let roster_change = left.roster_change.clone();
                if let Some(change) = roster_change.as_ref() {
                    session
                        .host()
                        .deliver_roster_change(user_id, username, change, None)
                        .await?;
                }
                let payload = XmlElement::namespaced("client-leave", PAM_NS)
                    .attr("channel", &channel)
                    .child(XmlElement::namespaced("leave", CORE_NS))
                    .finish();
                Ok(MixAction::Send(iq_result_to(
                    &request.id,
                    actor_bare,
                    full_jid,
                    &payload,
                )))
            } else {
                match session
                    .host()
                    .mix_service()
                    .lookup_remote_pam_operation(user_id, full_jid, &request.id, &request_digest)
                    .await?
                {
                    PamOperationReplay::Replay(response) => return Ok(MixAction::Send(response)),
                    PamOperationReplay::Pending => {
                        session.host().federation_outbox().wake_outbox();
                        return Ok(MixAction::None);
                    }
                    PamOperationReplay::Conflict => {
                        return Ok(MixAction::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "conflict",
                        )));
                    }
                    PamOperationReplay::Miss => {}
                }
                if !session.host().federation_domain_allowed(domain) {
                    return Ok(MixAction::Send(iq_error_to(
                        &request.id,
                        actor_bare,
                        full_jid,
                        "cancel",
                        "remote-server-not-found",
                    )));
                }
                let federation_id = Uuid::new_v4().to_string();
                let outbound = XmlElement::namespaced("iq", "jabber:server")
                    .attr("type", "set")
                    .attr("from", actor_bare)
                    .attr("to", &channel)
                    .attr("id", &federation_id)
                    .child(XmlElement::namespaced("leave", CORE_NS))
                    .finish();
                let admitted = session
                    .host()
                    .mix_service()
                    .begin_remote_pam_leave(BeginRemotePamLeave {
                        user_id,
                        actor_jid: actor_bare.to_owned(),
                        channel_jid: channel.clone(),
                        request_id: federation_id,
                        client_request_id: request.id.clone(),
                        requester_full_jid: full_jid.to_owned(),
                        request_digest,
                        remote_domain: domain.to_owned(),
                        outbound_stanza: outbound,
                        policy: session.host().federation_outbox().outbox_policy(),
                    })
                    .await?;
                match admitted {
                    PamOperationReplay::Replay(response) => return Ok(MixAction::Send(response)),
                    PamOperationReplay::Conflict => {
                        return Ok(MixAction::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "conflict",
                        )));
                    }
                    PamOperationReplay::Pending => session.host().federation_outbox().wake_outbox(),
                    PamOperationReplay::Miss => {
                        return Ok(MixAction::Send(iq_error_to(
                            &request.id,
                            actor_bare,
                            full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    }
                }
                Ok(MixAction::None)
            }
        }
        _ => unreachable!("PAM dispatcher only passes PAM requests"),
    }
}

pub async fn handle_local_mix_iq(
    session: &impl MixSession,
    request: OwnedIq,
    actor_bare: &str,
    reply_to: &str,
) -> Result<MixAction> {
    let from = request
        .to
        .as_deref()
        .unwrap_or(&mix_domain(session))
        .to_owned();
    if matches!(
        request.operation,
        IqOperation::Mam(_)
            | IqOperation::MamForm
            | IqOperation::MamMetadata
            | IqOperation::MamError(_)
    ) {
        return Ok(MixAction::SendMany(
            handle_mix_mam_iq(session.host(), &request, actor_bare, &from, reply_to).await?,
        ));
    }
    let response =
        handle_channel_iq(session.host(), &request, actor_bare, &from, reply_to, None).await?;
    Ok(MixAction::Send(response))
}

pub async fn try_mix_message(
    session: &impl MixSession,
    root: Node<'_, '_>,
    raw: &str,
) -> Result<Option<MixAction>> {
    let Some(to) = root.attribute("to") else {
        return Ok(None);
    };
    if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == mix_domain(session)) {
        return Ok(None);
    }
    session.frame_observer().enter(MixFrameStage::Policy);
    let Some(user) = session.user() else {
        return Ok(Some(MixAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    };
    let Some(full_jid) = session.full_jid() else {
        return Ok(Some(MixAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    };
    let actor_bare = format!("{}@{}", user.username, session.host().local_domain());
    let result = process_channel_message(
        session.host(),
        &actor_bare,
        full_jid,
        raw,
        Some(session.frame_observer()),
    )
    .await?;
    Ok(Some(result.map_or(MixAction::None, MixAction::Send)))
}

pub async fn try_mix_presence(
    session: &impl MixSession,
    root: Node<'_, '_>,
    raw: &str,
) -> Result<Option<MixAction>> {
    let Some(to) = root.attribute("to") else {
        return Ok(None);
    };
    if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == mix_domain(session)) {
        return Ok(None);
    }
    let Some(user) = session.user() else {
        return Ok(Some(MixAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    };
    let Some(full_jid) = session.full_jid() else {
        return Ok(Some(MixAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    };
    let actor_bare = format!("{}@{}", user.username, session.host().local_domain());
    // Directed MIX presence and verified-caps fallback share the exact
    // resource epoch. Record only a successfully applied transition: an
    // error response must not suppress later initialisation. The set is
    // resource-owned and therefore disappears with the session rather
    // than accumulating in a process-global keyed lock/tombstone map.
    let mix_presence_epoch = Arc::clone(session.mix_presence_gate()).lock_owned().await;
    if !mix_presence_route_is_current(
        session.host().as_ref(),
        full_jid,
        session.connection_id(),
        session.mix_presence_gate(),
        false,
    ) {
        return Ok(Some(MixAction::None));
    }
    let result = process_channel_presence(session.host(), &actor_bare, full_jid, raw).await?;
    if result.is_none() {
        let target = CanonicalJid::parse_bare(to)?.to_string();
        match root.attribute("type").unwrap_or("available") {
            "unavailable" => {
                session.mix_presence_fallback_suppressed().insert(target);
            }
            "available" => {
                session.mix_presence_fallback_suppressed().remove(&target);
            }
            _ => {}
        }
    }
    drop(mix_presence_epoch);
    Ok(Some(result.map_or(MixAction::None, MixAction::Send)))
}

/// XEP-0405 participant-server fan-out for a broadcast presence.  Only a
/// resource whose verified capabilities advertise MIX is represented in
/// a channel's presence node.
pub async fn forward_presence_to_mix_channels(
    session: &impl MixSession,
    kind: &str,
    advertised_capability: MixSessionCapability,
    raw: &str,
) -> Result<()> {
    let (Some(user), Some(full_jid)) = (session.user(), session.full_jid()) else {
        return Ok(());
    };
    let action = mix_broadcast_presence_action(kind, advertised_capability);
    if action == MixBroadcastPresenceAction::Ignore {
        return Ok(());
    }
    let synthesized_unavailable;
    let projected = if action == MixBroadcastPresenceAction::Retract && kind != "unavailable" {
        synthesized_unavailable = XmlElement::namespaced("presence", "jabber:client")
            .attr("from", full_jid)
            .attr("type", "unavailable")
            .finish();
        synthesized_unavailable.as_str()
    } else {
        raw
    };
    let actor_bare = format!("{}@{}", user.username, session.host().local_domain());
    for membership in session
        .host()
        .mix_service()
        .pam_memberships(user.id)
        .await?
    {
        if membership.state != "joined"
            || !membership
                .subscriptions
                .iter()
                .any(|node| node == NODE_PRESENCE)
        {
            continue;
        }
        let Ok(channel) = CanonicalJid::parse_bare(&membership.channel_jid) else {
            tracing::warn!(channel = %membership.channel_jid, "ignored malformed persisted MIX membership JID");
            continue;
        };
        let domain = channel.domainpart();
        let directed = northstar_xml_builder::rewrite::set_to(
            &northstar_xml_builder::rewrite::set_from(projected, full_jid),
            &membership.channel_jid,
        );
        if domain == mix_domain(session) {
            let _ =
                process_channel_presence(session.host(), &actor_bare, full_jid, &directed).await?;
        } else if session.host().federation_domain_allowed(domain) {
            let _ = session
                .host()
                .federation_outbox()
                .send(domain, directed, Some(actor_bare.clone()))
                .await;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixBroadcastPresenceAction {
    Publish,
    Retract,
    Ignore,
}

pub fn mix_broadcast_presence_action(
    kind: &str,
    capability: MixSessionCapability,
) -> MixBroadcastPresenceAction {
    match (kind, capability) {
        ("available", MixSessionCapability::Supported) => MixBroadcastPresenceAction::Publish,
        ("available" | "unavailable", _) => MixBroadcastPresenceAction::Retract,
        _ => MixBroadcastPresenceAction::Ignore,
    }
}
