use super::*;

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
