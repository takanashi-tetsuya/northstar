//! Handle federated presence, subscription transitions, probes and presence responses.

use super::*;

pub(crate) async fn route_inbound_presence(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
    connection_id: uuid::Uuid,
) -> Result<Option<String>> {
    let Ok(to_jid) = CanonicalJid::parse(to) else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let Some(recipient_name) = to_jid.localpart() else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let Some(recipient) = state
        .presence_service()
        .find_enabled_user(recipient_name)
        .await?
    else {
        return Ok(None);
    };
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
    let kind = root.attribute("type").unwrap_or("available");
    // Multiple authenticated streams for one remote domain can concurrently
    // carry presence for the same full JID. Choose one server-side order and
    // retain it through capability side effects and final local/cluster
    // routing; otherwise an older available could be delivered after a newer
    // unavailable even if the caps cache itself had already been cleaned.
    let federated_presence_epoch = if matches!(kind, "available" | "unavailable") {
        match crate::jid::canonical_session_key(from) {
            Ok(full_jid) => Some(state.federated_caps_gates().lock(&full_jid).await),
            Err(_) => None,
        }
    } else {
        None
    };
    if kind == "probe" {
        return route_inbound_presence_probe(state, root, from, &to_jid, &recipient).await;
    }
    let subscription_kind = matches!(
        kind,
        "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
    );
    if !subscription_kind
        && state
            .presence_service()
            .is_blocked_for_account(recipient.id, &recipient_bare, from)
            .await?
    {
        return Ok(None);
    }
    if subscription_kind
        && to_jid.resourcepart().is_some()
        && kind != "subscribe"
        && state.sessions_for(&to_jid.to_string()).is_empty()
        && !state
            .s2s_subscription_target_route_exists(&to_jid.to_string())
            .await
    {
        return Ok(None);
    }
    let subscription_from = subscription_kind
        .then(|| CanonicalJid::parse(from))
        .transpose()
        .context("validated federated sender became malformed")?
        .map(|jid| jid.bare());
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
    let canonical_subscription = subscription_from
        .as_deref()
        .map(|contact| canonical_subscription_stanza(raw, contact, to));
    if let Some(resource_epoch) = federated_presence_epoch.as_ref() {
        match crate::xmpp::protocol::caps::observe_federated_caps(
            state,
            root,
            from,
            connection_id,
            resource_epoch,
        )
        .await
        {
            crate::xmpp::protocol::caps::FederatedCapsObservationResult::Accepted => {}
            crate::xmpp::protocol::caps::FederatedCapsObservationResult::StaleOwner => {
                return Ok(None);
            }
            crate::xmpp::protocol::caps::FederatedCapsObservationResult::Saturated => {
                return Ok(Some(s2s_stanza_error(root, "wait", "resource-constraint")));
            }
        }
    }
    if subscription_kind {
        let contact = subscription_from.as_deref().expect("guarded above");
        let persisted = canonical_subscription.as_deref().expect("guarded above");
        let transition = match state
            .presence_service()
            .transition_inbound(recipient.id, state.local_domain(), contact, kind, persisted)
            .await?
        {
            crate::services::presence::PresenceMutation::Transition(transition) => transition,
            crate::services::presence::PresenceMutation::PolicyDenied(_)
            | crate::services::presence::PresenceMutation::Missing
            | crate::services::presence::PresenceMutation::Unauthorized => {
                // The exact local UUID disappeared/was disabled, or its
                // account-wide inbound policy denied the authenticated remote
                // stanza. Inbound federation intentionally has no C2S
                // generation authority of its own.
                return Ok(None);
            }
        };
        let recipient = transition.recipient.clone();
        let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());

        // Subscription notifications precede the corresponding roster push
        // (RFC 6121 sections 3.2/3.3). Incoming subscribe requests are sent to
        // available resources; the other state notifications go only to
        // resources that requested the roster.
        if transition.effect == crate::services::presence::InboundRemotePresenceEffect::Forward {
            let mut targets = state.session_entries_for(&recipient_bare);
            if kind == "subscribe" {
                targets.retain(|(_, target)| {
                    target.user_id == recipient.id
                        && target.auth_generation == recipient.auth_generation
                        && target.available.load(Ordering::Acquire)
                });
            } else {
                targets.retain(|(_, target)| {
                    target.user_id == recipient.id
                        && target.auth_generation == recipient.auth_generation
                        && target.available.load(Ordering::Acquire)
                        && target.roster_requested.load(Ordering::Acquire)
                });
            }
            for (target_jid, target) in targets {
                if state
                    .privacy_allows_session(&target, from, db::PrivacyStanzaKind::PresenceIn)
                    .await?
                {
                    let _ = target.sender.try_send(set_to(persisted, &target_jid));
                }
            }
        }

        if let Some(reply_kind) = transition.auto_reply {
            let response = presence_probe_status_response(
                &recipient_bare,
                contact,
                reply_kind,
                root.attribute("id"),
            );
            let remote_domain = CanonicalJid::parse(contact)
                .expect("canonical federated contact")
                .domainpart()
                .to_owned();
            if !state
                .federation_outbox()
                .send(&remote_domain, response, None)
                .await
            {
                return Ok(Some(s2s_stanza_error(root, "wait", "resource-constraint")));
            }
            if reply_kind == "subscribed" {
                send_current_presence_to_remote(state, &recipient_bare, contact).await;
            }
        }

        if transition.send_unavailable {
            send_unavailable_presence_to_remote(state, &recipient_bare, contact).await;
        }

        if let Some(change) = transition.change.as_ref() {
            if let Err(error) = crate::xmpp::protocol::roster::deliver_roster_change(
                state,
                recipient.id,
                &recipient.username,
                change,
                None,
            )
            .await
            {
                state.s2s_inbound_delivery_telemetry().post_accept_failed();
                tracing::warn!(?error, recipient_id = %recipient.id, contact = %contact, %kind, "federated roster transition was committed but roster push failed");
            }
        }
        if kind == "subscribe"
            && transition.effect == crate::services::presence::InboundRemotePresenceEffect::Forward
            && state.sessions_for(&recipient_bare).is_empty()
        {
            if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                state.s2s_inbound_delivery_telemetry().post_accept_failed();
                tracing::warn!(?error, recipient_id = %recipient.id, contact = %contact, "federated subscription was committed but push notification failed");
            }
        }
        return Ok(None);
    }
    let (delivery_target, delivery) = canonical_subscription.map_or_else(
        || (to, raw.to_owned()),
        |stanza| (recipient_bare.as_str(), stanza),
    );
    let mut targets = state.session_entries_for(delivery_target);
    if CanonicalJid::parse(delivery_target).is_ok_and(|jid| jid.resourcepart().is_none()) {
        targets.retain(|(_, target)| target.available.load(Ordering::Relaxed));
    }
    for (_, target) in targets {
        if state
            .privacy_allows_session(&target, from, db::PrivacyStanzaKind::PresenceIn)
            .await?
        {
            let _ = target.sender.try_send(delivery.clone());
        }
    }
    Ok(None)
}

pub(super) async fn send_unavailable_presence_to_remote(
    state: &AppState,
    owner: &str,
    contact: &str,
) {
    let remote_domain = CanonicalJid::parse(contact)
        .expect("canonical federated contact")
        .domainpart()
        .to_owned();
    let mut resources = state.session_entries_for(owner);
    resources.retain(|(_, session)| session.available.load(Ordering::Acquire));
    for (full_jid, session) in resources {
        match state
            .privacy_allows_session(&session, contact, db::PrivacyStanzaKind::PresenceOut)
            .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(?error, %full_jid, %contact, "privacy policy lookup failed for outbound unavailable presence");
                continue;
            }
        }
        let stanza = crate::xmpp::xml_builder::XmlElement::new("presence")
            .attr("xmlns", "jabber:client")
            .attr("from", &full_jid)
            .attr("to", contact)
            .attr("type", "unavailable")
            .finish();
        if !state
            .federation_outbox()
            .send(&remote_domain, stanza, None)
            .await
        {
            state.s2s_inbound_delivery_telemetry().post_accept_failed();
            tracing::warn!(owner = %owner, contact = %contact, "failed to admit required federated unavailable presence after subscription removal");
        }
    }
}

pub(super) async fn send_current_presence_to_remote(state: &AppState, owner: &str, contact: &str) {
    let remote_domain = CanonicalJid::parse(contact)
        .expect("canonical federated contact")
        .domainpart()
        .to_owned();
    let mut resources = state.session_entries_for(owner);
    resources.retain(|(_, session)| session.available.load(Ordering::Acquire));
    for (full_jid, session) in resources {
        match state
            .privacy_allows_session(&session, contact, db::PrivacyStanzaKind::PresenceOut)
            .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(?error, %full_jid, %contact, "privacy policy lookup failed for outbound current presence");
                continue;
            }
        }
        let stanza = session
            .last_presence
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .map(|presence| set_to(&presence, contact))
            .unwrap_or_else(|| {
                crate::xmpp::xml_builder::XmlElement::new("presence")
                    .attr("xmlns", "jabber:client")
                    .attr("from", &full_jid)
                    .attr("to", contact)
                    .finish()
            });
        if !state
            .federation_outbox()
            .send(&remote_domain, stanza, None)
            .await
        {
            state.s2s_inbound_delivery_telemetry().post_accept_failed();
            tracing::warn!(owner = %owner, contact = %contact, "failed to admit current presence after federated subscription approval");
        }
    }
}

pub(super) async fn route_inbound_presence_probe(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    requester: &str,
    target_jid: &CanonicalJid,
    recipient: &crate::services::presence::PresenceAccount,
) -> Result<Option<String>> {
    let requester_bare = crate::jid::canonical_bare_key(requester)?;
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
    let roster_authorized = state
        .s2s_roster_authorization_service()
        .allows_presence(recipient.id, &requester_bare)
        .await?;
    let directed_authorized = target_jid.resourcepart().is_some()
        && state
            .session_entries_for(&target_jid.to_string())
            .into_iter()
            .any(|(_, session)| {
                session.directed_presence.iter().any(|authorized| {
                    crate::xmpp::protocol::presence::directed_recipient_matches(
                        authorized.key(),
                        requester,
                    )
                })
            });
    if !roster_authorized && !directed_authorized {
        return Ok(Some(presence_probe_status_response(
            &recipient_bare,
            requester,
            "unsubscribed",
            root.attribute("id"),
        )));
    }

    let owner = if target_jid.resourcepart().is_some() {
        target_jid.to_string()
    } else {
        recipient_bare.clone()
    };
    let mut available = state.session_entries_for(&owner);
    available.retain(|(_, session)| session.available.load(Ordering::Relaxed));
    let mut privacy_allowed = Vec::with_capacity(available.len());
    for entry in available {
        if state
            .privacy_allows_session(&entry.1, requester, db::PrivacyStanzaKind::PresenceIn)
            .await?
            && state
                .privacy_allows_session(&entry.1, requester, db::PrivacyStanzaKind::PresenceOut)
                .await?
        {
            privacy_allowed.push(entry);
        }
    }
    let available = privacy_allowed;
    if available.is_empty() {
        return Ok(Some(presence_probe_status_response(
            &recipient_bare,
            requester,
            "unavailable",
            root.attribute("id"),
        )));
    }

    let requester_domain = CanonicalJid::parse(requester)
        .expect("validated federated probe sender")
        .domainpart()
        .to_owned();
    let full_target = target_jid.resourcepart().is_some();
    for (full_jid, session) in available {
        let last_presence = session
            .last_presence
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let response = if full_target {
            // RFC 6121 section 4.3.2: a full-JID probe must expose only the
            // fact that this exact resource is available, never show/status,
            // priority, caps, OMEMO or another presence extension.
            let original_id = last_presence.as_deref().and_then(|presence| {
                let document = Document::parse(presence).ok()?;
                document
                    .root_element()
                    .attribute("id")
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control)
                    })
                    .map(str::to_owned)
            });
            crate::xmpp::xml_builder::XmlElement::new("presence")
                .attr("xmlns", "jabber:server")
                .attr("from", &full_jid)
                .attr("to", requester)
                .optional_attr("id", original_id.as_deref())
                .finish()
        } else {
            last_presence
                .map(|presence| set_to(&presence, requester))
                .unwrap_or_else(|| {
                    crate::xmpp::xml_builder::XmlElement::new("presence")
                        .attr("xmlns", "jabber:server")
                        .attr("from", &full_jid)
                        .attr("to", requester)
                        .finish()
                })
        };
        // RFC 6121 section 4.3.2.1 preserves each available resource's
        // original presence id.  The probe id is mirrored only for
        // unavailable/unsubscribed/error responses above.
        if !state
            .federation_outbox()
            .send(&requester_domain, response, None)
            .await
        {
            return Ok(Some(s2s_stanza_error(root, "wait", "resource-constraint")));
        }
    }
    Ok(None)
}

pub(super) fn presence_probe_status_response(
    from: &str,
    to: &str,
    kind: &str,
    id: Option<&str>,
) -> String {
    let kind = match kind {
        "unavailable" => "unavailable",
        "unsubscribed" => "unsubscribed",
        _ => "error",
    };
    crate::xmpp::xml_builder::XmlElement::new("presence")
        .attr("xmlns", "jabber:server")
        .attr("from", from)
        .attr("to", to)
        .attr("type", kind)
        .optional_attr("id", id)
        .finish()
}

pub(super) fn canonical_subscription_stanza(raw: &str, from: &str, to: &str) -> String {
    crate::xmpp::xml_util::set_client_namespace(&set_to(&set_from(raw, from), to))
}
