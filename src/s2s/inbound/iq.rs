//! Route federated IQ requests and responses with account, resource and service authorization.

use super::*;
use northstar_roster_xmpp::FederatedPresenceHost as _;
use northstar_stream::protocol::SessionHost as _;

pub(super) fn is_xep0357_notification_publish(pubsub: roxmltree::Node<'_, '_>) -> bool {
    pubsub.children().any(|operation| {
        operation.is_element()
            && operation.tag_name().name() == "publish"
            && operation.tag_name().namespace() == Some("http://jabber.org/protocol/pubsub")
            && operation.children().any(|item| {
                item.is_element()
                    && item.tag_name().name() == "item"
                    && item.tag_name().namespace() == Some("http://jabber.org/protocol/pubsub")
                    && item.children().any(|payload| {
                        payload.is_element()
                            && payload.tag_name().name() == "notification"
                            && payload.tag_name().namespace() == Some("urn:xmpp:push:0")
                    })
            })
    })
}

pub(super) fn bare_account_iq_may_route_to_service_resource(
    target: &CanonicalJid,
    payload: roxmltree::Node<'_, '_>,
) -> bool {
    target.localpart().is_some()
        && target.resourcepart().is_none()
        && is_xep0357_notification_publish(payload)
}

pub(crate) async fn route_inbound_iq(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
) -> Result<Option<String>> {
    let kind = root.attribute("type").unwrap_or("get");
    let Ok(to_jid) = CanonicalJid::parse(to) else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let recipient_name = to_jid.localpart();
    let recipient = match recipient_name {
        Some(username) => state.presence_service().find_enabled_user(username).await?,
        None => None,
    };
    if let Some(recipient) = recipient.as_ref() {
        let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
        if state
            .presence_service()
            .is_blocked_for_account(recipient.id, &recipient_bare, from)
            .await?
        {
            return if matches!(kind, "get" | "set") {
                Ok(Some(s2s_iq_error(
                    root.attribute("id").unwrap_or_default(),
                    to,
                    from,
                    "service-unavailable",
                )))
            } else {
                Ok(None)
            };
        }
    }
    if matches!(kind, "result" | "error") {
        let id = root.attribute("id").unwrap_or_default();
        if crate::xmpp::protocol::caps::handle_federated_caps_response(state, id, kind, root, raw)
            .await
        {
            return Ok(None);
        }
        if crate::xmpp::protocol::misc::handle_push_delivery_response(state, id, kind, from).await?
        {
            return Ok(None);
        }
        // Never broadcast an uncorrelated response to every resource of an
        // account. IQ responses belong to an exact originating resource.
        if to_jid.resourcepart().is_none() {
            return Ok(None);
        }
        let mut delivered = false;
        for target in state.sessions_for(to) {
            if state
                .privacy_allows_session(&target, from, db::PrivacyStanzaKind::Iq)
                .await?
                && target.sender.try_send(raw.to_owned()).is_ok()
            {
                delivered = true;
                break;
            }
        }
        if !delivered {
            state
                .cluster()
                .route_s2s_iq_response_to_remote_resource(to, raw)
                .await;
        }
        return Ok(None);
    }

    if to_jid.localpart().is_some() && recipient.is_none() {
        // RFC 6121 section 8.5.1 is evaluated before any server-side IQ
        // extension handler. A ping, vCard or other payload must not turn a
        // nonexistent local account into an oracle that appears to exist.
        return Ok(Some(s2s_iq_error(
            root.attribute("id").unwrap_or_default(),
            to,
            from,
            "service-unavailable",
        )));
    }

    if to_jid.resourcepart().is_some() {
        let Some(recipient) = recipient.as_ref() else {
            return Ok(Some(s2s_iq_error(
                root.attribute("id").unwrap_or_default(),
                to,
                from,
                "service-unavailable",
            )));
        };
        // RFC 6121 section 8.5.3.1 applies the presence-leak gate to every
        // IQ get/set addressed to a matching full JID.  This includes Jingle
        // and unknown extension IQs; capability discovery is not special.
        if matches!(kind, "get" | "set") {
            let requester_bare = northstar_xmpp_types::jid::canonical_bare_key(from)?;
            let subscribed = state
                .s2s_roster_authorization_service()
                .allows_presence(recipient.id, &requester_bare)
                .await?;
            let directed = state
                .session_entries_for(to)
                .into_iter()
                .any(|(_, session)| {
                    session.directed_presence.iter().any(|authorized| {
                        northstar_presence_core::directed_recipient_matches(authorized.key(), from)
                    })
                });
            if !subscribed && !directed {
                return Ok(Some(s2s_iq_error(
                    root.attribute("id").unwrap_or_default(),
                    to,
                    from,
                    "service-unavailable",
                )));
            }
        }
        // RFC 6121 section 8.5.3.2.3 requires service-unavailable before a
        // server-side handler (including the XEP-0115 cache) can answer for
        // an exact resource which is not connected on any cluster node.
        let local_resource_matches = !state.session_entries_for(to).is_empty();
        let remote_resource_matches = state.cluster().s2s_remote_recipient_route_exists(to).await;
        if !local_resource_matches && !remote_resource_matches {
            return Ok(Some(s2s_iq_error(
                root.attribute("id").unwrap_or_default(),
                to,
                from,
                "service-unavailable",
            )));
        }
        let targets = state.sessions_for(to);
        if !targets.is_empty() {
            let mut allowed = false;
            for target in &targets {
                if state
                    .privacy_allows_session(target, from, db::PrivacyStanzaKind::Iq)
                    .await?
                {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return if matches!(kind, "get" | "set") {
                    Ok(Some(s2s_iq_error(
                        root.attribute("id").unwrap_or_default(),
                        to,
                        from,
                        "service-unavailable",
                    )))
                } else {
                    Ok(None)
                };
            }
        }
    }
    let id = root.attribute("id").unwrap_or_default();
    let Some(child) = root.children().find(|node| node.is_element()) else {
        return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
    };
    if kind == "set"
        && child.tag_name().name() == "jingle"
        && child.tag_name().namespace() == Some(northstar_message_core::jingle::JINGLE_NS)
    {
        if let Err(condition) =
            northstar_message_core::jingle::validate_jingle_iq(root, child, None)
        {
            return Ok(Some(s2s_iq_error(id, to, from, condition)));
        }
    }
    if kind == "get"
        && to.contains('/')
        && child.tag_name().name() == "query"
        && child.tag_name().namespace() == Some("http://jabber.org/protocol/disco#info")
    {
        if let Some(result) =
            crate::xmpp::protocol::caps::cached_disco_result(state, id, to, child.attribute("node"))
        {
            return Ok(Some(northstar_xml_builder::rewrite::set_to(&result, from)));
        }
    }
    if to_jid.localpart().is_none()
        && same_s2s_domain(
            to_jid.domainpart(),
            &format!("pubsub.{}", state.local_domain()),
        )
    {
        let reply =
            match northstar_pubsub_xmpp::pubsub::handle_request(state, from, kind, child).await {
                Ok(reply) => reply,
                Err(error) if northstar_pubsub_application::is_pubsub_mutation_busy(&error) => {
                    northstar_pubsub_xmpp::pubsub::PubSubReply::Error("resource-constraint")
                }
                Err(error) => return Err(error),
            };
        return Ok(Some(match reply {
            northstar_pubsub_xmpp::pubsub::PubSubReply::Result(payload) => {
                s2s_iq_result(id, to, from, &payload)
            }
            reply @ (northstar_pubsub_xmpp::pubsub::PubSubReply::Error(_)
            | northstar_pubsub_xmpp::pubsub::PubSubReply::ExtendedError(_)) => {
                northstar_pubsub_xmpp::pubsub::pubsub_s2s_iq_error(id, to, from, &reply)
            }
        }));
    }
    let namespace = child.tag_name().namespace().unwrap_or_default();
    match (child.tag_name().name(), namespace, kind) {
        ("ping", northstar_xep_0199::NAMESPACE, "get") if state.s2s_ping_route_enabled() => {
            if northstar_xep_0199::parse_ping_element(child).is_err() {
                Ok(Some(s2s_iq_error(id, to, from, "bad-request")))
            } else {
                Ok(Some(s2s_iq_result(
                    id,
                    to,
                    from,
                    northstar_xep_0199::build_response(),
                )))
            }
        }
        ("ping", northstar_xep_0199::NAMESPACE, "get") => {
            Ok(Some(s2s_iq_error(id, to, from, "service-unavailable")))
        }
        ("vCard", "vcard-temp", "get") => {
            let Some(owner_name) = recipient_name else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let payload = match state.profile_service().public_vcard(owner_name).await? {
                northstar_pubsub_application::profile::PublicVCard::MissingAccount => {
                    return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                }
                northstar_pubsub_application::profile::PublicVCard::Profile(Some(payload)) => {
                    payload
                }
                northstar_pubsub_application::profile::PublicVCard::Profile(None) => {
                    XmlElement::namespaced("vCard", "vcard-temp").finish()
                }
            };
            Ok(Some(s2s_iq_result(id, to, from, &payload)))
        }
        ("pubsub", "http://jabber.org/protocol/pubsub", "get") => Ok(Some(
            northstar_pubsub_xmpp::federated_pep::federated_pep_items(
                state,
                recipient_name,
                to_jid.resourcepart().is_some(),
                child,
                id,
                to,
                from,
            )
            .await?,
        )),
        ("pubsub", "http://jabber.org/protocol/pubsub", "set")
            if !is_xep0357_notification_publish(child) =>
        {
            Ok(Some(
                northstar_pubsub_xmpp::federated_pep::federated_pep_subscription(
                    state,
                    recipient_name,
                    to_jid.resourcepart().is_some(),
                    child,
                    id,
                    to,
                    from,
                )
                .await?,
            ))
        }
        ("query", "http://jabber.org/protocol/disco#info", "get") => {
            if to_jid.localpart().is_none()
                && same_s2s_domain(
                    to_jid.domainpart(),
                    &format!("pubsub.{}", state.local_domain()),
                )
            {
                let reply = northstar_pubsub_xmpp::pubsub::federated_disco_info(
                    state,
                    from,
                    child.attribute("node"),
                )
                .await?;
                return Ok(Some(match reply {
                    northstar_pubsub_xmpp::pubsub::PubSubReply::Result(payload) => {
                        s2s_iq_result(id, to, from, &payload)
                    }
                    reply @ (northstar_pubsub_xmpp::pubsub::PubSubReply::Error(_)
                    | northstar_pubsub_xmpp::pubsub::PubSubReply::ExtendedError(_)) => {
                        northstar_pubsub_xmpp::pubsub::pubsub_s2s_iq_error(id, to, from, &reply)
                    }
                }));
            }
            if let Some(owner_name) = recipient_name {
                let Some(owner) = state.pubsub_service().find_enabled_user(owner_name).await?
                else {
                    return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                };
                let Some(payload) = northstar_pubsub_xmpp::pep::federated_pep_disco_info(
                    state,
                    &owner,
                    from,
                    child.attribute("node"),
                )
                .await?
                else {
                    return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                };
                return Ok(Some(s2s_iq_result(id, to, from, &payload)));
            }
            let mut payload =
                XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info").child(
                    XmlElement::new("identity")
                        .attr("category", "server")
                        .attr("type", "im")
                        .attr("name", "Northstar XMPP Server"),
                );
            for feature in [
                "http://jabber.org/protocol/disco#info",
                "vcard-temp",
                "urn:xmpp:push:0",
                "urn:xmpp:sid:0",
            ] {
                payload.push_child(XmlElement::new("feature").attr("var", feature));
            }
            if state.xmpp_extension_enabled(northstar_xep_0199::XEP_ID) {
                payload.push_child(
                    XmlElement::new("feature").attr("var", northstar_xep_0199::NAMESPACE),
                );
            }
            Ok(Some(s2s_iq_result(id, to, from, &payload.finish())))
        }
        ("query", "http://jabber.org/protocol/disco#items", "get")
            if to_jid.localpart().is_none()
                && same_s2s_domain(
                    to_jid.domainpart(),
                    &format!("pubsub.{}", state.local_domain()),
                ) =>
        {
            let reply =
                northstar_pubsub_xmpp::pubsub::federated_disco_items(state, from, child).await?;
            Ok(Some(match reply {
                northstar_pubsub_xmpp::pubsub::PubSubReply::Result(payload) => {
                    s2s_iq_result(id, to, from, &payload)
                }
                reply @ (northstar_pubsub_xmpp::pubsub::PubSubReply::Error(_)
                | northstar_pubsub_xmpp::pubsub::PubSubReply::ExtendedError(_)) => {
                    northstar_pubsub_xmpp::pubsub::pubsub_s2s_iq_error(id, to, from, &reply)
                }
            }))
        }
        ("query", "http://jabber.org/protocol/disco#items", "get")
            if recipient_name.is_some() && to_jid.resourcepart().is_none() =>
        {
            let owner_name = recipient_name.expect("guarded above");
            let Some(owner) = state.pubsub_service().find_enabled_user(owner_name).await? else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let Some(payload) = northstar_pubsub_xmpp::pep::federated_pep_disco_items(
                state,
                &owner,
                from,
                child.attribute("node"),
            )
            .await?
            else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            Ok(Some(s2s_iq_result(id, to, from, &payload)))
        }
        _ => {
            let bare_target = to_jid.resourcepart().is_none();
            // RFC 6121 sections 8.5.2.1.3 and 8.5.2.2.3 require the server
            // to answer an IQ addressed to a bare account and MUST NOT route
            // it to account resources.  The sole compatibility extension is
            // the strict XEP-0357 notification payload: a configured Push
            // Service may be represented by a bare account JID and processes
            // the IQ through one deterministic service resource.  Domain-only
            // Push Service JIDs are handled as server services above.
            if bare_target && !bare_account_iq_may_route_to_service_resource(&to_jid, child) {
                return Ok(Some(s2s_iq_error(id, to, from, "service-unavailable")));
            }
            // Never spray the narrow service-resource exception across
            // resources: highest priority wins and the canonical full JID is
            // a deterministic tie-breaker.
            let mut targets = state.session_entries_for(to);
            if bare_target {
                targets.retain(|(_, target)| {
                    target.available.load(Ordering::Acquire)
                        && target.priority.load(Ordering::Acquire) >= 0
                });
                targets.sort_by(|(left_jid, left), (right_jid, right)| {
                    right
                        .priority
                        .load(Ordering::Acquire)
                        .cmp(&left.priority.load(Ordering::Acquire))
                        .then_with(|| left_jid.cmp(right_jid))
                });
            }
            let mut delivered = false;
            for (_, target) in targets {
                if state
                    .privacy_allows_session(&target, from, db::PrivacyStanzaKind::Iq)
                    .await?
                    && target.sender.try_send(raw.to_owned()).is_ok()
                {
                    delivered = true;
                    if bare_target {
                        break;
                    }
                }
            }
            if !delivered {
                delivered = state
                    .cluster()
                    .route_s2s_iq_request_remote(to, raw, bare_target)
                    .await;
            }
            if !delivered {
                return Ok(Some(s2s_iq_error(id, to, from, "service-unavailable")));
            }
            Ok(None)
        }
    }
}
