//! Route federated IQ requests and responses with account, resource and service authorization.

use super::*;

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
            let requester_bare = crate::jid::canonical_bare_key(from)?;
            let subscribed = state
                .s2s_roster_authorization_service()
                .allows_presence(recipient.id, &requester_bare)
                .await?;
            let directed = state
                .session_entries_for(to)
                .into_iter()
                .any(|(_, session)| {
                    session.directed_presence.iter().any(|authorized| {
                        crate::xmpp::protocol::presence::directed_recipient_matches(
                            authorized.key(),
                            from,
                        )
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
        let remote_resource_matches = state.s2s_remote_recipient_route_exists(to).await;
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
        && child.tag_name().namespace() == Some(crate::services::jingle::JINGLE_NS)
    {
        if let Err(condition) = crate::services::jingle::validate_jingle_iq(root, child, None) {
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
            return Ok(Some(crate::services::xml_util::set_to(&result, from)));
        }
    }
    if to_jid.localpart().is_none()
        && same_s2s_domain(
            to_jid.domainpart(),
            &format!("pubsub.{}", state.local_domain()),
        )
    {
        let reply =
            match crate::xmpp::protocol::pubsub::handle_request(state, from, kind, child).await {
                Ok(reply) => reply,
                Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
                    crate::xmpp::protocol::pubsub::PubSubReply::Error("resource-constraint")
                }
                Err(error) => return Err(error),
            };
        return Ok(Some(match reply {
            crate::xmpp::protocol::pubsub::PubSubReply::Result(payload) => {
                s2s_iq_result(id, to, from, &payload)
            }
            reply @ (crate::xmpp::protocol::pubsub::PubSubReply::Error(_)
            | crate::xmpp::protocol::pubsub::PubSubReply::ExtendedError(_)) => {
                crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(id, to, from, &reply)
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
                crate::services::profile::PublicVCard::MissingAccount => {
                    return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                }
                crate::services::profile::PublicVCard::Profile(Some(payload)) => payload,
                crate::services::profile::PublicVCard::Profile(None) => {
                    XmlElement::namespaced("vCard", "vcard-temp").finish()
                }
            };
            Ok(Some(s2s_iq_result(id, to, from, &payload)))
        }
        ("pubsub", "http://jabber.org/protocol/pubsub", "get") => {
            if to_jid.resourcepart().is_some()
                || child.children().filter(|node| node.is_element()).count() != 1
            {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            }
            let Some(items) = child
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "items")
            else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            if items
                .attributes()
                .any(|attribute| !matches!(attribute.name(), "node" | "max_items" | "subid"))
            {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            }
            let Some(node) = items.attribute("node").filter(|node| {
                !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
            }) else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let Some(owner_name) = recipient_name else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let Some(owner) = state.pubsub_service().find_enabled_user(owner_name).await? else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            if state
                .pubsub_service()
                .pep_node(owner.id, node)
                .await?
                .is_none()
            {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            }
            if !crate::xmpp::protocol::pep::pep_access_allowed(
                state.pubsub_service(),
                &owner,
                state.local_domain(),
                node,
                from,
            )
            .await?
            {
                return Ok(Some(s2s_iq_error(id, to, from, "not-authorized")));
            }
            let requested = items
                .children()
                .filter(|node| node.is_element())
                .map(|item| {
                    (item.tag_name().namespace() == Some("http://jabber.org/protocol/pubsub")
                        && item.tag_name().name() == "item"
                        && item.attributes().len() == 1
                        && item.attribute("id").is_some_and(|item_id| {
                            !item_id.is_empty()
                                && item_id.len() <= 1_024
                                && !item_id.chars().any(char::is_control)
                        })
                        && !item.children().any(|child| child.is_element()))
                    .then(|| item.attribute("id").unwrap_or_default())
                })
                .collect::<Option<Vec<_>>>();
            let Some(requested) =
                requested.filter(|items| items.len() <= db::PEP_MAX_ITEMS as usize)
            else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let max_items = match items.attribute("max_items") {
                Some(value) => match value.parse::<i64>() {
                    Ok(value) if value > 0 => value.min(db::PEP_MAX_ITEMS as i64),
                    _ => return Ok(Some(s2s_iq_error(id, to, from, "bad-request"))),
                },
                None => db::PEP_MAX_ITEMS as i64,
            };
            let stored = if requested.is_empty() {
                state
                    .pubsub_service()
                    .pep_items(owner.id, node, None, max_items)
                    .await?
            } else {
                state
                    .pubsub_service()
                    .pep_items_by_ids(owner.id, node, &requested, max_items)
                    .await?
            };
            if stored.is_empty() && !requested.is_empty() {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            }
            let mut item_list =
                crate::xmpp::xml_builder::XmlElement::new("items").attr("node", node);
            for (_, item) in stored {
                item_list = item_list
                    .validated_fragment(&item)
                    .context("stored PEP item is not valid XML")?;
            }
            let payload = crate::xmpp::xml_builder::XmlElement::new("pubsub")
                .attr("xmlns", "http://jabber.org/protocol/pubsub")
                .child(item_list)
                .finish();
            Ok(Some(s2s_iq_result(id, to, from, &payload)))
        }
        ("pubsub", "http://jabber.org/protocol/pubsub", "set")
            if !is_xep0357_notification_publish(child) =>
        {
            if to_jid.resourcepart().is_some() {
                return Ok(Some(s2s_iq_error(id, to, from, "jid-malformed")));
            }
            let Some(owner_name) = recipient_name else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let Some(owner) = state.pubsub_service().find_enabled_user(owner_name).await? else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let operations = child
                .children()
                .filter(|node| node.is_element())
                .collect::<Vec<_>>();
            if operations.len() != 1 {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            }
            let operation = operations[0];
            if operation.tag_name().namespace() != Some("http://jabber.org/protocol/pubsub")
                || !matches!(operation.tag_name().name(), "subscribe" | "unsubscribe")
            {
                return Ok(Some(s2s_iq_error(id, to, from, "feature-not-implemented")));
            }
            let Some(node) = operation.attribute("node").filter(|node| {
                !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
            }) else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let Some(requested) = operation.attribute("jid") else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let Ok(requested) = crate::jid::canonicalize(requested) else {
                return Ok(Some(s2s_iq_error(id, to, from, "jid-malformed")));
            };
            if operation.tag_name().name() == "subscribe" {
                let requested_subid = uuid::Uuid::new_v4().to_string();
                let outcome = match state
                    .pubsub_service()
                    .subscribe_pep_node(
                        northstar_pubsub_application::PepSubscribeCommand::from(
                            crate::services::pubsub::PepSubscribeWrite {
                                owner: &owner,
                                actor: crate::services::pubsub::PepSubscriptionActor {
                                    jid: from,
                                    local_account: None,
                                },
                                node,
                                subscriber_jid: &requested,
                                max_subscriptions: 1_000,
                                requested_subid: &requested_subid,
                            },
                        ),
                        &crate::xmpp::protocol::pep::prepare_pep_last_item_outbox,
                    )
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
                        return Ok(Some(crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(
                            id,
                            to,
                            from,
                            &crate::xmpp::protocol::pubsub::PubSubReply::Error(
                                "resource-constraint",
                            ),
                        )));
                    }
                    Err(error) => return Err(error),
                };
                let subscription = match outcome.outcome {
                    crate::services::pubsub::PepSubscribeOutcome::Subscribed(subscription) => {
                        subscription
                    }
                    crate::services::pubsub::PepSubscribeOutcome::NotFound => {
                        return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                    }
                    crate::services::pubsub::PepSubscribeOutcome::Forbidden => {
                        return Ok(Some(s2s_iq_error(id, to, from, "forbidden")));
                    }
                    crate::services::pubsub::PepSubscribeOutcome::NotAuthorized(_) => {
                        return Ok(Some(s2s_iq_error(id, to, from, "not-authorized")));
                    }
                    crate::services::pubsub::PepSubscribeOutcome::LimitExceeded => {
                        return Ok(Some(s2s_iq_error(id, to, from, "policy-violation")));
                    }
                };
                let payload = crate::xmpp::xml_builder::XmlElement::new("pubsub")
                    .attr("xmlns", "http://jabber.org/protocol/pubsub")
                    .child(
                        crate::xmpp::xml_builder::XmlElement::new("subscription")
                            .attr("node", node)
                            .attr("jid", &requested)
                            .attr("subscription", "subscribed")
                            .attr("subid", &subscription.subid),
                    )
                    .finish();
                Ok(Some(s2s_iq_result(id, to, from, &payload)))
            } else {
                let outcome = match state
                    .pubsub_service()
                    .unsubscribe_pep_node(
                        northstar_pubsub_application::PepUnsubscribeCommand::from(
                            crate::services::pubsub::PepUnsubscribeWrite {
                                owner: &owner,
                                actor: crate::services::pubsub::PepSubscriptionActor {
                                    jid: from,
                                    local_account: None,
                                },
                                node,
                                subscriber_jid: &requested,
                                subid: operation.attribute("subid"),
                            },
                        ),
                    )
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
                        return Ok(Some(crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(
                            id,
                            to,
                            from,
                            &crate::xmpp::protocol::pubsub::PubSubReply::Error(
                                "resource-constraint",
                            ),
                        )));
                    }
                    Err(error) => return Err(error),
                };
                match outcome.outcome {
                    crate::services::pubsub::PepUnsubscribeOutcome::Unsubscribed(_) => {}
                    crate::services::pubsub::PepUnsubscribeOutcome::NotFound => {
                        return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                    }
                    crate::services::pubsub::PepUnsubscribeOutcome::Forbidden => {
                        return Ok(Some(s2s_iq_error(id, to, from, "forbidden")));
                    }
                    crate::services::pubsub::PepUnsubscribeOutcome::InvalidSubid => {
                        return Ok(Some(s2s_iq_error(id, to, from, "unexpected-request")));
                    }
                }
                Ok(Some(s2s_iq_result(id, to, from, "")))
            }
        }
        ("query", "http://jabber.org/protocol/disco#info", "get") => {
            if to_jid.localpart().is_none()
                && same_s2s_domain(
                    to_jid.domainpart(),
                    &format!("pubsub.{}", state.local_domain()),
                )
            {
                let reply = crate::xmpp::protocol::pubsub::federated_disco_info(
                    state,
                    from,
                    child.attribute("node"),
                )
                .await?;
                return Ok(Some(match reply {
                    crate::xmpp::protocol::pubsub::PubSubReply::Result(payload) => {
                        s2s_iq_result(id, to, from, &payload)
                    }
                    reply @ (crate::xmpp::protocol::pubsub::PubSubReply::Error(_)
                    | crate::xmpp::protocol::pubsub::PubSubReply::ExtendedError(_)) => {
                        crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(id, to, from, &reply)
                    }
                }));
            }
            if let Some(owner_name) = recipient_name {
                let Some(owner) = state.pubsub_service().find_enabled_user(owner_name).await?
                else {
                    return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
                };
                let Some(payload) = crate::xmpp::protocol::pep::federated_pep_disco_info(
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
                crate::xmpp::protocol::pubsub::federated_disco_items(state, from, child).await?;
            Ok(Some(match reply {
                crate::xmpp::protocol::pubsub::PubSubReply::Result(payload) => {
                    s2s_iq_result(id, to, from, &payload)
                }
                reply @ (crate::xmpp::protocol::pubsub::PubSubReply::Error(_)
                | crate::xmpp::protocol::pubsub::PubSubReply::ExtendedError(_)) => {
                    crate::xmpp::protocol::pubsub::pubsub_s2s_iq_error(id, to, from, &reply)
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
            let Some(payload) = crate::xmpp::protocol::pep::federated_pep_disco_items(
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
