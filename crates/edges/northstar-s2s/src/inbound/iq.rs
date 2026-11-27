//! Route federated IQ requests and responses with account, resource and service authorization.

use super::*;
use crate::inbound_host::{InboundPepRequest, PubSubReply};
use northstar_stream::protocol::iq_visibility::LocalIqAdmission;

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

pub(super) async fn route_inbound_iq<H: InboundHost>(
    state: &H,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
) -> Result<Option<String>> {
    let kind = root.attribute("type").unwrap_or("get");
    let request = matches!(kind, "get" | "set");
    let id = root.attribute("id").unwrap_or_default();
    let unavailable = || request.then(|| s2s_iq_error(id, to, from, "service-unavailable"));
    let Ok(to_jid) = CanonicalJid::parse(to) else {
        return Ok(request.then(|| s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    if matches!(kind, "result" | "error") {
        // These authenticated return handlers own correlation and consume
        // their replies before any user-resource gate.
        if state
            .handle_federated_caps_response(id, kind, root, raw)
            .await
            || state.handle_push_delivery_response(id, kind, from).await?
        {
            return Ok(None);
        }
        if to_jid.resourcepart().is_none() {
            return Ok(None);
        }
    }

    let recipient_name = to_jid.localpart();
    let full_target = to_jid.resourcepart().is_some();
    let child = root.children().find(roxmltree::Node::is_element);
    let jingle_error = child
        .filter(|child| {
            kind == "set"
                && child.has_tag_name((northstar_message_core::jingle::JINGLE_NS, "jingle"))
        })
        .and_then(|child| {
            northstar_message_core::jingle::validate_jingle_iq(root, child, None).err()
        });
    let local_admission = if full_target {
        state
            .session_entries_for(to)
            .into_iter()
            .next()
            .map(|(jid, target)| LocalIqAdmission::capture(jid, &target, from, request))
            .transpose()?
    } else {
        None
    };
    let remote_route = if full_target && local_admission.is_none() && recipient_name.is_some() {
        state.capture_remote_iq_route(to).await?
    } else {
        None
    };
    if let Some(admission) = local_admission.as_ref() {
        if !state.authorize_iq_resource(admission).await? {
            return Ok(unavailable());
        }
        if !request {
            state.local_iq_handoff(admission, Some(raw));
            return Ok(None);
        }
        if !state.local_iq_handoff(admission, None) {
            return Ok(unavailable());
        }
    } else if let Some(route) = remote_route.as_ref() {
        if !request || !answers_for_full_resource(child, kind, jingle_error.is_some()) {
            return Ok(if state.remote_iq_handoff(route, raw, false).await {
                None
            } else {
                unavailable()
            });
        }
        if !state.remote_iq_handoff(route, raw, true).await {
            return Ok(unavailable());
        }
    } else if full_target {
        return Ok(unavailable());
    } else if let Some(username) = recipient_name {
        // Bare account IQ service policy remains account scoped.
        let Some(recipient) = state.find_enabled_presence_user(username).await? else {
            return Ok(unavailable());
        };
        let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
        if state
            .is_blocked_for_account(recipient.id, &recipient_bare, from)
            .await?
        {
            return Ok(unavailable());
        }
    }

    let reply = answer_or_forward_iq(
        state,
        AdmittedIqRequest {
            id,
            kind,
            raw,
            from,
            to,
            target: &to_jid,
            child,
            jingle_error,
            local_admission: local_admission.as_ref(),
        },
    )
    .await?;
    if reply.is_some() {
        let current = if let Some(admission) = local_admission.as_ref() {
            state.local_iq_handoff(admission, None)
        } else if let Some(route) = remote_route.as_ref() {
            state.remote_iq_route_current(route).await?
        } else {
            true
        };
        if !current {
            return Ok(unavailable());
        }
    }
    Ok(reply)
}

struct AdmittedIqRequest<'a, 'input> {
    id: &'a str,
    kind: &'a str,
    raw: &'a str,
    from: &'a str,
    to: &'a str,
    target: &'a CanonicalJid,
    child: Option<roxmltree::Node<'a, 'input>>,
    jingle_error: Option<&'static str>,
    local_admission: Option<&'a LocalIqAdmission<'a>>,
}

async fn answer_or_forward_iq<H: InboundHost>(
    state: &H,
    iq: AdmittedIqRequest<'_, '_>,
) -> Result<Option<String>> {
    let AdmittedIqRequest {
        id,
        kind,
        raw,
        from,
        to,
        target: to_jid,
        child,
        jingle_error,
        local_admission,
    } = iq;
    let recipient_name = to_jid.localpart();
    let Some(child) = child else {
        return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
    };
    if let Some(condition) = jingle_error {
        return Ok(Some(s2s_iq_error(id, to, from, condition)));
    }
    if kind == "get"
        && to.contains('/')
        && child.tag_name().name() == "query"
        && child.tag_name().namespace() == Some("http://jabber.org/protocol/disco#info")
    {
        if let Some(result) = state.cached_disco_result(id, to, child.attribute("node")) {
            return Ok(Some(northstar_xml_builder::rewrite::set_to(&result, from)));
        }
    }
    if to_jid.localpart().is_none()
        && same_s2s_domain(
            to_jid.domainpart(),
            &format!("pubsub.{}", state.local_domain()),
        )
    {
        let reply = match state.handle_pubsub_request(from, kind, child).await {
            Ok(reply) => reply,
            Err(error) if northstar_pubsub_application::is_pubsub_mutation_busy(&error) => {
                PubSubReply::Error("resource-constraint")
            }
            Err(error) => return Err(error),
        };
        return Ok(Some(match reply {
            PubSubReply::Result(payload) => s2s_iq_result(id, to, from, &payload),
            reply @ (PubSubReply::Error(_) | PubSubReply::ExtendedError(_)) => {
                pubsub_s2s_iq_error(id, to, from, &reply)
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
            let payload = match state.public_vcard(owner_name).await? {
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
            state
                .federated_pep_items(InboundPepRequest {
                    owner_name: recipient_name,
                    full_target: to_jid.resourcepart().is_some(),
                    child,
                    id,
                    to,
                    from,
                })
                .await?,
        )),
        ("pubsub", "http://jabber.org/protocol/pubsub", "set")
            if !is_xep0357_notification_publish(child) =>
        {
            Ok(Some(
                state
                    .federated_pep_subscription(InboundPepRequest {
                        owner_name: recipient_name,
                        full_target: to_jid.resourcepart().is_some(),
                        child,
                        id,
                        to,
                        from,
                    })
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
                let reply = state
                    .pubsub_disco_info(from, child.attribute("node"))
                    .await?;
                return Ok(Some(match reply {
                    PubSubReply::Result(payload) => s2s_iq_result(id, to, from, &payload),
                    reply @ (PubSubReply::Error(_) | PubSubReply::ExtendedError(_)) => {
                        pubsub_s2s_iq_error(id, to, from, &reply)
                    }
                }));
            }
            if let Some(owner_name) = recipient_name {
                let Some(payload) = state
                    .pep_disco_info(owner_name, from, child.attribute("node"))
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
            if state.s2s_ping_feature_enabled() {
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
            let reply = state.pubsub_disco_items(from, child).await?;
            Ok(Some(match reply {
                PubSubReply::Result(payload) => s2s_iq_result(id, to, from, &payload),
                reply @ (PubSubReply::Error(_) | PubSubReply::ExtendedError(_)) => {
                    pubsub_s2s_iq_error(id, to, from, &reply)
                }
            }))
        }
        ("query", "http://jabber.org/protocol/disco#items", "get")
            if recipient_name.is_some() && to_jid.resourcepart().is_none() =>
        {
            let owner_name = recipient_name.expect("guarded above");
            let Some(payload) = state
                .pep_disco_items(owner_name, from, child.attribute("node"))
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
            if bare_target && !bare_account_iq_may_route_to_service_resource(to_jid, child) {
                return Ok(Some(s2s_iq_error(id, to, from, "service-unavailable")));
            }
            // Never spray the narrow service-resource exception across
            // resources: highest priority wins and the canonical full JID is
            // a deterministic tie-breaker.
            let delivered = if let Some(admission) = local_admission {
                state.local_iq_handoff(admission, Some(raw))
            } else if bare_target {
                let mut targets = state.session_entries_for(to);
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
                let mut delivered = false;
                for (jid, target) in targets {
                    // Push-service routing has no presence grant requirement.
                    let admission = LocalIqAdmission::capture(jid, &target, from, false)?;
                    if state.authorize_iq_resource(&admission).await?
                        && state.local_iq_handoff(&admission, Some(raw))
                    {
                        delivered = true;
                        break;
                    }
                }
                delivered || state.route_s2s_iq_request_remote(to, raw, true).await
            } else {
                false
            };
            if !delivered {
                return Ok(Some(s2s_iq_error(id, to, from, "service-unavailable")));
            }
            Ok(None)
        }
    }
}

// Only these full-resource handlers can answer from the server. Forwarding
// asks the resource owner for a single admission combined with queue handoff.
fn answers_for_full_resource(
    child: Option<roxmltree::Node<'_, '_>>,
    kind: &str,
    invalid_jingle: bool,
) -> bool {
    let Some(child) = child else {
        return true;
    };
    if invalid_jingle {
        return true;
    }
    match (child.tag_name().name(), child.tag_name().namespace(), kind) {
        ("ping", Some(northstar_xep_0199::NAMESPACE), "get")
        | ("vCard", Some("vcard-temp"), "get")
        | ("pubsub", Some("http://jabber.org/protocol/pubsub"), "get")
        | ("query", Some("http://jabber.org/protocol/disco#info"), "get") => true,
        ("pubsub", Some("http://jabber.org/protocol/pubsub"), "set") => {
            !is_xep0357_notification_publish(child)
        }
        _ => false,
    }
}

fn pubsub_s2s_iq_error(id: &str, from: &str, to: &str, reply: &PubSubReply) -> String {
    use northstar_xep_0060::PubSubError;

    match reply {
        PubSubReply::Result(_) => northstar_xep_0060::build_s2s_iq_error(
            id,
            from,
            to,
            &PubSubError::simple("undefined-condition"),
        ),
        PubSubReply::Error(condition) => {
            northstar_xep_0060::build_s2s_iq_error(id, from, to, &PubSubError::simple(condition))
        }
        PubSubReply::ExtendedError(error) => {
            northstar_xep_0060::build_s2s_iq_error(id, from, to, error)
        }
    }
}

#[cfg(test)]
mod tests;
