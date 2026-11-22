//! Resolve stanza delivery and validate and route direct resource fan-out.

use super::delivery_send::{send_direct_delivery, DirectDeliveryRecipient, DirectDeliverySend};
use super::*;
use crate::{
    listener_dispatch::ClusterListenerDispatch, listener_mix_caps::ClusterListenerMixCaps,
};

pub(super) struct StanzaDelivery<'a> {
    stanza: &'a str,
    is_message_stanza: bool,
    resolved_message_delivery: Option<ResolvedNodeMessageDelivery>,
    direct_delivery_contract_valid: bool,
    carbons_only: bool,
    privacy_peer_kind: Option<(String, northstar_xep_0016::PrivacyStanzaKind)>,
}

pub(super) async fn resolve_stanza_delivery<'a, A: ClusterAdapters>(
    message_policy: &ClusterListenerMessagePolicy<A>,
    json: &serde_json::Value,
    target: &str,
    stanza: &'a str,
    parsed_stanza: &Option<roxmltree::Document<'_>>,
    (is_muc, is_muc_private): (bool, bool),
    turn: &mut ListenerTurn,
) -> ListenerStep<(StanzaDelivery<'a>, Vec<String>)> {
    let acknowledged_delivery = &mut turn.acknowledged_delivery;
    let is_message_stanza = parsed_stanza
        .as_ref()
        .is_some_and(|document| document.root_element().tag_name().name() == "message");
    let (resolved_message_delivery, direct_delivery_contract_valid) = if !is_muc && !is_muc_private
    {
        match requested_node_message_delivery(json, is_message_stanza) {
            Ok(Some(request)) => {
                match resolve_node_message_delivery(
                    message_policy.verifier(),
                    request,
                    stanza,
                    target,
                )
                .await
                {
                    Ok(resolved) => {
                        *acknowledged_delivery = Some(resolved.contract());
                        (Some(resolved), true)
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            target,
                            "rejected an unverified clustered message delivery contract"
                        );
                        (None, false)
                    }
                }
            }
            Ok(None) => (None, true),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    target,
                    "rejected an invalid clustered message delivery contract"
                );
                (None, false)
            }
        }
    } else {
        (None, true)
    };
    let carbons_only = json["carbons_only"].as_bool().unwrap_or(false);
    let privacy_peer_kind = parsed_stanza
        .as_ref()
        .and_then(|document| delivery_privacy_peer(document, carbons_only));
    // Both Carbon directions deliberately use a self-addressed outer
    // wrapper. If the exact forwarded conversation peer cannot be
    // recovered, an unfiltered fallback would bypass the resource's
    // active XEP-0016 list.
    if carbons_only && privacy_peer_kind.is_none() {
        return ListenerStep::Continue;
    }
    let mut muc_senders = roxmltree::Document::parse(stanza)
        .ok()
        .and_then(|document| document.root_element().attribute("from").map(str::to_owned))
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(real_sender) = json["real_sender"]
        .as_str()
        .and_then(|sender| northstar_xmpp_types::jid::canonicalize(sender).ok())
    {
        muc_senders.push(real_sender);
    }
    ListenerStep::Next((
        StanzaDelivery {
            stanza,
            is_message_stanza,
            resolved_message_delivery,
            direct_delivery_contract_valid,
            carbons_only,
            privacy_peer_kind,
        },
        muc_senders,
    ))
}

pub(super) struct DirectDeliveryOptions<'a> {
    blocklist_requested_only: bool,
    pub(super) roster_requested_only: bool,
    expected_user_id: Option<uuid::Uuid>,
    expected_auth_generation: Option<i64>,
    pub(super) roster_version: Option<i64>,
    pub(super) roster_annotated_stanza: Option<&'a str>,
    privacy_requested_only: bool,
    mix_capable_only: bool,
    pub(super) transport_receipt_required: bool,
    exclude_jids: HashSet<String>,
    carbon_muc_scope: Option<(String, String)>,
    primary_one_to_one: bool,
    available_only: bool,
    available_nonnegative_only: bool,
    pub(super) mix_request_id: Option<uuid::Uuid>,
}

pub(super) fn validate_direct_delivery<'a>(
    json: &'a serde_json::Value,
    target: &str,
    stanza: &str,
    parsed_stanza: &Option<roxmltree::Document<'_>>,
    parsed_presence_authority: Option<ClusterPresenceAuthority>,
    stanza_delivery: &StanzaDelivery<'_>,
) -> ListenerStep<DirectDeliveryOptions<'a>> {
    let StanzaDelivery {
        is_message_stanza,
        resolved_message_delivery,
        carbons_only,
        ..
    } = *stanza_delivery;
    let blocklist_requested_only = json["blocklist_requested_only"].as_bool().unwrap_or(false);
    let roster_requested_only = json["roster_requested_only"].as_bool().unwrap_or(false);
    let expected_user_id = match json.get("expected_user_id") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => {
            let Ok(value) = uuid::Uuid::parse_str(value) else {
                return ListenerStep::Continue;
            };
            Some(value)
        }
        Some(_) => return ListenerStep::Continue,
    };
    let expected_auth_generation = match json.get("expected_auth_generation") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => value.as_i64().filter(|value| *value >= 0),
    };
    if json
        .get("expected_auth_generation")
        .is_some_and(|value| !value.is_null() && expected_auth_generation.is_none())
    {
        return ListenerStep::Continue;
    }
    if let Some(authority) = parsed_presence_authority {
        if expected_user_id != Some(authority.recipient_id)
            || expected_auth_generation != Some(authority.recipient_auth_generation)
        {
            return ListenerStep::Continue;
        }
    }
    let roster_version = match json.get("roster_version") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => value.as_i64(),
    };
    let roster_annotated_stanza = match json.get("roster_annotated_stanza") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value))
            if value.len() <= northstar_stream::MAX_XMPP_FRAME_BYTES
                && roxmltree::Document::parse(value).is_ok() =>
        {
            Some(value.as_str())
        }
        Some(_) => return ListenerStep::Continue,
    };
    if roster_requested_only && (expected_user_id.is_none() || roster_version.is_none()) {
        return ListenerStep::Continue;
    }
    if roster_requested_only {
        let Some(roster_version) = roster_version else {
            return ListenerStep::Continue;
        };
        if cluster_roster_push_version(stanza) != Some(roster_version)
            || roster_annotated_stanza
                .is_some_and(|value| cluster_roster_push_version(value) != Some(roster_version))
        {
            return ListenerStep::Continue;
        }
    }
    if !roster_requested_only && (roster_version.is_some() || roster_annotated_stanza.is_some()) {
        return ListenerStep::Continue;
    }
    let privacy_requested_only = json["privacy_requested_only"].as_bool().unwrap_or(false);
    let mix_capable_only = match json.get("mix_capable_only") {
        None => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(_) => return ListenerStep::Continue,
    };
    let transport_receipt_required = match json.get("transport_receipt_required") {
        None => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(_) => return ListenerStep::Continue,
    };
    let mix_transport_receipt_required = match json.get("mix_transport_receipt_required") {
        None => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(_) => return ListenerStep::Continue,
    };
    let exclude_jids = delivery_exclusions(json);
    let Ok(carbon_muc_scope) = delivery_carbon_muc_scope(json) else {
        return ListenerStep::Continue;
    };
    let primary_one_to_one = json["primary_one_to_one"].as_bool().unwrap_or(false);
    let available_only = json["available_only"].as_bool().unwrap_or(false);
    let available_nonnegative_only = json["available_nonnegative_only"]
        .as_bool()
        .unwrap_or(false);
    let transport_receipt_stanza_valid = parsed_stanza.as_ref().is_some_and(|document| {
        let root = document.root_element();
        root.tag_name().name() == "iq"
            && root.tag_name().namespace() == Some("jabber:client")
            && matches!(root.attribute("type"), Some("result" | "error"))
            && root.attribute("id").is_some_and(|id| !id.is_empty())
            && root.attribute("to").is_some_and(|to| {
                matches!(
                    (
                        northstar_xmpp_types::jid::canonical_session_key(to),
                        northstar_xmpp_types::jid::canonical_session_key(target),
                    ),
                    (Ok(addressed), Ok(expected)) if addressed == expected
                )
            })
    });
    if transport_receipt_required
        && (is_message_stanza
            || expected_user_id.is_none()
            || !target.contains('/')
            || carbons_only
            || blocklist_requested_only
            || roster_requested_only
            || privacy_requested_only
            || mix_capable_only
            || primary_one_to_one
            || available_only
            || available_nonnegative_only
            || !exclude_jids.is_empty()
            || carbon_muc_scope.is_some()
            || !transport_receipt_stanza_valid)
    {
        return ListenerStep::Continue;
    }
    // This is intentionally a separate contract from the
    // exact-resource policy/PAM receipt above. A durable MIX
    // event is a bare-JID message, is routed only to resources
    // with verified MIX support, and may be acknowledged after
    // any one such resource obtains true transport ownership.
    // Reject every other combination rather than letting a
    // signed-but-malformed payload silently downgrade to an
    // in-memory `try_send` acknowledgement.
    if mix_transport_receipt_required
        && (transport_receipt_required
            || !is_message_stanza
            || !matches!(
                resolved_message_delivery,
                Some(ResolvedNodeMessageDelivery::Mix(_))
            )
            || !mix_capable_only
            || northstar_xmpp_types::jid::CanonicalJid::parse(target)
                .map_or(true, |jid| jid.resourcepart().is_some())
            || carbons_only
            || blocklist_requested_only
            || roster_requested_only
            || privacy_requested_only
            || primary_one_to_one
            || available_only
            || available_nonnegative_only
            || expected_user_id.is_some()
            || expected_auth_generation.is_some()
            || roster_version.is_some()
            || roster_annotated_stanza.is_some()
            || !exclude_jids.is_empty()
            || carbon_muc_scope.is_some())
    {
        return ListenerStep::Continue;
    }
    // A typed MIX contract is never a hint.  Requiring the
    // matching receipt flag in both directions prevents a
    // signed-but-malformed command from taking the volatile
    // queue branch while carrying a live recipient lease.
    if matches!(
        resolved_message_delivery,
        Some(ResolvedNodeMessageDelivery::Mix(_))
    ) != mix_transport_receipt_required
    {
        return ListenerStep::Continue;
    }
    let mix_request_id = if mix_transport_receipt_required {
        match json["request_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
        {
            Some(request_id) => Some(request_id),
            None => return ListenerStep::Continue,
        }
    } else {
        None
    };
    ListenerStep::Next(DirectDeliveryOptions {
        blocklist_requested_only,
        roster_requested_only,
        expected_user_id,
        expected_auth_generation,
        roster_version,
        roster_annotated_stanza,
        privacy_requested_only,
        mix_capable_only,
        transport_receipt_required,
        exclude_jids,
        carbon_muc_scope,
        primary_one_to_one,
        available_only,
        available_nonnegative_only,
        mix_request_id,
    })
}

pub(super) async fn fan_out_direct_delivery<A: ClusterAdapters>(
    dispatch: &ClusterListenerDispatch<A>,
    message_policy: &ClusterListenerMessagePolicy<A>,
    mix_caps: &ClusterListenerMixCaps,
    target: &str,
    stanza_delivery: &StanzaDelivery<'_>,
    options: &DirectDeliveryOptions<'_>,
    turn: &mut ListenerTurn,
) {
    let StanzaDelivery {
        stanza,
        is_message_stanza,
        resolved_message_delivery,
        direct_delivery_contract_valid,
        carbons_only,
        ref privacy_peer_kind,
    } = *stanza_delivery;
    let DirectDeliveryOptions {
        blocklist_requested_only,
        roster_requested_only,
        expected_user_id,
        expected_auth_generation,
        privacy_requested_only,
        mix_capable_only,
        ref exclude_jids,
        ref carbon_muc_scope,
        primary_one_to_one,
        available_only,
        available_nonnegative_only,
        ..
    } = *options;
    let ListenerTurn {
        delivered,
        accepted_full_jid,
        mix_supported,
        mix_unsupported,
        mix_unknown,
        mix_handoff,
        ..
    } = turn;
    let mut targets = dispatch.session_entries_for(target);
    if (primary_one_to_one || available_only || available_nonnegative_only) && !target.contains('/')
    {
        targets.retain(|(_, session)| {
            session.available.load(Ordering::Relaxed)
                && (!available_nonnegative_only || session.priority.load(Ordering::Relaxed) >= 0)
        });
    }
    if primary_one_to_one && !target.contains('/') {
        targets.sort_by(|(left_jid, left), (right_jid, right)| {
            right
                .priority
                .load(Ordering::Relaxed)
                .cmp(&left.priority.load(Ordering::Relaxed))
                .then_with(|| left_jid.cmp(right_jid))
        });
    }
    for (jid, session) in targets {
        if !direct_delivery_contract_valid
            || (is_message_stanza && resolved_message_delivery.is_none())
        {
            break;
        }
        if exclude_jids.contains(&jid)
            || !delivery_user_identity_matches(
                expected_user_id,
                expected_auth_generation,
                session.user_id,
                session.auth_generation,
            )
            || (carbons_only && !session.carbons.load(std::sync::atomic::Ordering::Acquire))
            || (blocklist_requested_only && !session.blocklist_requested.load(Ordering::Acquire))
            || (roster_requested_only && !session.roster_requested.load(Ordering::Acquire))
            || (privacy_requested_only && !session.privacy_requested.load(Ordering::Acquire))
            || carbon_muc_scope.as_ref().is_some_and(|(room, nick)| {
                session
                    .muc_memberships
                    .get(room)
                    .is_none_or(|membership| membership.nick != *nick)
            })
        {
            continue;
        }
        if !blocklist_requested_only && !roster_requested_only && !privacy_requested_only {
            if let Some((peer, kind)) = privacy_peer_kind.as_ref() {
                match message_policy
                    .privacy_allows_session(
                        session.user_id,
                        session.connection_id,
                        active_privacy_list(&session.privacy_active).as_deref(),
                        peer,
                        *kind,
                    )
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        // Delivery policy reads are fail closed.
                        // A database outage must never turn a deny
                        // list into an allow list on another node.
                        tracing::warn!(?error, %jid, "privacy policy lookup failed during clustered delivery");
                        continue;
                    }
                }
            }
        }
        if mix_capable_only {
            match mix_caps.capability(&jid) {
                ClusterMixCapability::Supported => {
                    *mix_supported = mix_supported.saturating_add(1);
                }
                ClusterMixCapability::Unsupported => {
                    *mix_unsupported = mix_unsupported.saturating_add(1);
                    continue;
                }
                ClusterMixCapability::Unknown => {
                    *mix_unknown = mix_unknown.saturating_add(1);
                    continue;
                }
            }
        }
        let delivery =
            if blocklist_requested_only || roster_requested_only || privacy_requested_only {
                set_to(stanza, &jid)
            } else {
                node_delivery_stanza(stanza, carbons_only, &jid)
            };
        let durable_delivery = if is_message_stanza {
            match resolved_message_delivery {
                Some(ResolvedNodeMessageDelivery::Volatile) => None,
                Some(ResolvedNodeMessageDelivery::Durable(durable))
                    if durable.recipient_id == session.user_id =>
                {
                    Some(durable)
                }
                Some(ResolvedNodeMessageDelivery::Durable(_))
                | Some(ResolvedNodeMessageDelivery::Mix(_))
                | None => None,
            }
        } else {
            None
        };
        let mix_delivery = if is_message_stanza {
            match resolved_message_delivery {
                Some(ResolvedNodeMessageDelivery::Mix(source)) => Some(source),
                Some(ResolvedNodeMessageDelivery::Volatile)
                | Some(ResolvedNodeMessageDelivery::Durable(_))
                | None => None,
            }
        } else {
            None
        };
        let DirectDeliverySend::Accepted(accepted) = send_direct_delivery(
            message_policy,
            dispatch,
            DirectDeliveryRecipient {
                session: &session,
                jid: &jid,
                delivery: &delivery,
            },
            options,
            mix_delivery,
            durable_delivery,
            mix_handoff,
        )
        .await
        else {
            break;
        };
        if accepted {
            if is_message_stanza {
                message_policy.record_online_queue_acceptance(
                    durable_delivery.is_some() || mix_delivery.is_some(),
                );
            }
            *delivered += 1;
            accepted_full_jid.get_or_insert(jid);
            if primary_one_to_one || mix_delivery.is_some() {
                break;
            }
        }
    }
}
