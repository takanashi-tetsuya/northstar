//! Resolve stanza delivery and validate and route direct resource fan-out.

use super::delivery_send::{send_direct_delivery, DirectDeliveryRecipient, DirectDeliverySend};
use super::*;
use crate::{
    listener_dispatch::ClusterListenerDispatch, listener_mix_caps::ClusterListenerMixCaps,
};
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_stream::local_routes::session_table::LocalSessionTable;

pub(super) mod exact_control;
mod notification;
mod policy;
mod roster;

use self::policy::{exact_iq_request, handoff_exact_iq, permits_direct_delivery};
pub(super) use self::roster::handoff_roster_push;
use self::roster::{roster_interest_missing, validate_roster_push, RosterPushOptions};

pub(super) struct StanzaDelivery<'a> {
    stanza: &'a str,
    is_message_stanza: bool,
    resolved_message_delivery: Option<ResolvedNodeMessageDelivery>,
    direct_delivery_contract_valid: bool,
    carbons_only: bool,
    privacy_peer_kind: Option<(String, northstar_xep_0016::PrivacyStanzaKind)>,
    pubsub_event: bool,
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
    let exact_control_version = exact_control::is_exact_control_version(json);
    let exact_iq = json.get("exact_iq_check_only").is_some();
    if exact_iq
        && (is_muc
            || is_muc_private
            || exact_iq_request(json, target, parsed_stanza.as_ref()).is_none())
    {
        return ListenerStep::Continue;
    }
    if exact_control_version && (is_muc || is_muc_private) {
        return ListenerStep::Continue;
    }
    let (resolved_message_delivery, direct_delivery_contract_valid) =
        if !is_muc && !is_muc_private && !exact_control_version && !exact_iq {
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
    let pubsub_event = parsed_stanza
        .as_ref()
        .is_some_and(notification::is_pubsub_event);
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
            pubsub_event,
        },
        muc_senders,
    ))
}

pub(super) struct DirectDeliveryOptions<'a> {
    blocklist_requested_only: bool,
    pub(super) roster_requested_only: bool,
    expected_user_id: Option<uuid::Uuid>,
    expected_auth_generation: Option<i64>,
    pub(super) expected_connections: Option<std::collections::BTreeMap<String, uuid::Uuid>>,
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
    pub(super) exact_control: Option<ExactControl>,
    exact_iq_request: Option<(bool, bool)>,
    pub(super) presence_delivery: Option<northstar_stream::outbound::PresenceDelivery>,
}

pub(super) fn validate_direct_delivery<'a>(
    json: &'a serde_json::Value,
    target: &str,
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
    let ListenerStep::Next((
        RosterPushOptions {
            roster_version,
            roster_annotated_stanza,
        },
        exact_control,
    )) = exact_control::validate_control_and_roster_push(
        json,
        target,
        parsed_stanza.as_ref(),
        roster_requested_only,
        (expected_user_id, expected_auth_generation),
    )
    else {
        return ListenerStep::Continue;
    };
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
    let exact_iq_request = exact_iq_request(json, target, parsed_stanza.as_ref());
    if exact_iq_request.is_some()
        && (exact_control.is_some() || carbons_only || json.get("expected_connections").is_none())
    {
        return ListenerStep::Continue;
    }
    let expected_connections = match (json.get("expected_connections"), &exact_control) {
        (_, Some(control)) => Some(control.expected_connections.clone()),
        (None, None) => None,
        (Some(value), None) => {
            let Ok(routes) = serde_json::from_value::<std::collections::BTreeMap<String, uuid::Uuid>>(
                value.clone(),
            ) else {
                return ListenerStep::Continue;
            };
            let Ok(target_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(target) else {
                return ListenerStep::Continue;
            };
            if json["protocol_version"].as_str() != Some(EXACT_MESSAGE_DELIVERY_VERSION)
                || (!is_message_stanza && exact_iq_request.is_none())
                || expected_user_id.is_none_or(|id| id.is_nil())
                || expected_auth_generation.is_none()
                || routes.is_empty()
                || blocklist_requested_only
                || roster_requested_only
                || privacy_requested_only
                || mix_capable_only
                || transport_receipt_required
                || routes.iter().any(|(key, connection_id)| {
                    connection_id.is_nil()
                        || northstar_xmpp_types::jid::CanonicalJid::parse(key).map_or(true, |jid| {
                            jid.resourcepart().is_none()
                                || jid.to_string() != *key
                                || jid.bare() != target_jid.bare()
                                || (target_jid.resourcepart().is_some() && key != target)
                        })
                })
            {
                return ListenerStep::Continue;
            }
            Some(routes)
        }
    };
    if carbons_only
        && (expected_connections.is_none()
            || !matches!(
                resolved_message_delivery,
                Some(ResolvedNodeMessageDelivery::Volatile)
            ))
    {
        return ListenerStep::Continue;
    }
    let presence_delivery = presence::delivery_scope(
        exact_control.as_ref(),
        json["current_presence_replay"].as_bool() == Some(true),
    );
    ListenerStep::Next(DirectDeliveryOptions {
        blocklist_requested_only,
        roster_requested_only,
        expected_user_id,
        expected_auth_generation,
        expected_connections,
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
        exact_control,
        exact_iq_request,
        presence_delivery,
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
        pubsub_event,
    } = *stanza_delivery;
    let DirectDeliveryOptions {
        blocklist_requested_only,
        roster_requested_only,
        expected_user_id,
        expected_auth_generation,
        ref expected_connections,
        privacy_requested_only,
        mix_capable_only,
        ref exclude_jids,
        ref carbon_muc_scope,
        primary_one_to_one,
        ..
    } = *options;
    let ListenerTurn {
        delivered,
        accepted_full_jid,
        mix_supported,
        mix_unsupported,
        mix_unknown,
        mix_handoff,
        control_processed,
        ..
    } = turn;
    let notification_source = if !carbons_only
        && matches!(
            resolved_message_delivery,
            Some(ResolvedNodeMessageDelivery::Volatile)
        ) {
        privacy_peer_kind.as_ref().and_then(|(peer, _)| {
            notification::source(peer, &message_policy.local_domain, pubsub_event)
        })
    } else {
        None
    };
    let mut notification_suppressed = false;
    let mut notification_retry = false;
    let mut targets = dispatch.session_entries_for(target);
    targets.retain(|(jid, session)| {
        expected_connections
            .as_ref()
            .is_none_or(|routes| routes.get(jid) == Some(&session.connection_id))
            && options.priority_matches(target, session)
    });
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
        if notification_source.is_some()
            && !delivery_user_identity_matches(
                expected_user_id,
                expected_auth_generation,
                session.user_id,
                session.auth_generation,
            )
        {
            notification_suppressed = true;
            continue;
        }
        if exclude_jids.contains(&jid)
            || (is_message_stanza
                && matches!(
                    resolved_message_delivery,
                    Some(ResolvedNodeMessageDelivery::Durable(durable))
                        if durable.recipient_id != session.user_id
                ))
            || !delivery_user_identity_matches(
                expected_user_id,
                expected_auth_generation,
                session.user_id,
                session.auth_generation,
            )
            || (blocklist_requested_only && !session.blocklist_requested.load(Ordering::Acquire))
            || roster_interest_missing(roster_requested_only, &session)
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
        if carbons_only {
            let route = ExactMessageRoute {
                full_jid: jid.clone(),
                account_id: session.user_id,
                auth_generation: session.auth_generation,
                connection_id: session.connection_id,
                node_id: None,
                priority: None,
                available: None,
            };
            let table = LocalSessionTable::new(Arc::clone(&dispatch.account_routes.sessions));
            let scope = carbon_muc_scope
                .as_ref()
                .map(|(room, nick)| (room.as_str(), nick.as_str()));
            let Some((peer, _)) = privacy_peer_kind else {
                continue;
            };
            let Some(active_list) = table.with_exact_carbon_route(&route, scope, |current| {
                active_privacy_list(&current.privacy_active)
            }) else {
                continue;
            };
            match message_policy
                .message
                .allows_carbon_on_route(&route, active_list.as_deref(), peer)
                .await
            {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    tracing::warn!(?error, %jid, "privacy policy failed closed for a clustered Carbon");
                    continue;
                }
            }
            let delivery = node_delivery_stanza(stanza, true, &jid);
            let accepted = table.with_exact_carbon_route(&route, scope, |current| {
                active_privacy_list(&current.privacy_active) == active_list
                    && current.sender.try_send(delivery).is_ok()
            });
            if accepted == Some(true) {
                message_policy.record_online_queue_acceptance(false);
                *delivered += 1;
                accepted_full_jid.get_or_insert(jid);
            }
            continue;
        }
        if let Some(source) = notification_source {
            use northstar_roster_application::notification_admission::NotificationHandoff;

            match notification::handoff(message_policy, dispatch, &jid, &session, source, stanza)
                .await
            {
                NotificationHandoff::Accepted => {
                    message_policy.record_online_queue_acceptance(false);
                    *delivered += 1;
                    accepted_full_jid.get_or_insert(jid);
                    if primary_one_to_one {
                        break;
                    }
                }
                NotificationHandoff::Suppressed => notification_suppressed = true,
                NotificationHandoff::Retry => notification_retry = true,
            }
            continue;
        }
        if let Some((request, check_only)) = options.exact_iq_request {
            let Some((peer, _)) = privacy_peer_kind else {
                continue;
            };
            let table = LocalSessionTable::new(Arc::clone(&dispatch.account_routes.sessions));
            if handoff_exact_iq(
                &message_policy.message,
                &table,
                (&jid, &session, peer),
                request,
                (!check_only).then_some(stanza),
            )
            .await
            {
                *delivered += 1;
                accepted_full_jid.get_or_insert(jid);
            }
            break;
        }
        let captured_terminal_policy = options
            .exact_control
            .as_ref()
            .is_some_and(|control| control.kind == ExactControlKind::TeardownUnavailable);
        // The validated transport receipt identifies server return-control.
        if !options.transport_receipt_required
            && !captured_terminal_policy
            && !permits_direct_delivery(
                message_policy,
                &session,
                &jid,
                privacy_peer_kind,
                blocklist_requested_only || roster_requested_only || privacy_requested_only,
                mix_capable_only,
            )
            .await
        {
            continue;
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
        let accepted = match send_direct_delivery(
            message_policy,
            dispatch,
            DirectDeliveryRecipient {
                session: &session,
                jid: &jid,
                target,
                delivery: &delivery,
            },
            options,
            mix_delivery,
            durable_delivery,
            mix_handoff,
        )
        .await
        {
            DirectDeliverySend::Accepted(accepted) => accepted,
            DirectDeliverySend::RetryExactPresence => {
                *control_processed = Some(false);
                continue;
            }
            DirectDeliverySend::StopFanout => break,
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
    if notification_suppressed && !notification_retry && *delivered == 0 {
        // Use the existing correlated acknowledgement for a terminal policy
        // result, leaving its delivered count reserved for queue acceptance.
        *control_processed = Some(true);
    }
}

impl DirectDeliveryOptions<'_> {
    pub(super) fn priority_matches(
        &self,
        target: &str,
        session: &northstar_stream::local_routes::session::OnlineSession,
    ) -> bool {
        let (available, priority) = session.presence_route_state();
        self.priority_matches_state(target, available, priority)
    }

    pub(super) fn priority_matches_state(
        &self,
        target: &str,
        available: bool,
        priority: i16,
    ) -> bool {
        target.contains('/')
            || if self.available_nonnegative_only {
                available && priority >= 0
            } else {
                !(self.primary_one_to_one || self.available_only) || available
            }
    }
}

#[cfg(test)]
impl<A: ClusterAdapters> ClusterListenerDispatch<A> {
    pub(crate) async fn test_direct_message_delivery(
        &self,
        admission: &ClusterListenerAdmission,
        message_policy: &ClusterListenerMessagePolicy<A>,
        mix_caps: &ClusterListenerMixCaps,
        json: &serde_json::Value,
    ) -> (usize, Option<String>, Option<NodeDeliveryContract>) {
        let ListenerStep::Next(ListenerCommand {
            target, mut turn, ..
        }) = super::envelope::prepare_listener_command(
            admission,
            json,
            DELIVERY_CONTRACT_PROTOCOL_VERSION,
        )
        else {
            panic!("test command must be accepted for dispatch");
        };
        let stanza = json["stanza"].as_str().unwrap();
        let parsed_stanza = Some(roxmltree::Document::parse(stanza).unwrap());
        let ListenerStep::Next((delivery, _)) = resolve_stanza_delivery(
            message_policy,
            json,
            target,
            stanza,
            &parsed_stanza,
            (false, false),
            &mut turn,
        )
        .await
        else {
            panic!("test message must be resolved for dispatch");
        };
        let ListenerStep::Next(options) =
            validate_direct_delivery(json, target, &parsed_stanza, None, &delivery)
        else {
            panic!("test command must be valid for direct fan-out");
        };
        fan_out_direct_delivery(
            self,
            message_policy,
            mix_caps,
            target,
            &delivery,
            &options,
            &mut turn,
        )
        .await;
        (
            turn.delivered,
            turn.accepted_full_jid,
            turn.acknowledged_delivery,
        )
    }
}
