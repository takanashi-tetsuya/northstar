//! Delivery of federated `<message/>` stanzas: an S2S inbound message to a local account.

use crate::messaging::archive_admission::archive_candidate;
use crate::ports::FederatedMessageHost;
use anyhow::Result;
use northstar_federation_core::wire::{s2s_stanza_error, same_s2s_domain};
use northstar_message_application::messaging::{
    ArchiveDirection, DirectMessageRouter, DirectRouteDelivery, DirectRouteOutcome,
    DirectRouteRejection, DirectRouteRequest, DirectRouteTarget, FullJidFallbackPort,
    LocalRecipientDecision,
};
use northstar_message_application::retractions::ArchiveWrite;
use northstar_message_core::validation::strip_untrusted_direct_delays;
use northstar_xep_0359::{add_stanza_id, strip_stanza_ids_by_domain};
use northstar_xml_builder::message_policy::{
    encrypted_archive_stanza, mam_storage_eligible, offline_storage_permitted,
};
use northstar_xml_builder::stanza::{is_encrypted, stanza_error_type};
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use std::ops::ControlFlow;
use std::sync::atomic::Ordering;

use self::degraded::{
    degraded_inbound_direct_eligible, degraded_inbound_privacy_uses_default, inbound_live_effect,
    InboundLiveEffect,
};
use self::route_port::FederatedDirectRoute;

mod continuation;
mod degraded;
mod durable_commit;
mod recipient_policy;
mod retraction;
mod route_port;

pub async fn route_inbound_message<H: FederatedMessageHost>(
    state: &H,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
    authenticated_domain: &str,
) -> Result<Option<String>> {
    if let Err(condition) = state.validate_routed_message(root) {
        return Ok(inbound_message_error(
            root,
            stanza_error_type(condition),
            condition,
        ));
    }
    let personal_retraction_command =
        match northstar_message_core::retraction::personal_retraction_command(root) {
            Ok(command) => command,
            Err(_) => return Ok(inbound_message_error(root, "modify", "bad-request")),
        };
    let personal_retraction = personal_retraction_command.is_some();
    let from_jid = match CanonicalJid::parse(from) {
        Ok(from) => from,
        Err(_) => return Ok(inbound_message_error(root, "modify", "jid-malformed")),
    };
    let canonical_from = from_jid.to_string();
    let Ok(to_jid) = CanonicalJid::parse(to) else {
        return Ok(inbound_message_error(root, "modify", "jid-malformed"));
    };
    let bare_target = to_jid.resourcepart().is_none();
    let degraded_spool_eligible = degraded_inbound_direct_eligible(
        root,
        bare_target,
        personal_retraction,
        state.archive_requires_encryption(),
    );
    // Push-disable and retraction are mutations too. Reject unsupported
    // stanzas before either handler can write anything while Redis is down.
    if degraded_inbound_privacy_uses_default(
        state.message_service().direct_mode(),
        degraded_spool_eligible,
    )
    .is_none()
    {
        return Ok(inbound_message_error(root, "wait", "service-unavailable"));
    }
    if state.handle_push_disable(root, from, to).await? {
        return Ok(None);
    }
    let Some(recipient_name) = to_jid.localpart() else {
        return Ok(inbound_message_error(root, "modify", "jid-malformed"));
    };
    let recipient = match state
        .message_service()
        .resolve_local_recipient(recipient_name, state.local_domain(), from)
        .await?
    {
        LocalRecipientDecision::Missing => {
            return Ok(
                if northstar_message_core::missing_user_message_should_error(
                    root.attribute("type").unwrap_or("normal"),
                ) {
                    inbound_message_error(root, "cancel", "service-unavailable")
                } else {
                    None
                },
            );
        }
        LocalRecipientDecision::Blocked => {
            return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
        }
        LocalRecipientDecision::Deliver(recipient) => recipient,
    };
    let recipient_bare = format!("{}@{}", recipient.username, state.local_domain());
    let message_type = root.attribute("type").unwrap_or("normal");
    if personal_retraction && !matches!(message_type, "normal" | "chat") {
        return Ok(inbound_message_error(root, "modify", "bad-request"));
    }
    let recipient_policy::RecipientPolicy {
        privacy_candidates: _privacy_candidates,
        remote_route_exists,
        default_privacy_denied,
    } = match recipient_policy::select(
        state,
        root,
        from,
        to,
        &recipient,
        message_type,
        bare_target,
        degraded_spool_eligible,
    )
    .await?
    {
        ControlFlow::Continue(policy) => policy,
        ControlFlow::Break(action) => return Ok(action),
    };
    let stable_id = state.message_events().new_stanza_id();
    let recipient_by = format!("{}@{}", recipient.username, state.local_domain());
    let authoritative_raw = strip_stanza_ids_by_domain(
        &strip_untrusted_direct_delays(raw, Some(authenticated_domain)),
        state.local_domain(),
    );
    let annotated = add_stanza_id(&authoritative_raw, &recipient_by, stable_id);
    let encrypted = is_encrypted(root);
    let durable_content_allowed = encrypted || !state.archive_requires_encryption();
    let persistence_allowed = personal_retraction || offline_storage_permitted(root);
    let archive = if encrypted {
        if let Some(command) = personal_retraction_command.as_ref() {
            northstar_xml_builder::message_policy::encrypted_retraction_archive_stanza(
                &annotated,
                &command.target_id,
            )
        } else {
            encrypted_archive_stanza(&annotated)
        }
    } else {
        annotated.clone()
    };
    // The history transaction decides this candidate's MAM policy. A
    // volatile route can accept the stanza first, with log-only failure
    // handling for the subsequent history write.
    let archive_write = ArchiveWrite {
        id: stable_id,
        owner_id: recipient.id,
        peer_jid: &canonical_from,
        stanza: &archive,
        encrypted,
        stanza_id: root.attribute("id"),
    };
    let candidate = archive_candidate(
        archive_write.clone(),
        ArchiveDirection::Inbound,
        !personal_retraction
            && state
                .message_service()
                .archive_content_eligible(mam_storage_eligible(root), encrypted),
    );
    let mut history_committed = false;
    let mut durable_c2s_delivery = None;
    let mut live_claim_id = None;
    let direct_delivery_mode = northstar_message_core::direct_delivery_mode(root);
    if let ControlFlow::Break(action) = durable_commit::commit(
        state,
        root,
        &recipient,
        personal_retraction,
        message_type,
        direct_delivery_mode,
        durable_content_allowed,
        persistence_allowed,
        authenticated_domain,
        &recipient_bare,
        &authoritative_raw,
        &annotated,
        &candidate,
        stable_id,
        &canonical_from,
        encrypted,
        degraded_spool_eligible,
        default_privacy_denied,
        &mut history_committed,
        &mut durable_c2s_delivery,
        &mut live_claim_id,
    )
    .await?
    {
        return Ok(action);
    }
    // The remaining paths are live-only. The durable branch above already
    // returned for a committed spool, while a race into degradation before
    // a volatile route or retraction must fail without side effects.
    match inbound_live_effect(
        state.message_service().direct_mode(),
        durable_c2s_delivery.is_some(),
    ) {
        InboundLiveEffect::Proceed => {}
        InboundLiveEffect::AcceptedSpool => {
            state
                .message_service()
                .rearm_unrouted_live_direct(recipient.id, stable_id, &mut live_claim_id)
                .await;
            return Ok(None);
        }
        InboundLiveEffect::Reject => {
            return Ok(inbound_message_error(root, "wait", "service-unavailable"));
        }
    }
    let mut targets = state.session_entries_for(to);
    if bare_target {
        targets.retain(|(_, session)| {
            session.available.load(Ordering::Relaxed)
                && session.priority.load(Ordering::Relaxed) >= 0
        });
        if message_type != "headline" {
            targets.sort_by(|(left_jid, left), (right_jid, right)| {
                right
                    .priority
                    .load(Ordering::Relaxed)
                    .cmp(&left.priority.load(Ordering::Relaxed))
                    .then_with(|| left_jid.cmp(right_jid))
            });
        }
    }
    let mut allowed_targets = Vec::with_capacity(targets.len());
    for target in targets {
        match FullJidFallbackPort::privacy_allows_fallback(state, &target.1, from).await {
            Ok(true) => allowed_targets.push(target),
            Ok(false) => {}
            Err(error) if durable_c2s_delivery.is_some() => {
                state.record_s2s_post_accept_failure();
                tracing::warn!(?error, recipient_id = %recipient.id,
                    "privacy policy failed closed after durable S2S admission");
            }
            Err(error) => return Err(error),
        }
    }
    let targets = allowed_targets;
    if let ControlFlow::Break(action) = retraction::apply(
        state,
        root,
        personal_retraction_command.as_ref(),
        bare_target,
        &targets,
        remote_route_exists,
        message_type,
        &annotated,
        stable_id,
        &recipient,
        &canonical_from,
        encrypted,
        &archive_write,
        authenticated_domain,
        &mut history_committed,
        &mut durable_c2s_delivery,
        &mut live_claim_id,
    )
    .await?
    {
        return Ok(action);
    }
    let delivery = durable_c2s_delivery.map_or(DirectRouteDelivery::Volatile, |message_id| {
        DirectRouteDelivery::Committed(northstar_stream::outbound::DurableDelivery {
            recipient_id: recipient.id,
            message_id,
            claim_id: live_claim_id,
        })
    });
    let outcome = DirectMessageRouter::route_federated(
        &FederatedDirectRoute(state),
        DirectRouteRequest {
            message_type,
            target: if bare_target {
                DirectRouteTarget::Bare(to)
            } else {
                DirectRouteTarget::Full {
                    jid: to,
                    bare: &recipient_by,
                }
            },
            sender: from,
            recipient_id: recipient.id,
            stanza: &annotated,
            delivery,
            approved_targets: &targets,
            enforce_direct_health: true,
        },
        history_committed,
    )
    .await?;
    let (delivered, delivered_key) = match outcome {
        DirectRouteOutcome::Routed { accepted_full_jid } => (true, accepted_full_jid),
        DirectRouteOutcome::Unrouted => (false, None),
        DirectRouteOutcome::AcceptedForRecovery { stage, reason } => {
            tracing::debug!(
                ?stage,
                ?reason,
                "accepted federated direct message deferred to recovery"
            );
            return Ok(None);
        }
        DirectRouteOutcome::AcceptedBeforeDegradation | DirectRouteOutcome::Dropped => {
            return Ok(None)
        }
        DirectRouteOutcome::Rejected(reason) => {
            let kind = match reason {
                DirectRouteRejection::Unavailable => "wait",
                DirectRouteRejection::NoMatchingResource => "cancel",
            };
            return Ok(inbound_message_error(root, kind, "service-unavailable"));
        }
    };

    continuation::finish(
        state,
        root,
        delivered,
        &delivered_key,
        message_type,
        durable_c2s_delivery,
        &candidate,
        from,
        authenticated_domain,
        &recipient_by,
        &annotated,
        &recipient,
        stable_id,
        direct_delivery_mode,
        persistence_allowed,
        durable_content_allowed,
        history_committed,
        &archive,
        encrypted,
    )
    .await
}

/// Select a single XEP-0359 identity asserted by the exact domain
/// authenticated on this S2S stream. IDs by an unrelated domain are ordinary
/// forwarded payload and can never suppress delivery. Multiple assertions by
/// the same authority are treated as ambiguous and simply disable dedupe.
fn authoritative_remote_stanza_identity(
    root: roxmltree::Node<'_, '_>,
    authenticated_domain: &str,
) -> Option<(String, String, String)> {
    let authenticated_domain = prepare_domainpart(authenticated_domain).ok()?;
    let mut candidates = root.children().filter_map(|node| {
        if !node.is_element()
            || node.tag_name().name() != "stanza-id"
            || node.tag_name().namespace() != Some("urn:xmpp:sid:0")
        {
            return None;
        }
        let raw_by = node.attribute("by")?;
        let by = CanonicalJid::parse(raw_by).ok()?;
        let identity = node.attribute("id")?;
        if identity.is_empty() || identity.len() > 1_024 || identity.chars().any(char::is_control) {
            return None;
        }
        (by.domainpart() == authenticated_domain)
            .then(|| (raw_by.to_owned(), by.to_string(), identity.to_owned()))
    });
    let candidate = candidates.next()?;
    candidates.next().is_none().then_some(candidate)
}

/// RFC 6120 §8.3.1 forbids replying to an error stanza with another stanza
/// error.  Keep the guard next to the S2S message pipeline so every early
/// validation, privacy and routing rejection shares the same behavior.
fn inbound_message_error(
    root: roxmltree::Node<'_, '_>,
    error_type: &str,
    condition: &str,
) -> Option<String> {
    (root.attribute("type") != Some("error")).then(|| s2s_stanza_error(root, error_type, condition))
}

#[cfg(test)]
fn offline_quota_error(root: roxmltree::Node<'_, '_>) -> String {
    s2s_stanza_error(root, "wait", "resource-constraint")
}

#[cfg(test)]
fn recipient_unavailable_error(root: roxmltree::Node<'_, '_>) -> String {
    s2s_stanza_error(root, "wait", "recipient-unavailable")
}

fn is_remote_muc_private_message(
    root: roxmltree::Node<'_, '_>,
    from: &str,
    authenticated_domain: &str,
) -> bool {
    prepare_domainpart(authenticated_domain).is_ok_and(|domain| {
        domain.strip_prefix("conference.").is_some()
            && CanonicalJid::parse(from).is_ok_and(|jid| {
                jid.resourcepart().is_some() && same_s2s_domain(jid.domainpart(), &domain)
            })
    }) && matches!(
        root.attribute("type").unwrap_or("normal"),
        "chat" | "normal"
    )
}

#[cfg(test)]
#[path = "federated_message_tests.rs"]
mod tests;
