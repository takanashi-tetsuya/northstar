mod direct_route;

use direct_route::S2sDirectRoutePort;

use crate::{
    cluster::{DirectPostCommitMode, DirectSpoolEligibility},
    db,
    jid::{prepare_domainpart, CanonicalJid},
    services::{
        messaging::{
            DirectMessageRouter, DirectRouteDelivery, DirectRouteOutcome, DirectRouteRejection,
            DirectRouteRequest, DirectRouteTarget, DurableAdmissionOutcome, IdentityAuthority,
            LocalDelivery, LocalRecipientDecision, MessageIdentity, MessagePostCommit,
            OfflineAdmissionOutcome, OfflineMessageAdmission, PersonalMessageDestination,
            ValidatedPersonalMessage,
        },
        retractions::{
            ArchiveWrite, DeliveryProjection, OwnerProjection, RetractionCommand, RetractionOutcome,
        },
    },
    state::AppState,
    xmpp::xml_builder::XmlElement,
    xmpp::xml_util::*,
};
use anyhow::{Context, Result};
use futures::FutureExt;
use roxmltree::Document;
use std::borrow::Cow;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;

use super::*;

mod dispatch;
mod iq;
mod negotiation;
mod presence;
mod session;

use self::dispatch::route_inbound_for_connection_owned;
use self::iq::route_inbound_iq;
use self::negotiation::{
    authenticated_s2s_sender, inbound_connection, inbound_xmpps_connection,
    locally_hosted_identity_domain, same_s2s_domain,
};
use self::presence::route_inbound_presence;
use self::session::drive_authenticated_inbound;

pub(crate) use self::dispatch::{
    route_inbound_component_owned, route_inbound_for_connection, InboundFederationRoute,
};
pub(crate) use self::session::reply_within_peer_limit;
pub use self::session::{serve, serve_s2s_tls};

#[cfg(test)]
use self::dispatch::{
    s2s_stream_address_error, valid_inbound_wire_namespace, validate_inbound_core_stanza,
    InboundCoreValidation,
};
#[cfg(test)]
use self::iq::{bare_account_iq_may_route_to_service_resource, is_xep0357_notification_publish};
#[cfg(test)]
use self::negotiation::{
    hosted_s2s_domain, is_certificate_downgrade, parse_bidi_request,
    restore_inherited_dialback_namespace, valid_external_auth_shape, valid_starttls_request,
    BidiRequest,
};
#[cfg(test)]
use self::presence::{canonical_subscription_stanza, presence_probe_status_response};
#[cfg(test)]
use self::session::{initial_bidi_route_admissible, wait_for_federation_shutdown};

/// A degraded node can accept only an account-scoped, recoverable direct
/// message. Resource-affine and transient stanzas require a live route.
fn degraded_inbound_direct_eligible(
    root: roxmltree::Node<'_, '_>,
    bare_target: bool,
    personal_retraction: bool,
    archive_requires_encryption: bool,
) -> bool {
    bare_target
        && matches!(
            root.attribute("type").unwrap_or("normal"),
            "normal" | "chat"
        )
        && !personal_retraction
        && !root.children().any(|node| {
            node.is_element()
                && ((node.tag_name().name() == "x"
                    && node.tag_name().namespace() == Some("jabber:x:conference"))
                    || (node.tag_name().name() == "pubsub"
                        && node.tag_name().namespace()
                            == Some("http://jabber.org/protocol/pubsub")))
        })
        && !signal_only_inbound_direct_message(root)
        && crate::xmpp::protocol::messaging::direct_delivery_mode(root)
            == crate::xmpp::protocol::messaging::DirectDeliveryMode::Durable
        && (!archive_requires_encryption || is_encrypted(root))
}

/// A storage hint does not turn a receipt or chat-state signal into a
/// recoverable direct message when live delivery is unavailable.
fn signal_only_inbound_direct_message(root: roxmltree::Node<'_, '_>) -> bool {
    let mut signal = false;
    for node in root.children().filter(roxmltree::Node::is_element) {
        let namespace = node.tag_name().namespace().unwrap_or_default();
        let name = node.tag_name().name();
        let is_signal = (namespace == "http://jabber.org/protocol/chatstates"
            && matches!(
                name,
                "active" | "composing" | "paused" | "inactive" | "gone"
            ))
            || (namespace == "urn:xmpp:receipts" && name == "received")
            || (namespace == "urn:xmpp:chat-markers:0" && matches!(name, "markable" | "displayed"));
        if is_signal {
            signal = true;
            continue;
        }
        if namespace == "urn:xmpp:hints"
            || (matches!(namespace, "" | "jabber:client" | "jabber:server") && name == "thread")
            || namespace == "urn:xmpp:sid:0"
            || (namespace == "urn:northstar:pow:1" && name == "pow")
        {
            continue;
        }
        return false;
    }
    signal
}

fn degraded_inbound_privacy_uses_default(
    mode: DirectPostCommitMode,
    spool_eligible: bool,
) -> Option<bool> {
    match mode {
        DirectPostCommitMode::Live => Some(false),
        DirectPostCommitMode::SpoolOnly if spool_eligible => Some(true),
        DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected => None,
    }
}

fn inbound_direct_spool_eligibility(
    statically_eligible: bool,
    default_privacy_denied: bool,
) -> DirectSpoolEligibility {
    if statically_eligible && !default_privacy_denied {
        DirectSpoolEligibility::Eligible
    } else {
        DirectSpoolEligibility::LiveOnly
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InboundLiveEffect {
    Proceed,
    AcceptedSpool,
    Reject,
}

fn inbound_live_effect(mode: DirectPostCommitMode, committed: bool) -> InboundLiveEffect {
    match mode {
        DirectPostCommitMode::Live => InboundLiveEffect::Proceed,
        DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected if committed => {
            InboundLiveEffect::AcceptedSpool
        }
        DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected => {
            InboundLiveEffect::Reject
        }
    }
}

pub(crate) async fn route_inbound_message(
    state: &AppState,
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
        match crate::xmpp::protocol::retractions::personal_retraction_command(root) {
            Ok(command) => command,
            Err(()) => return Ok(inbound_message_error(root, "modify", "bad-request")),
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
    if crate::xmpp::protocol::misc::handle_push_disable(state, root, from, to).await? {
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
                if crate::xmpp::protocol::messaging::missing_user_message_should_error(
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
    if bare_target {
        match crate::xmpp::protocol::messaging::bare_message_route(message_type) {
            crate::xmpp::protocol::messaging::BareMessageRoute::Reject => {
                return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
            }
            crate::xmpp::protocol::messaging::BareMessageRoute::Ignore => return Ok(None),
            crate::xmpp::protocol::messaging::BareMessageRoute::Primary
            | crate::xmpp::protocol::messaging::BareMessageRoute::All => {}
        }
    }
    // Resolve local per-resource privacy policy before any archive or delivery
    // admission.  A resource's active list replaces the account default; if
    // there is no online route, the durable default governs offline storage.
    // A degraded node cannot trust cached sessions or a Redis route to choose
    // a resource policy, so use the account default for the spool admission.
    let Some(spool_only_privacy) = degraded_inbound_privacy_uses_default(
        state.message_service().direct_mode(),
        degraded_spool_eligible,
    ) else {
        return Ok(inbound_message_error(root, "wait", "service-unavailable"));
    };
    let mut privacy_candidates = if spool_only_privacy {
        Vec::new()
    } else {
        state.session_entries_for(to)
    };
    if bare_target {
        privacy_candidates.retain(|(_, session)| {
            session.available.load(Ordering::Relaxed)
                && session.priority.load(Ordering::Relaxed) >= 0
        });
    }
    let unfiltered_privacy_candidates = privacy_candidates.len();
    let mut privacy_allowed = false;
    for (_, target) in &privacy_candidates {
        if state
            .privacy_allows_session(target, from, db::PrivacyStanzaKind::Message)
            .await?
        {
            privacy_allowed = true;
            break;
        }
    }
    if unfiltered_privacy_candidates > 0 && !privacy_allowed {
        return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
    }
    let remote_route_exists =
        !spool_only_privacy && state.s2s_remote_recipient_route_exists(to).await;
    // Even with a healthy resource route, a statically spoolable message
    // might enter SpoolOnly during its PostgreSQL transaction. Bind that
    // transition to the account-default privacy decision before admission.
    let no_live_route = unfiltered_privacy_candidates == 0 && !remote_route_exists;
    let default_privacy_denied = if degraded_spool_eligible || no_live_route {
        match state
            .message_service()
            .default_recipient_privacy_denies(recipient.id, from)
            .await
        {
            Ok(denied) => denied,
            Err(error) if !no_live_route => {
                tracing::warn!(?error, recipient_id = %recipient.id,
                    "account-default privacy unavailable; S2S message remains live-only");
                true
            }
            Err(error) => return Err(error),
        }
    } else {
        false
    };
    if no_live_route && default_privacy_denied {
        return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
    }
    // Deterministic full-resource failure is still a truthful stanza error
    // before admission. After the durable transaction commits, the same
    // condition can only be a routing race and must be recovered from the
    // resource-affine outbox without returning an error.
    if !bare_target && unfiltered_privacy_candidates == 0 && !remote_route_exists {
        match crate::xmpp::protocol::messaging::full_no_match_route(message_type) {
            crate::xmpp::protocol::messaging::FullNoMatchRoute::Ignore => return Ok(None),
            crate::xmpp::protocol::messaging::FullNoMatchRoute::Reject => {
                return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
            }
            crate::xmpp::protocol::messaging::FullNoMatchRoute::FallbackChat => {}
        }
    }
    let stable_id = uuid::Uuid::new_v4();
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
            crate::xmpp::protocol::retractions::encrypted_retraction_archive(
                &annotated,
                &command.target_id,
            )
        } else {
            encrypted_archive_stanza(&annotated)
        }
    } else {
        annotated.clone()
    };
    // MAM policy lookup is read-only and must finish before any delivery
    // queue or offline transaction accepts the stanza. Once accepted, later
    // archive/retraction failures are log-only to prevent duplicate retries.
    let archive_allowed = state
        .message_service()
        .archive_enabled(
            recipient.id,
            &canonical_from,
            mam_storage_eligible(root),
            encrypted,
            personal_retraction,
        )
        .await?;
    let mut history_committed = false;
    let mut durable_c2s_delivery = None;
    let mut live_claim_id = None;
    let direct_delivery_mode = crate::xmpp::protocol::messaging::direct_delivery_mode(root);
    if !personal_retraction
        && matches!(message_type, "normal" | "chat")
        && crate::xmpp::protocol::messaging::durable_direct_delivery_allowed(
            direct_delivery_mode,
            durable_content_allowed,
        )
    {
        if !persistence_allowed {
            // DirectDeliveryMode::Durable is defined by this condition. Keep
            // this assertion close to the admission boundary so future policy
            // changes cannot accidentally create a non-recoverable write.
            anyhow::bail!("durable inbound message lost its persistence projection");
        }
        let writes = archive_allowed
            .then_some(ArchiveWrite {
                id: stable_id,
                owner_id: recipient.id,
                peer_jid: &canonical_from,
                stanza: &archive,
                encrypted,
                stanza_id: root.attribute("id"),
            })
            .into_iter()
            .collect::<Vec<_>>();
        let identity_parts = authoritative_remote_stanza_identity(root, authenticated_domain);
        let identity =
            identity_parts
                .as_ref()
                .map(
                    |(actor_scope_raw, actor_scope, identity_value)| MessageIdentity {
                        authority: IdentityAuthority::AuthenticatedRemoteStanza,
                        actor_scope_raw,
                        actor_scope,
                        target_scope: &recipient_bare,
                        value: identity_value,
                        payload: &authoritative_raw,
                    },
                );
        let delayed = add_delay_from(&annotated, chrono::Utc::now(), Some(state.local_domain()));
        let delivery = ValidatedPersonalMessage {
            local_actor_id: None,
            identity,
            archives: &writes,
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: stable_id,
                recipient_id: recipient.id,
                recipient_bare_jid: &recipient_bare,
                sender_jid: &canonical_from,
                stanza: &delayed,
                encrypted,
                mam_backed: archive_allowed,
            }),
        };
        let eligibility =
            inbound_direct_spool_eligibility(degraded_spool_eligible, default_privacy_denied);
        match state
            .message_service()
            .admit_personal_message_with_mode(&delivery, eligibility)
            .await
            .map(|admitted| (admitted.commit, admitted.mode, admitted.live_claim_id))
        {
            Ok((
                DurableAdmissionOutcome::Stored { post_commit, .. },
                post_commit_mode,
                admitted_claim_id,
            )) => {
                history_committed = archive_allowed;
                let MessagePostCommit::RouteLocalDelivery { delivery_id, .. } = post_commit else {
                    state.s2s_inbound_delivery_telemetry().post_accept_failed();
                    tracing::warn!(%stable_id, "committed S2S ingress returned a non-local delivery plan");
                    return Ok(None);
                };
                durable_c2s_delivery = Some(delivery_id);
                live_claim_id = admitted_claim_id;
                // A committed spool row has no safe live owner during Redis
                // degradation. A second read covers a mode change after the
                // PostgreSQL commit; neither case may trigger local/cluster
                // routing, Carbons, Push, or an offline fallback.
                if post_commit_mode != DirectPostCommitMode::Live
                    || state.message_service().direct_mode() != DirectPostCommitMode::Live
                {
                    state
                        .message_service()
                        .rearm_unrouted_live_direct(recipient.id, delivery_id, &mut live_claim_id)
                        .await;
                    tracing::debug!(%stable_id, recipient_id = %recipient.id,
                        "S2S direct committed to PostgreSQL spool for recovery");
                    return Ok(None);
                }
            }
            Ok((DurableAdmissionOutcome::Replay, _, _)) => return Ok(None),
            Ok((DurableAdmissionOutcome::AccountUnavailable, _, _)) => return Ok(None),
            Err(error) => {
                tracing::warn!(?error, %authenticated_domain, "inbound message history/C2S admission failed atomically");
                return Ok(inbound_message_error(root, "wait", "resource-constraint"));
            }
        }
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
        match state
            .privacy_allows_session(&target.1, from, db::PrivacyStanzaKind::Message)
            .await
        {
            Ok(true) => allowed_targets.push(target),
            Ok(false) => {}
            Err(error) if durable_c2s_delivery.is_some() => {
                state.s2s_inbound_delivery_telemetry().post_accept_failed();
                tracing::warn!(?error, recipient_id = %recipient.id,
                    "privacy policy failed closed after durable S2S admission");
            }
            Err(error) => return Err(error),
        }
    }
    let targets = allowed_targets;
    if let Some(command) = personal_retraction_command.as_ref() {
        if state.message_service().direct_mode() != DirectPostCommitMode::Live {
            return Ok(inbound_message_error(root, "wait", "service-unavailable"));
        }
        // A full-JID route that is deterministically invalid must be rejected
        // before creating a durable projection. Chat fallback remains valid;
        // a bare target may recover through the offline outbox.
        if !bare_target && targets.is_empty() && !remote_route_exists {
            match crate::xmpp::protocol::messaging::full_no_match_route(message_type) {
                crate::xmpp::protocol::messaging::FullNoMatchRoute::Ignore => return Ok(None),
                crate::xmpp::protocol::messaging::FullNoMatchRoute::Reject => {
                    return Ok(inbound_message_error(root, "cancel", "service-unavailable"));
                }
                crate::xmpp::protocol::messaging::FullNoMatchRoute::FallbackChat => {}
            }
        }
        let writes = archive_allowed
            .then_some(ArchiveWrite {
                id: stable_id,
                owner_id: recipient.id,
                peer_jid: &canonical_from,
                stanza: &archive,
                encrypted,
                stanza_id: root.attribute("id"),
            })
            .into_iter()
            .collect::<Vec<_>>();
        let delayed = add_delay_from(&annotated, chrono::Utc::now(), Some(state.local_domain()));
        let limits = state.offline_delivery_limits();
        let delivery = DeliveryProjection {
            id: stable_id,
            recipient_id: recipient.id,
            local_actor_id: None,
            sender_jid: &canonical_from,
            stanza: &delayed,
            encrypted,
            max_messages: limits.max_messages,
            max_bytes: limits.max_bytes,
            ttl_days: limits.ttl_days,
            mam_backed: archive_allowed,
        };
        match state
            .retraction_service()
            .apply_with_delivery(
                &[OwnerProjection {
                    owner_id: recipient.id,
                    peer_jid: &canonical_from,
                }],
                &canonical_from,
                &RetractionCommand {
                    target_id: &command.target_id,
                    action_id: &command.action_id,
                    semantic_payload: &command.semantic_payload,
                },
                &writes,
                Some(&delivery),
                None,
            )
            .await
        {
            Ok(RetractionOutcome::Applied {
                live_claim_id: admitted_claim_id,
                ..
            }) => {
                history_committed = true;
                durable_c2s_delivery = Some(stable_id);
                live_claim_id = admitted_claim_id;
            }
            Ok(RetractionOutcome::Replay) => return Ok(None),
            Ok(RetractionOutcome::Conflict) => {
                return Ok(inbound_message_error(root, "cancel", "conflict"));
            }
            Ok(RetractionOutcome::Forbidden) => {
                return Ok(inbound_message_error(root, "auth", "forbidden"));
            }
            Ok(RetractionOutcome::AccountUnavailable) => return Ok(None),
            Ok(RetractionOutcome::CapacityExceeded) => {
                return Ok(inbound_message_error(root, "wait", "resource-constraint"));
            }
            Err(error) => {
                tracing::warn!(?error, %authenticated_domain, "inbound retraction admission failed atomically before delivery");
                return Ok(inbound_message_error(root, "wait", "resource-constraint"));
            }
        }
    }
    let delivery = durable_c2s_delivery.map_or(DirectRouteDelivery::Volatile, |message_id| {
        DirectRouteDelivery::Committed(crate::xmpp::outbound::DurableDelivery {
            recipient_id: recipient.id,
            message_id,
            claim_id: live_claim_id,
        })
    });
    let outcome = DirectMessageRouter::route_federated(
        &S2sDirectRoutePort(state),
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

    if !delivered && message_type == "headline" {
        return Ok(None);
    }

    if delivered {
        if !history_committed {
            finalize_accepted_inbound_history(
                state,
                root,
                AcceptedInboundHistory {
                    telemetry: state.s2s_accepted_history_telemetry(),
                    recipient_id: recipient.id,
                    canonical_from: &canonical_from,
                    stable_id,
                    archive_allowed,
                    archive: &archive,
                    encrypted,
                    route: "s2s-online",
                },
            )
            .await;
        }
        let remote_muc_private_message =
            is_remote_muc_private_message(root, from, authenticated_domain);
        if state.message_service().direct_mode() == DirectPostCommitMode::Live
            && should_carbon(root)
            && !remote_muc_private_message
        {
            if let Some(delivered_key) = delivered_key.as_deref() {
                crate::services::message_carbons::send_received_carbons(
                    state,
                    &recipient_by,
                    Some(delivered_key),
                    &annotated,
                )
                .await;
            }
        }
        state.s2s_inbound_delivery_telemetry().routed();
        return Ok(None);
    }
    if durable_c2s_delivery.is_some() {
        if state.message_service().direct_mode() == DirectPostCommitMode::Live {
            if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                state.s2s_inbound_delivery_telemetry().post_accept_failed();
                tracing::warn!(?error, %stable_id, recipient_id = %recipient.id, "durable inbound C2S message was accepted but push notification failed");
            }
        }
        return Ok(None);
    }
    if direct_delivery_mode
        == crate::xmpp::protocol::messaging::DirectDeliveryMode::VolatileExplicitNoStore
    {
        return Ok(inbound_message_error(root, "wait", "service-unavailable"));
    }
    if !persistence_allowed {
        return Ok(None);
    }
    if persistence_allowed
        && matches!(
            root.attribute("type").unwrap_or("normal"),
            "normal" | "chat"
        )
        && durable_content_allowed
    {
        match inbound_live_effect(state.message_service().direct_mode(), history_committed) {
            InboundLiveEffect::Proceed => {}
            InboundLiveEffect::AcceptedSpool => return Ok(None),
            InboundLiveEffect::Reject => {
                return Ok(inbound_message_error(root, "wait", "service-unavailable"));
            }
        }
        let delayed = add_delay_from(&archive, chrono::Utc::now(), Some(state.local_domain()));
        let offline_outcome = state
            .message_service()
            .store_offline(OfflineMessageAdmission {
                recipient_id: recipient.id,
                recipient_bare_jid: &recipient_by,
                sender_jid: from,
                stanza: &delayed,
                encrypted,
                mam_backed: archive_allowed,
                identity: None,
            })
            .await?;
        if offline_outcome == OfflineAdmissionOutcome::RecipientUnavailable {
            return Ok(None);
        }
        if offline_outcome == OfflineAdmissionOutcome::QuotaExceeded {
            if history_committed {
                if state.message_service().direct_mode() == DirectPostCommitMode::Live {
                    if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                        state.s2s_inbound_delivery_telemetry().post_accept_failed();
                        tracing::warn!(?error, %stable_id, recipient_id = %recipient.id, "MAM-backed inbound message was accepted but offline quota and push delivery both failed");
                    }
                }
                return Ok(None);
            }
            return Ok(inbound_message_error(root, "wait", "resource-constraint"));
        }
        if !history_committed {
            finalize_accepted_inbound_history(
                state,
                root,
                AcceptedInboundHistory {
                    telemetry: state.s2s_accepted_history_telemetry(),
                    recipient_id: recipient.id,
                    canonical_from: &canonical_from,
                    stable_id,
                    archive_allowed,
                    archive: &archive,
                    encrypted,
                    route: "s2s-offline",
                },
            )
            .await;
        }
        if state.message_service().direct_mode() == DirectPostCommitMode::Live {
            if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                state.s2s_inbound_delivery_telemetry().post_accept_failed();
                tracing::warn!(?error, %stable_id, recipient_id = %recipient.id, "inbound offline message was accepted but push notification failed");
            }
        }
        return Ok(None);
    }
    Ok(inbound_message_error(root, "wait", "recipient-unavailable"))
}

/// Complete ordinary best-effort history after a legacy online/offline route.
/// Personal retractions are deliberately excluded: their authorization,
/// tombstones, action MAM, and delivery outbox commit before fanout.
struct AcceptedInboundHistory<'a> {
    telemetry: super::telemetry::AcceptedHistoryTelemetry<'a>,
    recipient_id: uuid::Uuid,
    canonical_from: &'a str,
    stable_id: uuid::Uuid,
    archive_allowed: bool,
    archive: &'a str,
    encrypted: bool,
    route: &'static str,
}

async fn finalize_accepted_inbound_history(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    history: AcceptedInboundHistory<'_>,
) {
    let AcceptedInboundHistory {
        telemetry,
        recipient_id,
        canonical_from,
        stable_id,
        archive_allowed,
        archive,
        encrypted,
        route,
    } = history;
    let writes = archive_allowed
        .then_some(ArchiveWrite {
            id: stable_id,
            owner_id: recipient_id,
            peer_jid: canonical_from,
            stanza: archive,
            encrypted,
            stanza_id: root.attribute("id"),
        })
        .into_iter()
        .collect::<Vec<_>>();
    debug_assert!(
        crate::xmpp::protocol::retractions::personal_retraction_command(root)
            .ok()
            .flatten()
            .is_none(),
        "personal retraction reached post-delivery history finalization"
    );
    let history_result = state.message_service().admit_history(&writes).await;
    if let Err(error) = history_result {
        telemetry.failed();
        tracing::warn!(?error, %stable_id, %route, %recipient_id, "accepted inbound message history transaction failed");
    }
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

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(test)]
const MODULE_SOURCE: &[(&str, &str)] = &[
    ("inbound", include_str!("inbound.rs")),
    ("negotiation", include_str!("inbound/negotiation.rs")),
    ("session", include_str!("inbound/session.rs")),
    ("dispatch", include_str!("inbound/dispatch.rs")),
    ("presence", include_str!("inbound/presence.rs")),
    ("iq", include_str!("inbound/iq.rs")),
    ("direct_route", include_str!("inbound/direct_route.rs")),
];

#[cfg(test)]
fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[path = "inbound_tests.rs"]
mod tests;

#[cfg(test)]
mod module_source_tests;
