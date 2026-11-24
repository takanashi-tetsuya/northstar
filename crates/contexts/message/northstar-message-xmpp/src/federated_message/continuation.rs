use super::{
    degraded::{inbound_live_effect, InboundLiveEffect},
    inbound_message_error, is_remote_muc_private_message,
};
use crate::ports::FederatedMessageHost;
use anyhow::Result;
use northstar_message_application::messaging::{
    ArchiveCandidate, LocalRecipient, OfflineAdmissionOutcome, OfflineMessageAdmission,
};
use northstar_message_core::{DirectDeliveryMode, DirectPostCommitMode};
use northstar_xep_0280::should_copy as should_carbon;
use northstar_xml_builder::message_policy::add_delay_from;
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the original route outcome and follow-up inputs"
)]
pub(super) async fn finish<H: FederatedMessageHost>(
    state: &H,
    root: roxmltree::Node<'_, '_>,
    delivered: bool,
    delivered_key: &Option<String>,
    message_type: &str,
    durable_c2s_delivery: Option<Uuid>,
    candidate: &Option<ArchiveCandidate<'_>>,
    from: &str,
    authenticated_domain: &str,
    recipient_by: &str,
    annotated: &str,
    recipient: &LocalRecipient,
    stable_id: Uuid,
    direct_delivery_mode: DirectDeliveryMode,
    persistence_allowed: bool,
    durable_content_allowed: bool,
    history_committed: bool,
    archive: &str,
    encrypted: bool,
) -> Result<Option<String>> {
    if !delivered && message_type == "headline" {
        return Ok(None);
    }

    if delivered {
        if durable_c2s_delivery.is_none() {
            finalize_accepted_inbound_history(state, root, candidate.as_ref(), "s2s-online").await;
        }
        let remote_muc_private_message =
            is_remote_muc_private_message(root, from, authenticated_domain);
        if state.message_service().direct_mode() == DirectPostCommitMode::Live
            && should_carbon(root)
            && !remote_muc_private_message
        {
            if let Some(delivered_key) = delivered_key.as_deref() {
                northstar_message_application::message_carbons::send_received_carbons(
                    state,
                    recipient_by,
                    Some(delivered_key),
                    annotated,
                )
                .await;
            }
        }
        state.record_s2s_message_routed();
        return Ok(None);
    }
    if durable_c2s_delivery.is_some() {
        if state.message_service().direct_mode() == DirectPostCommitMode::Live {
            if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                state.record_s2s_post_accept_failure();
                tracing::warn!(?error, %stable_id, recipient_id = %recipient.id, "durable inbound C2S message was accepted but push notification failed");
            }
        }
        return Ok(None);
    }
    if direct_delivery_mode == northstar_message_core::DirectDeliveryMode::VolatileExplicitNoStore {
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
        let delayed = add_delay_from(
            archive,
            state.message_events().now(),
            Some(state.local_domain()),
        );
        let offline_outcome = state
            .message_service()
            .store_offline(OfflineMessageAdmission {
                recipient_id: recipient.id,
                recipient_bare_jid: recipient_by,
                sender_jid: from,
                stanza: &delayed,
                encrypted,
                // No durable history admission preceded this fallback.
                mam_backed: false,
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
                        state.record_s2s_post_accept_failure();
                        tracing::warn!(?error, %stable_id, recipient_id = %recipient.id, "MAM-backed inbound message was accepted but offline quota and push delivery both failed");
                    }
                }
                return Ok(None);
            }
            return Ok(inbound_message_error(root, "wait", "resource-constraint"));
        }
        finalize_accepted_inbound_history(state, root, candidate.as_ref(), "s2s-offline").await;
        if state.message_service().direct_mode() == DirectPostCommitMode::Live {
            if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                state.record_s2s_post_accept_failure();
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
async fn finalize_accepted_inbound_history<H: FederatedMessageHost>(
    state: &H,
    root: roxmltree::Node<'_, '_>,
    candidate: Option<&ArchiveCandidate<'_>>,
    route: &'static str,
) {
    debug_assert!(
        northstar_message_core::retraction::personal_retraction_command(root)
            .ok()
            .flatten()
            .is_none(),
        "personal retraction reached post-delivery history finalization"
    );
    let Some(candidate) = candidate else {
        return;
    };
    let stable_id = candidate.projection.id;
    let recipient_id = candidate.projection.owner_id;
    let history_result = state
        .message_service()
        .admit_history(std::slice::from_ref(candidate))
        .await;
    if let Err(error) = history_result {
        state.record_s2s_post_accept_failure();
        tracing::warn!(?error, %stable_id, %route, %recipient_id, "accepted inbound message history transaction failed");
    }
}
