use super::inbound_message_error;
use crate::ports::FederatedMessageHost;
use anyhow::Result;
use northstar_message_application::messaging::LocalRecipient;
use northstar_message_application::retractions::{
    ArchiveWrite, DeliveryProjection, OwnerProjection, RetractionCommand, RetractionOutcome,
};
use northstar_message_core::{retraction::PersonalRetractionCommand, DirectPostCommitMode};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_xml_builder::message_policy::add_delay_from;
use std::ops::ControlFlow::{self, Break, Continue};
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the exact retraction inputs and outer admission state"
)]
pub(super) async fn apply<H: FederatedMessageHost>(
    state: &H,
    root: roxmltree::Node<'_, '_>,
    personal_retraction_command: Option<&PersonalRetractionCommand>,
    bare_target: bool,
    targets: &[(String, OnlineSession)],
    remote_route_exists: bool,
    message_type: &str,
    annotated: &str,
    stable_id: Uuid,
    recipient: &LocalRecipient,
    canonical_from: &str,
    encrypted: bool,
    archive_write: &ArchiveWrite<'_>,
    authenticated_domain: &str,
    history_committed: &mut bool,
    durable_c2s_delivery: &mut Option<Uuid>,
    live_claim_id: &mut Option<Uuid>,
) -> Result<ControlFlow<Option<String>>> {
    if let Some(command) = personal_retraction_command {
        if state.message_service().direct_mode() != DirectPostCommitMode::Live {
            return Ok(Break(inbound_message_error(
                root,
                "wait",
                "service-unavailable",
            )));
        }
        // A full-JID route that is deterministically invalid must be rejected
        // before creating a durable projection. Chat fallback remains valid;
        // a bare target may recover through the offline outbox.
        if !bare_target && targets.is_empty() && !remote_route_exists {
            match northstar_message_core::full_no_match_route(message_type) {
                northstar_message_core::FullNoMatchRoute::Ignore => return Ok(Break(None)),
                northstar_message_core::FullNoMatchRoute::Reject => {
                    return Ok(Break(inbound_message_error(
                        root,
                        "cancel",
                        "service-unavailable",
                    )));
                }
                northstar_message_core::FullNoMatchRoute::FallbackChat => {}
            }
        }
        let delayed = add_delay_from(
            annotated,
            state.message_events().now(),
            Some(state.local_domain()),
        );
        let limits = state.offline_delivery_limits();
        let delivery = DeliveryProjection {
            id: stable_id,
            recipient_id: recipient.id,
            local_actor_id: None,
            sender_jid: canonical_from,
            stanza: &delayed,
            encrypted,
            max_messages: limits.max_messages,
            max_bytes: limits.max_bytes,
            ttl_days: limits.ttl_days,
            mam_backed: true,
        };
        match state
            .retraction_service()
            .apply_with_delivery(
                &[OwnerProjection {
                    owner_id: recipient.id,
                    peer_jid: canonical_from,
                }],
                canonical_from,
                &RetractionCommand {
                    actor_fence: None,
                    target_id: &command.target_id,
                    action_id: &command.action_id,
                    semantic_payload: &command.semantic_payload,
                },
                std::slice::from_ref(archive_write),
                Some(&delivery),
                None,
            )
            .await
        {
            Ok(RetractionOutcome::Applied {
                live_claim_id: admitted_claim_id,
                ..
            }) => {
                *history_committed = true;
                *durable_c2s_delivery = Some(stable_id);
                *live_claim_id = admitted_claim_id;
            }
            Ok(RetractionOutcome::Replay) => return Ok(Break(None)),
            Ok(RetractionOutcome::Conflict) => {
                return Ok(Break(inbound_message_error(root, "cancel", "conflict")));
            }
            Ok(RetractionOutcome::Forbidden) => {
                return Ok(Break(inbound_message_error(root, "auth", "forbidden")));
            }
            Ok(RetractionOutcome::AccountUnavailable) => return Ok(Break(None)),
            Ok(RetractionOutcome::CapacityExceeded) => {
                return Ok(Break(inbound_message_error(
                    root,
                    "wait",
                    "resource-constraint",
                )));
            }
            Err(error) => {
                tracing::warn!(?error, %authenticated_domain, "inbound retraction admission failed atomically before delivery");
                return Ok(Break(inbound_message_error(
                    root,
                    "wait",
                    "resource-constraint",
                )));
            }
        }
    }
    Ok(Continue(()))
}
