use super::*;
use northstar_message_application::messaging::LocalRecipient;
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the exact retraction inputs and outer admission state"
)]
pub(super) async fn apply<S: MessageSession>(
    session: &S,
    state: &S::Host,
    root: Node<'_, '_>,
    personal_retraction: bool,
    message_type: &str,
    exact_full_target_can_route: bool,
    local_projection: &LocalOriginalProjection<'_, '_>,
    recipient_delivery: &str,
    recipient_stable_id: Uuid,
    recipient: &LocalRecipient,
    user_id: Uuid,
    from: &str,
    encrypted: bool,
    to: &str,
    history_committed: &mut bool,
    durable_c2s_delivery: &mut Option<Uuid>,
    live_claim_id: &mut Option<Uuid>,
    message_admission_lease: &mut Option<MessageAdmissionLease>,
) -> Result<Option<S::Action>> {
    if personal_retraction {
        // Retractions mutate durable history and therefore always use the
        // recoverable C2S projection. They must never share a stanza with
        // an invitation or enter a volatile message-type route.
        if !matches!(message_type, "normal" | "chat") {
            return Ok(Some(message_error(root, "modify", "bad-request")));
        }
        if !exact_full_target_can_route {
            return Ok(Some(message_error(root, "cancel", "service-unavailable")));
        }
        let writes = local_projection
            .archive_projections()
            .map(|(_, write)| write)
            .collect::<Vec<_>>();
        let delayed_delivery = add_delay_from(
            recipient_delivery,
            northstar_time::Utc::now(),
            Some(state.local_domain()),
        );
        let offline_limits = state.offline_delivery_limits();
        let delivery = DeliveryProjection {
            id: recipient_stable_id,
            recipient_id: recipient.id,
            local_actor_id: Some(user_id),
            sender_jid: from,
            stanza: &delayed_delivery,
            encrypted,
            max_messages: offline_limits.max_messages,
            max_bytes: offline_limits.max_bytes,
            ttl_days: offline_limits.ttl_days,
            mam_backed: writes.iter().any(|write| write.owner_id == recipient.id),
        };
        session.enter_frame_stage(MessageFrameStage::Admission);
        match apply_personal_retraction(
            state,
            user_id,
            from,
            Some(recipient.id),
            to,
            root,
            &writes,
            &delivery,
        )
        .await
        {
            Ok(RetractionOutcome::Applied {
                live_claim_id: admitted_claim_id,
                ..
            }) => {
                *history_committed = true;
                *durable_c2s_delivery = Some(recipient_stable_id);
                *live_claim_id = admitted_claim_id;
                finalize_admission(
                    session,
                    message_admission_lease,
                    "local-retraction-durable-c2s",
                )
                .await;
            }
            Ok(RetractionOutcome::Replay) => {
                finalize_admission(session, message_admission_lease, "local-retraction-replay")
                    .await;
                return Ok(Some(S::Action::none()));
            }
            Ok(RetractionOutcome::Conflict) => {
                return Ok(Some(message_error(root, "cancel", "conflict")));
            }
            Ok(RetractionOutcome::Forbidden) => {
                return Ok(Some(message_error(root, "auth", "forbidden")));
            }
            Ok(RetractionOutcome::AccountUnavailable) => {
                return Ok(Some(message_error(root, "cancel", "service-unavailable")));
            }
            Ok(RetractionOutcome::CapacityExceeded) => {
                return Ok(Some(message_error(root, "wait", "resource-constraint")));
            }
            Err(error) => {
                tracing::warn!(?error, recipient_id = %recipient.id, "local retraction admission failed atomically before delivery");
                return Ok(Some(message_error(root, "wait", "resource-constraint")));
            }
        }
    }
    Ok(None)
}
