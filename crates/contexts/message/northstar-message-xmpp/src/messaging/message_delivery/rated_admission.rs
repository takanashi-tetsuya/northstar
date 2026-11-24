use super::*;
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the original proof inputs and admission lease"
)]
pub(super) async fn begin<S: MessageSession>(
    session: &S,
    state: &S::Host,
    root: Node<'_, '_>,
    user_id: Uuid,
    from: &str,
    to: &str,
    original_direct: &OriginalDirectMessage<'_>,
    pow_intent_payload: &str,
    actors: &[String],
    proof: &Option<PowProof>,
    message_admission_lease: &mut Option<MessageAdmissionLease>,
) -> Result<Option<S::Action>> {
    if let Some(normalized_admission_payload) = original_direct.rated_payload() {
        let subject = format!("message:{}", user_id);
        session.enter_frame_stage(MessageFrameStage::Admission);
        let request = MessageAdmissionRequest {
            actor_id: user_id,
            account_bare: bare_jid(from),
            normalized_target: to,
            origin_id: original_direct.origin_id.as_deref(),
            normalized_payload: normalized_admission_payload,
            pow_intent_payload,
            subject: &subject,
            actors,
            proof: proof.as_ref(),
        };
        let service = state.message_admission_service();
        let admission = if let Some(operation) = session.message_operation() {
            match operation.begin(&request) {
                Ok(retained) => {
                    service
                        .begin_message_admission_retained(&request, &retained)
                        .await
                }
                Err(error) => Err(error),
            }
        } else {
            // Direct handle() callers retain the established convenience
            // path. Production process_frame() always supplies an owner.
            service.begin_message_admission(&request).await
        };
        match admission {
            Ok(MessageAdmissionStart::Proceed { lease, requirement }) => {
                debug_assert_eq!(requirement.action, "message");
                *message_admission_lease = lease;
            }
            Ok(MessageAdmissionStart::ReplayAccepted) => return Ok(Some(S::Action::none())),
            Ok(MessageAdmissionStart::InProgress { requirement }) => {
                state.personal_message_telemetry().rate_limited();
                return Ok(Some(S::Action::send(abuse_stanza_error(
                    root,
                    &requirement,
                ))));
            }
            Ok(MessageAdmissionStart::Denied(error)) => {
                state.personal_message_telemetry().rate_limited();
                return Ok(Some(S::Action::send(abuse_stanza_error(
                    root,
                    error.requirement(),
                ))));
            }
            Ok(MessageAdmissionStart::Conflict) => {
                return Ok(Some(message_error(root, "cancel", "conflict")));
            }
            Ok(MessageAdmissionStart::CapacityLimited) => {
                state.personal_message_telemetry().rate_limited();
                return Ok(Some(message_error(root, "wait", "resource-constraint")));
            }
            Err(error) => {
                // Fail closed before routing/archive. A backend failure may
                // leave this admission or a separate guard transaction
                // unconfirmed; it does not prove rollback or permit retry.
                if northstar_abuse_policy::message_admission::is_abuse_state_busy(&error) {
                    tracing::warn!(user_id = %user_id, "message anti-abuse actor state was busy; rejected without waiting on a database connection lock");
                    state.personal_message_telemetry().rate_limited();
                    return Ok(Some(message_error(root, "wait", "resource-constraint")));
                }
                tracing::error!(?error, user_id = %user_id, "message anti-abuse backend failed before acceptance");
                state.personal_message_telemetry().abuse_backend_failed();
                return Ok(Some(message_error(root, "wait", "resource-constraint")));
            }
        }
    }
    Ok(None)
}
