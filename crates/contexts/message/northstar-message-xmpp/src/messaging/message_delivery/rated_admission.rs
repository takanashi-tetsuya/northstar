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
        return match admission {
            Ok(decision) => Ok(apply_decision(
                root,
                decision,
                message_admission_lease,
                || {
                    state.personal_message_telemetry().rate_limited();
                },
            )),
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
                Ok(Some(message_error(root, "wait", "resource-constraint")))
            }
        };
    }
    Ok(None)
}

fn apply_decision<A: MessageOutcome>(
    root: Node<'_, '_>,
    decision: MessageAdmissionStart,
    message_admission_lease: &mut Option<MessageAdmissionLease>,
    rate_limited: impl FnOnce(),
) -> Option<A> {
    let action = match decision {
        MessageAdmissionStart::Proceed { lease, requirement } => {
            debug_assert_eq!(requirement.action, "message");
            *message_admission_lease = lease;
            return None;
        }
        MessageAdmissionStart::ReplayAccepted => A::none(),
        MessageAdmissionStart::InProgress { requirement } => {
            rate_limited();
            message_refusal(root, || abuse_stanza_error(root, &requirement))
        }
        MessageAdmissionStart::Denied(error) => {
            rate_limited();
            message_refusal(root, || abuse_stanza_error(root, error.requirement()))
        }
        MessageAdmissionStart::Conflict => message_error(root, "cancel", "conflict"),
        MessageAdmissionStart::CapacityLimited => {
            rate_limited();
            message_error(root, "wait", "resource-constraint")
        }
    };
    Some(action)
}

#[cfg(test)]
mod tests;
