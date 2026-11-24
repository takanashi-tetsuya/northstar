use super::*;
use northstar_message_application::messaging::{
    direct_workflow::PreparedLiveDirect, LocalRecipient,
};
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the exact prepared inputs and outer admission state"
)]
pub(super) async fn commit<'live, S: MessageSession>(
    session: &S,
    state: &S::Host,
    root: Node<'_, '_>,
    direct_delivery_candidate: bool,
    direct_delivery_mode: DirectDeliveryMode,
    durable_content_allowed: bool,
    origin_id: Option<&str>,
    from: &str,
    to: &str,
    rewritten: &str,
    local_projection: &'live LocalOriginalProjection<'_, '_>,
    archive_eligibility: LocalArchiveEligibility,
    user_id: Uuid,
    local_actor_fence: Option<ActorGenerationFence>,
    candidates: &[ArchiveCandidate<'_>],
    recipient_stable_id: Uuid,
    recipient: &LocalRecipient,
    recipient_by: &str,
    encrypted: bool,
    degraded_spool_eligible: bool,
    spool_privacy_permits: bool,
    message_admission_lease: &mut Option<MessageAdmissionLease>,
    history_committed: &mut bool,
    durable_c2s_delivery: &mut Option<Uuid>,
    live_claim_id: &mut Option<Uuid>,
    prepared_live: &mut Option<PreparedLiveDirect<'live>>,
) -> Result<Option<S::Action>> {
    if direct_delivery_candidate
        && durable_direct_delivery_allowed(direct_delivery_mode, durable_content_allowed)
    {
        let identity = origin_id.map(|identity_value| {
            let actor_scope = bare_jid(from);
            let target_scope = bare_jid(to);
            MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: actor_scope,
                actor_scope,
                target_scope,
                value: identity_value,
                payload: rewritten,
            }
        });
        let delayed_projection =
            local_projection.delayed(state.message_events().now(), archive_eligibility);
        let admission = ValidatedPersonalMessage {
            local_actor_id: Some(user_id),
            local_actor_fence,
            identity,
            archives: candidates,
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: recipient_stable_id,
                recipient_id: recipient.id,
                recipient_bare_jid: recipient_by,
                sender_jid: from,
                stanza: &delayed_projection.stanza,
                encrypted,
            }),
        };
        let eligibility = direct_spool_eligibility(degraded_spool_eligible, spool_privacy_permits);
        session.enter_frame_stage(MessageFrameStage::Admission);
        let service = state.message_service();
        if let Some(operation) = session.message_operation() {
            let prepared = match delayed_projection.bind(operation, admission, eligibility) {
                Ok(prepared) => prepared,
                Err(error) => {
                    tracing::warn!(?error, recipient_id = %recipient.id, "local history/C2S admission did not return a confirmed result");
                    return Ok(Some(message_error(root, "wait", "resource-constraint")));
                }
            };
            let applied = service
                .admit_prepared_personal_message_with_mode(prepared)
                .await;
            match continue_prepared_local_direct(
                applied,
                message_admission_lease,
                state.message_admission_service(),
                state,
                || session.enter_frame_stage(MessageFrameStage::Followup),
            )
            .await
            {
                ContinuedLocalDirect::Accepted => return Ok(Some(S::Action::none())),
                ContinuedLocalDirect::Reject(error) => {
                    let (kind, condition) = error.stanza_error();
                    return Ok(Some(message_error(root, kind, condition)));
                }
                ContinuedLocalDirect::Live(live) => {
                    *history_committed = live.archive_written();
                    let source = live.source();
                    *durable_c2s_delivery = Some(source.message_id);
                    *live_claim_id = source.claim_id;
                    *prepared_live = Some(live);
                }
            }
        } else {
            // Compatibility callers without a frame owner retain their
            // original application and post-commit behavior.
            let admitted = service
                .admit_personal_message_with_mode(&admission, eligibility)
                .await;
            match admitted.map(|result| (result.commit, result.mode, result.live_claim_id)) {
                Ok((
                    DurableAdmissionOutcome::Stored {
                        archive_written,
                        post_commit,
                    },
                    post_commit_mode,
                    admitted_claim_id,
                )) => {
                    *history_committed = archive_written;
                    let MessagePostCommit::RouteLocalDelivery { delivery_id, .. } = post_commit
                    else {
                        return Ok(Some(message_error(root, "wait", "internal-server-error")));
                    };
                    *durable_c2s_delivery = Some(delivery_id);
                    *live_claim_id = admitted_claim_id;
                    tracing::debug!(
                        recipient_id = %recipient.id,
                        message_id = %recipient_stable_id,
                        target = %to,
                        "committed durable C2S delivery before route attempt"
                    );
                    finalize_admission(
                        session,
                        message_admission_lease,
                        if post_commit_mode == DirectPostCommitMode::Live {
                            "local-durable-c2s"
                        } else {
                            "local-durable-c2s-spooled"
                        },
                    )
                    .await;
                    if post_commit_mode != DirectPostCommitMode::Live
                        || state.message_service().direct_mode() != DirectPostCommitMode::Live
                    {
                        service
                            .rearm_unrouted_live_direct(recipient.id, delivery_id, live_claim_id)
                            .await;
                        tracing::debug!(
                            recipient_id = %recipient.id,
                            message_id = %recipient_stable_id,
                            "C2S direct committed to PostgreSQL spool for recovery"
                        );
                        return Ok(Some(S::Action::none()));
                    }
                }
                Ok((DurableAdmissionOutcome::Replay, _, _)) => {
                    finalize_admission(
                        session,
                        message_admission_lease,
                        "local-durable-c2s-replay",
                    )
                    .await;
                    return Ok(Some(S::Action::none()));
                }
                Ok((DurableAdmissionOutcome::AccountUnavailable, _, _)) => {
                    return Ok(Some(message_error(root, "cancel", "service-unavailable")));
                }
                Err(error) => {
                    if let Some(confirmed) = preserved_transaction(&error) {
                        match confirmed {
                            TransactionOutcome::Stored {
                                recipient_id,
                                delivery_id,
                                live_claim_id,
                                ..
                            } => {
                                state.personal_message_telemetry().post_accept_failed();
                                finalize_admission(
                                    session,
                                    message_admission_lease,
                                    "local-durable-c2s-continuation-unknown",
                                )
                                .await;
                                let mut claim = *live_claim_id;
                                service
                                    .rearm_unrouted_live_direct(
                                        *recipient_id,
                                        *delivery_id,
                                        &mut claim,
                                    )
                                    .await;
                                return Ok(Some(S::Action::none()));
                            }
                            TransactionOutcome::Replay { .. } => {
                                finalize_admission(
                                    session,
                                    message_admission_lease,
                                    "local-durable-c2s-replay-continuation-unknown",
                                )
                                .await;
                                return Ok(Some(S::Action::none()));
                            }
                            TransactionOutcome::AccountUnavailable => {
                                return Ok(Some(message_error(
                                    root,
                                    "cancel",
                                    "service-unavailable",
                                )))
                            }
                        }
                    }
                    tracing::warn!(?error, recipient_id = %recipient.id, "local history/C2S admission did not return a confirmed result");
                    return Ok(Some(message_error(root, "wait", "resource-constraint")));
                }
            }
        }
    }
    Ok(None)
}
