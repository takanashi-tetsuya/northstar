use super::*;
use northstar_message_application::messaging::LocalRecipient;
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the original offline follow-up inputs"
)]
pub(super) async fn finish<S: MessageSession>(
    session: &S,
    state: &S::Host,
    root: Node<'_, '_>,
    delivered: bool,
    direct_delivery_mode: DirectDeliveryMode,
    live_delivery_id: Option<Uuid>,
    stored_offline: &mut bool,
    local_direct: bool,
    recipient: &LocalRecipient,
    recipient_stable_id: Uuid,
    message_type: &str,
    persistence_allowed: bool,
    durable_content_allowed: bool,
    message_admission_lease: &mut Option<MessageAdmissionLease>,
    recipient_archive_stanza: &str,
    recipient_by: &str,
    from: &str,
    encrypted: bool,
    actor_fence: Option<ActorGenerationFence>,
    policy: DirectMessagePolicy<'_>,
    history_committed: bool,
) -> Result<Option<S::Action>> {
    if !delivered {
        if direct_delivery_mode == DirectDeliveryMode::VolatileExplicitNoStore {
            // XEP-0334 no-store forbids every durable fallback, but it
            // does not forbid an online volatile delivery. Only report a
            // failure after local and cluster routes have actually
            // declined the stanza.
            return Ok(Some(message_error(root, "wait", "service-unavailable")));
        }
        if live_delivery_id.is_some() {
            *stored_offline = true;
            if local_direct && state.message_service().direct_mode() != DirectPostCommitMode::Live {
                return Ok(Some(S::Action::none()));
            }
            // This check precedes the Push call; a provider request
            // already in flight cannot be recalled by a later transition.
            if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                state.personal_message_telemetry().post_accept_failed();
                tracing::warn!(?error, recipient_id = %recipient.id, %recipient_stable_id, "durable direct MUC invite was accepted but push notification failed");
            }
        } else {
            match undelivered_disposition(
                message_type,
                persistence_allowed,
                durable_content_allowed,
            ) {
                UndeliveredDisposition::Drop => {
                    finalize_admission(session, message_admission_lease, "undelivered-drop").await;
                    return Ok(Some(S::Action::none()));
                }
                UndeliveredDisposition::RejectCancel => {
                    return Ok(Some(message_error(root, "cancel", "service-unavailable")));
                }
                UndeliveredDisposition::RejectWait => {
                    return Ok(Some(message_error(root, "wait", "service-unavailable")));
                }
                UndeliveredDisposition::StoreOffline => {
                    let delayed = add_delay_from(
                        recipient_archive_stanza,
                        state.message_events().now(),
                        Some(state.local_domain()),
                    );
                    let offline = admit_offline_then_push(
                        state.message_service().store_offline(
                            northstar_message_application::messaging::OfflineMessageAdmission {
                                recipient_id: recipient.id,
                                recipient_bare_jid: recipient_by,
                                sender_jid: from,
                                stanza: &delayed,
                                encrypted,
                                // No durable history admission preceded this fallback.
                                mam_backed: false,
                                identity: message_admission_lease
                                    .as_ref()
                                    .map(|lease| &lease.offline_dedupe),
                                actor_fence,
                                policy,
                            },
                        ),
                        history_committed,
                        async {
                            if local_direct
                                && state.message_service().direct_mode()
                                    != DirectPostCommitMode::Live
                            {
                                Ok(())
                            } else {
                                state.dispatch_push_notification(recipient.id).await
                            }
                        },
                    )
                    .await;
                    let offline = match offline {
                        Ok(offline) => offline,
                        Err(error) => {
                            if let Some(denial) =
                                error.downcast_ref::<northstar_message_core::DirectPolicyDenial>()
                            {
                                return Ok(Some(durable_commit::policy_error(root, *denial)));
                            }
                            return Err(error);
                        }
                    };
                    match offline.admission {
                        OfflineAdmissionOutcome::QuotaExceeded if history_committed => {
                            // A pre-admitted recipient MAM row is durable
                            // recovery. Returning an error here would invite a
                            // duplicate retry after the server already
                            // accepted the origin-id.
                            if let Some(error) = offline.push_error {
                                state.personal_message_telemetry().post_accept_failed();
                                tracing::warn!(?error, recipient_id = %recipient.id, %recipient_stable_id, "MAM-backed message was accepted but offline quota and push delivery both failed");
                            }
                            *stored_offline = true;
                        }
                        OfflineAdmissionOutcome::QuotaExceeded => {
                            return Ok(Some(message_error(root, "wait", "service-unavailable")));
                        }
                        OfflineAdmissionOutcome::Stored => {
                            *stored_offline = true;
                            if let Some(error) = offline.push_error {
                                state.personal_message_telemetry().post_accept_failed();
                                tracing::warn!(?error, recipient_id = %recipient.id, %recipient_stable_id, "offline message was accepted but push notification failed");
                            }
                        }
                        OfflineAdmissionOutcome::Replay => {
                            // The content row may already have been delivered
                            // and deleted. The compact tombstone is the
                            // terminal acceptance record; do not enqueue or
                            // notify a second time.
                            *stored_offline = true;
                        }
                        OfflineAdmissionOutcome::RecipientUnavailable => {
                            return Ok(Some(message_error(root, "cancel", "service-unavailable")));
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}
