use super::*;
use northstar_xmpp_types::jid::CanonicalJid;
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "retain the outbound route inputs and admission lease"
)]
pub(super) async fn route<S: MessageSession>(
    session: &S,
    state: &S::Host,
    root: Node<'_, '_>,
    remote_domain: Option<&str>,
    routed_raw: &str,
    from: &str,
    personal_retraction: bool,
    grant_revision: Option<(Uuid, i64)>,
    message_admission_lease: &mut Option<MessageAdmissionLease>,
    personal_retraction_target: &Option<String>,
    user_id: Uuid,
    local_actor_fence: Option<ActorGenerationFence>,
    to: &str,
    invitation: &Option<DirectInvitation<'_>>,
    target_jid: &CanonicalJid,
) -> Result<Option<S::Action>> {
    if let Some(domain) = remote_domain {
        if !state.xmpp_external_route_domain_allowed(domain) {
            return Ok(Some(message_error(
                root,
                "cancel",
                "remote-server-not-found",
            )));
        }
        let stable_id = state.message_events().new_stanza_id();
        let rewritten = set_from(routed_raw, from);
        let routed = strip_stanza_ids_by_domain(&rewritten, state.local_domain());
        let sender_archive = add_stanza_id(&rewritten, bare_jid(from), stable_id);
        if !personal_retraction
            && direct_delivery_mode(root) == DirectDeliveryMode::VolatileExplicitNoStore
        {
            if grant_revision.is_some() {
                // Granting affiliation for a members-only invitation is
                // a durable authorization mutation. Never send an invite
                // which the recipient could not subsequently exercise.
                return Ok(Some(message_error(root, "wait", "service-unavailable")));
            }
            // A persistent S2S outbox would contradict the explicit
            // XEP-0334 no-store request. Only an already authenticated,
            // writable S2S/Bidi stream may accept this stanza. The
            // helper waits for the actual socket write and never creates
            // a connection, database admission row, archive or retry.
            if !state
                .send_volatile(state.local_domain(), domain, routed)
                .await
            {
                tracing::debug!(
                    source_domain = %state.local_domain(),
                    target_domain = %domain,
                    "volatile no-store stanza was not accepted by an authenticated S2S route"
                );
                return Ok(Some(message_error(root, "wait", "service-unavailable")));
            }
            finalize_admission(session, message_admission_lease, "remote-no-store").await;
            if should_carbon(root) {
                send_sent_carbons(state, from, &sender_archive, None, None).await;
            }
            state.personal_message_telemetry().message_routed();
            return Ok(Some(S::Action::none()));
        }
        let encrypted = is_encrypted(root);
        let archive = if encrypted {
            if let Some(target_id) = personal_retraction_target.as_deref() {
                encrypted_retraction_archive_stanza(&sender_archive, target_id)
            } else {
                encrypted_archive_stanza(&sender_archive)
            }
        } else {
            sender_archive.clone()
        };
        let archive_write = ArchiveWrite {
            id: stable_id,
            owner_id: user_id,
            peer_jid: to,
            stanza: &archive,
            encrypted,
            stanza_id: root.attribute("id"),
        };
        let candidate = archive_candidate(
            archive_write.clone(),
            ArchiveDirection::Outbound,
            !personal_retraction
                && state
                    .message_service()
                    .archive_content_eligible(mam_storage_eligible(root), encrypted),
        );
        let invitation_sent = if let (Some(invitation), Some(revision)) =
            (invitation, grant_revision)
        {
            let actor_scope = bare_jid(from);
            let target_scope = bare_jid(to);
            let origin_id = direct_origin_id(root);
            let identity = origin_id.as_deref().map(|id| MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: actor_scope,
                actor_scope,
                target_scope,
                value: id,
                payload: &rewritten,
            });
            let admission = ValidatedPersonalMessage {
                local_actor_id: Some(user_id),
                local_actor_fence,
                identity,
                archives: candidate.as_slice(),
                destination: PersonalMessageDestination::Federation(FederationDelivery {
                    local_actor_id: user_id,
                    target_domain: domain,
                    stanza: &routed,
                    bounce_to: Some(from),
                    limits: state.federation_outbox_policy(),
                }),
            };
            let grant = invitation_admission::prepare_grant(
                state, invitation, revision, stable_id, &admission,
            )?;
            session.enter_frame_stage(MessageFrameStage::Admission);
            match grant.admit(state).await {
                Ok(Ok(GrantDelivery::Open)) => false,
                Ok(Ok(GrantDelivery::Granted { wake_operation, .. })) => {
                    state.wake_federation_outbox();
                    if wake_operation {
                        if let Err(error) = state.wake_committed_direct_muc_invite(stable_id).await
                        {
                            state.personal_message_telemetry().post_accept_failed();
                            tracing::warn!(?error, %stable_id, "accepted federated direct MUC invite cluster wake failed");
                        }
                    }
                    true
                }
                Ok(Ok(GrantDelivery::Replay)) => {
                    finalize_admission(
                        session,
                        message_admission_lease,
                        "remote-muc-invite-replay",
                    )
                    .await;
                    return Ok(Some(S::Action::none()));
                }
                Ok(Err(refusal)) => {
                    return Ok(Some(invitation_admission::refused(root, refusal)));
                }
                Err(error) => {
                    tracing::warn!(?error, invitee = %target_jid.bare(), "federated direct MUC invite admission failed atomically");
                    return Ok(Some(message_error(root, "wait", "resource-constraint")));
                }
            }
        } else {
            false
        };
        if personal_retraction {
            session.enter_frame_stage(MessageFrameStage::Admission);
            match apply_outbound_personal_retraction(
                state,
                user_id,
                local_actor_fence,
                from,
                to,
                root,
                std::slice::from_ref(&archive_write),
                domain,
                &routed,
            )
            .await
            {
                Ok(RetractionOutcome::Applied { .. }) => {
                    state.wake_federation_outbox();
                }
                Ok(RetractionOutcome::Replay) => {
                    finalize_admission(
                        session,
                        message_admission_lease,
                        "remote-retraction-replay",
                    )
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
                    tracing::warn!(?error, %domain, "remote retraction history/outbox admission failed atomically");
                    return Ok(Some(message_error(root, "wait", "remote-server-timeout")));
                }
            }
        } else if !invitation_sent {
            let actor_scope = bare_jid(from);
            let target_scope = bare_jid(to);
            let origin_id = direct_origin_id(root);
            // The S2S outbox is itself the recoverable projection for a
            // federated message.  Keep the trusted origin-id even when
            // REQUIRE_ENCRYPTED_ARCHIVE suppresses the plaintext MAM
            // projection; otherwise an exact retry can enqueue twice and
            // a changed payload can reuse the same origin-id.
            let identity = origin_id.as_deref().map(|id| MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: actor_scope,
                actor_scope,
                target_scope,
                value: id,
                payload: &rewritten,
            });
            let admission = ValidatedPersonalMessage {
                local_actor_id: Some(user_id),
                local_actor_fence,
                identity,
                archives: candidate.as_slice(),
                destination: PersonalMessageDestination::Federation(FederationDelivery {
                    local_actor_id: user_id,
                    target_domain: domain,
                    stanza: &routed,
                    bounce_to: Some(from),
                    limits: state.federation_outbox_policy(),
                }),
            };
            session.enter_frame_stage(MessageFrameStage::Admission);
            match wake_federation_outbox_after_commit(
                state.message_service().admit_personal_message(&admission),
                || state.wake_federation_outbox(),
            )
            .await
            {
                Ok(DurableAdmissionOutcome::Stored { post_commit, .. }) => {
                    debug_assert_eq!(post_commit, MessagePostCommit::WakeFederationOutbox);
                }
                Ok(DurableAdmissionOutcome::Replay) => {
                    finalize_admission(session, message_admission_lease, "remote-replay").await;
                    return Ok(Some(S::Action::none()));
                }
                Ok(DurableAdmissionOutcome::AccountUnavailable) => {
                    return Ok(Some(message_error(root, "cancel", "service-unavailable")));
                }
                Err(error) => {
                    tracing::warn!(?error, %domain, "remote message history/outbox admission failed atomically");
                    return Ok(Some(message_error(root, "wait", "remote-server-timeout")));
                }
            }
        }
        finalize_admission(session, message_admission_lease, "remote-outbox").await;
        // Every durable remote path above commits its sender MAM/retraction
        // projection and S2S outbox in the same transaction. There is no
        // post-accept history write here that could fail and invite an
        // unsafe client retry.
        if should_carbon(root) {
            send_sent_carbons(state, from, &sender_archive, None, None).await;
        }
        state.personal_message_telemetry().message_routed();
        return Ok(Some(S::Action::none()));
    }
    Ok(None)
}
