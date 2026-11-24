//! Admits a client message stanza, archives it and delivers it to online, offline, carbon and federated recipients.

use super::archive_admission::archive_candidate;
use super::*;
use northstar_message_application::messaging::invitation_admission::DirectInvitation;
use northstar_message_core::ActorGenerationFence;
use std::ops::ControlFlow;

use self::invitation_admission::GrantDelivery;

mod carbons;
mod durable_commit;
mod invitation_admission;
mod local_targets;
mod offline_fallback;
mod outbound_remote;
mod rated_admission;
mod retraction;

pub async fn message<S: MessageSession>(
    session: &S,
    root: Node<'_, '_>,
    raw: &str,
    client_raw: &str,
) -> Result<S::Action> {
    let state = session.host();
    session.enter_frame_stage(MessageFrameStage::Policy);
    let telemetry = state.personal_message_telemetry();
    let _routing_timer = telemetry.start_routing_timer();
    let Some(user_id) = session.account_id() else {
        return Ok(message_error(root, "auth", "not-authorized"));
    };
    let Some(from) = session.full_jid() else {
        return Ok(message_error(root, "cancel", "not-authorized"));
    };
    let local_actor_fence = session.message_actor().map(|actor| actor.fence());
    if let Err(condition) = state.validate_routed_message(root) {
        // RFC 6120 section 8.3.1: never answer an error stanza with a
        // second stanza error. This validation boundary runs before every
        // local archive, Carbon and offline side effect.
        return Ok(if root.attribute("type") == Some("error") {
            S::Action::none()
        } else {
            message_error(root, stanza_error_type(condition), condition)
        });
    }
    // Defense in depth for a cross-feature mutation ambiguity. A direct
    // MUC invitation can grant affiliation, so a stanza which also carries
    // a personal retraction must be rejected before either operation is
    // classified or any database-backed invitation lookup runs. The
    // retraction parser independently rejects this shape for S2S and every
    // other caller.
    if mixes_personal_retraction_and_direct_invite(root) {
        return Ok(message_error(root, "modify", "bad-request"));
    }
    let personal_retraction_target = match retraction_target(root) {
        Ok(target) => target,
        Err(_) => return Ok(message_error(root, "modify", "bad-request")),
    };
    let personal_retraction = personal_retraction_target.is_some();
    if personal_retraction && has_explicit_no_store_hint(root) {
        // A personal-history retraction is itself a durable history
        // mutation. Accepting it while promising no-store would make the
        // stanza's persistence semantics internally contradictory.
        return Ok(message_error(root, "wait", "service-unavailable"));
    }
    // Read-only target parsing precedes PubSub authorization forms, PoW
    // consumption and all other message side effects. During degradation,
    // even a long-lived C2S stream cannot admit an unsupported direct.
    let raw_to = root.attribute("to").unwrap_or_else(|| bare_jid(from));
    let target_jid = match northstar_xmpp_types::jid::CanonicalJid::parse(raw_to) {
        Ok(target) => target,
        Err(_) => return Ok(message_error(root, "modify", "jid-malformed")),
    };
    let canonical_to = target_jid.to_string();
    let to = canonical_to.as_str();
    let local_direct =
        target_jid.domainpart() == state.local_domain() && target_jid.localpart().is_some();
    let degraded_spool_eligible = degraded_local_direct_eligible(
        root,
        target_jid.resourcepart().is_none(),
        personal_retraction,
        state.archive_requires_encryption(),
    );
    if local_direct {
        match state.message_service().direct_mode() {
            DirectPostCommitMode::Live => {}
            DirectPostCommitMode::SpoolOnly if degraded_spool_eligible => {}
            DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected => {
                return Ok(message_error(root, "wait", "service-unavailable"));
            }
        }
    }
    if session.pubsub_authorization_response(root).await? {
        return Ok(S::Action::none());
    }
    let proof = root
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "pow"
                && node.tag_name().namespace() == Some("urn:northstar:pow:1")
        })
        .and_then(|node| {
            Some(PowProof {
                challenge_id: node.attribute("challenge")?.parse().ok()?,
                nonce: node.attribute("nonce")?.to_owned(),
            })
        });
    let actors = vec![
        format!("ip:{}", session.peer_ip()),
        format!("user:{}", user_id),
        format!("behavior:{}", user_id),
    ];
    // The legacy XEP-0280 `<private/>` control applies independently at
    // the sender and recipient servers.  Preserve it on the routed copy;
    // removing it here would let the remote recipient server create a
    // Carbon the sender explicitly suppressed.  Only the local PoW
    // envelope and untrusted direct delay assertions are consumed.
    let routed_raw = strip_untrusted_direct_delays(&strip_pow_element(raw), None);
    let pow_intent_payload = message_pow_intent_payload(client_raw);
    let original_direct = OriginalDirectMessage::capture(root, user_id, from, to, &routed_raw);
    let mut message_admission_lease = None;
    if let Some(action) = rated_admission::begin(
        session,
        state,
        root,
        user_id,
        from,
        to,
        &original_direct,
        &pow_intent_payload,
        &actors,
        &proof,
        &mut message_admission_lease,
    )
    .await?
    {
        return Ok(action);
    }
    session.enter_frame_stage(MessageFrameStage::Policy);
    let invitation_room = direct_invite_admission(session, root);
    let active_privacy = session.active_privacy();
    let target_domain = target_jid.domainpart();
    let local_invitee = target_domain == state.local_domain()
        || target_domain == session.upload_domain()
        || target_domain == session.pubsub_domain();
    let invitation = invitation_room.as_deref().map(|room| DirectInvitation {
        room,
        actor_id: user_id,
        actor_jid: from,
        invitee_jid: to,
        local_recipient_name: target_jid.localpart().filter(|_| local_invitee),
        active_privacy: active_privacy.as_deref(),
    });
    let invitation_outcome = match invitation_admission::check(state, root, &invitation).await? {
        ControlFlow::Continue(outcome) => outcome,
        ControlFlow::Break(action) => return Ok(action),
    };
    if session.push_disable_message(root, from, to).await? {
        return Ok(S::Action::none());
    }
    let invitation_admission::OutboundAuthorization {
        invitation_recipient,
        grant_revision,
    } = match invitation_admission::authorize(
        state,
        root,
        invitation_outcome,
        user_id,
        from,
        &active_privacy,
        to,
    )
    .await?
    {
        ControlFlow::Continue(authorization) => authorization,
        ControlFlow::Break(action) => return Ok(action),
    };
    session.enter_frame_stage(MessageFrameStage::Handler);
    if let Some(action) = session.try_mix_message(root, &routed_raw).await? {
        if action.is_none() {
            finalize_message_admission(session, &mut message_admission_lease, "mix").await;
        }
        return Ok(action);
    }
    if target_jid.domainpart() == session.muc_domain() {
        let action = session.muc_message(root, &routed_raw).await?;
        if action.is_none() {
            finalize_message_admission(session, &mut message_admission_lease, "muc").await;
        }
        if action.is_none() && should_carbon(root) {
            let room_jid = target_jid.bare();
            let muc_scope = target_jid.resourcepart().and_then(|_| {
                session
                    .joined_room_nick(&room_jid)
                    .map(|nick| (room_jid.clone(), nick))
            });
            let forwarded = set_from(&routed_raw, from);
            if target_jid.resourcepart().is_none() {
                // Mediated invitations are addressed to the room bare
                // JID and are explicitly Carbon-eligible under rules:0.
                send_sent_carbons(state, from, &forwarded, None, None).await;
            } else if let Some((room_jid, nick)) = muc_scope.as_ref() {
                send_sent_carbons(
                    state,
                    from,
                    &forwarded,
                    None,
                    Some((room_jid.as_str(), nick.as_str())),
                )
                .await;
            }
        }
        return Ok(action);
    }

    session.enter_frame_stage(MessageFrameStage::Policy);
    let remote_domain = (target_domain != state.local_domain()
        && target_domain != session.muc_domain()
        && target_domain != session.upload_domain()
        && target_domain != session.pubsub_domain())
    .then_some(target_domain);
    if let Some(action) = outbound_remote::route(
        session,
        state,
        root,
        remote_domain,
        &routed_raw,
        from,
        personal_retraction,
        grant_revision,
        &mut message_admission_lease,
        &personal_retraction_target,
        user_id,
        local_actor_fence,
        to,
        &invitation,
        &target_jid,
    )
    .await?
    {
        return Ok(action);
    }
    let Some(recipient_local) = target_jid.localpart() else {
        return Ok(message_error(root, "cancel", "service-unavailable"));
    };
    let recipient_decision = if invitation.is_some() {
        invitation_recipient.map_or(
            LocalRecipientDecision::Missing,
            LocalRecipientDecision::Deliver,
        )
    } else {
        state
            .message_service()
            .resolve_local_recipient(recipient_local, state.local_domain(), from)
            .await?
    };
    let recipient = match recipient_decision {
        LocalRecipientDecision::Deliver(recipient) => recipient,
        LocalRecipientDecision::Blocked => {
            return Ok(message_error(root, "cancel", "service-unavailable"));
        }
        LocalRecipientDecision::Missing => {
            if missing_user_message_should_error(root.attribute("type").unwrap_or("normal")) {
                return Ok(message_error(root, "cancel", "service-unavailable"));
            }
            finalize_message_admission(session, &mut message_admission_lease, "missing-user-drop")
                .await;
            return Ok(S::Action::none());
        }
    };
    let message_type = root.attribute("type").unwrap_or("normal");
    let bare_target = target_jid.resourcepart().is_none();
    // RFC 6121 §8.5.2.1 gives bare-account message types deliberately
    // different routing semantics.
    if bare_target {
        match bare_message_route(message_type) {
            BareMessageRoute::Reject => {
                return Ok(message_error(root, "cancel", "service-unavailable"));
            }
            BareMessageRoute::Ignore => {
                finalize_message_admission(
                    session,
                    &mut message_admission_lease,
                    "bare-target-drop",
                )
                .await;
                return Ok(S::Action::none());
            }
            BareMessageRoute::Primary | BareMessageRoute::All => {}
        }
    }
    let sender_stable_id = state.message_events().new_stanza_id();
    let recipient_stable_id = if recipient.id == user_id {
        sender_stable_id
    } else {
        state.message_events().new_stanza_id()
    };
    let recipient_by = format!("{}@{}", recipient.username, state.local_domain());
    let encrypted = is_encrypted(root);
    let local_projection = original_direct.project_local(
        LocalProjectionAuthority {
            recipient_id: recipient.id,
            recipient_bare: &recipient_by,
            sender_stable_id,
            recipient_stable_id,
            domain: state.local_domain(),
        },
        encrypted,
        personal_retraction_target.as_deref(),
    );
    let rewritten = local_projection.rewritten.as_str();
    let sender_archive = local_projection.sender_archive.as_str();
    let recipient_delivery = local_projection.recipient_delivery.as_str();
    let recipient_archive_stanza = local_projection.recipient_archive_stanza.as_str();
    let durable_content_allowed = encrypted || !state.archive_requires_encryption();
    let persistence_allowed = personal_retraction || offline_storage_permitted(root);
    let archive_eligible = !personal_retraction
        && state
            .message_service()
            .archive_content_eligible(mam_storage_eligible(root), encrypted);
    let archive_eligibility = LocalArchiveEligibility {
        sender_eligible: archive_eligible,
        recipient_eligible: archive_eligible,
    };
    let candidates = local_projection.archive_candidates(archive_eligibility);
    let local_targets::LocalTargets {
        spool_only_now,
        targets,
        default_privacy_for_spool: _default_privacy_for_spool,
        spool_privacy_permits,
    } = match local_targets::select::<S>(
        state,
        root,
        local_direct,
        degraded_spool_eligible,
        to,
        bare_target,
        message_type,
        from,
        &recipient,
    )
    .await?
    {
        ControlFlow::Continue(targets) => targets,
        ControlFlow::Break(action) => return Ok(action),
    };
    // A trusted client origin-id is account scoped. Commit the durable
    // delivery and any selected archives before fanout. A retried origin-id is
    // consumed before any resource can observe a duplicate. The exact
    // sanitized client payload (without random server stanza-ids) is the
    // collision-safe replay value.
    let origin_id = original_direct.origin_id.as_deref();
    let exact_full_target_can_route = bare_target
        || message_type == "chat"
        || !targets.is_empty()
        || (!spool_only_now && state.personal_message_remote_resource_exists(to).await);
    let mut history_committed = false;
    let mut durable_c2s_delivery = None;
    let mut prepared_live = None;
    let mut live_claim_id = None;
    let durable_direct_invite = match invitation_admission::commit_local(
        session,
        state,
        root,
        &invitation,
        grant_revision,
        message_type,
        persistence_allowed,
        exact_full_target_can_route,
        recipient_delivery,
        from,
        origin_id,
        to,
        rewritten,
        user_id,
        local_actor_fence,
        &candidates,
        recipient_stable_id,
        &recipient,
        &recipient_by,
        encrypted,
        &mut live_claim_id,
        &mut message_admission_lease,
    )
    .await?
    {
        ControlFlow::Continue(delivery) => delivery,
        ControlFlow::Break(action) => return Ok(action),
    };
    let direct_delivery_candidate = durable_direct_invite.is_none()
        && matches!(message_type, "normal" | "chat")
        && exact_full_target_can_route
        && !personal_retraction;
    let direct_delivery_mode = direct_delivery_mode(root);
    if let Some(action) = durable_commit::commit(
        session,
        state,
        root,
        direct_delivery_candidate,
        direct_delivery_mode,
        durable_content_allowed,
        origin_id,
        from,
        to,
        rewritten,
        &local_projection,
        archive_eligibility,
        user_id,
        local_actor_fence,
        &candidates,
        recipient_stable_id,
        &recipient,
        &recipient_by,
        encrypted,
        degraded_spool_eligible,
        spool_privacy_permits,
        &mut message_admission_lease,
        &mut history_committed,
        &mut durable_c2s_delivery,
        &mut live_claim_id,
        &mut prepared_live,
    )
    .await?
    {
        return Ok(action);
    }
    if let Some(action) = retraction::apply(
        session,
        state,
        root,
        personal_retraction,
        message_type,
        exact_full_target_can_route,
        &local_projection,
        recipient_delivery,
        recipient_stable_id,
        &recipient,
        user_id,
        local_actor_fence,
        from,
        encrypted,
        to,
        &mut history_committed,
        &mut durable_c2s_delivery,
        &mut live_claim_id,
        &mut message_admission_lease,
    )
    .await?
    {
        return Ok(action);
    }
    let live_delivery_id = durable_direct_invite.or(durable_c2s_delivery);
    let delivery = match live_delivery_id {
        Some(message_id) => {
            DirectRouteDelivery::Committed(northstar_delivery_core::DurableDelivery {
                recipient_id: recipient.id,
                message_id,
                claim_id: live_claim_id,
            })
        }
        None => DirectRouteDelivery::Volatile,
    };
    session.enter_frame_stage(MessageFrameStage::Routing);
    let outcome = if let Some(live) = prepared_live {
        live.route_with(state, &targets).await?
    } else {
        let route_request = DirectRouteRequest {
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
            stanza: recipient_delivery,
            delivery,
            approved_targets: &targets,
            enforce_direct_health: local_direct,
        };
        DirectMessageRouter::route(state, route_request).await?
    };
    let (delivered, delivered_key) = match outcome {
        DirectRouteOutcome::Routed { accepted_full_jid } => (true, accepted_full_jid),
        DirectRouteOutcome::Unrouted => (false, None),
        DirectRouteOutcome::AcceptedForRecovery { stage, reason } => {
            tracing::debug!(
                ?stage,
                ?reason,
                "accepted direct message deferred to durable ownership/recovery"
            );
            return Ok(S::Action::none());
        }
        DirectRouteOutcome::AcceptedBeforeDegradation => {
            finalize_message_admission(
                session,
                &mut message_admission_lease,
                "online-before-degrade",
            )
            .await;
            return Ok(S::Action::none());
        }
        DirectRouteOutcome::Dropped => {
            finalize_message_admission(session, &mut message_admission_lease, "full-target-drop")
                .await;
            return Ok(S::Action::none());
        }
        DirectRouteOutcome::Rejected(reason) => {
            let kind = match reason {
                DirectRouteRejection::Unavailable => "wait",
                DirectRouteRejection::NoMatchingResource => "cancel",
            };
            return Ok(message_error(root, kind, "service-unavailable"));
        }
    };

    session.enter_frame_stage(MessageFrameStage::Followup);
    let mut stored_offline = false;
    if let Some(action) = offline_fallback::finish(
        session,
        state,
        root,
        delivered,
        direct_delivery_mode,
        live_delivery_id,
        &mut stored_offline,
        local_direct,
        &recipient,
        recipient_stable_id,
        message_type,
        persistence_allowed,
        durable_content_allowed,
        &mut message_admission_lease,
        recipient_archive_stanza,
        &recipient_by,
        from,
        encrypted,
        history_committed,
        user_id,
        to,
        &delivered_key,
        recipient_delivery,
    )
    .await?
    {
        return Ok(action);
    }

    // Durable deliveries have already decided their archive projections.
    // Volatile deliveries reach history after route acceptance.
    let accepted_route = if stored_offline { "offline" } else { "online" };
    finalize_message_admission(session, &mut message_admission_lease, accepted_route).await;
    debug_assert!(
        !personal_retraction || history_committed,
        "a personal retraction reached fanout without durable admission"
    );
    if live_delivery_id.is_none() && !personal_retraction {
        let history_result = state.message_service().admit_history(&candidates).await;
        if let Err(error) = history_result {
            state.personal_message_telemetry().post_accept_failed();
            tracing::warn!(?error, %sender_stable_id, route = accepted_route, "accepted message history transaction failed atomically");
        }
    }
    carbons::send(
        state,
        root,
        local_direct,
        &recipient,
        user_id,
        &delivered_key,
        from,
        sender_archive,
    )
    .await;
    state.personal_message_telemetry().message_routed();
    Ok(S::Action::none())
}

async fn finalize_admission<S: MessageSession>(
    session: &S,
    message_admission_lease: &mut Option<MessageAdmissionLease>,
    route: &'static str,
) {
    finalize_message_admission(session, message_admission_lease, route).await;
}
