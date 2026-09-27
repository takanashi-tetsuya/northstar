use super::{Action, ProtocolSession};
use crate::cluster::{DirectPostCommitMode, DirectSpoolEligibility};
use crate::services::messaging::{
    admit_offline_then_push, committed_live_delivery_has_fence, ArchiveWrite,
    DurableAdmissionOutcome, FederationDelivery, FullJidFallback, FullJidFallbackResult,
    IdentityAuthority, LocalDelivery, LocalMucInviteAdmission, LocalRecipientDecision,
    MessageIdentity, MessagePostCommit, OfflineAdmissionOutcome, OnlineMessageRouter,
    OutboundPolicyDecision, PersonalMessageDestination, RemoteMucInviteAdmission,
    RemoteMucInviteAdmissionOutcome, ValidatedPersonalMessage,
};
use crate::services::muc::{ClusterMucAffiliationSubject, DurableMucInviteOutcome};
use crate::services::privacy::PrivacyStanzaKind;
use crate::services::retractions::{DeliveryProjection, RetractionOutcome};
use crate::xmpp::xml_util::*;
use crate::{
    abuse::{MessageAdmissionLease, MessageAdmissionRequest, MessageAdmissionStart, PowProof},
    state::bare_jid,
};
use anyhow::Result;
pub(crate) use northstar_message_core::{
    bare_message_route, durable_direct_delivery_allowed, durable_full_no_match_recovers,
    full_no_match_route, missing_user_message_should_error, undelivered_disposition,
    BareMessageRoute, DirectDeliveryMode, FullNoMatchRoute, UndeliveredDisposition,
};
use roxmltree::Node;
use std::{future::Future, sync::atomic::Ordering};

fn mixes_personal_retraction_and_direct_invite(root: Node<'_, '_>) -> bool {
    let has_retraction = root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "retract"
            && node.tag_name().namespace() == Some("urn:xmpp:message-retract:1")
    });
    has_retraction
        && root.children().any(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("jabber:x:conference")
        })
}

/// A degraded cluster can only accept a durable bare-account direct message.
/// The recipient spool is account scoped; an exact resource or an invitation
/// cannot be represented by that authority while Redis is unavailable.
fn degraded_local_direct_eligible(
    root: Node<'_, '_>,
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
        && !signal_only_direct_message(root)
        && direct_delivery_mode(root) == DirectDeliveryMode::Durable
        && (!archive_requires_encryption || is_encrypted(root))
}

/// An explicit store hint does not turn a receipt/chat-state signal into
/// ordinary direct content for degraded admission.
fn signal_only_direct_message(root: Node<'_, '_>) -> bool {
    let mut signal = false;
    for node in root.children().filter(|node| node.is_element()) {
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
            || (matches!(namespace, "" | "jabber:client") && name == "thread")
            || namespace == "urn:xmpp:sid:0"
            || (namespace == "urn:northstar:pow:1" && name == "pow")
        {
            continue;
        }
        return false;
    }
    signal
}

fn direct_spool_eligibility(
    stanza_eligible: bool,
    account_default_privacy_permits: bool,
) -> DirectSpoolEligibility {
    if stanza_eligible && account_default_privacy_permits {
        DirectSpoolEligibility::Eligible
    } else {
        DirectSpoolEligibility::LiveOnly
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalDirectLiveEffect {
    Proceed,
    AcceptedForRecovery,
    Reject,
}

fn local_direct_live_effect(mode: DirectPostCommitMode, committed: bool) -> LocalDirectLiveEffect {
    match mode {
        DirectPostCommitMode::Live => LocalDirectLiveEffect::Proceed,
        DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected if committed => {
            LocalDirectLiveEffect::AcceptedForRecovery
        }
        DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected => {
            LocalDirectLiveEffect::Reject
        }
    }
}

/// An outbox wake is only a hint to process a row that has already committed.
/// A failed or replayed admission must never send a new wake to the worker.
async fn wake_federation_outbox_after_commit<F, W>(
    commit: F,
    wake: W,
) -> Result<DurableAdmissionOutcome>
where
    F: Future<Output = Result<DurableAdmissionOutcome>>,
    W: FnOnce(),
{
    let outcome = commit.await?;
    if matches!(
        outcome,
        DurableAdmissionOutcome::Stored {
            post_commit: MessagePostCommit::WakeFederationOutbox,
            ..
        }
    ) {
        wake();
    }
    Ok(outcome)
}

impl ProtocolSession {
    pub(crate) async fn message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        client_raw: &str,
    ) -> Result<Action> {
        let telemetry = self.state.personal_message_telemetry();
        let _routing_timer = telemetry.start_routing_timer();
        let Some(user) = &self.authenticated else {
            return Ok(message_error(root, "auth", "not-authorized"));
        };
        let Some(from) = self.full_jid.as_deref() else {
            return Ok(message_error(root, "cancel", "not-authorized"));
        };
        if let Err(condition) = self.state.validate_routed_message(root) {
            // RFC 6120 section 8.3.1: never answer an error stanza with a
            // second stanza error. This validation boundary runs before every
            // local archive, Carbon and offline side effect.
            return Ok(if root.attribute("type") == Some("error") {
                Action::None
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
        let personal_retraction_target = match super::retractions::retraction_target(root) {
            Ok(target) => target,
            Err(()) => return Ok(message_error(root, "modify", "bad-request")),
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
        let target_jid = match crate::jid::CanonicalJid::parse(raw_to) {
            Ok(target) => target,
            Err(_) => return Ok(message_error(root, "modify", "jid-malformed")),
        };
        let canonical_to = target_jid.to_string();
        let to = canonical_to.as_str();
        let local_direct = target_jid.domainpart() == self.state.local_domain()
            && target_jid.localpart().is_some();
        let degraded_spool_eligible = degraded_local_direct_eligible(
            root,
            target_jid.resourcepart().is_none(),
            personal_retraction,
            self.state.archive_requires_encryption(),
        );
        if local_direct {
            match self.state.message_service().direct_mode() {
                DirectPostCommitMode::Live => {}
                DirectPostCommitMode::SpoolOnly if degraded_spool_eligible => {}
                DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected => {
                    return Ok(message_error(root, "wait", "service-unavailable"));
                }
            }
        }
        match self.pubsub_authorization_response(root).await {
            Ok(true) => return Ok(Action::None),
            Ok(false) => {}
            Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
                tracing::warn!(
                    "dropping PubSub authorization form while mutation capacity is exhausted"
                );
                return Ok(Action::None);
            }
            Err(error) => return Err(error),
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
            format!("ip:{}", self.peer_ip),
            format!("user:{}", user.id),
            format!("behavior:{}", user.id),
        ];
        // The legacy XEP-0280 `<private/>` control applies independently at
        // the sender and recipient servers.  Preserve it on the routed copy;
        // removing it here would let the remote recipient server create a
        // Carbon the sender explicitly suppressed.  Only the local PoW
        // envelope and untrusted direct delay assertions are consumed.
        let routed_raw = strip_untrusted_direct_delays(&strip_pow_element(raw), None);
        let pow_intent_payload = message_pow_intent_payload(client_raw);
        let mut message_admission_lease = None;
        if is_abuse_rated_message(root) {
            let normalized_admission_payload =
                set_root_attribute(&set_from(&routed_raw, bare_jid(from)), "to", to);
            let subject = format!("message:{}", user.id);
            let admission_origin_id = direct_origin_id(root);
            let admission = self
                .state
                .message_admission_service()
                .begin_message_admission(&MessageAdmissionRequest {
                    actor_id: user.id,
                    account_bare: bare_jid(from),
                    normalized_target: to,
                    origin_id: admission_origin_id.as_deref(),
                    normalized_payload: &normalized_admission_payload,
                    pow_intent_payload: &pow_intent_payload,
                    subject: &subject,
                    actors: &actors,
                    proof: proof.as_ref(),
                })
                .await;
            match admission {
                Ok(MessageAdmissionStart::Proceed { lease, requirement }) => {
                    debug_assert_eq!(requirement.action, "message");
                    message_admission_lease = lease;
                }
                Ok(MessageAdmissionStart::ReplayAccepted) => return Ok(Action::None),
                Ok(MessageAdmissionStart::InProgress { requirement }) => {
                    self.state.personal_message_telemetry().rate_limited();
                    return Ok(Action::Send(abuse_stanza_error(root, &requirement)));
                }
                Ok(MessageAdmissionStart::Denied(error)) => {
                    self.state.personal_message_telemetry().rate_limited();
                    return Ok(Action::Send(abuse_stanza_error(root, error.requirement())));
                }
                Ok(MessageAdmissionStart::Conflict) => {
                    return Ok(message_error(root, "cancel", "conflict"));
                }
                Ok(MessageAdmissionStart::CapacityLimited) => {
                    self.state.personal_message_telemetry().rate_limited();
                    return Ok(message_error(root, "wait", "resource-constraint"));
                }
                Err(error) => {
                    // Proof consumption, actor advancement and the pending
                    // admission all roll back on this path. Fail closed before
                    // any routing/archive side effect.
                    if crate::abuse::is_abuse_state_busy(&error) {
                        tracing::warn!(user_id = %user.id, "message anti-abuse actor state was busy; rejected without waiting on a database connection lock");
                        self.state.personal_message_telemetry().rate_limited();
                        return Ok(message_error(root, "wait", "resource-constraint"));
                    }
                    tracing::error!(?error, user_id = %user.id, "message anti-abuse backend failed before acceptance");
                    self.state
                        .personal_message_telemetry()
                        .abuse_backend_failed();
                    return Ok(message_error(root, "wait", "resource-constraint"));
                }
            }
        }
        let direct_invite_admission = self.direct_invite_admission(root, user.id).await?;
        if direct_invite_admission == DirectInviteAdmission::Forbidden {
            return Ok(message_error(root, "auth", "forbidden"));
        }
        if self.push_disable_message(root, from, to).await? {
            return Ok(Action::None);
        }
        let active_privacy = self
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        // XEP-0191 is account scoped and applies to every outbound stanza,
        // including local service addresses such as MUC and MIX. The service
        // always evaluates that non-overridable rule before XEP-0016.
        match self
            .state
            .message_service()
            .authorize_outbound_message(user.id, bare_jid(from), active_privacy.as_deref(), to)
            .await?
        {
            OutboundPolicyDecision::Allowed => {}
            OutboundPolicyDecision::Blocked => return Ok(message_blocked_error(root)),
            OutboundPolicyDecision::PrivacyDenied => {
                return Ok(message_error(root, "cancel", "service-unavailable"));
            }
        }
        if let Some(action) = self.try_mix_message(root, &routed_raw).await? {
            if matches!(action, Action::None) {
                self.finalize_message_admission(&mut message_admission_lease, "mix")
                    .await;
            }
            return Ok(action);
        }
        if target_jid.domainpart() == self.muc_domain() {
            let action = self.muc_message(root, &routed_raw).await?;
            if matches!(action, Action::None) {
                self.finalize_message_admission(&mut message_admission_lease, "muc")
                    .await;
            }
            if matches!(action, Action::None) && should_carbon(root) {
                let room_jid = target_jid.bare();
                let muc_scope = target_jid.resourcepart().and_then(|_| {
                    self.joined_rooms
                        .get(&room_jid)
                        .map(|membership| (room_jid.clone(), membership.nick.clone()))
                });
                let forwarded = set_from(&routed_raw, from);
                if target_jid.resourcepart().is_none() {
                    // Mediated invitations are addressed to the room bare
                    // JID and are explicitly Carbon-eligible under rules:0.
                    self.send_sent_carbons(from, &forwarded, None, None).await;
                } else if let Some((room_jid, nick)) = muc_scope.as_ref() {
                    self.send_sent_carbons(
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

        let target_domain = target_jid.domainpart();
        let remote_domain = (target_domain != self.state.local_domain()
            && target_domain != self.muc_domain()
            && target_domain != self.upload_domain()
            && target_domain != self.pubsub_domain())
        .then_some(target_domain);
        if let Some(domain) = remote_domain {
            if !self.state.xmpp_external_route_domain_allowed(domain) {
                return Ok(message_error(root, "cancel", "remote-server-not-found"));
            }
            let stable_id = uuid::Uuid::new_v4();
            let rewritten = set_from(&routed_raw, from);
            let routed = strip_stanza_ids_by_domain(&rewritten, self.state.local_domain());
            let sender_archive = add_stanza_id(&rewritten, bare_jid(from), stable_id);
            if !personal_retraction
                && direct_delivery_mode(root) == DirectDeliveryMode::VolatileExplicitNoStore
            {
                if matches!(
                    direct_invite_admission,
                    DirectInviteAdmission::MembersOnly { .. }
                ) {
                    // Granting affiliation for a members-only invitation is
                    // a durable authorization mutation. Never send an invite
                    // which the recipient could not subsequently exercise.
                    return Ok(message_error(root, "wait", "service-unavailable"));
                }
                // A persistent S2S outbox would contradict the explicit
                // XEP-0334 no-store request. Only an already authenticated,
                // writable S2S/Bidi stream may accept this stanza. The
                // helper waits for the actual socket write and never creates
                // a connection, database admission row, archive or retry.
                if !crate::s2s::send_volatile_on_authenticated_route(
                    &self.state,
                    self.state.local_domain(),
                    domain,
                    routed,
                )
                .await
                {
                    tracing::debug!(
                        source_domain = %self.state.local_domain(),
                        target_domain = %domain,
                        "volatile no-store stanza was not accepted by an authenticated S2S route"
                    );
                    return Ok(message_error(root, "wait", "service-unavailable"));
                }
                self.finalize_message_admission(&mut message_admission_lease, "remote-no-store")
                    .await;
                if should_carbon(root) {
                    self.send_sent_carbons(from, &sender_archive, None, None)
                        .await;
                }
                self.state.personal_message_telemetry().message_routed();
                return Ok(Action::None);
            }
            let encrypted = is_encrypted(root);
            let archive_allowed = self
                .state
                .message_service()
                .archive_enabled(
                    user.id,
                    to,
                    mam_storage_eligible(root),
                    encrypted,
                    personal_retraction,
                )
                .await?;
            let archive = if encrypted {
                if let Some(target_id) = personal_retraction_target.as_deref() {
                    super::retractions::encrypted_retraction_archive(&sender_archive, target_id)
                } else {
                    encrypted_archive_stanza(&sender_archive)
                }
            } else {
                sender_archive.clone()
            };
            let writes = archive_allowed
                .then_some(ArchiveWrite {
                    id: stable_id,
                    owner_id: user.id,
                    peer_jid: to,
                    stanza: &archive,
                    encrypted,
                    stanza_id: root.attribute("id"),
                })
                .into_iter()
                .collect::<Vec<_>>();
            if let DirectInviteAdmission::MembersOnly {
                room_id,
                room_epoch,
                config_version,
            } = direct_invite_admission
            {
                let cluster_authority = self.state.direct_muc_invite_cluster_authority(
                    stable_id,
                    room_epoch,
                    config_version,
                    user.id,
                    from,
                    ClusterMucAffiliationSubject::Federated {
                        bare_jid: target_jid.bare(),
                    },
                )?;
                let actor_scope = bare_jid(from);
                let target_scope = bare_jid(to);
                let invitee_bare_jid = target_jid.bare();
                let origin_id = direct_origin_id(root);
                let identity = origin_id.as_deref().map(|id| MessageIdentity {
                    authority: IdentityAuthority::LocalOrigin,
                    actor_scope_raw: actor_scope,
                    actor_scope,
                    target_scope,
                    value: id,
                    payload: &rewritten,
                });
                let admission = RemoteMucInviteAdmission {
                    local_actor_id: user.id,
                    identity,
                    archives: &writes,
                    room_id,
                    invitee_bare_jid: &invitee_bare_jid,
                    target_domain: domain,
                    stanza: &routed,
                    bounce_to: Some(from),
                    outbox_policy: self.state.federation_outbox().outbox_policy().into(),
                    cluster_authority: cluster_authority.as_ref(),
                };
                match self
                    .state
                    .message_service()
                    .admit_remote_muc_invite(&admission)
                    .await
                {
                    Ok(RemoteMucInviteAdmissionOutcome::Stored) => {
                        self.state.federation_outbox().wake_outbox();
                        if cluster_authority.is_some() {
                            if let Err(error) =
                                self.state.wake_committed_direct_muc_invite(stable_id).await
                            {
                                self.state.personal_message_telemetry().post_accept_failed();
                                tracing::warn!(?error, %stable_id, "accepted federated direct MUC invite cluster wake failed");
                            }
                        }
                    }
                    Ok(RemoteMucInviteAdmissionOutcome::Replay) => {
                        self.finalize_message_admission(
                            &mut message_admission_lease,
                            "remote-muc-invite-replay",
                        )
                        .await;
                        return Ok(Action::None);
                    }
                    Ok(RemoteMucInviteAdmissionOutcome::AccountUnavailable) => {
                        // Treat a sender account disabled/revoked during the
                        // admission transaction like the other durable send
                        // paths.  Do not expose whether the account, room or
                        // federation authority changed concurrently.
                        return Ok(message_error(root, "cancel", "service-unavailable"));
                    }
                    Ok(RemoteMucInviteAdmissionOutcome::Rejected) => {
                        return Ok(message_error(root, "auth", "forbidden"));
                    }
                    Ok(RemoteMucInviteAdmissionOutcome::Stale) => {
                        return Ok(message_error(root, "cancel", "item-not-found"));
                    }
                    Ok(RemoteMucInviteAdmissionOutcome::Conflict) => {
                        return Ok(message_error(root, "cancel", "conflict"));
                    }
                    Err(error) => {
                        tracing::warn!(?error, invitee = %target_jid.bare(), "federated direct MUC invite admission failed atomically");
                        return Ok(message_error(root, "wait", "resource-constraint"));
                    }
                }
            } else if personal_retraction {
                match self
                    .apply_outbound_personal_retraction(
                        user.id, from, to, root, &writes, domain, &routed,
                    )
                    .await
                {
                    Ok(RetractionOutcome::Applied { .. }) => {
                        self.state.federation_outbox().wake_outbox();
                    }
                    Ok(RetractionOutcome::Replay) => {
                        self.finalize_message_admission(
                            &mut message_admission_lease,
                            "remote-retraction-replay",
                        )
                        .await;
                        return Ok(Action::None);
                    }
                    Ok(RetractionOutcome::Conflict) => {
                        return Ok(message_error(root, "cancel", "conflict"));
                    }
                    Ok(RetractionOutcome::Forbidden) => {
                        return Ok(message_error(root, "auth", "forbidden"));
                    }
                    Ok(RetractionOutcome::AccountUnavailable) => {
                        return Ok(message_error(root, "cancel", "service-unavailable"));
                    }
                    Ok(RetractionOutcome::CapacityExceeded) => {
                        return Ok(message_error(root, "wait", "resource-constraint"));
                    }
                    Err(error) => {
                        tracing::warn!(?error, %domain, "remote retraction history/outbox admission failed atomically");
                        return Ok(message_error(root, "wait", "remote-server-timeout"));
                    }
                }
            } else {
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
                    local_actor_id: Some(user.id),
                    identity,
                    archives: &writes,
                    destination: PersonalMessageDestination::Federation(FederationDelivery {
                        local_actor_id: user.id,
                        target_domain: domain,
                        stanza: &routed,
                        bounce_to: Some(from),
                        limits: self.state.federation_outbox().outbox_policy(),
                    }),
                };
                match wake_federation_outbox_after_commit(
                    self.state
                        .message_service()
                        .admit_personal_message(&admission),
                    || self.state.federation_outbox().wake_outbox(),
                )
                .await
                {
                    Ok(DurableAdmissionOutcome::Stored { post_commit, .. }) => {
                        debug_assert_eq!(post_commit, MessagePostCommit::WakeFederationOutbox);
                    }
                    Ok(DurableAdmissionOutcome::Replay) => {
                        self.finalize_message_admission(
                            &mut message_admission_lease,
                            "remote-replay",
                        )
                        .await;
                        return Ok(Action::None);
                    }
                    Ok(DurableAdmissionOutcome::AccountUnavailable) => {
                        return Ok(message_error(root, "cancel", "service-unavailable"));
                    }
                    Err(error) => {
                        tracing::warn!(?error, %domain, "remote message history/outbox admission failed atomically");
                        return Ok(message_error(root, "wait", "remote-server-timeout"));
                    }
                }
            }
            self.finalize_message_admission(&mut message_admission_lease, "remote-outbox")
                .await;
            // Every durable remote path above commits its sender MAM/retraction
            // projection and S2S outbox in the same transaction. There is no
            // post-accept history write here that could fail and invite an
            // unsafe client retry.
            if should_carbon(root) {
                self.send_sent_carbons(from, &sender_archive, None, None)
                    .await;
            }
            self.state.personal_message_telemetry().message_routed();
            return Ok(Action::None);
        }
        let Some(recipient_local) = target_jid.localpart() else {
            return Ok(message_error(root, "cancel", "service-unavailable"));
        };
        let recipient = match self
            .state
            .message_service()
            .resolve_local_recipient(recipient_local, self.state.local_domain(), from)
            .await?
        {
            LocalRecipientDecision::Deliver(recipient) => recipient,
            LocalRecipientDecision::Blocked => {
                return Ok(message_error(root, "cancel", "service-unavailable"));
            }
            LocalRecipientDecision::Missing => {
                if missing_user_message_should_error(root.attribute("type").unwrap_or("normal")) {
                    return Ok(message_error(root, "cancel", "service-unavailable"));
                }
                self.finalize_message_admission(&mut message_admission_lease, "missing-user-drop")
                    .await;
                return Ok(Action::None);
            }
        };
        // A direct MUC invitation can grant access to a members-only room, but
        // that authorization is a side effect of an accepted message. Merely
        // parsing the stanza must never mutate affiliation state: full-JID
        // routing rejection, offline quota failure, no-store, and blocking all
        // remain side-effect free.
        let direct_invite_room = match direct_invite_admission {
            DirectInviteAdmission::MembersOnly { room_id, .. } => Some(room_id),
            DirectInviteAdmission::None => None,
            DirectInviteAdmission::Forbidden => unreachable!("rejected before routing"),
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
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "bare-target-drop",
                    )
                    .await;
                    return Ok(Action::None);
                }
                BareMessageRoute::Primary | BareMessageRoute::All => {}
            }
        }
        let sender_stable_id = uuid::Uuid::new_v4();
        let recipient_stable_id = if recipient.id == user.id {
            sender_stable_id
        } else {
            uuid::Uuid::new_v4()
        };
        let recipient_by = format!("{}@{}", recipient.username, self.state.local_domain());
        let rewritten = set_from(&routed_raw, from);
        let routed = strip_stanza_ids_by_domain(&rewritten, self.state.local_domain());
        let sender_archive = add_stanza_id(&rewritten, bare_jid(from), sender_stable_id);
        let recipient_delivery = if recipient.id == user.id {
            sender_archive.clone()
        } else {
            add_stanza_id(&routed, &recipient_by, recipient_stable_id)
        };
        let encrypted = is_encrypted(root);
        let durable_content_allowed = encrypted || !self.state.archive_requires_encryption();
        let persistence_allowed = personal_retraction || offline_storage_permitted(root);
        let archive_allowed_by_stanza = personal_retraction || mam_storage_eligible(root);
        let sender_archive_stanza = if encrypted {
            if let Some(target_id) = personal_retraction_target.as_deref() {
                super::retractions::encrypted_retraction_archive(&sender_archive, target_id)
            } else {
                encrypted_archive_stanza(&sender_archive)
            }
        } else {
            sender_archive.clone()
        };
        let recipient_archive_stanza = if encrypted {
            if let Some(target_id) = personal_retraction_target.as_deref() {
                super::retractions::encrypted_retraction_archive(&recipient_delivery, target_id)
            } else {
                encrypted_archive_stanza(&recipient_delivery)
            }
        } else {
            recipient_delivery.clone()
        };
        let stanza_id = root.attribute("id");
        let sender_history_enabled = self
            .state
            .message_service()
            .archive_enabled(
                user.id,
                to,
                archive_allowed_by_stanza,
                encrypted,
                personal_retraction,
            )
            .await?;
        let recipient_history_enabled = if recipient.id == user.id {
            sender_history_enabled
        } else {
            self.state
                .message_service()
                .archive_enabled(
                    recipient.id,
                    from,
                    archive_allowed_by_stanza,
                    encrypted,
                    personal_retraction,
                )
                .await?
        };
        let spool_only_now = if local_direct {
            match self.state.message_service().direct_mode() {
                DirectPostCommitMode::Live => false,
                DirectPostCommitMode::SpoolOnly if degraded_spool_eligible => true,
                DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected => {
                    return Ok(message_error(root, "wait", "service-unavailable"));
                }
            }
        } else {
            false
        };
        // The degraded destination is the PostgreSQL recipient spool. Redis
        // session discovery cannot establish a live route in this mode.
        let mut targets = if spool_only_now {
            Vec::new()
        } else {
            self.state.session_entries_for(to)
        };
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
        let unfiltered_local_targets = targets.len();
        let mut privacy_allowed_targets = Vec::with_capacity(targets.len());
        for target in targets {
            if self
                .state
                .privacy_allows_session(&target.1, from, PrivacyStanzaKind::Message)
                .await?
            {
                privacy_allowed_targets.push(target);
            }
        }
        let targets = privacy_allowed_targets;
        if unfiltered_local_targets > 0 && targets.is_empty() {
            return Ok(message_error(root, "cancel", "service-unavailable"));
        }
        let remote_route_exists = if spool_only_now {
            false
        } else {
            self.state.personal_message_remote_resource_exists(to).await
        };
        // A live resource's active privacy list may override the account
        // default. If mode changes to SpoolOnly inside the PG transaction,
        // however, the delivery becomes account-scoped. Read that default
        // even when a live resource exists so the transaction can be marked
        // LiveOnly when an account spool would violate recipient privacy.
        let default_privacy_for_spool = if degraded_spool_eligible {
            Some(
                self.state
                    .message_service()
                    .default_recipient_privacy_denies(recipient.id, from)
                    .await,
            )
        } else {
            None
        };
        let spool_privacy_permits = matches!(&default_privacy_for_spool, Some(Ok(false)));
        if targets.is_empty() && !remote_route_exists {
            let default_denies = match default_privacy_for_spool {
                Some(result) => result?,
                None => {
                    self.state
                        .message_service()
                        .default_recipient_privacy_denies(recipient.id, from)
                        .await?
                }
            };
            if default_denies {
                return Ok(message_error(root, "cancel", "service-unavailable"));
            }
        }
        // A trusted client origin-id is account scoped.  When the recipient's
        // personal archive is part of this admission, commit every owner
        // projection before fanout. A concurrent/retried origin-id is then
        // consumed before any resource can observe a duplicate. The exact
        // sanitized client payload (without random server stanza-ids) is the
        // collision-safe replay value.
        let origin_id = direct_origin_id(root);
        let exact_full_target_can_route = bare_target
            || message_type == "chat"
            || !targets.is_empty()
            || (!spool_only_now && self.state.personal_message_remote_resource_exists(to).await);
        let mut history_committed = false;
        let mut durable_c2s_delivery = None;
        let mut live_claim_id = None;
        let direct_delivery_candidate = direct_invite_room.is_none()
            && matches!(message_type, "normal" | "chat")
            && exact_full_target_can_route
            && !personal_retraction;
        let direct_delivery_mode = direct_delivery_mode(root);
        if direct_delivery_candidate
            && durable_direct_delivery_allowed(direct_delivery_mode, durable_content_allowed)
        {
            let mut writes = Vec::with_capacity(2);
            if sender_history_enabled {
                writes.push(ArchiveWrite {
                    id: sender_stable_id,
                    owner_id: user.id,
                    peer_jid: to,
                    stanza: &sender_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            if recipient.id != user.id && recipient_history_enabled {
                writes.push(ArchiveWrite {
                    id: recipient_stable_id,
                    owner_id: recipient.id,
                    peer_jid: from,
                    stanza: &recipient_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            let identity = origin_id.as_deref().map(|identity_value| {
                let actor_scope = bare_jid(from);
                let target_scope = bare_jid(to);
                MessageIdentity {
                    authority: IdentityAuthority::LocalOrigin,
                    actor_scope_raw: actor_scope,
                    actor_scope,
                    target_scope,
                    value: identity_value,
                    payload: &rewritten,
                }
            });
            let delayed_delivery = add_delay_from(
                &recipient_delivery,
                chrono::Utc::now(),
                Some(self.state.local_domain()),
            );
            let admission = ValidatedPersonalMessage {
                local_actor_id: Some(user.id),
                identity,
                archives: &writes,
                destination: PersonalMessageDestination::Local(LocalDelivery {
                    delivery_id: recipient_stable_id,
                    recipient_id: recipient.id,
                    recipient_bare_jid: &recipient_by,
                    sender_jid: from,
                    stanza: &delayed_delivery,
                    encrypted,
                    mam_backed: recipient_history_enabled,
                }),
            };
            let eligibility =
                direct_spool_eligibility(degraded_spool_eligible, spool_privacy_permits);
            let admitted = self
                .state
                .message_service()
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
                    history_committed = archive_written;
                    let MessagePostCommit::RouteLocalDelivery { delivery_id, .. } = post_commit
                    else {
                        return Ok(message_error(root, "wait", "internal-server-error"));
                    };
                    durable_c2s_delivery = Some(delivery_id);
                    live_claim_id = admitted_claim_id;
                    tracing::debug!(
                        recipient_id = %recipient.id,
                        message_id = %recipient_stable_id,
                        target = %to,
                        "committed durable C2S delivery before route attempt"
                    );
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        if post_commit_mode == DirectPostCommitMode::Live {
                            "local-durable-c2s"
                        } else {
                            "local-durable-c2s-spooled"
                        },
                    )
                    .await;
                    // A committed spool row is accepted for recovery. It has
                    // no live owner while Redis is degraded, so do not attempt
                    // local delivery, Redis routing, Push, Carbons or a later
                    // transient/offline fallback. The second mode read also
                    // catches degradation during PoW finalization.
                    if post_commit_mode != DirectPostCommitMode::Live
                        || self.state.message_service().direct_mode() != DirectPostCommitMode::Live
                    {
                        self.state
                            .message_service()
                            .rearm_unrouted_live_direct(
                                recipient.id,
                                delivery_id,
                                &mut live_claim_id,
                            )
                            .await;
                        tracing::debug!(
                            recipient_id = %recipient.id,
                            message_id = %recipient_stable_id,
                            "C2S direct committed to PostgreSQL spool for recovery"
                        );
                        return Ok(Action::None);
                    }
                }
                Ok((DurableAdmissionOutcome::Replay, _, _)) => {
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "local-durable-c2s-replay",
                    )
                    .await;
                    return Ok(Action::None);
                }
                Ok((DurableAdmissionOutcome::AccountUnavailable, _, _)) => {
                    return Ok(message_error(root, "cancel", "service-unavailable"));
                }
                Err(error) => {
                    tracing::warn!(?error, recipient_id = %recipient.id, "local history/C2S admission failed atomically");
                    return Ok(message_error(root, "wait", "resource-constraint"));
                }
            }
        }
        if personal_retraction {
            // Retractions mutate durable history and therefore always use the
            // recoverable C2S projection. They must never share a stanza with
            // an invitation or enter a volatile message-type route.
            if direct_invite_room.is_some() || !matches!(message_type, "normal" | "chat") {
                return Ok(message_error(root, "modify", "bad-request"));
            }
            if !exact_full_target_can_route {
                return Ok(message_error(root, "cancel", "service-unavailable"));
            }
            let mut writes = Vec::with_capacity(2);
            if sender_history_enabled {
                writes.push(ArchiveWrite {
                    id: sender_stable_id,
                    owner_id: user.id,
                    peer_jid: to,
                    stanza: &sender_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            if recipient.id != user.id && recipient_history_enabled {
                writes.push(ArchiveWrite {
                    id: recipient_stable_id,
                    owner_id: recipient.id,
                    peer_jid: from,
                    stanza: &recipient_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            let delayed_delivery = add_delay_from(
                &recipient_delivery,
                chrono::Utc::now(),
                Some(self.state.local_domain()),
            );
            let offline_limits = self.state.offline_delivery_limits();
            let delivery = DeliveryProjection {
                id: recipient_stable_id,
                recipient_id: recipient.id,
                local_actor_id: Some(user.id),
                sender_jid: from,
                stanza: &delayed_delivery,
                encrypted,
                max_messages: offline_limits.max_messages,
                max_bytes: offline_limits.max_bytes,
                ttl_days: offline_limits.ttl_days,
                mam_backed: recipient_history_enabled,
            };
            match self
                .apply_personal_retraction(
                    user.id,
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
                    history_committed = true;
                    durable_c2s_delivery = Some(recipient_stable_id);
                    live_claim_id = admitted_claim_id;
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "local-retraction-durable-c2s",
                    )
                    .await;
                }
                Ok(RetractionOutcome::Replay) => {
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "local-retraction-replay",
                    )
                    .await;
                    return Ok(Action::None);
                }
                Ok(RetractionOutcome::Conflict) => {
                    return Ok(message_error(root, "cancel", "conflict"));
                }
                Ok(RetractionOutcome::Forbidden) => {
                    return Ok(message_error(root, "auth", "forbidden"));
                }
                Ok(RetractionOutcome::AccountUnavailable) => {
                    return Ok(message_error(root, "cancel", "service-unavailable"));
                }
                Ok(RetractionOutcome::CapacityExceeded) => {
                    return Ok(message_error(root, "wait", "resource-constraint"));
                }
                Err(error) => {
                    tracing::warn!(?error, recipient_id = %recipient.id, "local retraction admission failed atomically before delivery");
                    return Ok(message_error(root, "wait", "resource-constraint"));
                }
            }
        }
        if direct_invite_room.is_some() {
            if !matches!(message_type, "normal" | "chat") {
                return Ok(message_error(root, "modify", "bad-request"));
            }
            // A members-only direct invitation needs a durable pending row to
            // make affiliation and delivery one recoverable state machine.
            // Honor an explicit no-store hint by declining instead of
            // silently persisting that row or reintroducing the crash gap.
            if !persistence_allowed {
                return Ok(message_error(root, "wait", "service-unavailable"));
            }
            // RFC 6121 does not permit a normal message to a vanished full
            // resource to fall back to the bare account. Perform that
            // rejection before the durable admission transaction.
            if !bare_target
                && full_no_match_route(message_type) == FullNoMatchRoute::Reject
                && targets.is_empty()
            {
                let remote_exact = self.state.personal_message_remote_resource_exists(to).await;
                if !remote_exact {
                    return Ok(message_error(root, "cancel", "service-unavailable"));
                }
            }
        }
        // All fallible policy reads and deterministic routing rejections are
        // complete. From this point a direct invite is durably recoverable
        // before any in-memory delivery queue can observe it.
        let durable_direct_invite = if let Some(room_id) = direct_invite_room {
            let (room_epoch, config_version) = match direct_invite_admission {
                DirectInviteAdmission::MembersOnly {
                    room_epoch,
                    config_version,
                    ..
                } => (room_epoch, config_version),
                _ => unreachable!("durable direct invite has room authority"),
            };
            let cluster_authority = self.state.direct_muc_invite_cluster_authority(
                recipient_stable_id,
                room_epoch,
                config_version,
                user.id,
                from,
                ClusterMucAffiliationSubject::Local {
                    user_id: recipient.id,
                    bare_jid: recipient_by.clone(),
                },
            )?;
            let delayed = add_delay_from(
                &recipient_delivery,
                chrono::Utc::now(),
                Some(bare_jid(from)),
            );
            let mut writes = Vec::with_capacity(2);
            if sender_history_enabled {
                writes.push(ArchiveWrite {
                    id: sender_stable_id,
                    owner_id: user.id,
                    peer_jid: to,
                    stanza: &sender_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            if recipient.id != user.id && recipient_history_enabled {
                writes.push(ArchiveWrite {
                    id: recipient_stable_id,
                    owner_id: recipient.id,
                    peer_jid: from,
                    stanza: &recipient_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            let identity = origin_id.as_deref().map(|identity_value| {
                let actor_scope = bare_jid(from);
                let target_scope = bare_jid(to);
                MessageIdentity {
                    authority: IdentityAuthority::LocalOrigin,
                    actor_scope_raw: actor_scope,
                    actor_scope,
                    target_scope,
                    value: identity_value,
                    payload: &rewritten,
                }
            });
            let invitation = LocalMucInviteAdmission {
                local_actor_id: user.id,
                identity,
                archives: &writes,
                delivery_id: recipient_stable_id,
                recipient_id: recipient.id,
                recipient_bare_jid: &recipient_by,
                sender_jid: from,
                stanza: &delayed,
                encrypted,
                mam_backed: recipient_history_enabled,
                room_id,
                cluster_authority: cluster_authority.as_ref(),
            };
            match self
                .state
                .message_service()
                .admit_local_muc_invite(&invitation)
                .await?
            {
                DurableMucInviteOutcome::Stored {
                    id,
                    live_claim_id: admitted_claim_id,
                    ..
                } => {
                    history_committed = true;
                    live_claim_id = admitted_claim_id;
                    if cluster_authority.is_some() {
                        if let Err(error) = self
                            .state
                            .wake_committed_direct_muc_invite(recipient_stable_id)
                            .await
                        {
                            self.state.personal_message_telemetry().post_accept_failed();
                            tracing::warn!(?error, %recipient_stable_id, "accepted local direct MUC invite cluster wake failed");
                        }
                    }
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "local-muc-invite",
                    )
                    .await;
                    Some(id)
                }
                DurableMucInviteOutcome::Replay { .. } => {
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "local-muc-invite-replay",
                    )
                    .await;
                    return Ok(Action::None);
                }
                DurableMucInviteOutcome::QuotaExceeded => {
                    return Ok(message_error(root, "wait", "resource-constraint"));
                }
                DurableMucInviteOutcome::Outcast | DurableMucInviteOutcome::AuthorityRejected => {
                    return Ok(message_error(root, "auth", "forbidden"));
                }
                DurableMucInviteOutcome::RecipientUnavailable => {
                    return Ok(message_error(root, "cancel", "service-unavailable"));
                }
                DurableMucInviteOutcome::Stale => {
                    return Ok(message_error(root, "cancel", "item-not-found"));
                }
            }
        } else {
            None
        };
        let live_delivery_id = durable_direct_invite.or(durable_c2s_delivery);
        let live_delivery_message_id = live_delivery_id.unwrap_or(recipient_stable_id);
        if live_delivery_id.is_some()
            && !committed_live_delivery_has_fence(
                self.state
                    .message_service()
                    .clustered_direct_admission_enabled(),
                live_delivery_message_id,
                live_claim_id,
            )
        {
            // A clustered Stored outcome must carry its exact precommit
            // reservation. Never turn an accepted row into an unfenced live
            // delivery even if the health mode recovered after COMMIT.
            self.state.personal_message_telemetry().post_accept_failed();
            tracing::error!(recipient_id = %recipient.id, message_id = ?live_delivery_id,
                "clustered durable direct admission lacked live reservation");
            return Ok(Action::None);
        }
        let live_delivery = live_delivery_id.map(|message_id| crate::outbound::DurableDelivery {
            recipient_id: recipient.id,
            message_id,
            claim_id: live_claim_id,
        });
        let deliver_all = bare_target && bare_message_route(message_type) == BareMessageRoute::All;
        if local_direct {
            // A mode transition can happen while policy reads or PoW
            // finalization await. A committed row remains accepted for
            // recovery, whereas an uncommitted transient stanza must fail.
            match local_direct_live_effect(
                self.state.message_service().direct_mode(),
                live_delivery_id.is_some(),
            ) {
                LocalDirectLiveEffect::Proceed => {}
                LocalDirectLiveEffect::AcceptedForRecovery => {
                    self.state
                        .message_service()
                        .rearm_unrouted_live_direct(
                            recipient.id,
                            live_delivery_message_id,
                            &mut live_claim_id,
                        )
                        .await;
                    return Ok(Action::None);
                }
                LocalDirectLiveEffect::Reject => {
                    return Ok(message_error(root, "wait", "service-unavailable"));
                }
            }
        }
        let route = OnlineMessageRouter::dispatch(
            &*self.state,
            to,
            &recipient_delivery,
            live_delivery,
            deliver_all,
            &targets,
        )
        .await;
        let mut delivered = route.delivered;
        let mut delivered_key = route.accepted_full_jid;

        // RFC 6121 §8.5.3.2 permits chat fallback after an exact resource
        // disappears. The service preserves post-commit privacy/error behavior.
        if !delivered && !bare_target {
            if local_direct {
                match local_direct_live_effect(
                    self.state.message_service().direct_mode(),
                    live_delivery_id.is_some(),
                ) {
                    LocalDirectLiveEffect::Proceed => {}
                    LocalDirectLiveEffect::AcceptedForRecovery => {
                        self.state
                            .message_service()
                            .rearm_unrouted_live_direct(
                                recipient.id,
                                live_delivery_message_id,
                                &mut live_claim_id,
                            )
                            .await;
                        return Ok(Action::None);
                    }
                    LocalDirectLiveEffect::Reject => {
                        return Ok(message_error(root, "wait", "service-unavailable"));
                    }
                }
            }
            let fallback = OnlineMessageRouter::full_jid_fallback(
                &*self.state,
                FullJidFallback {
                    message_type,
                    full_target: to,
                    bare_target: &recipient_by,
                    sender: from,
                    recipient_id: recipient.id,
                    stanza: &recipient_delivery,
                    delivery: live_delivery,
                },
            )
            .await;
            let fallback = match fallback {
                Ok(fallback) => fallback,
                Err(error) if live_delivery_id.is_some() => {
                    self.state
                        .message_service()
                        .rearm_unrouted_live_direct(
                            recipient.id,
                            live_delivery_message_id,
                            &mut live_claim_id,
                        )
                        .await;
                    self.state.personal_message_telemetry().post_accept_failed();
                    tracing::warn!(?error, recipient_id = %recipient.id, %recipient_stable_id,
                        "full-JID fallback failed after durable admission; row remains recoverable");
                    return Ok(Action::None);
                }
                Err(error) => return Err(error),
            };
            match fallback {
                FullJidFallbackResult::Dropped => {
                    self.state
                        .message_service()
                        .rearm_unrouted_live_direct(
                            recipient.id,
                            live_delivery_message_id,
                            &mut live_claim_id,
                        )
                        .await;
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "full-target-drop",
                    )
                    .await;
                    return Ok(Action::None);
                }
                FullJidFallbackResult::Rejected => {
                    if live_delivery_id.is_some() {
                        self.state
                            .message_service()
                            .rearm_unrouted_live_direct(
                                recipient.id,
                                live_delivery_message_id,
                                &mut live_claim_id,
                            )
                            .await;
                        self.state.personal_message_telemetry().post_accept_failed();
                        tracing::warn!(recipient_id = %recipient.id, %recipient_stable_id,
                            "full-JID fallback rejected after durable admission; row remains recoverable");
                        return Ok(Action::None);
                    }
                    return Ok(message_error(root, "cancel", "service-unavailable"));
                }
                FullJidFallbackResult::Undelivered => {}
                FullJidFallbackResult::Delivered(key) => {
                    delivered = true;
                    delivered_key = key;
                }
            }
        }

        if !delivered {
            self.state
                .message_service()
                .rearm_unrouted_live_direct(
                    recipient.id,
                    live_delivery_message_id,
                    &mut live_claim_id,
                )
                .await;
        }

        if local_direct {
            match local_direct_live_effect(
                self.state.message_service().direct_mode(),
                live_delivery_id.is_some(),
            ) {
                LocalDirectLiveEffect::Proceed => {}
                LocalDirectLiveEffect::AcceptedForRecovery => return Ok(Action::None),
                LocalDirectLiveEffect::Reject if delivered => {
                    // The live queue accepted the volatile stanza before the
                    // transition. An error now would invite a duplicate.
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "online-before-degrade",
                    )
                    .await;
                    return Ok(Action::None);
                }
                LocalDirectLiveEffect::Reject => {
                    return Ok(message_error(root, "wait", "service-unavailable"));
                }
            }
        }

        let mut stored_offline = false;
        if !delivered {
            if direct_delivery_mode == DirectDeliveryMode::VolatileExplicitNoStore {
                // XEP-0334 no-store forbids every durable fallback, but it
                // does not forbid an online volatile delivery. Only report a
                // failure after local and cluster routes have actually
                // declined the stanza.
                return Ok(message_error(root, "wait", "service-unavailable"));
            }
            if live_delivery_id.is_some() {
                stored_offline = true;
                if local_direct
                    && self.state.message_service().direct_mode() != DirectPostCommitMode::Live
                {
                    return Ok(Action::None);
                }
                // This check precedes the Push call; a provider request
                // already in flight cannot be recalled by a later transition.
                if let Err(error) = self.notify_push(recipient.id).await {
                    self.state.personal_message_telemetry().post_accept_failed();
                    tracing::warn!(?error, recipient_id = %recipient.id, %recipient_stable_id, "durable direct MUC invite was accepted but push notification failed");
                }
            } else {
                match undelivered_disposition(
                    message_type,
                    persistence_allowed,
                    durable_content_allowed,
                ) {
                    UndeliveredDisposition::Drop => {
                        self.finalize_message_admission(
                            &mut message_admission_lease,
                            "undelivered-drop",
                        )
                        .await;
                        return Ok(Action::None);
                    }
                    UndeliveredDisposition::RejectCancel => {
                        return Ok(message_error(root, "cancel", "service-unavailable"));
                    }
                    UndeliveredDisposition::RejectWait => {
                        return Ok(message_error(root, "wait", "service-unavailable"));
                    }
                    UndeliveredDisposition::StoreOffline => {
                        let delayed = add_delay_from(
                            &recipient_archive_stanza,
                            chrono::Utc::now(),
                            Some(self.state.local_domain()),
                        );
                        let offline = admit_offline_then_push(
                            self.state.message_service().store_offline(
                                crate::services::messaging::OfflineMessageAdmission {
                                    recipient_id: recipient.id,
                                    recipient_bare_jid: &recipient_by,
                                    sender_jid: from,
                                    stanza: &delayed,
                                    encrypted,
                                    mam_backed: recipient_history_enabled,
                                    identity: message_admission_lease
                                        .as_ref()
                                        .map(|lease| &lease.offline_dedupe),
                                },
                            ),
                            history_committed,
                            async {
                                if local_direct
                                    && self.state.message_service().direct_mode()
                                        != DirectPostCommitMode::Live
                                {
                                    Ok(())
                                } else {
                                    self.state.dispatch_push_notification(recipient.id).await
                                }
                            },
                        )
                        .await?;
                        match offline.admission {
                            OfflineAdmissionOutcome::QuotaExceeded if history_committed => {
                                // A pre-admitted recipient MAM row is durable
                                // recovery. Returning an error here would invite a
                                // duplicate retry after the server already
                                // accepted the origin-id.
                                if let Some(error) = offline.push_error {
                                    self.state.personal_message_telemetry().post_accept_failed();
                                    tracing::warn!(?error, recipient_id = %recipient.id, %recipient_stable_id, "MAM-backed message was accepted but offline quota and push delivery both failed");
                                }
                                stored_offline = true;
                            }
                            OfflineAdmissionOutcome::QuotaExceeded => {
                                return Ok(message_error(root, "wait", "service-unavailable"));
                            }
                            OfflineAdmissionOutcome::Stored => {
                                stored_offline = true;
                                if let Some(error) = offline.push_error {
                                    self.state.personal_message_telemetry().post_accept_failed();
                                    tracing::warn!(?error, recipient_id = %recipient.id, %recipient_stable_id, "offline message was accepted but push notification failed");
                                }
                            }
                            OfflineAdmissionOutcome::Replay => {
                                // The content row may already have been delivered
                                // and deleted. The compact tombstone is the
                                // terminal acceptance record; do not enqueue or
                                // notify a second time.
                                stored_offline = true;
                            }
                            OfflineAdmissionOutcome::RecipientUnavailable => {
                                return Ok(message_error(root, "cancel", "service-unavailable"));
                            }
                        }
                    }
                }
            }
        } else if should_carbon(root)
            && recipient.id != user.id
            && (!local_direct
                || self.state.message_service().direct_mode() == DirectPostCommitMode::Live)
        {
            if let Some(delivered_key) = delivered_key.as_deref() {
                self.send_received_carbons(bare_jid(to), Some(delivered_key), &recipient_delivery)
                    .await;
            }
        }

        // Durable direct deliveries and all personal retractions committed
        // their complete history/delivery transaction before routing. Only
        // legacy best-effort non-retraction message types may archive here.
        let accepted_route = if stored_offline { "offline" } else { "online" };
        self.finalize_message_admission(&mut message_admission_lease, accepted_route)
            .await;
        debug_assert!(
            !personal_retraction || history_committed,
            "a personal retraction reached fanout without durable admission"
        );
        if !history_committed && !personal_retraction {
            let mut writes = Vec::with_capacity(2);
            if sender_history_enabled {
                writes.push(ArchiveWrite {
                    id: sender_stable_id,
                    owner_id: user.id,
                    peer_jid: to,
                    stanza: &sender_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            if recipient.id != user.id && recipient_history_enabled {
                writes.push(ArchiveWrite {
                    id: recipient_stable_id,
                    owner_id: recipient.id,
                    peer_jid: from,
                    stanza: &recipient_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            let history_result = if writes.is_empty() {
                Ok(())
            } else {
                self.state.message_service().admit_history(&writes).await
            };
            if let Err(error) = history_result {
                self.state.personal_message_telemetry().post_accept_failed();
                tracing::warn!(?error, %sender_stable_id, route = accepted_route, "accepted message history transaction failed atomically");
            }
        }
        if should_carbon(root)
            && (!local_direct
                || self.state.message_service().direct_mode() == DirectPostCommitMode::Live)
        {
            let delivered_self = (recipient.id == user.id)
                .then_some(delivered_key.as_deref())
                .flatten();
            self.send_sent_carbons(from, &sender_archive, delivered_self, None)
                .await;
        }
        self.state.personal_message_telemetry().message_routed();
        Ok(Action::None)
    }

    async fn finalize_message_admission(
        &self,
        lease: &mut Option<MessageAdmissionLease>,
        route: &'static str,
    ) {
        let Some(lease) = lease.take() else {
            return;
        };
        if let Err(error) = self
            .state
            .message_admission_service()
            .accept_message_admission(&lease)
            .await
        {
            // The route has already accepted the stanza. Returning an error
            // would encourage a duplicate retry, so expose the remaining
            // at-least-once recovery window only through logs and metrics.
            self.state.personal_message_telemetry().post_accept_failed();
            tracing::warn!(
                ?error,
                route,
                "accepted message PoW admission could not be finalized"
            );
        }
    }

    async fn direct_invite_admission(
        &self,
        root: Node<'_, '_>,
        inviter_id: uuid::Uuid,
    ) -> Result<DirectInviteAdmission> {
        let Some(room_jid) = root
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "x"
                    && node.tag_name().namespace() == Some("jabber:x:conference")
            })
            .and_then(|node| node.attribute("jid"))
            .and_then(|jid| crate::jid::CanonicalJid::parse_bare(jid).ok())
            .filter(|jid| jid.domainpart() == self.muc_domain() && jid.localpart().is_some())
        else {
            return Ok(DirectInviteAdmission::None);
        };
        let Some(room) = self
            .state
            .muc_service()
            .room(
                room_jid
                    .localpart()
                    .expect("validated MUC room has a localpart"),
            )
            .await?
        else {
            return Ok(DirectInviteAdmission::None);
        };
        if !room.members_only {
            return Ok(DirectInviteAdmission::None);
        }
        let affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, inviter_id)
            .await?;
        Ok(
            if affiliation
                .as_deref()
                .is_some_and(|value| matches!(value, "owner" | "admin" | "member"))
            {
                DirectInviteAdmission::MembersOnly {
                    room_id: room.id,
                    room_epoch: room.room_epoch,
                    config_version: room.config_version,
                }
            } else {
                DirectInviteAdmission::Forbidden
            },
        )
    }

    pub(crate) async fn send_sent_carbons(
        &self,
        from: &str,
        forwarded: &str,
        delivered_self: Option<&str>,
        muc_scope: Option<(&str, &str)>,
    ) {
        crate::services::message_carbons::send_sent_carbons(
            &*self.state,
            from,
            forwarded,
            delivered_self,
            muc_scope,
        )
        .await;
    }

    pub(crate) async fn send_received_carbons(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) {
        crate::services::message_carbons::send_received_carbons(
            &*self.state,
            recipient,
            delivered,
            forwarded,
        )
        .await;
    }
}

fn direct_origin_id(root: Node<'_, '_>) -> Option<String> {
    root.children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "origin-id"
                && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
        })
        .and_then(|node| node.attribute("id"))
        .map(str::to_owned)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectInviteAdmission {
    None,
    MembersOnly {
        room_id: uuid::Uuid,
        room_epoch: uuid::Uuid,
        config_version: i64,
    },
    Forbidden,
}

/// RFC 6120 forbids generating a stanza error in response to a stanza that
/// is already of type `error`. Keep that invariant at every rejection point
/// in the message pipeline, including policy and federation failures.
fn message_error(root: Node<'_, '_>, error_type: &str, condition: &str) -> Action {
    if root.attribute("type") == Some("error") {
        Action::None
    } else {
        Action::Send(stanza_error(root, error_type, condition))
    }
}

fn message_blocked_error(root: Node<'_, '_>) -> Action {
    if root.attribute("type") == Some("error") {
        Action::None
    } else {
        Action::Send(blocked_stanza_error(root))
    }
}

#[cfg(test)]
fn offline_storage_eligible(root: Node<'_, '_>) -> bool {
    matches!(
        root.attribute("type").unwrap_or("normal"),
        "normal" | "chat"
    )
}

/// Classify direct messages without conflating an explicit XEP-0334 privacy
/// request with the protocol defaults for ephemeral signal-only messages.
pub(crate) fn direct_delivery_mode(root: Node<'_, '_>) -> DirectDeliveryMode {
    northstar_message_core::classify_direct_delivery(
        has_explicit_no_store_hint(root),
        offline_storage_permitted(root),
    )
}

/// Return the exact client-controlled commitment used by PoW v2. Routing uses
/// a separate server-authoritative stanza whose `from` and inherited
/// `xml:lang` may have been materialized at dispatch. Those assertions must
/// never become bytes the client is required to predict.
fn message_pow_intent_payload(client_raw: &str) -> String {
    strip_untrusted_direct_delays(&strip_pow_element(client_raw), None)
}

#[cfg(test)]
mod tests {
    use super::{
        bare_message_route, degraded_local_direct_eligible, direct_delivery_mode,
        direct_spool_eligibility, durable_direct_delivery_allowed, durable_full_no_match_recovers,
        full_no_match_route, local_direct_live_effect, message_pow_intent_payload,
        missing_user_message_should_error, mixes_personal_retraction_and_direct_invite,
        offline_storage_eligible, undelivered_disposition, wake_federation_outbox_after_commit,
        BareMessageRoute, DirectDeliveryMode, DirectPostCommitMode, DirectSpoolEligibility,
        DurableAdmissionOutcome, FullNoMatchRoute, LocalDirectLiveEffect, MessagePostCommit,
        UndeliveredDisposition,
    };
    use crate::{
        abuse::{AbuseAction, PowIntent},
        xmpp::xml_util::{
            set_from, set_root_attribute, strip_pow_element, strip_untrusted_direct_delays,
        },
    };
    use roxmltree::Document;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn federation_outbox_wake_waits_for_durable_commit() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let wake_count = Arc::clone(&wakes);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (commit_tx, commit_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            wake_federation_outbox_after_commit(
                async move {
                    started_tx.send(()).unwrap();
                    commit_rx.await.unwrap()
                },
                move || {
                    wake_count.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await
        });

        started_rx.await.unwrap();
        assert_eq!(wakes.load(Ordering::SeqCst), 0);
        commit_tx
            .send(Ok(DurableAdmissionOutcome::Stored {
                archive_written: true,
                post_commit: MessagePostCommit::WakeFederationOutbox,
            }))
            .unwrap();
        assert!(matches!(
            task.await.unwrap().unwrap(),
            DurableAdmissionOutcome::Stored { .. }
        ));
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn federation_outbox_wake_ignores_failed_and_non_stored_commits() {
        let wakes = AtomicUsize::new(0);
        let outcomes = [
            (Err(anyhow::anyhow!("injected commit failure")), true),
            (Ok(DurableAdmissionOutcome::Replay), false),
            (Ok(DurableAdmissionOutcome::AccountUnavailable), false),
            (
                Ok(DurableAdmissionOutcome::Stored {
                    archive_written: false,
                    post_commit: MessagePostCommit::RouteLocalDelivery {
                        delivery_id: uuid::Uuid::nil(),
                        recipient_id: uuid::Uuid::nil(),
                    },
                }),
                false,
            ),
        ];
        for (outcome, expected_error) in outcomes {
            let result = wake_federation_outbox_after_commit(std::future::ready(outcome), || {
                wakes.fetch_add(1, Ordering::SeqCst);
            })
            .await;
            assert_eq!(result.is_err(), expected_error);
            assert_eq!(wakes.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn signal_only_messages_use_volatile_online_delivery() {
        for xml in [
            "<message type='chat'><received xmlns='urn:xmpp:receipts' id='m1'/></message>",
            "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                direct_delivery_mode(document.root_element()),
                DirectDeliveryMode::Volatile
            );
        }

        let durable = Document::parse("<message type='chat'><body>hello</body></message>").unwrap();
        assert_eq!(
            direct_delivery_mode(durable.root_element()),
            DirectDeliveryMode::Durable
        );

        let no_store = Document::parse(
            "<message type='chat'><body>private</body><no-store xmlns='urn:xmpp:hints'/></message>",
        )
        .unwrap();
        assert_eq!(
            direct_delivery_mode(no_store.root_element()),
            DirectDeliveryMode::VolatileExplicitNoStore
        );
        assert!(durable_direct_delivery_allowed(
            DirectDeliveryMode::Durable,
            true
        ));
        assert!(!durable_direct_delivery_allowed(
            DirectDeliveryMode::Durable,
            false
        ));
        assert!(!durable_direct_delivery_allowed(
            DirectDeliveryMode::Volatile,
            true
        ));
    }

    #[test]
    fn degraded_direct_spool_accepts_only_bare_storage_eligible_content() {
        let accepted = [
            "<message type='chat'><body>hello</body></message>",
            "<message type='chat'><body>hello</body><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
            "<message type='normal'><body>hello</body></message>",
            "<message><body>hello</body></message>",
        ];
        for xml in accepted {
            let document = Document::parse(xml).unwrap();
            assert!(degraded_local_direct_eligible(
                document.root_element(),
                true,
                false,
                false,
            ));
        }

        let rejected = [
            "<message type='chat'><body>private</body><no-store xmlns='urn:xmpp:hints'/></message>",
            "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
            "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/><store xmlns='urn:xmpp:hints'/></message>",
            "<message type='chat'><received xmlns='urn:xmpp:receipts' id='m1'/><store xmlns='urn:xmpp:hints'/></message>",
            "<message type='headline'><body>news</body></message>",
            "<message type='groupchat'><body>hello</body></message>",
            "<message type='chat'><body>join</body><x xmlns='jabber:x:conference' jid='room@conference.example.test'/></message>",
            "<message type='normal'><pubsub xmlns='http://jabber.org/protocol/pubsub' node='push'><affiliation affiliation='none' jid='push.example.test'/></pubsub><store xmlns='urn:xmpp:hints'/></message>",
        ];
        for xml in rejected {
            let document = Document::parse(xml).unwrap();
            assert!(
                !degraded_local_direct_eligible(document.root_element(), true, false, false,),
                "unexpected degraded spool eligibility: {xml}"
            );
        }

        let plain = Document::parse("<message type='chat'><body>hello</body></message>").unwrap();
        assert!(
            !degraded_local_direct_eligible(plain.root_element(), false, false, false,),
            "a full JID has no account-scoped spool fallback"
        );
        assert!(
            !degraded_local_direct_eligible(plain.root_element(), true, true, false,),
            "a retraction is a separate history mutation"
        );
        assert!(
            !degraded_local_direct_eligible(plain.root_element(), true, false, true,),
            "deployment encryption policy still applies"
        );
    }

    #[test]
    fn account_privacy_denial_keeps_a_live_route_out_of_degraded_spool() {
        assert_eq!(
            direct_spool_eligibility(true, true),
            DirectSpoolEligibility::Eligible
        );
        assert_eq!(
            direct_spool_eligibility(true, false),
            DirectSpoolEligibility::LiveOnly
        );
        assert_eq!(
            direct_spool_eligibility(false, true),
            DirectSpoolEligibility::LiveOnly
        );
    }

    #[test]
    fn mode_change_after_commit_preserves_recovery_without_live_effects() {
        for mode in [
            DirectPostCommitMode::SpoolOnly,
            DirectPostCommitMode::Rejected,
        ] {
            assert_eq!(
                local_direct_live_effect(mode, true),
                LocalDirectLiveEffect::AcceptedForRecovery
            );
            assert_eq!(
                local_direct_live_effect(mode, false),
                LocalDirectLiveEffect::Reject
            );
        }
        assert_eq!(
            local_direct_live_effect(DirectPostCommitMode::Live, true),
            LocalDirectLiveEffect::Proceed
        );
    }

    #[test]
    fn routed_copy_preserves_private_marker_for_recipient_server() {
        let source = "<message to='bob@example.net' type='chat'><private xmlns='urn:xmpp:carbons:2'/><body>secret</body><pow xmlns='urn:northstar:pow:1' challenge='1' nonce='2'/></message>";
        let routed = strip_untrusted_direct_delays(&strip_pow_element(source), None);
        assert!(routed.contains("<private xmlns='urn:xmpp:carbons:2'/>"));
        assert!(!routed.contains("urn:northstar:pow:1"));
    }

    #[test]
    fn mixed_retraction_and_direct_invite_is_rejected_before_branch_selection() {
        let mixed = Document::parse(
            "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='target'/><x xmlns='jabber:x:conference' jid='room@conference.example.test'/></message>",
        )
        .unwrap();
        assert!(mixes_personal_retraction_and_direct_invite(
            mixed.root_element()
        ));

        let fallback = Document::parse(
            "<message id='action'><body>removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target'/></message>",
        )
        .unwrap();
        assert!(!mixes_personal_retraction_and_direct_invite(
            fallback.root_element()
        ));
    }

    #[test]
    fn message_pow_commits_client_bytes_not_server_routing_assertions() {
        let client = "<message xmlns='jabber:client' to='bob@example.test' type='chat'><body>one</body><pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000001' nonce='0'/></message>";
        let client_document = Document::parse(client).unwrap();
        let language = set_root_attribute(client, "xml:lang", "en");
        let authoritative = set_from(&language, "alice@example.test/phone");
        assert_ne!(
            message_pow_intent_payload(client),
            message_pow_intent_payload(&authoritative),
            "server assertions must be distinguishable from the client commitment"
        );

        let challenge = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            message_pow_intent_payload(client).as_bytes(),
        );
        // Dispatch retains `client` alongside `authoritative`; verification
        // therefore reconstructs exactly the intent the client requested.
        let verification = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            message_pow_intent_payload(client).as_bytes(),
        );
        assert_eq!(challenge, verification);
        assert_eq!(client_document.root_element().attribute("from"), None);

        let changed = client.replace("<body>one</body>", "<body>owe</body>");
        let changed = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            message_pow_intent_payload(&changed).as_bytes(),
        );
        assert_ne!(
            challenge, changed,
            "one client payload byte change must reject"
        );
    }

    #[test]
    fn offline_storage_is_limited_to_normal_and_chat_messages() {
        for kind in [None, Some("normal"), Some("chat")] {
            let attribute = kind
                .map(|kind| format!(" type='{kind}'"))
                .unwrap_or_default();
            let xml = format!("<message{attribute}/>");
            let document = Document::parse(&xml).unwrap();
            assert!(offline_storage_eligible(document.root_element()));
        }
        for kind in ["groupchat", "headline", "error"] {
            let xml = format!("<message type='{kind}'/>");
            let document = Document::parse(&xml).unwrap();
            assert!(!offline_storage_eligible(document.root_element()));
        }
    }

    #[test]
    fn rfc6121_message_routing_modes_are_type_specific() {
        assert_eq!(bare_message_route("normal"), BareMessageRoute::Primary);
        assert_eq!(bare_message_route("chat"), BareMessageRoute::Primary);
        assert_eq!(bare_message_route("headline"), BareMessageRoute::All);
        assert_eq!(bare_message_route("groupchat"), BareMessageRoute::Reject);
        assert_eq!(bare_message_route("error"), BareMessageRoute::Ignore);

        assert_eq!(full_no_match_route("chat"), FullNoMatchRoute::FallbackChat);
        for kind in ["normal", "groupchat", "headline"] {
            assert_eq!(full_no_match_route(kind), FullNoMatchRoute::Reject);
        }
        assert_eq!(full_no_match_route("error"), FullNoMatchRoute::Ignore);
        assert!(durable_full_no_match_recovers("normal", true));
        assert!(!durable_full_no_match_recovers("normal", false));
        assert!(!durable_full_no_match_recovers("chat", true));

        for kind in ["normal", "chat", "groupchat"] {
            assert!(missing_user_message_should_error(kind));
        }
        for kind in ["headline", "error"] {
            assert!(!missing_user_message_should_error(kind));
        }
    }

    #[test]
    fn durable_direct_message_kinds_never_use_multi_resource_fanout() {
        for kind in ["normal", "chat"] {
            assert_ne!(bare_message_route(kind), BareMessageRoute::All);
        }
        assert_eq!(bare_message_route("headline"), BareMessageRoute::All);
    }

    #[test]
    fn only_offline_admission_can_cross_the_personal_side_effect_boundary() {
        assert_eq!(
            undelivered_disposition("headline", true, true),
            UndeliveredDisposition::Drop
        );
        assert_eq!(
            undelivered_disposition("chat", false, true),
            UndeliveredDisposition::Drop
        );
        assert_eq!(
            undelivered_disposition("groupchat", true, true),
            UndeliveredDisposition::RejectCancel
        );
        assert_eq!(
            undelivered_disposition("chat", true, false),
            UndeliveredDisposition::RejectWait
        );
        for kind in ["normal", "chat"] {
            assert_eq!(
                undelivered_disposition(kind, true, true),
                UndeliveredDisposition::StoreOffline
            );
        }
    }
}
