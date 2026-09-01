use super::{Action, ProtocolSession};
use crate::services::messaging::{
    ArchiveWrite, DurableAdmissionOutcome, LocalMessageAdmission, LocalMucInviteAdmission,
    LocalRecipientDecision, MessageIdentity, OfflineAdmissionOutcome, OutboundPolicyDecision,
    RemoteMessageAdmission, RemoteMucInviteAdmission, RemoteMucInviteAdmissionOutcome,
};
use crate::services::muc::{
    ClusterMucAffiliationSubject, ClusterMucInviteAuthority, ClusterMucPrincipal,
    DurableMucInviteOutcome,
};
use crate::services::privacy::PrivacyStanzaKind;
use crate::services::retractions::{DeliveryProjection, RetractionOutcome};
use crate::xmpp::xml_util::*;
use crate::{
    abuse::{MessageAdmissionLease, MessageAdmissionRequest, MessageAdmissionStart, PowProof},
    state::{bare_jid, AppState},
};
use anyhow::Result;
use futures::{stream::FuturesUnordered, StreamExt};
use roxmltree::Node;
use std::{future::Future, pin::Pin, sync::atomic::Ordering, time::Duration};

const CARBON_FANOUT_CONCURRENCY: usize = 8;
// Carbons are post-accept, volatile copies. A half-second queue/privacy budget
// isolates a slow resource while the eight-wide bound keeps the default
// 64-resource account fanout below the old five-second shared deadline even
// when every target is unhealthy.
const CARBON_TARGET_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CarbonFanoutAttempt {
    Delivered,
    Skipped,
    Failed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CarbonFanoutSummary {
    delivered: usize,
    failed: usize,
    timed_out: usize,
    timed_out_targets: Vec<String>,
}

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

type CarbonFanoutFuture<'a> = Pin<Box<dyn Future<Output = CarbonFanoutAttempt> + Send + 'a>>;

async fn timed_carbon_attempt(
    target: String,
    attempt: CarbonFanoutFuture<'_>,
    target_timeout: Duration,
) -> (
    String,
    Result<CarbonFanoutAttempt, tokio::time::error::Elapsed>,
) {
    (target, tokio::time::timeout(target_timeout, attempt).await)
}

async fn bounded_carbon_fanout(
    attempts: Vec<(String, CarbonFanoutFuture<'_>)>,
    concurrency: usize,
    target_timeout: Duration,
) -> CarbonFanoutSummary {
    // Clamp even internal callers so a future refactor cannot accidentally
    // turn per-message fanout into an unbounded set of in-flight DB/queue
    // operations.
    let concurrency = concurrency.clamp(1, CARBON_FANOUT_CONCURRENCY);
    let mut pending = attempts.into_iter();
    let mut in_flight = FuturesUnordered::new();
    for (target, attempt) in pending.by_ref().take(concurrency) {
        in_flight.push(timed_carbon_attempt(target, attempt, target_timeout));
    }
    let mut summary = CarbonFanoutSummary::default();
    while let Some((target, result)) = in_flight.next().await {
        match result {
            Ok(CarbonFanoutAttempt::Delivered) => summary.delivered += 1,
            Ok(CarbonFanoutAttempt::Skipped) => {}
            Ok(CarbonFanoutAttempt::Failed) => summary.failed += 1,
            Err(_) => {
                summary.failed += 1;
                summary.timed_out += 1;
                summary.timed_out_targets.push(target);
            }
        }
        if let Some((target, attempt)) = pending.next() {
            in_flight.push(timed_carbon_attempt(target, attempt, target_timeout));
        }
    }
    summary
}

impl ProtocolSession {
    pub(crate) async fn message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        client_raw: &str,
    ) -> Result<Action> {
        let _routing_timer = self.state.metrics.routing_duration_seconds.start_timer();
        let Some(user) = &self.authenticated else {
            return Ok(message_error(root, "auth", "not-authorized"));
        };
        let Some(from) = self.full_jid.as_deref() else {
            return Ok(message_error(root, "cancel", "not-authorized"));
        };
        if let Err(condition) = validate_routed_message(root) {
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
        // RFC 6120 section 10.3.1 treats a client message without `to` as
        // addressed to the sender's bare JID. This is commonly used to fan a
        // message out to the account's other available resources.
        let raw_to = root.attribute("to").unwrap_or_else(|| bare_jid(from));
        let target_jid = match crate::jid::CanonicalJid::parse(raw_to) {
            Ok(target) => target,
            Err(_) => return Ok(message_error(root, "modify", "jid-malformed")),
        };
        let canonical_to = target_jid.to_string();
        let to = canonical_to.as_str();
        let mut message_admission_lease = None;
        if is_abuse_rated_message(root) {
            let normalized_admission_payload =
                set_root_attribute(&set_from(&routed_raw, bare_jid(from)), "to", to);
            let subject = format!("message:{}", user.id);
            let admission_origin_id = direct_origin_id(root);
            let admission = self
                .state
                .abuse
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
                    self.state
                        .metrics
                        .rate_limited_total
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(Action::Send(abuse_stanza_error(root, &requirement)));
                }
                Ok(MessageAdmissionStart::Denied(error)) => {
                    self.state
                        .metrics
                        .rate_limited_total
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(Action::Send(abuse_stanza_error(root, error.requirement())));
                }
                Ok(MessageAdmissionStart::Conflict) => {
                    return Ok(message_error(root, "cancel", "conflict"));
                }
                Ok(MessageAdmissionStart::CapacityLimited) => {
                    self.state
                        .metrics
                        .rate_limited_total
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(message_error(root, "wait", "resource-constraint"));
                }
                Err(error) => {
                    // Proof consumption, actor advancement and the pending
                    // admission all roll back on this path. Fail closed before
                    // any routing/archive side effect.
                    if crate::abuse::is_abuse_state_busy(&error) {
                        tracing::warn!(user_id = %user.id, "message anti-abuse actor state was busy; rejected without waiting on a database connection lock");
                        self.state
                            .metrics
                            .rate_limited_total
                            .fetch_add(1, Ordering::Relaxed);
                        return Ok(message_error(root, "wait", "resource-constraint"));
                    }
                    tracing::error!(?error, user_id = %user.id, "message anti-abuse backend failed before acceptance");
                    self.state
                        .metrics
                        .anti_abuse_backend_failures_total
                        .fetch_add(1, Ordering::Relaxed);
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
        let remote_domain = (target_domain != self.state.config.domain
            && target_domain != self.muc_domain()
            && target_domain != self.upload_domain()
            && target_domain != self.pubsub_domain())
        .then_some(target_domain);
        if let Some(domain) = remote_domain {
            if !self.state.config.external_route_domain_allowed(domain) {
                return Ok(message_error(root, "cancel", "remote-server-not-found"));
            }
            let stable_id = uuid::Uuid::new_v4();
            let rewritten = set_from(&routed_raw, from);
            let routed = strip_stanza_ids_by_domain(&rewritten, &self.state.config.domain);
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
                    &self.state.config.domain,
                    domain,
                    routed,
                )
                .await
                {
                    tracing::debug!(
                        source_domain = %self.state.config.domain,
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
                self.state
                    .metrics
                    .messages_routed_total
                    .fetch_add(1, Ordering::Relaxed);
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
                let cluster_authority = if self.state.cluster.is_enabled() {
                    self.state
                        .cluster
                        .admit(crate::cluster::ClusterOperation::MucMutation)?;
                    Some(ClusterMucInviteAuthority {
                        operation_id: stable_id,
                        expected_room_epoch: room_epoch,
                        expected_config_version: config_version,
                        actor: ClusterMucPrincipal::Local {
                            user_id: user.id,
                            bare_jid: bare_jid(from).to_owned(),
                        },
                        actor_full_jid: from.to_owned(),
                        actor_target: None,
                        subject: ClusterMucAffiliationSubject::Federated {
                            bare_jid: target_jid.bare(),
                        },
                        reason: None,
                    })
                } else {
                    None
                };
                let actor_scope = bare_jid(from);
                let target_scope = bare_jid(to);
                let invitee_bare_jid = target_jid.bare();
                let origin_id = direct_origin_id(root);
                let identity = origin_id.as_deref().map(|id| MessageIdentity {
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
                    outbox_policy: self.state.federation.outbox_policy().into(),
                    cluster_authority: cluster_authority.as_ref(),
                };
                match self
                    .state
                    .message_service()
                    .admit_remote_muc_invite(&admission)
                    .await
                {
                    Ok(RemoteMucInviteAdmissionOutcome::Stored) => {
                        self.state.federation.wake_outbox();
                        if cluster_authority.is_some() {
                            if let Err(error) = self
                                .state
                                .muc_service()
                                .wake_committed_operation(&self.state.cluster, stable_id)
                                .await
                            {
                                self.state
                                    .metrics
                                    .post_accept_side_effect_failures_total
                                    .fetch_add(1, Ordering::Relaxed);
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
                        self.state.federation.wake_outbox();
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
                    actor_scope_raw: actor_scope,
                    actor_scope,
                    target_scope,
                    value: id,
                    payload: &rewritten,
                });
                let admission = RemoteMessageAdmission {
                    local_actor_id: user.id,
                    identity,
                    archives: &writes,
                    target_domain: domain,
                    stanza: &routed,
                    bounce_to: Some(from),
                    outbox_policy: self.state.federation.outbox_policy().into(),
                };
                match self
                    .state
                    .message_service()
                    .admit_remote_message(&admission)
                    .await
                {
                    Ok(DurableAdmissionOutcome::Stored { .. }) => {
                        self.state.federation.wake_outbox();
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
            self.state
                .metrics
                .messages_routed_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Action::None);
        }
        let Some(recipient_local) = target_jid.localpart() else {
            return Ok(message_error(root, "cancel", "service-unavailable"));
        };
        let recipient = match self
            .state
            .message_service()
            .resolve_local_recipient(recipient_local, &self.state.config.domain, from)
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
        let recipient_by = format!("{}@{}", recipient.username, self.state.config.domain);
        let rewritten = set_from(&routed_raw, from);
        let routed = strip_stanza_ids_by_domain(&rewritten, &self.state.config.domain);
        let sender_archive = add_stanza_id(&rewritten, bare_jid(from), sender_stable_id);
        let recipient_delivery = if recipient.id == user.id {
            sender_archive.clone()
        } else {
            add_stanza_id(&routed, &recipient_by, recipient_stable_id)
        };
        let encrypted = is_encrypted(root);
        let durable_content_allowed = encrypted || !self.state.config.require_encrypted_archive;
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
        let mut targets = self.state.session_entries_for(to);
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
        let remote_route_exists = self
            .state
            .cluster
            .lookup_nodes(to)
            .await
            .is_ok_and(|nodes| {
                nodes
                    .into_iter()
                    .any(|node| node != self.state.cluster.node_id)
            });
        if targets.is_empty()
            && !remote_route_exists
            && self
                .state
                .message_service()
                .default_recipient_privacy_denies(recipient.id, from)
                .await?
        {
            return Ok(message_error(root, "cancel", "service-unavailable"));
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
            || self
                .state
                .cluster
                .lookup_nodes(to)
                .await
                .is_ok_and(|nodes| {
                    nodes
                        .into_iter()
                        .any(|node_id| node_id != self.state.cluster.node_id)
                });
        let mut history_committed = false;
        let mut durable_c2s_delivery = None;
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
                Some(&self.state.config.domain),
            );
            let admission = LocalMessageAdmission {
                local_actor_id: Some(user.id),
                identity,
                archives: &writes,
                delivery_id: recipient_stable_id,
                recipient_id: recipient.id,
                recipient_bare_jid: &recipient_by,
                sender_jid: from,
                stanza: &delayed_delivery,
                encrypted,
                mam_backed: recipient_history_enabled,
            };
            match self
                .state
                .message_service()
                .admit_local_message(&admission)
                .await
            {
                Ok(DurableAdmissionOutcome::Stored { archive_written }) => {
                    history_committed = archive_written;
                    durable_c2s_delivery = Some(recipient_stable_id);
                    tracing::debug!(
                        recipient_id = %recipient.id,
                        message_id = %recipient_stable_id,
                        target = %to,
                        "committed durable C2S delivery before route attempt"
                    );
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "local-durable-c2s",
                    )
                    .await;
                }
                Ok(DurableAdmissionOutcome::Replay) => {
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "local-durable-c2s-replay",
                    )
                    .await;
                    return Ok(Action::None);
                }
                Ok(DurableAdmissionOutcome::AccountUnavailable) => {
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
                Some(&self.state.config.domain),
            );
            let delivery = DeliveryProjection {
                id: recipient_stable_id,
                recipient_id: recipient.id,
                local_actor_id: Some(user.id),
                sender_jid: from,
                stanza: &delayed_delivery,
                encrypted,
                max_messages: self.state.config.offline_max_messages_per_account,
                max_bytes: self.state.config.offline_max_bytes_per_account,
                ttl_days: self.state.config.offline_message_ttl_days,
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
                Ok(RetractionOutcome::Applied { .. }) => {
                    history_committed = true;
                    durable_c2s_delivery = Some(recipient_stable_id);
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
                let remote_exact = self
                    .state
                    .cluster
                    .lookup_nodes(to)
                    .await
                    .is_ok_and(|nodes| {
                        nodes
                            .into_iter()
                            .any(|node_id| node_id != self.state.cluster.node_id)
                    });
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
            let cluster_authority = if self.state.cluster.is_enabled() {
                self.state
                    .cluster
                    .admit(crate::cluster::ClusterOperation::MucMutation)?;
                Some(ClusterMucInviteAuthority {
                    operation_id: recipient_stable_id,
                    expected_room_epoch: room_epoch,
                    expected_config_version: config_version,
                    actor: ClusterMucPrincipal::Local {
                        user_id: user.id,
                        bare_jid: bare_jid(from).to_owned(),
                    },
                    actor_full_jid: from.to_owned(),
                    actor_target: None,
                    subject: ClusterMucAffiliationSubject::Local {
                        user_id: recipient.id,
                        bare_jid: recipient_by.clone(),
                    },
                    reason: None,
                })
            } else {
                None
            };
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
                DurableMucInviteOutcome::Stored { id, .. } => {
                    history_committed = true;
                    if cluster_authority.is_some() {
                        if let Err(error) = self
                            .state
                            .muc_service()
                            .wake_committed_operation(&self.state.cluster, recipient_stable_id)
                            .await
                        {
                            self.state
                                .metrics
                                .post_accept_side_effect_failures_total
                                .fetch_add(1, Ordering::Relaxed);
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
        let live_delivery = live_delivery_id.map(|message_id| crate::outbound::DurableDelivery {
            recipient_id: recipient.id,
            message_id,
            claim_id: None,
        });
        let deliver_all = bare_target && bare_message_route(message_type) == BareMessageRoute::All;
        // A durable spool row has exactly one transport owner. RFC 6121
        // multi-resource fan-out is reserved for headline stanzas, while
        // durable direct delivery and durable MUC invitations are restricted
        // to normal/chat. A future routing change must introduce per-resource
        // projections instead of attaching one fence to several SM/BOSH
        // queues.
        debug_assert!(
            !(live_delivery.is_some() && deliver_all),
            "one durable C2S fence cannot be fanned out to multiple resources"
        );
        let mut delivered_keys = Vec::new();
        for (key, target) in &targets {
            let accepted = if let Some(delivery) = live_delivery {
                target
                    .sender
                    .try_send_durable(recipient_delivery.clone(), delivery)
                    .is_ok()
            } else {
                target.sender.try_send(recipient_delivery.clone()).is_ok()
            };
            if accepted {
                let counter = if live_delivery.is_some() {
                    &self.state.metrics.online_queue_durable_acceptances_total
                } else {
                    &self.state.metrics.online_queue_volatile_acceptances_total
                };
                counter.fetch_add(1, Ordering::Relaxed);
                delivered_keys.push(key.clone());
                if !deliver_all {
                    break;
                }
            }
        }
        let mut delivered = !delivered_keys.is_empty();
        let mut delivered_key = delivered_keys.first().cloned();

        if deliver_all {
            if let Ok(nodes) = self.state.cluster.lookup_nodes(to).await {
                for node_id in nodes {
                    if node_id == self.state.cluster.node_id {
                        continue;
                    }
                    let accepted = if let Some(delivery) = live_delivery {
                        self.state
                            .cluster
                            .send_to_node_available_durable(
                                &node_id,
                                to,
                                &recipient_delivery,
                                delivery,
                            )
                            .await
                            .unwrap_or(false)
                    } else {
                        self.state
                            .cluster
                            .send_to_node_available(&node_id, to, &recipient_delivery)
                            .await
                            .unwrap_or(false)
                    };
                    if accepted {
                        delivered = true;
                    }
                }
            }
        } else if !delivered {
            if let Ok(nodes) = self.state.cluster.lookup_nodes(to).await {
                for node_id in nodes {
                    if node_id != self.state.cluster.node_id {
                        let receipt = if let Some(delivery) = live_delivery {
                            self.state
                                .cluster
                                .send_to_node_primary_durable(
                                    &node_id,
                                    to,
                                    &recipient_delivery,
                                    delivery,
                                )
                                .await
                                .unwrap_or_default()
                        } else {
                            self.state
                                .cluster
                                .send_to_node_primary(&node_id, to, &recipient_delivery)
                                .await
                                .unwrap_or_default()
                        };
                        if accepted_cluster_message_delivery(&self.state, &node_id, to, &receipt) {
                            delivered = true;
                            delivered_key = receipt.accepted_full_jid;
                            break;
                        }
                    }
                }
            }
        }

        // RFC 6121 §8.5.3.2 lets a chat addressed to a vanished resource
        // fall back to the account's most available resource. Other message
        // types addressed to a non-matching full JID are never stored as if
        // they had been sent to the bare account.
        if !delivered && !bare_target {
            let allow_bare_fallback = match full_no_match_route(message_type) {
                FullNoMatchRoute::Ignore => {
                    self.finalize_message_admission(
                        &mut message_admission_lease,
                        "full-target-drop",
                    )
                    .await;
                    return Ok(Action::None);
                }
                FullNoMatchRoute::Reject
                    if durable_full_no_match_recovers(message_type, live_delivery.is_some()) =>
                {
                    self.state
                        .metrics
                        .post_accept_side_effect_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        recipient_id = %recipient.id,
                        target = %to,
                        "exact full-JID route disappeared after durable admission; resource-affine row remains replayable"
                    );
                    false
                }
                FullNoMatchRoute::Reject => {
                    return Ok(message_error(root, "cancel", "service-unavailable"));
                }
                FullNoMatchRoute::FallbackChat => true,
            };

            if allow_bare_fallback {
                let mut fallback_targets = self.state.session_entries_for(&recipient_by);
                fallback_targets.retain(|(_, session)| {
                    session.available.load(Ordering::Relaxed)
                        && session.priority.load(Ordering::Relaxed) >= 0
                });
                fallback_targets.sort_by(|(left_jid, left), (right_jid, right)| {
                    right
                        .priority
                        .load(Ordering::Relaxed)
                        .cmp(&left.priority.load(Ordering::Relaxed))
                        .then_with(|| left_jid.cmp(right_jid))
                });
                let mut allowed_fallback = Vec::with_capacity(fallback_targets.len());
                for target in fallback_targets {
                    match self
                        .state
                        .privacy_allows_session(&target.1, from, PrivacyStanzaKind::Message)
                        .await
                    {
                        Ok(true) => allowed_fallback.push(target),
                        Ok(false) => {}
                        Err(error) if live_delivery.is_some() => {
                            // The durable C2S/invitation projection was committed
                            // before attempting the exact full-JID route. A
                            // transient privacy backend failure while considering
                            // RFC 6121 chat fallback must fail closed for this
                            // resource, but it must not turn the already accepted
                            // message into a client-visible failure and invite a
                            // duplicate retry.
                            self.state
                                .metrics
                                .post_accept_side_effect_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                ?error,
                                target = %target.0,
                                recipient_id = %recipient.id,
                                "privacy policy failed closed during post-admission full-JID fallback"
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
                for (key, target) in allowed_fallback {
                    let accepted = if let Some(delivery) = live_delivery {
                        target
                            .sender
                            .try_send_durable(recipient_delivery.clone(), delivery)
                            .is_ok()
                    } else {
                        target.sender.try_send(recipient_delivery.clone()).is_ok()
                    };
                    if accepted {
                        let counter = if live_delivery.is_some() {
                            &self.state.metrics.online_queue_durable_acceptances_total
                        } else {
                            &self.state.metrics.online_queue_volatile_acceptances_total
                        };
                        counter.fetch_add(1, Ordering::Relaxed);
                        delivered_key = Some(key);
                        delivered = true;
                        break;
                    }
                }
                if !delivered {
                    if let Ok(nodes) = self.state.cluster.lookup_nodes(&recipient_by).await {
                        for node_id in nodes {
                            if node_id == self.state.cluster.node_id {
                                continue;
                            }
                            let receipt = if let Some(delivery) = live_delivery {
                                self.state
                                    .cluster
                                    .send_to_node_primary_durable(
                                        &node_id,
                                        &recipient_by,
                                        &recipient_delivery,
                                        delivery,
                                    )
                                    .await
                                    .unwrap_or_default()
                            } else {
                                self.state
                                    .cluster
                                    .send_to_node_primary(
                                        &node_id,
                                        &recipient_by,
                                        &recipient_delivery,
                                    )
                                    .await
                                    .unwrap_or_default()
                            };
                            if accepted_cluster_message_delivery(
                                &self.state,
                                &node_id,
                                &recipient_by,
                                &receipt,
                            ) {
                                delivered = true;
                                delivered_key = receipt.accepted_full_jid;
                                break;
                            }
                        }
                    }
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
                if let Err(error) = self.notify_push(recipient.id).await {
                    self.state
                        .metrics
                        .post_accept_side_effect_failures_total
                        .fetch_add(1, Ordering::Relaxed);
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
                            Some(&self.state.config.domain),
                        );
                        let offline_outcome = self
                            .state
                            .message_service()
                            .store_offline(crate::services::messaging::OfflineMessageAdmission {
                                recipient_id: recipient.id,
                                recipient_bare_jid: &recipient_by,
                                sender_jid: from,
                                stanza: &delayed,
                                encrypted,
                                mam_backed: recipient_history_enabled,
                                identity: message_admission_lease
                                    .as_ref()
                                    .map(|lease| &lease.offline_dedupe),
                            })
                            .await?;
                        match offline_outcome {
                            OfflineAdmissionOutcome::QuotaExceeded if history_committed => {
                                // A pre-admitted recipient MAM row is durable
                                // recovery. Returning an error here would invite a
                                // duplicate retry after the server already
                                // accepted the origin-id.
                                if let Err(error) = self.notify_push(recipient.id).await {
                                    self.state
                                        .metrics
                                        .post_accept_side_effect_failures_total
                                        .fetch_add(1, Ordering::Relaxed);
                                    tracing::warn!(?error, recipient_id = %recipient.id, %recipient_stable_id, "MAM-backed message was accepted but offline quota and push delivery both failed");
                                }
                                stored_offline = true;
                            }
                            OfflineAdmissionOutcome::QuotaExceeded => {
                                return Ok(message_error(root, "wait", "service-unavailable"));
                            }
                            OfflineAdmissionOutcome::Stored => {
                                stored_offline = true;
                                if let Err(error) = self.notify_push(recipient.id).await {
                                    self.state
                                        .metrics
                                        .post_accept_side_effect_failures_total
                                        .fetch_add(1, Ordering::Relaxed);
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
        } else if should_carbon(root) && recipient.id != user.id {
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
                self.state
                    .metrics
                    .post_accept_side_effect_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(?error, %sender_stable_id, route = accepted_route, "accepted message history transaction failed atomically");
            }
        }
        if should_carbon(root) {
            let delivered_self = (recipient.id == user.id)
                .then_some(delivered_key.as_deref())
                .flatten();
            self.send_sent_carbons(from, &sender_archive, delivered_self, None)
                .await;
        }
        self.state
            .metrics
            .messages_routed_total
            .fetch_add(1, Ordering::Relaxed);
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
        if let Err(error) = self.state.abuse.accept_message_admission(&lease).await {
            // The route has already accepted the stanza. Returning an error
            // would encourage a duplicate retry, so expose the remaining
            // at-least-once recovery window only through logs and metrics.
            self.state
                .metrics
                .post_accept_side_effect_failures_total
                .fetch_add(1, Ordering::Relaxed);
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
        let current = crate::jid::canonical_session_key(from).unwrap_or_else(|_| from.to_owned());
        let bare = bare_jid(from);
        let Some(peer) = carbon_forwarded_recipient(forwarded) else {
            tracing::warn!(%bare, direction = "sent", "suppressed a Carbon whose forwarded recipient was not a canonical JID");
            return;
        };
        let sessions = self.state.session_entries_for(bare);
        let mut selected_resources = 0_usize;
        let state = &self.state;
        let peer_ref = peer.as_str();
        let attempts: Vec<(String, CarbonFanoutFuture<'_>)> = sessions
            .iter()
            .filter_map(|(jid, session)| {
            if !carbon_resource_selected(
                jid,
                session.carbons.load(Ordering::Acquire),
                &[Some(current.as_str()), delivered_self],
            ) {
                return None;
            }
            selected_resources += 1;
            if muc_scope.is_some_and(|(room, nick)| {
                session
                    .muc_memberships
                    .get(room)
                    .is_none_or(|membership| membership.nick != nick)
            }) {
                return None;
            }
            // Use the exact canonical route key inspected above. Rebuilding
            // it from the caller's bare JID and a stored resource can create
            // a differently-spelled `to` address at federation/IDNA
            // boundaries, which standards clients are allowed to reject.
            let target_jid = jid.clone();
            let timeout_target = target_jid.clone();
            let session = session.clone();
            Some((timeout_target, Box::pin(async move {
                match state
                    .privacy_allows_session(&session, peer_ref, PrivacyStanzaKind::Message)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => return CarbonFanoutAttempt::Skipped,
                    Err(error) => {
                        tracing::warn!(?error, %target_jid, direction = "sent", "privacy policy failed closed for a local Carbon");
                        return CarbonFanoutAttempt::Skipped;
                    }
                }
                let Some(carbon) = carbon_message("sent", bare, &target_jid, forwarded) else {
                    state
                        .metrics
                        .carbon_post_accept_delivery_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::error!(%target_jid, direction = "sent", "suppressed an invalid XEP-0280 Carbon payload");
                    return CarbonFanoutAttempt::Failed;
                };
                if session.sender.send(carbon).await.is_err() {
                    state
                        .metrics
                        .carbon_post_accept_delivery_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%target_jid, direction = "sent", "post-accept Carbon could not be admitted to the local session queue");
                    CarbonFanoutAttempt::Failed
                } else {
                    tracing::trace!(%target_jid, peer = %peer_ref, direction = "sent", "delivered a local XEP-0280 Carbon");
                    CarbonFanoutAttempt::Delivered
                }
            }) as CarbonFanoutFuture<'_>))
        })
            .collect();
        let summary =
            bounded_carbon_fanout(attempts, CARBON_FANOUT_CONCURRENCY, CARBON_TARGET_TIMEOUT).await;
        for target_jid in &summary.timed_out_targets {
            state
                .metrics
                .carbon_post_accept_delivery_failures_total
                .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .carbon_fanout_target_timeouts_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%target_jid, direction = "sent", "post-accept Carbon target exceeded its independent fanout deadline");
        }
        let delivered_resources = summary.delivered;
        tracing::debug!(
            %bare,
            session_resources = sessions.len(),
            selected_resources,
            delivered_resources,
            failed_resources = summary.failed,
            timed_out_resources = summary.timed_out,
            direction = "sent",
            "completed local XEP-0280 Carbon fanout"
        );

        match self.state.cluster.lookup_nodes(bare).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id != self.state.cluster.node_id {
                        let Some(carbon) = carbon_message("sent", bare, bare, forwarded) else {
                            self.state
                                .metrics
                                .carbon_post_accept_delivery_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::error!(%node_id, %bare, direction = "sent", "suppressed an invalid cluster XEP-0280 Carbon payload");
                            continue;
                        };
                        // Put the primary receiving resource first: a version 1
                        // cluster peer understands only that scalar exclusion.
                        // The version 2 list also excludes the sending resource.
                        let mut exclusions = delivered_self.into_iter().collect::<Vec<_>>();
                        exclusions.push(&current);
                        let routed = if let Some((room, nick)) = muc_scope {
                            self.state
                                .cluster
                                .send_to_node_muc_carbons_excluding(
                                    &node_id,
                                    bare,
                                    &carbon,
                                    &exclusions,
                                    room,
                                    nick,
                                )
                                .await
                        } else {
                            self.state
                                .cluster
                                .send_to_node_excluding(&node_id, bare, &carbon, true, &exclusions)
                                .await
                        };
                        if let Err(error) = routed {
                            self.state
                                .metrics
                                .carbon_post_accept_delivery_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(%node_id, %bare, ?error, direction = "sent", "post-accept Carbon could not be routed to a cluster peer");
                        }
                    }
                }
            }
            Err(error) => {
                self.state
                    .metrics
                    .carbon_post_accept_delivery_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%bare, ?error, direction = "sent", "cluster Carbon recipient lookup failed after primary acceptance");
            }
        }
    }

    pub(crate) async fn send_received_carbons(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) {
        send_received_carbons_for_state(&self.state, recipient, delivered, forwarded).await;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BareMessageRoute {
    Primary,
    All,
    Reject,
    Ignore,
}

pub(crate) fn bare_message_route(kind: &str) -> BareMessageRoute {
    match kind {
        "headline" => BareMessageRoute::All,
        "groupchat" => BareMessageRoute::Reject,
        "error" => BareMessageRoute::Ignore,
        _ => BareMessageRoute::Primary,
    }
}

pub(crate) fn missing_user_message_should_error(kind: &str) -> bool {
    !matches!(kind, "headline" | "error")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FullNoMatchRoute {
    FallbackChat,
    Reject,
    Ignore,
}

pub(crate) fn full_no_match_route(kind: &str) -> FullNoMatchRoute {
    match kind {
        "chat" => FullNoMatchRoute::FallbackChat,
        "error" => FullNoMatchRoute::Ignore,
        _ => FullNoMatchRoute::Reject,
    }
}

/// Once the database delivery projection commits, a disappearing exact route
/// is a worker/transport recovery condition rather than a truthful stanza
/// rejection. Returning an error would invite a duplicate client retry.
pub(crate) fn durable_full_no_match_recovers(kind: &str, durable_committed: bool) -> bool {
    durable_committed && full_no_match_route(kind) == FullNoMatchRoute::Reject
}

#[cfg(test)]
fn offline_storage_eligible(root: Node<'_, '_>) -> bool {
    matches!(
        root.attribute("type").unwrap_or("normal"),
        "normal" | "chat"
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UndeliveredDisposition {
    Drop,
    RejectCancel,
    RejectWait,
    StoreOffline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectDeliveryMode {
    Durable,
    Volatile,
    VolatileExplicitNoStore,
}

/// Classify direct messages without conflating an explicit XEP-0334 privacy
/// request with the protocol defaults for ephemeral signal-only messages.
pub(crate) fn direct_delivery_mode(root: Node<'_, '_>) -> DirectDeliveryMode {
    if has_explicit_no_store_hint(root) {
        DirectDeliveryMode::VolatileExplicitNoStore
    } else if offline_storage_permitted(root) {
        DirectDeliveryMode::Durable
    } else {
        DirectDeliveryMode::Volatile
    }
}

pub(crate) fn durable_direct_delivery_allowed(
    mode: DirectDeliveryMode,
    content_storage_allowed: bool,
) -> bool {
    mode == DirectDeliveryMode::Durable && content_storage_allowed
}

/// Decide the fate of a message only after all online routes have declined
/// it. This is intentionally pure: every non-Store outcome returns before
/// offline, MAM, or retraction mutations can run.
pub(crate) fn undelivered_disposition(
    message_type: &str,
    persistence_allowed: bool,
    content_storage_allowed: bool,
) -> UndeliveredDisposition {
    if message_type == "headline" || !persistence_allowed {
        return UndeliveredDisposition::Drop;
    }
    if !matches!(message_type, "normal" | "chat") {
        return UndeliveredDisposition::RejectCancel;
    }
    if !content_storage_allowed {
        return UndeliveredDisposition::RejectWait;
    }
    UndeliveredDisposition::StoreOffline
}

fn carbon_resource_selected(jid: &str, enabled: bool, excluded: &[Option<&str>]) -> bool {
    enabled && !excluded.iter().flatten().any(|excluded| jid == *excluded)
}

/// Version 1 peers can only return an uncorrelated legacy delivered-count.
/// Treat a positive count as accepted during rolling upgrades so a stanza
/// that may already have reached a resource is never duplicated into offline
/// storage. Version 2/3 peers are required by ClusterManager to return a
/// nonce-correlated acknowledgement.
pub(crate) fn accepted_cluster_message_delivery(
    state: &AppState,
    node_id: &str,
    target: &str,
    receipt: &crate::cluster::NodeDeliveryReceipt,
) -> bool {
    if receipt.delivered && !receipt.acknowledged {
        state
            .metrics
            .cluster_legacy_delivery_acceptances_total
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%node_id, %target, "accepted legacy uncorrelated cluster message delivery acknowledgement");
    }
    receipt.delivered
}

/// Deliver a received Carbon for an already-authorized, already-routed stanza.
///
/// S2S delivery uses this entry point after block-list evaluation and after the
/// primary resource has been chosen.  Keeping the forwarding primitive here
/// prevents federation code from constructing server-asserted Carbon wrappers.
pub(crate) async fn send_received_carbons_for_state(
    state: &AppState,
    recipient: &str,
    delivered: Option<&str>,
    forwarded: &str,
) {
    let Some(peer) = carbon_forwarded_sender(forwarded) else {
        tracing::warn!(%recipient, direction = "received", "suppressed a Carbon whose forwarded sender was not a canonical JID");
        return;
    };
    let sessions = state.session_entries_for(recipient);
    let session_resources = sessions.len();
    let mut selected_resources = 0_usize;
    let peer_ref = peer.as_str();
    // Materialize an owned attempt set before the first await. Keeping the
    // `sessions.iter()` adapter inside the generic async fan-out made its
    // future carry a borrowed-iterator closure whose higher-ranked `FnOnce`
    // lifetime could not be proven `Send` by federated callers. Each selected
    // session was cloned by the old code anyway, so moving the request-owned
    // snapshot preserves target selection and ordering while removing that
    // artificial lifetime coupling.
    let attempts: Vec<(String, CarbonFanoutFuture<'_>)> = sessions
        .into_iter()
        .filter_map(|(jid, session)| {
        if !carbon_resource_selected(&jid, session.carbons.load(Ordering::Acquire), &[delivered]) {
            return None;
        }
        selected_resources += 1;
        let target_jid = jid;
        let timeout_target = target_jid.clone();
        Some((timeout_target, Box::pin(async move {
            match state
                .privacy_allows_session(&session, peer_ref, PrivacyStanzaKind::Message)
                .await
            {
                Ok(true) => {}
                Ok(false) => return CarbonFanoutAttempt::Skipped,
                Err(error) => {
                    tracing::warn!(?error, %target_jid, direction = "received", "privacy policy failed closed for a local Carbon");
                    return CarbonFanoutAttempt::Skipped;
                }
            }
            let Some(carbon) = carbon_message("received", recipient, &target_jid, forwarded)
            else {
                state
                    .metrics
                    .carbon_post_accept_delivery_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::error!(%target_jid, direction = "received", "suppressed an invalid XEP-0280 Carbon payload");
                return CarbonFanoutAttempt::Failed;
            };
            if session.sender.send(carbon).await.is_err() {
                state
                    .metrics
                    .carbon_post_accept_delivery_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%target_jid, direction = "received", "post-accept Carbon could not be admitted to the local session queue");
                CarbonFanoutAttempt::Failed
            } else {
                tracing::trace!(%target_jid, peer = %peer_ref, direction = "received", "delivered a local XEP-0280 Carbon");
                CarbonFanoutAttempt::Delivered
            }
        }) as CarbonFanoutFuture<'_>))
    })
        .collect();
    let summary =
        bounded_carbon_fanout(attempts, CARBON_FANOUT_CONCURRENCY, CARBON_TARGET_TIMEOUT).await;
    for target_jid in &summary.timed_out_targets {
        state
            .metrics
            .carbon_post_accept_delivery_failures_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .carbon_fanout_target_timeouts_total
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%target_jid, direction = "received", "post-accept Carbon target exceeded its independent fanout deadline");
    }
    let delivered_resources = summary.delivered;
    tracing::debug!(
        %recipient,
        session_resources,
        selected_resources,
        delivered_resources,
        failed_resources = summary.failed,
        timed_out_resources = summary.timed_out,
        direction = "received",
        "completed local XEP-0280 Carbon fanout"
    );

    match state.cluster.lookup_nodes(recipient).await {
        Ok(nodes) => {
            for node_id in nodes {
                if node_id != state.cluster.node_id {
                    let Some(carbon) = carbon_message("received", recipient, recipient, forwarded)
                    else {
                        state
                            .metrics
                            .carbon_post_accept_delivery_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::error!(%node_id, %recipient, direction = "received", "suppressed an invalid cluster XEP-0280 Carbon payload");
                        continue;
                    };
                    if let Err(error) = state
                        .cluster
                        .send_to_node(&node_id, recipient, &carbon, true, delivered)
                        .await
                    {
                        state
                            .metrics
                            .carbon_post_accept_delivery_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%node_id, %recipient, ?error, direction = "received", "post-accept Carbon could not be routed to a cluster peer");
                    }
                }
            }
        }
        Err(error) => {
            state
                .metrics
                .carbon_post_accept_delivery_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%recipient, ?error, direction = "received", "cluster Carbon recipient lookup failed after primary acceptance");
        }
    }
}

fn carbon_forwarded_sender(forwarded: &str) -> Option<String> {
    let document = roxmltree::Document::parse(forwarded).ok()?;
    let root = document.root_element();
    (root.tag_name().name() == "message")
        .then(|| root.attribute("from"))
        .flatten()
        .and_then(|from| crate::jid::canonicalize(from).ok())
}

fn carbon_forwarded_recipient(forwarded: &str) -> Option<String> {
    let document = roxmltree::Document::parse(forwarded).ok()?;
    let root = document.root_element();
    (root.tag_name().name() == "message")
        .then(|| root.attribute("to"))
        .flatten()
        .and_then(|to| crate::jid::canonicalize(to).ok())
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
        bare_message_route, carbon_forwarded_recipient, carbon_forwarded_sender,
        carbon_resource_selected, direct_delivery_mode, durable_direct_delivery_allowed,
        durable_full_no_match_recovers, full_no_match_route, message_pow_intent_payload,
        missing_user_message_should_error, mixes_personal_retraction_and_direct_invite,
        offline_storage_eligible, undelivered_disposition, BareMessageRoute, CarbonFanoutAttempt,
        CarbonFanoutFuture, DirectDeliveryMode, FullNoMatchRoute, UndeliveredDisposition,
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

    #[test]
    fn carbons_are_resource_scoped_and_never_echo_to_primary_delivery() {
        assert!(carbon_resource_selected(
            "alice@example.test/tablet",
            true,
            &[Some("alice@example.test/phone")]
        ));
        assert!(!carbon_resource_selected(
            "alice@example.test/phone",
            true,
            &[Some("alice@example.test/phone")]
        ));
        assert!(!carbon_resource_selected(
            "alice@example.test/tablet",
            false,
            &[]
        ));
    }

    #[test]
    fn received_carbon_privacy_peer_is_the_forwarded_sender() {
        assert_eq!(
            carbon_forwarded_sender(
                "<message xmlns='jabber:client' from='Blocked@Example.test/Phone' to='alice@example.test/Tablet'/>",
            ),
            Some("blocked@example.test/Phone".to_owned())
        );
        assert_eq!(carbon_forwarded_sender("<message/>"), None);
        assert_eq!(
            carbon_forwarded_sender("<presence from='a@example.test'/>"),
            None
        );
    }

    #[test]
    fn sent_carbon_privacy_peer_is_the_forwarded_recipient() {
        assert_eq!(
            carbon_forwarded_recipient(
                "<message xmlns='jabber:client' from='alice@example.test/Phone' to='Blocked@Example.test/Tablet'/>",
            ),
            Some("blocked@example.test/Tablet".to_owned())
        );
        assert_eq!(carbon_forwarded_recipient("<message/>"), None);
        assert_eq!(
            carbon_forwarded_recipient("<presence to='a@example.test'/>"),
            None
        );
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

    #[tokio::test]
    async fn one_slow_carbon_target_does_not_starve_later_healthy_resources() {
        let (slow_tx, _slow_rx) = tokio::sync::mpsc::channel(1);
        let slow = crate::outbound::OutboundSender::new(slow_tx);
        slow.try_send("occupied".to_owned()).unwrap();
        let (fast_one_tx, mut fast_one_rx) = tokio::sync::mpsc::channel(1);
        let (fast_two_tx, mut fast_two_rx) = tokio::sync::mpsc::channel(1);
        let targets = vec![
            ("slow", slow),
            (
                "fast-one",
                crate::outbound::OutboundSender::new(fast_one_tx),
            ),
            (
                "fast-two",
                crate::outbound::OutboundSender::new(fast_two_tx),
            ),
        ];
        let attempts: Vec<(String, CarbonFanoutFuture<'_>)> = targets
            .into_iter()
            .map(|(target, sender)| {
                (
                    target.to_owned(),
                    Box::pin(async move {
                        if sender.send(format!("carbon-{target}")).await.is_ok() {
                            CarbonFanoutAttempt::Delivered
                        } else {
                            CarbonFanoutAttempt::Failed
                        }
                    }) as CarbonFanoutFuture<'_>,
                )
            })
            .collect();
        let summary = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            super::bounded_carbon_fanout(attempts, 2, std::time::Duration::from_millis(50)),
        )
        .await
        .expect("bounded Carbon fanout did not complete");
        assert_eq!(summary.delivered, 2);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.timed_out, 1);
        assert_eq!(summary.timed_out_targets, vec!["slow"]);
        assert_eq!(fast_one_rx.recv().await.unwrap().stanza, "carbon-fast-one");
        assert_eq!(fast_two_rx.recv().await.unwrap().stanza, "carbon-fast-two");
    }

    #[tokio::test]
    async fn carbon_fanout_never_exceeds_its_fixed_concurrency_bound() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let attempts: Vec<(String, CarbonFanoutFuture<'_>)> = (0..24)
            .map(|index| {
                let active = Arc::clone(&active);
                let maximum = Arc::clone(&maximum);
                (
                    format!("resource-{index}"),
                    Box::pin(async move {
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        maximum.fetch_max(now, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        CarbonFanoutAttempt::Delivered
                    }) as CarbonFanoutFuture<'_>,
                )
            })
            .collect();
        let summary =
            super::bounded_carbon_fanout(attempts, 3, std::time::Duration::from_secs(1)).await;
        assert_eq!(summary.delivered, 24);
        assert_eq!(summary.failed, 0);
        assert!(maximum.load(Ordering::SeqCst) <= 3);
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
    fn self_messages_exclude_sending_and_primary_receiving_resources() {
        let excluded = [
            Some("alice@example.test/phone"),
            Some("alice@example.test/laptop"),
        ];
        assert!(!carbon_resource_selected(
            "alice@example.test/phone",
            true,
            &excluded
        ));
        assert!(!carbon_resource_selected(
            "alice@example.test/laptop",
            true,
            &excluded
        ));
        assert!(carbon_resource_selected(
            "alice@example.test/tablet",
            true,
            &excluded
        ));
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
