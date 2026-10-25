//! Admits a client message stanza, archives it and delivers it to online, offline, carbon and federated recipients.

use super::*;

impl ProtocolSession {
    pub(crate) async fn message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        client_raw: &str,
    ) -> Result<Action> {
        self.enter_frame_stage(Stage::MessagePolicy);
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
        let personal_retraction_target = match super::super::retractions::retraction_target(root) {
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
        let target_jid = match northstar_xmpp_types::jid::CanonicalJid::parse(raw_to) {
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
        let original_direct = OriginalDirectMessage::capture(root, user.id, from, to, &routed_raw);
        let mut message_admission_lease = None;
        if let Some(normalized_admission_payload) = original_direct.rated_payload() {
            let subject = format!("message:{}", user.id);
            self.enter_frame_stage(Stage::MessageAdmission);
            let request = MessageAdmissionRequest {
                actor_id: user.id,
                account_bare: bare_jid(from),
                normalized_target: to,
                origin_id: original_direct.origin_id.as_deref(),
                normalized_payload: normalized_admission_payload,
                pow_intent_payload: &pow_intent_payload,
                subject: &subject,
                actors: &actors,
                proof: proof.as_ref(),
            };
            let service = self.state.message_admission_service();
            let admission = if let Some(operation) = self.message_operation() {
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
                    // Fail closed before routing/archive. A backend failure may
                    // leave this admission or a separate guard transaction
                    // unconfirmed; it does not prove rollback or permit retry.
                    if crate::services::abuse::is_abuse_state_busy(&error) {
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
        self.enter_frame_stage(Stage::MessagePolicy);
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
        self.enter_frame_stage(Stage::Handler);
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

        self.enter_frame_stage(Stage::MessagePolicy);
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
                    super::super::retractions::encrypted_retraction_archive(
                        &sender_archive,
                        target_id,
                    )
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
                self.enter_frame_stage(Stage::MessageAdmission);
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
                self.enter_frame_stage(Stage::MessageAdmission);
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
                self.enter_frame_stage(Stage::MessageAdmission);
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
        let encrypted = is_encrypted(root);
        let local_projection = original_direct.project_local(
            LocalProjectionAuthority {
                recipient_id: recipient.id,
                recipient_bare: &recipient_by,
                sender_stable_id,
                recipient_stable_id,
                domain: self.state.local_domain(),
            },
            encrypted,
            personal_retraction_target.as_deref(),
        );
        let rewritten = local_projection.rewritten.as_str();
        let sender_archive = local_projection.sender_archive.as_str();
        let recipient_delivery = local_projection.recipient_delivery.as_str();
        let sender_archive_stanza = local_projection.sender_archive_stanza.as_str();
        let recipient_archive_stanza = local_projection.recipient_archive_stanza.as_str();
        let durable_content_allowed = encrypted || !self.state.archive_requires_encryption();
        let persistence_allowed = personal_retraction || offline_storage_permitted(root);
        let archive_allowed_by_stanza = personal_retraction || mam_storage_eligible(root);
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
        let origin_id = original_direct.origin_id.as_deref();
        let exact_full_target_can_route = bare_target
            || message_type == "chat"
            || !targets.is_empty()
            || (!spool_only_now && self.state.personal_message_remote_resource_exists(to).await);
        let mut history_committed = false;
        let mut durable_c2s_delivery = None;
        let mut prepared_live = None;
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
                    stanza: sender_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            if recipient.id != user.id && recipient_history_enabled {
                writes.push(ArchiveWrite {
                    id: recipient_stable_id,
                    owner_id: recipient.id,
                    peer_jid: from,
                    stanza: recipient_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
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
            let delayed_projection = local_projection.delayed(
                chrono::Utc::now(),
                LocalArchivePolicy {
                    sender_enabled: sender_history_enabled,
                    recipient_enabled: recipient_history_enabled,
                },
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
                    stanza: &delayed_projection.stanza,
                    encrypted,
                    mam_backed: recipient_history_enabled,
                }),
            };
            let eligibility =
                direct_spool_eligibility(degraded_spool_eligible, spool_privacy_permits);
            self.enter_frame_stage(Stage::MessageAdmission);
            let service = self.state.message_service();
            if let Some(operation) = self.message_operation() {
                let prepared = match delayed_projection.bind(operation, admission, eligibility) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        tracing::warn!(?error, recipient_id = %recipient.id, "local history/C2S admission did not return a confirmed result");
                        return Ok(message_error(root, "wait", "resource-constraint"));
                    }
                };
                let applied = service
                    .admit_prepared_personal_message_with_mode(prepared)
                    .await;
                match continue_prepared_local_direct(
                    applied,
                    &mut message_admission_lease,
                    self.state.message_admission_service(),
                    &*self.state,
                    || self.enter_frame_stage(Stage::MessageFollowup),
                )
                .await
                {
                    ContinuedLocalDirect::Accepted => return Ok(Action::None),
                    ContinuedLocalDirect::Reject(error) => {
                        let (kind, condition) = error.stanza_error();
                        return Ok(message_error(root, kind, condition));
                    }
                    ContinuedLocalDirect::Live(live) => {
                        history_committed = live.archive_written();
                        let source = live.source();
                        durable_c2s_delivery = Some(source.message_id);
                        live_claim_id = source.claim_id;
                        prepared_live = Some(live);
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
                        if post_commit_mode != DirectPostCommitMode::Live
                            || self.state.message_service().direct_mode()
                                != DirectPostCommitMode::Live
                        {
                            service
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
                        if let Some(confirmed) = preserved_transaction(&error) {
                            match confirmed {
                                TransactionOutcome::Stored {
                                    recipient_id,
                                    delivery_id,
                                    live_claim_id,
                                    ..
                                } => {
                                    self.state.personal_message_telemetry().post_accept_failed();
                                    self.finalize_message_admission(
                                        &mut message_admission_lease,
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
                                    return Ok(Action::None);
                                }
                                TransactionOutcome::Replay { .. } => {
                                    self.finalize_message_admission(
                                        &mut message_admission_lease,
                                        "local-durable-c2s-replay-continuation-unknown",
                                    )
                                    .await;
                                    return Ok(Action::None);
                                }
                                TransactionOutcome::AccountUnavailable => {
                                    return Ok(message_error(root, "cancel", "service-unavailable"))
                                }
                            }
                        }
                        tracing::warn!(?error, recipient_id = %recipient.id, "local history/C2S admission did not return a confirmed result");
                        return Ok(message_error(root, "wait", "resource-constraint"));
                    }
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
                    stanza: sender_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            if recipient.id != user.id && recipient_history_enabled {
                writes.push(ArchiveWrite {
                    id: recipient_stable_id,
                    owner_id: recipient.id,
                    peer_jid: from,
                    stanza: recipient_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            let delayed_delivery = add_delay_from(
                recipient_delivery,
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
            self.enter_frame_stage(Stage::MessageAdmission);
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
            let delayed =
                add_delay_from(recipient_delivery, chrono::Utc::now(), Some(bare_jid(from)));
            let mut writes = Vec::with_capacity(2);
            if sender_history_enabled {
                writes.push(ArchiveWrite {
                    id: sender_stable_id,
                    owner_id: user.id,
                    peer_jid: to,
                    stanza: sender_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            if recipient.id != user.id && recipient_history_enabled {
                writes.push(ArchiveWrite {
                    id: recipient_stable_id,
                    owner_id: recipient.id,
                    peer_jid: from,
                    stanza: recipient_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
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
            self.enter_frame_stage(Stage::MessageAdmission);
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
        let delivery = match live_delivery_id {
            Some(message_id) => {
                DirectRouteDelivery::Committed(crate::xmpp::outbound::DurableDelivery {
                    recipient_id: recipient.id,
                    message_id,
                    claim_id: live_claim_id,
                })
            }
            None => DirectRouteDelivery::Volatile,
        };
        self.enter_frame_stage(Stage::MessageRouting);
        let outcome = if let Some(live) = prepared_live {
            live.route_with(&*self.state, &targets).await?
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
            DirectMessageRouter::route(&*self.state, route_request).await?
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
                return Ok(Action::None);
            }
            DirectRouteOutcome::AcceptedBeforeDegradation => {
                self.finalize_message_admission(
                    &mut message_admission_lease,
                    "online-before-degrade",
                )
                .await;
                return Ok(Action::None);
            }
            DirectRouteOutcome::Dropped => {
                self.finalize_message_admission(&mut message_admission_lease, "full-target-drop")
                    .await;
                return Ok(Action::None);
            }
            DirectRouteOutcome::Rejected(reason) => {
                let kind = match reason {
                    DirectRouteRejection::Unavailable => "wait",
                    DirectRouteRejection::NoMatchingResource => "cancel",
                };
                return Ok(message_error(root, kind, "service-unavailable"));
            }
        };

        self.enter_frame_stage(Stage::MessageFollowup);
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
                            recipient_archive_stanza,
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
                self.send_received_carbons(bare_jid(to), Some(delivered_key), recipient_delivery)
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
                    stanza: sender_archive_stanza,
                    encrypted,
                    stanza_id,
                });
            }
            if recipient.id != user.id && recipient_history_enabled {
                writes.push(ArchiveWrite {
                    id: recipient_stable_id,
                    owner_id: recipient.id,
                    peer_jid: from,
                    stanza: recipient_archive_stanza,
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
            self.send_sent_carbons(from, sender_archive, delivered_self, None)
                .await;
        }
        self.state.personal_message_telemetry().message_routed();
        Ok(Action::None)
    }
}
