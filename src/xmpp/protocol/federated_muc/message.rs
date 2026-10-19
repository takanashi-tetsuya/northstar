//! Federated MUC message handling for remote room actors.

use super::*;

/// Handle messages from a remote room actor. Authorization is bound to the
/// occupant endpoint, not merely to a claimed room nickname.
pub(crate) fn federated_muc_message<'a>(
    state: &'a AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    root: Node<'_, '_>,
    raw: &str,
) -> impl std::future::Future<Output = Result<Option<String>>> + Send + 'a {
    let authenticated_domain = authenticated_domain.to_owned();
    let request =
        FederatedMessageRequest::from_node(root, raw, state.validate_routed_message(root));
    async move {
        federated_muc_message_owned(state, &authenticated_domain, connection_id, request).await
    }
}

async fn federated_muc_message_owned(
    state: &AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    request: FederatedMessageRequest,
) -> Result<Option<String>> {
    let from = request.stanza.from.as_str();
    let to = request.stanza.to.as_str();
    if let Some((error_type, condition)) = request.validation_error {
        // RFC 6120 section 8.3.1 forbids reflecting an error in response to
        // another error stanza. Other malformed remote MUC messages get the
        // same bounded modern-message validation as local C2S messages before
        // any room/archive admission can observe them.
        if request.stanza.kind.as_deref() == Some("error") {
            return Ok(None);
        }
        return Ok(federated_error(
            &request.stanza,
            from,
            error_type,
            condition,
        ));
    }
    if !authenticated_remote_actor(authenticated_domain, from) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    let actor_full_jid = crate::jid::canonicalize(from)
        .expect("authenticated_remote_actor already validated the full JID");
    // The clustered invitation authority is account scoped, while the exact
    // full JID remains independently bound to the authenticated occupancy.
    // Derive both from the already authenticated S2S actor; never reuse the
    // room JID, invitee JID or an unprepared `from` value as the principal.
    let actor_bare_jid = crate::jid::canonical_bare_key(&actor_full_jid)?;
    let Ok(to_jid) = crate::jid::CanonicalJid::parse(to) else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        ));
    };
    let room_jid = to_jid.bare();
    if to_jid.domainpart() != muc_domain(state) || to_jid.localpart().is_none() {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    let decline = match &request.decline {
        Ok(decline) => decline.clone(),
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    if let Some((target_raw, reason)) = decline {
        if to_jid.resourcepart().is_some()
            || !matches!(request.stanza.kind.as_deref(), None | Some("normal"))
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
        if state
            .muc_service()
            .federated_room_snapshot(localpart(&room_jid))
            .await?
            .is_none()
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        let Ok(target) = crate::jid::CanonicalJid::parse(&target_raw) else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            ));
        };
        let Some(target_localpart) = target.localpart() else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            ));
        };
        let mut decline = XmlElement::new("decline").attr("from", bare_jid(&actor_full_jid));
        if let Some(reason) = reason.as_deref() {
            decline.push_child(XmlElement::new("reason").text(reason.to_owned()));
        }
        let forwarded = XmlElement::namespaced("message", "jabber:client")
            .attr("from", &room_jid)
            .attr("to", &target_raw)
            .attr("type", "normal")
            .attr(
                "id",
                request
                    .stanza
                    .id
                    .as_deref()
                    .filter(|id| !id.is_empty() && id.len() <= 128)
                    .unwrap_or("muc-decline"),
            )
            .child(
                XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user").child(decline),
            )
            .validated_fragment(&request.hints)?
            .finish();
        if target.domainpart() == state.local_domain() {
            let Some(recipient) = state
                .muc_service()
                .enabled_local_account(target_localpart)
                .await?
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            };
            let target_bare = target.bare();
            if state
                .muc_service()
                .is_blocked_for_account(recipient.id, &target_bare, &room_jid)
                .await?
                || state
                    .muc_service()
                    .is_blocked_for_account(recipient.id, &target_bare, &actor_full_jid)
                    .await?
            {
                return Ok(None);
            }
            let mut targets = state.session_entries_for(&target_raw);
            if target.resourcepart().is_none() {
                targets.retain(|(_, session)| {
                    session.available.load(Ordering::Relaxed)
                        && session.priority.load(Ordering::Relaxed) >= 0
                });
                targets.sort_by(|(left_jid, left), (right_jid, right)| {
                    right
                        .priority
                        .load(Ordering::Relaxed)
                        .cmp(&left.priority.load(Ordering::Relaxed))
                        .then_with(|| left_jid.cmp(right_jid))
                });
            }
            let mut delivered = targets
                .into_iter()
                .any(|(_, session)| session.sender.try_send(forwarded.clone()).is_ok());
            if !delivered {
                delivered = state
                    .route_federated_muc_account_message_remote(&target_raw, &forwarded, None)
                    .await
                    .is_some();
            }
            if !delivered && request.temporary_storage {
                let delayed = add_delay_from(&forwarded, chrono::Utc::now(), Some(&room_jid));
                let outcome = state
                    .muc_service()
                    .store_federated_muc_offline(
                        recipient.id,
                        &room_jid,
                        &delayed,
                        false,
                        super::super::muc::temporary_muc_offline_policy(state),
                    )
                    .await?;
                if outcome == OfflineStoreOutcome::QuotaExceeded {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "wait",
                        "resource-constraint",
                    ));
                }
                if outcome == OfflineStoreOutcome::RecipientUnavailable {
                    return Ok(None);
                }
                if let Err(error) = state.dispatch_push_notification(recipient.id).await {
                    tracing::warn!(?error, recipient_id = %recipient.id, %room_jid, "accepted federated offline MUC invitation decline could not trigger push notification");
                }
            }
            return Ok(None);
        }
        if !state.xmpp_external_route_domain_allowed(target.domainpart())
            || !state
                .federation_outbox()
                .send(target.domainpart(), forwarded, Some(room_jid.clone()))
                .await
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "wait",
                "remote-server-timeout",
            ));
        }
        return Ok(None);
    }
    let Some((_, own)) = state
        .muc_occupants_for(&room_jid)
        .into_iter()
        .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid))
    else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-acceptable",
        ));
    };
    if !federated_endpoint_matches(&own, authenticated_domain) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    // Only an available presence refresh may transfer the transport endpoint
    // of an existing federated occupant. Message traffic is authorized by the
    // authenticated domain but must not silently seize the occupant from the
    // connection/incarnation admitted by the room authority.
    let Some(room) = state
        .muc_service()
        .federated_room_snapshot(localpart(&room_jid))
        .await?
    else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    };
    let voice_form = match &request.voice_form {
        Ok(form) => form.as_ref(),
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    if let Some(voice_form) = voice_form {
        if to_jid.resourcepart().is_some()
            || !matches!(request.stanza.kind.as_deref(), None | Some("normal"))
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
        let mut occupants = state
            .federated_muc_global_occupants(&room_jid)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(nick, json)| {
                serde_json::from_str::<SerializableMucOccupant>(&json)
                    .ok()
                    .map(|occupant| (nick, occupant))
            })
            .collect::<std::collections::HashMap<_, _>>();
        for (_, occupant) in state.muc_occupants_for(&room_jid) {
            occupants.insert(
                occupant.nick.clone(),
                SerializableMucOccupant::from(&occupant),
            );
        }
        match voice_form {
            super::super::muc::MucVoiceForm::Request => {
                if !room.moderated || own.role != "visitor" {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                }
                let voice_request =
                    super::super::muc::muc_voice_request(&room_jid, &own.full_jid, &own.nick);
                for moderator in occupants
                    .values()
                    .filter(|occupant| occupant.role == "moderator")
                {
                    if let Some(local) = state.local_muc_occupant_exact(moderator.into()) {
                        let _ = state
                            .deliver_to_muc_occupant(
                                &local,
                                set_to(&voice_request, &local.full_jid),
                            )
                            .await;
                    }
                    state
                        .federated_muc_publish_private_message(
                            &room_jid,
                            &moderator.nick,
                            &voice_request,
                            &own.full_jid,
                        )
                        .await?;
                }
                return Ok(None);
            }
            super::super::muc::MucVoiceForm::Approval { jid, nick, allow } => {
                if own.role != "moderator" {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                }
                let Some(target) = occupants.get(nick) else {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                if target.full_jid != *jid || target.role != "visitor" {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "not-allowed",
                    ));
                }
                if !allow {
                    return Ok(None);
                }
                if !state.federated_muc_pg_authority_enabled() {
                    // A single-node room deliberately keeps live occupancy
                    // authority in this process. Cluster occupancy rows do
                    // not exist in that deployment mode, so requiring one
                    // would reject every otherwise valid federated voice
                    // approval. Serialize the mutation with joins, leaves,
                    // configuration changes and SM restoration, then re-check
                    // both exact transport incarnations before granting the
                    // role. This prevents a departed occupant from inheriting
                    // an approval after reusing the same nickname.
                    let service = state.muc_service();
                    let _guard = service.lock_local_room_mutation(room.id).await;
                    let Some(current_room) = service
                        .federated_room_snapshot(localpart(&room_jid))
                        .await?
                    else {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    };
                    if current_room.id != room.id || current_room.room_epoch != room.room_epoch {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                    let Some(current_actor) = state.local_muc_occupant_exact((&own).into()) else {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    };
                    if current_actor.full_jid != own.full_jid
                        || current_actor.connection_id != own.connection_id
                        || current_actor.cluster_epoch != own.cluster_epoch
                        || current_actor.role != "moderator"
                        || !federated_endpoint_matches(&current_actor, authenticated_domain)
                    {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                    let Some(updated_occupant) = state.set_local_muc_role_exact(
                        crate::services::muc::LocalMucOccupantIdentity::from(target),
                        "visitor",
                        "participant",
                        None,
                    ) else {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    };
                    let updated = SerializableMucOccupant::from(&updated_occupant);
                    for (_, recipient) in state.muc_occupants_for(&room_jid) {
                        let self_presence = recipient.full_jid == updated.full_jid
                            && recipient.connection_id == updated.connection_id
                            && recipient.cluster_epoch == updated.cluster_epoch;
                        let presence = muc_presence_stanza(
                            &updated,
                            &recipient.full_jid,
                            false,
                            self_presence,
                            false,
                            request.stanza.id.as_deref(),
                            updated.room_non_anonymous
                                || self_presence
                                || recipient.role == "moderator",
                        );
                        let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
                    }
                    return Ok(None);
                }
                let service = state.muc_service();
                let Some(actor_target) = service
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                    .await?
                else {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                };
                let Some(target_authority) = service
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &target.nick)
                    .await?
                else {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                if actor_target.full_jid != own.full_jid
                    || actor_target.connection_uuid != own.connection_id
                    || target_authority.full_jid != target.full_jid
                    || target_authority.connection_uuid != target.connection_id
                {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                }
                let operation_id = crate::services::muc::operation_id(&serde_json::json!({
                    "kind":"voice_approval","stream":connection_id,
                    "stanza_id":request.stanza.id,"room":room_jid,
                    "actor":actor_target,"target":target_authority,"role":"participant"
                }))?;
                match service
                    .change_local_cluster_role(
                        operation_id,
                        &actor_target,
                        &target_authority,
                        "participant",
                        None,
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                    _ => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                }
                if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                    tracing::warn!(?error, %operation_id, "committed federated MUC voice approval wake failed; PostgreSQL outbox will catch up");
                }
                return Ok(None);
            }
        }
    }
    if to.contains('/') {
        if !room.allow_private_messages {
            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
        }
        if !matches!(
            request.stanza.kind.as_deref().unwrap_or("normal"),
            "chat" | "normal"
        ) {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
        let Some(target_nick) = to_jid.resourcepart() else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            ));
        };
        let local_target = state.local_muc_occupant_by_nick(&room_jid, target_nick);
        let (target_full_jid, route_via_cluster) = if let Some(target) = &local_target {
            (target.full_jid.clone(), false)
        } else {
            let global = state.federated_muc_global_occupants(&room_jid).await?;
            let Some(target) = global
                .get(target_nick)
                .and_then(|json| serde_json::from_str::<SerializableMucOccupant>(json).ok())
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            };
            (target.full_jid, true)
        };
        let private = set_muc_occupant_id(
            &add_stanza_id(
                &set_to(
                    &set_from(&request.stanza.raw, &format!("{room_jid}/{}", own.nick)),
                    &target_full_jid,
                ),
                &room_jid,
                uuid::Uuid::new_v4(),
            ),
            &own.occupant_id,
        );
        if route_via_cluster {
            state
                .federated_muc_publish_private_message(
                    &room_jid,
                    target_nick,
                    &private,
                    &actor_full_jid,
                )
                .await?;
        } else if let Some(target) = local_target {
            let blocked = state
                .blocked_muc_recipient_accounts(
                    std::slice::from_ref(&target),
                    &[format!("{room_jid}/{}", own.nick), actor_full_jid.clone()],
                )
                .await;
            if !crate::jid::canonical_bare_key(&target.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                let _ = state
                    .deliver_to_muc_occupant_unchecked(&target, private)
                    .await;
            }
        }
        return Ok(None);
    }
    if request.stanza.kind.as_deref() != Some("groupchat") {
        let privileged_inviter = matches!(own.affiliation.as_str(), "owner" | "admin");
        if !request.invites.is_empty()
            && !privileged_inviter
            && (own.role == "visitor" || !room.allow_invites)
        {
            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
        }
        let mut delivered_invitation = false;
        for invite in &request.invites {
            let Some(invitee_raw) = invite.invitee.as_deref() else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "bad-request",
                ));
            };
            let Ok(invitee) = crate::jid::CanonicalJid::parse(invitee_raw) else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let Some(invitee_localpart) = invitee.localpart() else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let invitee_jid = invitee.to_string();
            let invitee_bare = invitee.bare();
            let invitee_domain = invitee.domainpart();
            if invitee_domain == state.local_domain() {
                if let Some(local_user) = state
                    .muc_service()
                    .enabled_local_account(invitee_localpart)
                    .await?
                {
                    let blocked_room = state
                        .muc_service()
                        .is_blocked_for_account(local_user.id, &invitee_bare, &room_jid)
                        .await?;
                    let blocked_inviter = state
                        .muc_service()
                        .is_blocked_for_account(local_user.id, &invitee_bare, &actor_full_jid)
                        .await?;
                    if blocked_room || blocked_inviter {
                        delivered_invitation = true;
                        continue;
                    }
                }
            }
            let reason = invite.reason.as_deref();
            let mut invite_out = XmlElement::new("invite").attr("from", from);
            if let Some(reason) = reason {
                invite_out.push_child(XmlElement::new("reason").text(reason.to_owned()));
            }
            let local_durable_invite_id =
                if room.members_only && invitee_domain == state.local_domain() {
                    Some(crate::services::muc::operation_id(&serde_json::json!({
                        "kind":"muc_invitation","stream":connection_id,
                        "stanza_id":request.stanza.id,"room":room_jid,
                        "actor":actor_full_jid,"invitee":invitee_bare,"reason":reason,
                    }))?)
                } else {
                    None
                };
            let invitation = set_muc_occupant_id(
                &add_stanza_id(
                    &XmlElement::namespaced("message", "jabber:client")
                        .attr("from", &room_jid)
                        .attr("to", &invitee_jid)
                        .attr("type", "normal")
                        .child(
                            XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
                                .child(invite_out),
                        )
                        .validated_fragment(&request.hints)?
                        .finish(),
                    &room_jid,
                    uuid::Uuid::new_v4(),
                ),
                &own.occupant_id,
            );
            let invitation = local_durable_invite_id.map_or(invitation.clone(), |id| {
                add_stanza_id(&invitation, &invitee_bare, id)
            });
            if invitee_domain == state.local_domain() {
                let Some(local_user) = state
                    .muc_service()
                    .enabled_local_account(invitee_localpart)
                    .await?
                else {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                if room.members_only && !request.temporary_storage {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "wait",
                        "service-unavailable",
                    ));
                }
                let mut live_claim_id = None;
                let durable_invite = if room.members_only {
                    let delayed = add_delay_from(&invitation, chrono::Utc::now(), Some(&room_jid));
                    let cluster_authority = if state.federated_muc_pg_authority_enabled() {
                        state.federated_muc_admit_mutation()?;
                        let Some(actor_target) = state
                            .muc_service()
                            .local_cluster_occupancy_target(
                                room.id,
                                own.cluster_epoch,
                                own.connection_id,
                            )
                            .await?
                        else {
                            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                        };
                        Some(ClusterMucInviteAuthority {
                            operation_id: local_durable_invite_id
                                .expect("local members-only invite allocates a fence"),
                            expected_room_epoch: room.room_epoch,
                            expected_config_version: room.config_version,
                            actor: ClusterMucPrincipal::Federated {
                                bare_jid: actor_bare_jid.clone(),
                                authenticated_domain: authenticated_domain.to_owned(),
                            },
                            actor_full_jid: actor_full_jid.clone(),
                            actor_target: Some(actor_target),
                            subject: ClusterMucAffiliationSubject::Local {
                                user_id: local_user.id,
                                bare_jid: invitee_bare.clone(),
                            },
                            reason: reason.map(str::to_owned),
                        })
                    } else {
                        None
                    };
                    match state
                        .muc_service()
                        .admit_local_invite_command(
                            local_durable_invite_id
                                .expect("local members-only invite allocates a fence"),
                            room.id,
                            local_user.id,
                            &room_jid,
                            &delayed,
                            false,
                            super::super::muc::temporary_muc_offline_policy(state),
                            cluster_authority.as_ref(),
                        )
                        .await?
                    {
                        DurableMucInviteOutcome::Stored {
                            id,
                            live_claim_id: admitted_claim_id,
                            ..
                        } => {
                            live_claim_id = admitted_claim_id;
                            if let Some(authority) = &cluster_authority {
                                if let Err(error) = state
                                    .wake_committed_muc_operation(authority.operation_id)
                                    .await
                                {
                                    tracing::warn!(?error, operation_id = %authority.operation_id,
                                        "committed federated MUC invitation wake failed");
                                }
                            }
                            Some(id)
                        }
                        DurableMucInviteOutcome::Replay { .. } => {
                            if let Some(authority) = &cluster_authority {
                                state
                                    .wake_committed_muc_operation(authority.operation_id)
                                    .await?;
                            }
                            return Ok(None);
                        }
                        DurableMucInviteOutcome::QuotaExceeded => {
                            return Ok(federated_error(
                                &request.stanza,
                                from,
                                "wait",
                                "resource-constraint",
                            ));
                        }
                        DurableMucInviteOutcome::RecipientUnavailable => {
                            // The local invitee disappeared after the initial
                            // route lookup.  Suppress the invitation without
                            // exposing account lifecycle state to the remote
                            // room occupant.
                            return Ok(None);
                        }
                        DurableMucInviteOutcome::Outcast => {
                            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                        }
                        DurableMucInviteOutcome::AuthorityRejected => {
                            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                        }
                        DurableMucInviteOutcome::Stale => {
                            return Ok(federated_error(
                                &request.stanza,
                                from,
                                "cancel",
                                "item-not-found",
                            ));
                        }
                    }
                } else {
                    None
                };
                let mut targets = state.session_entries_for(&invitee_jid);
                if invitee.resourcepart().is_none() {
                    targets.retain(|(_, session)| {
                        session.available.load(Ordering::Relaxed)
                            && session.priority.load(Ordering::Relaxed) >= 0
                    });
                    targets.sort_by(|(left_jid, left), (right_jid, right)| {
                        right
                            .priority
                            .load(Ordering::Relaxed)
                            .cmp(&left.priority.load(Ordering::Relaxed))
                            .then_with(|| left_jid.cmp(right_jid))
                    });
                }
                if let Some(message_id) = durable_invite {
                    if state.federated_muc_pg_authority_enabled()
                        && (!crate::services::messaging::committed_live_delivery_has_fence(
                            true,
                            message_id,
                            live_claim_id,
                        ) || state.message_service().direct_mode()
                            != crate::cluster::DirectPostCommitMode::Live)
                    {
                        state
                            .message_service()
                            .rearm_unrouted_live_direct(
                                local_user.id,
                                message_id,
                                &mut live_claim_id,
                            )
                            .await;
                        return Ok(None);
                    }
                }
                let live_delivery =
                    durable_invite.map(|message_id| crate::xmpp::outbound::DurableDelivery {
                        recipient_id: local_user.id,
                        message_id,
                        claim_id: live_claim_id,
                    });
                let mut delivered = false;
                let mut delivered_full_jid = None;
                for (full_jid, session) in targets {
                    let accepted = if let Some(delivery) = live_delivery {
                        session
                            .sender
                            .try_send_durable(invitation.clone(), delivery)
                            .is_ok()
                    } else {
                        session.sender.try_send(invitation.clone()).is_ok()
                    };
                    if accepted {
                        state
                            .federated_muc_telemetry()
                            .online_queue_result(true, live_delivery.is_some());
                        delivered = true;
                        delivered_full_jid = Some(full_jid);
                        break;
                    }
                }
                if !delivered {
                    if let Some(message_id) = durable_invite {
                        if state.federated_muc_pg_authority_enabled()
                            && state.message_service().direct_mode()
                                != crate::cluster::DirectPostCommitMode::Live
                        {
                            state
                                .message_service()
                                .rearm_unrouted_live_direct(
                                    local_user.id,
                                    message_id,
                                    &mut live_claim_id,
                                )
                                .await;
                            return Ok(None);
                        }
                    }
                    if let Some(route) = state
                        .route_federated_muc_account_message_remote(
                            &invitee_jid,
                            &invitation,
                            live_delivery,
                        )
                        .await
                    {
                        delivered = true;
                        delivered_full_jid = route.accepted_full_jid;
                    }
                }
                if !delivered {
                    if let Some(message_id) = durable_invite {
                        state
                            .message_service()
                            .rearm_unrouted_live_direct(
                                local_user.id,
                                message_id,
                                &mut live_claim_id,
                            )
                            .await;
                    }
                }
                if delivered {
                    if request.carbon_eligible
                        && state.message_service().direct_mode()
                            == crate::cluster::DirectPostCommitMode::Live
                    {
                        crate::services::message_carbons::send_received_carbons(
                            state,
                            &invitee_bare,
                            delivered_full_jid.as_deref(),
                            &invitation,
                        )
                        .await;
                    }
                } else if durable_invite.is_none() && request.temporary_storage {
                    let delayed = add_delay_from(&invitation, chrono::Utc::now(), Some(&room_jid));
                    let offline_outcome = state
                        .muc_service()
                        .store_federated_muc_offline(
                            local_user.id,
                            &room_jid,
                            &delayed,
                            false,
                            super::super::muc::temporary_muc_offline_policy(state),
                        )
                        .await?;
                    if offline_outcome == OfflineStoreOutcome::QuotaExceeded {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "wait",
                            "resource-constraint",
                        ));
                    }
                    if offline_outcome == OfflineStoreOutcome::RecipientUnavailable {
                        return Ok(None);
                    }
                }
                if !delivered
                    && request.temporary_storage
                    && state.message_service().direct_mode()
                        == crate::cluster::DirectPostCommitMode::Live
                {
                    if let Err(error) = state.dispatch_push_notification(local_user.id).await {
                        tracing::warn!(?error, recipient_id = %local_user.id, %room_jid, "accepted federated offline mediated MUC invitation could not trigger push notification");
                    }
                }
            } else if room.members_only {
                let operation_id = crate::services::muc::operation_id(&serde_json::json!({
                    "kind":"muc_invitation","stream":connection_id,
                    "stanza_id":request.stanza.id,"room":room_jid,
                    "actor":actor_full_jid,"invitee":invitee_bare,"reason":reason,
                }))?;
                let cluster_authority = if state.federated_muc_pg_authority_enabled() {
                    state.federated_muc_admit_mutation()?;
                    let Some(actor_target) = state
                        .muc_service()
                        .local_cluster_occupancy_target(
                            room.id,
                            own.cluster_epoch,
                            own.connection_id,
                        )
                        .await?
                    else {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    };
                    Some(ClusterMucInviteAuthority {
                        operation_id,
                        expected_room_epoch: room.room_epoch,
                        expected_config_version: room.config_version,
                        actor: ClusterMucPrincipal::Federated {
                            bare_jid: actor_bare_jid.clone(),
                            authenticated_domain: authenticated_domain.to_owned(),
                        },
                        actor_full_jid: actor_full_jid.clone(),
                        actor_target: Some(actor_target),
                        subject: ClusterMucAffiliationSubject::Federated {
                            bare_jid: invitee_bare.clone(),
                        },
                        reason: reason.map(str::to_owned),
                    })
                } else {
                    None
                };
                match state
                    .muc_service()
                    .admit_federated_invite_command(
                        room.id,
                        &invitee_bare,
                        invitee_domain,
                        &invitation,
                        Some(&room_jid),
                        state.federation_outbox().outbox_policy(),
                        cluster_authority.as_ref(),
                    )
                    .await
                {
                    Ok(true) => {
                        state.federation_outbox().wake_outbox();
                        if cluster_authority.is_some() {
                            state.wake_committed_muc_operation(operation_id).await?;
                        }
                    }
                    Ok(false) => {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                    Err(error) => {
                        tracing::warn!(?error, %invitee_bare, %room_jid, "federated mediated MUC invite admission failed atomically");
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "wait",
                            "resource-constraint",
                        ));
                    }
                }
            } else if !state
                .federation_outbox()
                .send(invitee_domain, invitation, Some(room_jid.clone()))
                .await
            {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "remote-server-timeout",
                ));
            }
            delivered_invitation = true;
        }
        return if delivered_invitation {
            Ok(None)
        } else {
            Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ))
        };
    }
    // In single-node mode the room map is the occupancy authority. Serialize
    // the final remote endpoint/incarnation check, durable admission and live
    // fan-out with the same room gate used by kick/ban/leave. Cluster mode
    // instead presents the exact PostgreSQL occupancy tuple below.
    let local_authority_guard = if state.federated_muc_pg_authority_enabled() {
        None
    } else {
        Some(state.muc_service().lock_local_room_mutation(room.id).await)
    };
    let Some(refreshed_room) = state
        .muc_service()
        .federated_room_snapshot(localpart(&room_jid))
        .await?
    else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    };
    if refreshed_room.id != room.id || refreshed_room.room_epoch != room.room_epoch {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    let Some((_, refreshed_own)) =
        state
            .muc_occupants_for(&room_jid)
            .into_iter()
            .find(|(_, occupant)| {
                occupant.full_jid == own.full_jid
                    && occupant.connection_id == own.connection_id
                    && occupant.cluster_epoch == own.cluster_epoch
                    && occupant.nick == own.nick
            })
    else {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    };
    if !federated_endpoint_matches(&refreshed_own, authenticated_domain) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    let room = refreshed_room;
    let own = refreshed_own;
    let current_affiliation = state
        .muc_service()
        .federated_affiliation(room.id, &actor_bare_jid)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if current_affiliation != own.affiliation
        || current_affiliation == "outcast"
        || (room.members_only && current_affiliation == "none")
    {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    let cluster_target = if state.federated_muc_pg_authority_enabled() {
        let Some(target) = state
            .muc_service()
            .local_cluster_occupancy_target(room.id, own.cluster_epoch, own.connection_id)
            .await?
            .filter(|target| {
                target.room_epoch == room.room_epoch
                    && target.full_jid == own.full_jid
                    && target.nick == own.nick
                    && target.connection_uuid == own.connection_id
            })
        else {
            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
        };
        Some(target)
    } else {
        None
    };
    if own.role == "visitor" {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    let subject_command = match &request.subject {
        Ok(subject) => subject.as_deref(),
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    let origin_id = match &request.origin_id {
        Ok(origin_id) => origin_id.as_deref(),
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    let author_retraction = match request.author_retraction {
        Ok(retraction) => retraction,
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    if subject_command.is_some() && author_retraction.is_some() {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "bad-request",
        ));
    }
    if subject_command.is_some()
        && own.role != "moderator"
        && !(room.allow_subject_change && own.role == "participant")
    {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    let stable_id = uuid::Uuid::new_v4();
    let reflected = set_muc_occupant_id(
        &add_stanza_id(
            &set_to(
                &set_from(&request.stanza.raw, &format!("{room_jid}/{}", own.nick)),
                &room_jid,
            ),
            &room_jid,
            stable_id,
        ),
        &own.occupant_id,
    );
    let encrypted = request.encrypted;
    let archive_enabled = room.logging_enabled
        && request.permanent_storage
        && (encrypted || !state.archive_requires_encryption());
    let archive = if archive_enabled && encrypted {
        encrypted_archive_stanza(&reflected)
    } else {
        reflected.clone()
    };
    let actor_scope = crate::jid::canonical_bare_key(&actor_full_jid)?;
    let actor_authority = MucActorAuthority {
        clustered: state.federated_muc_pg_authority_enabled(),
        expected_room_epoch: room.room_epoch,
        principal: MucActorPrincipal::Federated {
            bare_jid: actor_bare_jid.clone(),
            authenticated_domain: authenticated_domain.to_owned(),
        },
        actor_scope: actor_scope.clone(),
        full_jid: actor_full_jid.clone(),
        nick: own.nick.clone(),
        occupant_incarnation: own.cluster_epoch,
        connection_uuid: own.connection_id,
        expected_role: own.role.clone(),
        expected_affiliation: current_affiliation.clone(),
        cluster_target,
    };
    if let Some(target_id) = author_retraction {
        let Some(original) = state
            .muc_service()
            .federated_message_by_id(room.id, target_id)
            .await?
        else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        };
        if crate::jid::canonical_bare_key(&original.sender_jid)
            .ok()
            .as_deref()
            != Some(actor_scope.as_str())
        {
            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
        }
        let Ok(original_document) = roxmltree::Document::parse(&original.stanza) else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "wait",
                "internal-server-error",
            ));
        };
        let original_root = original_document.root_element();
        if original_root.tag_name().name() != "message"
            || original_root.attribute("type") != Some("groupchat")
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "not-acceptable",
            ));
        }
        let stamp = chrono::Utc::now();
        let tombstone = XmlElement::namespaced("message", "jabber:client")
            .attr("from", original_root.attribute("from").unwrap_or(&room_jid))
            .attr("to", &room_jid)
            .attr("type", "groupchat")
            .attr("id", original_root.attribute("id").unwrap_or_default())
            .child(
                XmlElement::namespaced("stanza-id", "urn:xmpp:sid:0")
                    .attr("id", target_id)
                    .attr("by", &room_jid),
            )
            .child(
                XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0").attr(
                    "id",
                    muc_occupant_id(&room.occupant_id_secret, &original.sender_jid),
                ),
            )
            .child(
                XmlElement::namespaced("retracted", "urn:xmpp:message-retract:1")
                    .attr("stamp", stamp.format("%Y-%m-%dT%H:%M:%SZ")),
            )
            .finish();
        match state
            .muc_service()
            .retract_local_message_and_archive_action(MucRetractionMutation {
                action_id: stable_id,
                room_id: room.id,
                target_id,
                expected_stanza: &original.stanza,
                actor_scope: &actor_scope,
                sender_jid: &actor_full_jid,
                nick: &own.nick,
                tombstone: &tombstone,
                action_stanza: &reflected,
                reason: None,
                kind: MucRetractionKind::Author,
                authority: actor_authority,
            })
            .await?
        {
            MucRetractionOutcome::Applied => {}
            MucRetractionOutcome::Unauthorized => {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
        }
    } else if let Some(subject) = subject_command {
        let service = state.muc_service();
        if state.federated_muc_pg_authority_enabled() {
            let Some(actor_target) = service
                .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                .await?
            else {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            };
            if actor_target.full_jid != own.full_jid
                || actor_target.connection_uuid != own.connection_id
            {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            let operation_id = crate::services::muc::operation_id(&serde_json::json!({
                "kind":"subject","stream":connection_id,"stanza_id":request.stanza.id,
                "room":room_jid,"actor":actor_target,"subject":subject,"archive":archive_enabled
            }))?;
            match service
                .set_local_cluster_subject(
                    operation_id,
                    room.room_epoch,
                    room.config_version,
                    &actor_target,
                    MucSubjectMutation {
                        stanza_id: stable_id,
                        room_id: room.id,
                        actor_scope: &actor_scope,
                        sender_jid: &actor_full_jid,
                        nick: &own.nick,
                        subject,
                        stanza: &archive,
                        encrypted,
                    },
                    archive_enabled,
                )
                .await?
            {
                ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                ClusterMucTransitionOutcome::Unauthorized => {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                }
                _ => return Ok(federated_error(&request.stanza, from, "cancel", "conflict")),
            }
            if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                tracing::warn!(?error, %operation_id, "committed federated MUC subject wake failed; PostgreSQL outbox will catch up");
            }
            return Ok(None);
        }
        match service
            .set_local_subject(
                MucSubjectMutation {
                    stanza_id: stable_id,
                    room_id: room.id,
                    actor_scope: &actor_scope,
                    sender_jid: &actor_full_jid,
                    nick: &own.nick,
                    subject,
                    stanza: &archive,
                    encrypted,
                },
                archive_enabled,
                actor_authority,
            )
            .await?
        {
            MucSubjectOutcome::Applied => {}
            MucSubjectOutcome::Unauthorized => {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            MucSubjectOutcome::Stale => {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
        }
    } else {
        let admission = state
            .muc_service()
            .admit_local_discussion(MucDiscussion {
                id: stable_id,
                room_id: room.id,
                actor_scope: actor_scope.clone(),
                origin_id: origin_id.map(str::to_owned),
                sender_jid: actor_full_jid.clone(),
                nick: own.nick.clone(),
                stanza: archive.clone(),
                encrypted,
                archive: archive_enabled,
                retention_days: state.muc_mam_retention_days(),
                authority: actor_authority,
            })
            .await?;
        match admission {
            MucDiscussionAdmission::Stored(_) => {}
            MucDiscussionAdmission::Replay(_) => return Ok(None),
            MucDiscussionAdmission::Unauthorized => {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            MucDiscussionAdmission::Stale => {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
        }
    }
    match state
        .federated_muc_publish_room_message(&room_jid, &reflected, Some(&actor_full_jid))
        .await
    {
        Ok(()) => {}
        Err(_) => record_federated_muc_post_commit_failure(
            state,
            &room_jid,
            "*",
            "cluster groupchat fan-out",
        ),
    }
    let occupants = state
        .muc_occupants_for(&room_jid)
        .into_iter()
        .map(|(_, occupant)| occupant)
        .collect::<Vec<_>>();
    let blocked = state
        .blocked_muc_recipient_accounts(
            &occupants,
            &[format!("{room_jid}/{}", own.nick), actor_full_jid.clone()],
        )
        .await;
    for occupant in occupants {
        if crate::jid::canonical_bare_key(&occupant.full_jid)
            .is_ok_and(|owner| blocked.contains(&owner))
        {
            continue;
        }
        let delivery = set_to(&reflected, &occupant.full_jid);
        if !state
            .deliver_to_muc_occupant_unchecked(&occupant, delivery)
            .await
        {
            record_federated_muc_post_commit_failure(
                state,
                &room_jid,
                &occupant.full_jid,
                "occupant groupchat queue",
            );
        }
    }
    drop(local_authority_guard);
    state.federated_muc_telemetry().message_routed();
    Ok(None)
}
