//! Federated MUC presence handling for remote room actors.

use super::*;

/// Handle a presence addressed to a local conference room by a remote entity.
/// `authenticated_domain` and `connection_id` MUST come from the authenticated
/// S2S stream, never from stanza attributes.
pub(crate) fn federated_muc_presence<'a>(
    state: &'a AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    root: Node<'_, '_>,
    raw: &str,
) -> impl std::future::Future<Output = Result<Option<String>>> + Send + 'a {
    let authenticated_domain = authenticated_domain.to_owned();
    let request = FederatedPresenceRequest::from_node(root, raw);
    async move {
        federated_muc_presence_owned(state, &authenticated_domain, connection_id, request).await
    }
}

async fn federated_muc_presence_owned(
    state: &AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    request: FederatedPresenceRequest,
) -> Result<Option<String>> {
    let from = request.stanza.from.as_str();
    let to = request.stanza.to.as_str();
    if !authenticated_remote_actor(authenticated_domain, from) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    let actor = crate::jid::CanonicalJid::parse(from)
        .expect("authenticated_remote_actor already validated the full JID");
    let actor_full_jid = actor.to_string();
    let actor_bare_jid = actor.bare();
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
    let nick = to_jid.resourcepart().unwrap_or_default();
    if !valid_muc_room(localpart(&room_jid)) || !valid_muc_nick(nick) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        ));
    }

    let existing = state
        .muc_occupants_for(&room_jid)
        .into_iter()
        .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid));
    if matches!(
        request.stanza.kind.as_deref(),
        Some("unavailable" | "error")
    ) {
        if let Some((_, occupant)) = existing {
            let exact_connection = matches!(
                &occupant.endpoint,
                MucOccupantEndpoint::Federated { connection_id: owner, .. }
                    if *owner == connection_id && occupant.connection_id == connection_id
            );
            if !federated_endpoint_matches(&occupant, authenticated_domain) || !exact_connection {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "not-authorized",
                ));
            }
            let status = (request.stanza.kind.as_deref() == Some("error")).then_some(333);
            unregister_remote_occupant(state, occupant, status).await?;
        }
        return Ok(None);
    }
    if request.stanza.kind.is_some() {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "bad-request",
        ));
    }
    if let Some((_, mut occupant)) = existing {
        let mut guarded_room = None;
        let local_actor_guard = if state.federated_muc_pg_authority_enabled() {
            None
        } else {
            let Some(initial_room) = state
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
            let guard = state
                .muc_service()
                .lock_local_room_mutation(initial_room.id)
                .await;
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
            if refreshed_room.room_epoch != initial_room.room_epoch {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
            let Some((_, current)) =
                state
                    .muc_occupants_for(&room_jid)
                    .into_iter()
                    .find(|(_, current)| {
                        same_remote_actor(&current.full_jid, &actor_full_jid)
                            && current.cluster_epoch == occupant.cluster_epoch
                            && current.connection_id == occupant.connection_id
                    })
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "not-acceptable",
                ));
            };
            occupant = current;
            guarded_room = Some(refreshed_room);
            Some(guard)
        };
        let exact_connection = matches!(
            &occupant.endpoint,
            MucOccupantEndpoint::Federated { connection_id: owner, .. }
                if *owner == connection_id && occupant.connection_id == connection_id
        );
        if !federated_endpoint_matches(&occupant, authenticated_domain) {
            tracing::debug!(room=%room_jid, existing_connection_id=%occupant.connection_id,
                incoming_connection_id=%connection_id, exact_connection,
                "federated MUC presence rejected an existing occupant endpoint");
            return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
        }
        if !exact_connection {
            if !is_idempotent_remote_join(&occupant, authenticated_domain, &actor_full_jid, nick) {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
            let mut rebind_operation = None;
            if state.federated_muc_pg_authority_enabled() {
                state.federated_muc_admit_mutation()?;
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
                let Some(target) = state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        occupant.cluster_epoch,
                        occupant.connection_id,
                    )
                    .await?
                else {
                    return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                };
                let operation_id = uuid::Uuid::new_v4();
                match state
                    .muc_service()
                    .rebind_federated_cluster_occupancy(
                        operation_id,
                        &target,
                        state.federated_muc_owner_node_id(),
                        authenticated_domain,
                        connection_id,
                        std::time::Duration::from_secs(90),
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        rebind_operation = Some(operation_id);
                    }
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "auth",
                            "not-authorized",
                        ));
                    }
                    _ => {
                        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                    }
                }
            }
            if let Some(operation_id) = rebind_operation {
                if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                    tracing::warn!(?error, %operation_id, room=%room_jid,
                        "federated MUC rebind committed; polling will deliver its event");
                }
            }
            let rebound = if let Some(rebound) =
                state.rebind_local_federated_muc_occupant_exact(&occupant, connection_id)
            {
                rebound
            } else {
                // The old stream may have removed its local entry after the
                // PostgreSQL commit. Restore only an empty slot; never replace
                // a newer incarnation or a different connection.
                let mut replacement = occupant.clone();
                replacement.connection_id = connection_id;
                replacement.endpoint = MucOccupantEndpoint::Federated {
                    authenticated_domain: authenticated_domain.to_owned(),
                    connection_id,
                };
                match state.publish_local_muc_join_if_vacant(&replacement) {
                    crate::xmpp::local_routes::muc::LocalMucJoinPublication::Published
                    | crate::xmpp::local_routes::muc::LocalMucJoinPublication::AlreadyPublished => {
                        replacement
                    }
                    crate::xmpp::local_routes::muc::LocalMucJoinPublication::Occupied => {
                        tracing::warn!(room=%room_jid, %nick,
                            "committed federated MUC rebind found a different local projection");
                        return Ok(None);
                    }
                }
            };
            occupant = rebound;
        }
        if occupant.nick != nick {
            let room = if let Some(room) = guarded_room.as_ref() {
                room.clone()
            } else {
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
                room
            };
            let affiliation = state
                .muc_service()
                .federated_affiliation(room.id, &actor_bare_jid)
                .await?;
            if affiliation.as_deref() == Some("outcast") {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            if room.members_only && affiliation.is_none() {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "registration-required",
                ));
            }
            if state
                .muc_service()
                .federated_nick_reserved_for_other(room.id, &actor_bare_jid, nick)
                .await?
            {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
            occupant.affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
            occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if room.moderated && occupant.affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();
            occupant.room_non_anonymous = room.non_anonymous;
            let old_occupant = occupant.clone();
            let old_serializable = SerializableMucOccupant::from(&old_occupant);
            let old_nick = occupant.nick.clone();
            occupant.nick = nick.to_owned();
            occupant.payload = request.payload.clone();
            occupant.endpoint = MucOccupantEndpoint::Federated {
                authenticated_domain: canonical_authenticated_domain(authenticated_domain),
                connection_id,
            };
            let new_serializable = SerializableMucOccupant::from(&occupant);
            let old_json = serde_json::to_string(&old_serializable)?;
            let new_json = serde_json::to_string(&new_serializable)?;
            let mut cluster_operation = None;
            if state.federated_muc_pg_authority_enabled() {
                state.federated_muc_admit_mutation()?;
                let target = state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        occupant.cluster_epoch,
                        occupant.connection_id,
                    )
                    .await?
                    .context("federated MUC rename lost its exact PG occupancy")?;
                let operation_id = uuid::Uuid::new_v4();
                match state
                    .muc_service()
                    .rename_local_cluster_occupancy(
                        operation_id,
                        &target,
                        state.federated_muc_owner_node_id(),
                        nick,
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        cluster_operation = Some(operation_id)
                    }
                    ClusterMucTransitionOutcome::Conflict => {
                        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                    }
                    ClusterMucTransitionOutcome::Stale
                    | ClusterMucTransitionOutcome::Destroyed
                    | ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "not-acceptable",
                        ));
                    }
                }
                if let Err(error) = state
                    .federated_muc_rename_occupant(
                        &room_jid,
                        &old_nick,
                        nick,
                        occupant.cluster_epoch,
                        &old_json,
                        &new_json,
                    )
                    .await
                {
                    tracing::warn!(?error, room=%room_jid,
                        "could not refresh Redis MUC nickname soft-state after PG commit");
                }
            } else {
                match state
                    .federated_muc_rename_occupant(
                        &room_jid,
                        &old_nick,
                        nick,
                        occupant.cluster_epoch,
                        &old_json,
                        &new_json,
                    )
                    .await?
                {
                    crate::cluster::MucRename::Renamed => {}
                    crate::cluster::MucRename::Conflict => {
                        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                    }
                    crate::cluster::MucRename::Stale => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "not-acceptable",
                        ));
                    }
                }
            }
            let move_outcome = state.move_local_muc_nickname_exact(
                crate::services::muc::LocalMucOccupantIdentity::from(&old_occupant),
                &occupant,
                cluster_operation.is_some(),
            );
            match move_outcome {
                crate::xmpp::local_routes::muc::LocalMucNicknameMove::Published
                | crate::xmpp::local_routes::muc::LocalMucNicknameMove::AlreadyPublished => {}
                crate::xmpp::local_routes::muc::LocalMucNicknameMove::DeferredToReconciliation
                    if cluster_operation.is_some() =>
                {
                    tracing::warn!(room=%room_jid, %nick,
                        "PG-authoritative federated MUC rename found another local incarnation; reconciliation will repair the cache");
                }
                crate::xmpp::local_routes::muc::LocalMucNicknameMove::CollisionRestored
                | crate::xmpp::local_routes::muc::LocalMucNicknameMove::CollisionRestoreFailed => {
                    if move_outcome == crate::xmpp::local_routes::muc::LocalMucNicknameMove::CollisionRestoreFailed {
                        tracing::error!(room=%room_jid, old_nick=%old_nick,
                            "could not restore federated MUC actor after nickname collision");
                    }
                    drop(local_actor_guard);
                    let _ = state
                        .federated_muc_rename_occupant(
                            &room_jid,
                            nick,
                            &old_nick,
                            occupant.cluster_epoch,
                            &new_json,
                            &old_json,
                        )
                        .await;
                    return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                }
                _ => {
                    if cluster_operation.is_none() {
                        drop(local_actor_guard);
                        let _ = state
                            .federated_muc_rename_occupant(
                                &room_jid,
                                nick,
                                &old_nick,
                                occupant.cluster_epoch,
                                &new_json,
                                &old_json,
                            )
                            .await;
                    }
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "not-acceptable",
                    ));
                }
            }
            drop(local_actor_guard);
            if let Some(operation_id) = cluster_operation {
                if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                    tracing::warn!(?error, %operation_id, room=%room_jid,
                        "federated MUC rename committed; signed wake will be recovered by polling");
                }
                return Ok(None);
            }
            state
                .federated_muc_publish_nickname_change(
                    &room_jid,
                    &old_serializable,
                    &new_serializable,
                    request.stanza.id.as_deref(),
                )
                .await?;
            for (_, recipient) in state.muc_occupants_for(&room_jid) {
                let recipient_serializable = SerializableMucOccupant::from(&recipient);
                let unavailable = muc_nickname_change_presence(
                    &old_serializable,
                    &recipient_serializable,
                    nick,
                    request.stanza.id.as_deref(),
                );
                let _ = state.deliver_to_muc_occupant(&recipient, unavailable).await;
                let self_presence = recipient.full_jid == actor_full_jid;
                let available = muc_presence_stanza(
                    &new_serializable,
                    &recipient.full_jid,
                    false,
                    self_presence,
                    false,
                    request.stanza.id.as_deref(),
                    room.non_anonymous || self_presence || recipient.role == "moderator",
                );
                let _ = state.deliver_to_muc_occupant(&recipient, available).await;
            }
            return Ok(None);
        }
        if !is_idempotent_remote_join(&occupant, authenticated_domain, &actor_full_jid, nick) {
            tracing::debug!(room=%room_jid, %nick,
                "federated MUC presence rejected a non-idempotent actor refresh");
            return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
        }
        if let Some(room) = guarded_room.as_ref() {
            let affiliation = state
                .muc_service()
                .federated_affiliation(room.id, &actor_bare_jid)
                .await?;
            if affiliation.as_deref() == Some("outcast") {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            if room.members_only && affiliation.is_none() {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "registration-required",
                ));
            }
            occupant.affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
            occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if room.moderated && occupant.affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();
            occupant.room_non_anonymous = room.non_anonymous;
        }
        occupant.endpoint = MucOccupantEndpoint::Federated {
            authenticated_domain: canonical_authenticated_domain(authenticated_domain),
            connection_id,
        };
        occupant.payload = request.payload.clone();
        if state.federated_muc_pg_authority_enabled() {
            let room = state
                .muc_service()
                .federated_room_snapshot(localpart(&room_jid))
                .await?
                .context("federated MUC presence refresh references a missing room")?;
            let target = state
                .muc_service()
                .local_cluster_occupancy_target(
                    room.id,
                    occupant.cluster_epoch,
                    occupant.connection_id,
                )
                .await?
                .context("federated MUC presence refresh lost its exact PG occupancy")?;
            if !state
                .muc_service()
                .refresh_local_cluster_presence(
                    &target,
                    state.federated_muc_owner_node_id(),
                    &occupant.payload,
                    std::time::Duration::from_secs(90),
                )
                .await?
            {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "not-acceptable",
                ));
            }
        }
        let refreshed = state.refresh_local_muc_presence_exact(&occupant, guarded_room.is_some());
        occupant = if let Some(refreshed) = refreshed {
            refreshed
        } else if state.federated_muc_pg_authority_enabled() {
            tracing::warn!(room=%room_jid, %nick,
                "PG-authoritative MUC presence refresh lost its exact local incarnation; reconciliation will repair the cache");
            return Ok(None);
        } else if state.local_muc_occupant_by_nick(&room_jid, nick).is_some() {
            tracing::debug!(room=%room_jid, %nick,
                "federated MUC presence refresh found a different local occupant");
            return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
        } else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "not-acceptable",
            ));
        };
        drop(local_actor_guard);
        let serializable = SerializableMucOccupant::from(&occupant);
        if state.federated_muc_redis_transport_enabled() {
            let json = serde_json::to_string(&serializable)?;
            if state.federated_muc_pg_authority_enabled() {
                if let Err(error) = state
                    .federated_muc_register_occupant(&room_jid, nick, &json)
                    .await
                {
                    tracing::warn!(?error, room=%room_jid, nick=%nick,
                        "could not refresh Redis MUC presence soft-state");
                }
            } else if !state
                .federated_muc_register_occupant(&room_jid, nick, &json)
                .await?
            {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "not-acceptable",
                ));
            }
            state
                .federated_muc_publish_presence(
                    &room_jid,
                    &serializable,
                    false,
                    false,
                    request.stanza.id.as_deref(),
                )
                .await?;
        }
        for (_, recipient) in state.muc_occupants_for(&room_jid) {
            let self_presence = recipient.full_jid == actor_full_jid;
            if request.muc_join && self_presence {
                continue;
            }
            let update = muc_presence_stanza(
                &serializable,
                &recipient.full_jid,
                false,
                self_presence,
                false,
                request.stanza.id.as_deref(),
                serializable.room_non_anonymous || self_presence || recipient.role == "moderator",
            );
            let _ = state.deliver_to_muc_occupant(&recipient, update).await;
        }
        if request.muc_join {
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
            let history_request = match request.history_request {
                Ok(request) => request,
                Err(()) => {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "modify",
                        "bad-request",
                    ));
                }
            };
            let mut roster_nicks = std::collections::HashSet::new();
            for (_, present) in state.muc_occupants_for(&room_jid) {
                if present.cluster_epoch == occupant.cluster_epoch
                    || !roster_nicks.insert(present.nick.clone())
                {
                    continue;
                }
                let roster_presence = muc_presence_stanza(
                    &SerializableMucOccupant::from(&present),
                    &actor_full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                );
                let _ = state
                    .deliver_to_muc_occupant(&occupant, roster_presence)
                    .await;
            }
            for json in state
                .federated_muc_global_occupants(&room_jid)
                .await?
                .into_values()
            {
                let Ok(present) = serde_json::from_str::<SerializableMucOccupant>(&json) else {
                    continue;
                };
                if present.cluster_epoch == occupant.cluster_epoch
                    || !roster_nicks.insert(present.nick.clone())
                {
                    continue;
                }
                let roster_presence = muc_presence_stanza(
                    &present,
                    &actor_full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                );
                let _ = state
                    .deliver_to_muc_occupant(&occupant, roster_presence)
                    .await;
            }
            let self_presence = muc_presence_stanza(
                &serializable,
                &actor_full_jid,
                false,
                true,
                false,
                request.stanza.id.as_deref(),
                true,
            );
            let _ = state
                .deliver_to_muc_occupant(&occupant, self_presence)
                .await;
            let mut history = Vec::new();
            if history_request.max_stanzas != 0 && room.logging_enabled {
                for message in state
                    .muc_service()
                    .federated_history_since(room.id, 100, history_request.since)
                    .await?
                {
                    let stanza =
                        federated_history_stanza(&room, &message.stanza, &message.sender_jid);
                    history.push(set_to(
                        &add_delay_from(&stanza, message.created_at, Some(&room_jid)),
                        &actor_full_jid,
                    ));
                }
            }
            for delivery in super::super::muc::apply_muc_history_bounds(history, history_request) {
                let _ = state.deliver_to_muc_occupant(&occupant, delivery).await;
            }
            let subject =
                super::super::muc::current_muc_subject_stanza(&room, &room_jid, &actor_full_jid);
            let _ = state.deliver_to_muc_occupant(&occupant, subject).await;
        }
        return Ok(None);
    }

    let (room, created) = match state
        .muc_service()
        .get_or_create_federated_room(localpart(&room_jid), &actor_full_jid)
        .await
    {
        Ok(result) => result,
        Err(error) if crate::services::muc::is_capacity_exhausted(&error) => {
            state.federated_muc_telemetry().capacity_rejected();
            return Ok(federated_error(
                &request.stanza,
                from,
                "wait",
                "resource-constraint",
            ));
        }
        Err(error) => return Err(error),
    };
    if !created && room.configuration_is_expired(chrono::Utc::now()) {
        // PostgreSQL records the tombstone and terminal audience outbox in
        // one transaction. Redis is not an executable control plane.
        let _ = state
            .muc_service()
            .delete_expired_locked_room(room.id)
            .await?;
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    if !created
        && room.is_locked()
        && !room.can_configure_locked_room(&actor_full_jid, chrono::Utc::now())
    {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    if created {
        let _ =
            super::super::mix_muc::maybe_link_local_mirror(state, &room.localpart, &actor_bare_jid)
                .await?;
    }
    let affiliation = state
        .muc_service()
        .federated_affiliation(room.id, &actor_bare_jid)
        .await?;
    if affiliation.as_deref() == Some("outcast") {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    if let Some(password_hash) = room.password_hash.as_deref() {
        let supplied = zeroize::Zeroizing::new(request.password.clone());
        let password_hash = zeroize::Zeroizing::new(password_hash.to_owned());
        let valid = match crate::security::password_work::run(move || {
            Ok(crate::services::muc::verify_room_password(
                &password_hash,
                &supplied,
            ))
        })
        .await
        {
            Ok(valid) => valid,
            Err(error) if error.is_overloaded() => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "resource-constraint",
                ));
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "room password verification task failed: {error}"
                ));
            }
        };
        if !valid {
            return Ok(federated_error(
                &request.stanza,
                from,
                "auth",
                "not-authorized",
            ));
        }
    }
    let local_join_guard = if state.federated_muc_pg_authority_enabled() {
        None
    } else {
        Some(state.muc_service().lock_local_room_mutation(room.id).await)
    };
    let (room, affiliation) = if local_join_guard.is_some() {
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
        match refreshed_room.join_snapshot_consistency(&room) {
            Ok(()) => {}
            Err(MucJoinSnapshotError::RoomReplaced) => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
            Err(MucJoinSnapshotError::ConfigurationChanged) => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "resource-constraint",
                ));
            }
        }
        if refreshed_room.configuration_is_expired(chrono::Utc::now())
            || (refreshed_room.is_locked()
                && !refreshed_room.can_configure_locked_room(&actor_full_jid, chrono::Utc::now()))
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        let refreshed_affiliation = state
            .muc_service()
            .federated_affiliation(refreshed_room.id, &actor_bare_jid)
            .await?;
        (refreshed_room, refreshed_affiliation)
    } else {
        (room, affiliation)
    };
    if affiliation.as_deref() == Some("outcast") {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    if room.members_only && affiliation.is_none() {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "registration-required",
        ));
    }
    if state
        .muc_service()
        .federated_nick_reserved_for_other(room.id, &actor_bare_jid, nick)
        .await?
    {
        tracing::debug!(room=%room_jid, %nick,
            "federated MUC join rejected a reserved nickname");
        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
    }
    let local_occupant_count = if state.federated_muc_pg_authority_enabled() {
        0
    } else {
        state.muc_occupants_for(&room_jid).len()
    };
    let privileged_join = matches!(affiliation.as_deref(), Some("owner" | "admin"));
    let effective_capacity = room.max_occupants as usize + usize::from(privileged_join) * 10;
    if !state.federated_muc_pg_authority_enabled() && local_occupant_count >= effective_capacity {
        return Ok(federated_error(
            &request.stanza,
            from,
            "wait",
            "service-unavailable",
        ));
    }
    if !state.federated_muc_pg_authority_enabled()
        && state.local_muc_occupant_by_nick(&room_jid, nick).is_some()
    {
        tracing::debug!(room=%room_jid, %nick,
            "federated MUC join rejected an occupied local nickname");
        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
    }
    let history_request = match request.history_request {
        Ok(history_request) => history_request,
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
    let role = if matches!(affiliation.as_str(), "owner" | "admin") {
        "moderator"
    } else if room.moderated && affiliation == "none" {
        "visitor"
    } else {
        "participant"
    }
    .to_owned();
    let occupant = MucOccupant {
        full_jid: actor_full_jid.clone(),
        room_jid: room_jid.clone(),
        nick: nick.to_owned(),
        endpoint: MucOccupantEndpoint::Federated {
            authenticated_domain: canonical_authenticated_domain(authenticated_domain),
            connection_id,
        },
        affiliation,
        role,
        room_non_anonymous: room.non_anonymous,
        occupant_id: muc_occupant_id(&room.occupant_id_secret, &actor_bare_jid),
        cluster_epoch: uuid::Uuid::new_v4(),
        connection_id,
        sm_session_id: None,
        payload: request.payload.clone(),
    };
    let serializable = SerializableMucOccupant::from(&occupant);
    let exact_occupant_json = serde_json::to_string(&serializable)?;
    let mut cluster_event_id = None;
    if state.federated_muc_pg_authority_enabled() {
        state.federated_muc_admit_mutation()?;
        let principal = ClusterMucPrincipal::Federated {
            bare_jid: actor_bare_jid.clone(),
            authenticated_domain: canonical_authenticated_domain(authenticated_domain),
        };
        let cluster_operation_id = uuid::Uuid::new_v4();
        match state
            .muc_service()
            .claim_local_cluster_occupancy(ClusterMucJoin {
                operation_id: cluster_operation_id,
                room_id: room.id,
                expected_room_epoch: room.room_epoch,
                expected_config_version: room.config_version,
                principal,
                full_jid: &actor_full_jid,
                nick,
                owner_node_id: state.federated_muc_owner_node_id(),
                connection_uuid: connection_id,
                connection_epoch: 1,
                sm_session_id: None,
                occupant_incarnation: occupant.cluster_epoch,
                presence_payload: &occupant.payload,
                lease: std::time::Duration::from_secs(90),
            })
            .await?
        {
            ClusterMucJoinOutcome::Joined(authority) | ClusterMucJoinOutcome::Replay(authority) => {
                debug_assert_eq!(authority.occupant_incarnation, occupant.cluster_epoch);
            }
            ClusterMucJoinOutcome::Outcast => {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            ClusterMucJoinOutcome::MembershipRequired => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "registration-required",
                ));
            }
            conflict @ (ClusterMucJoinOutcome::ReservedNickname
            | ClusterMucJoinOutcome::NicknameConflict
            | ClusterMucJoinOutcome::FullJidConflict) => {
                tracing::debug!(room=%room_jid, %nick, ?conflict,
                    "federated MUC join rejected by PostgreSQL occupancy authority");
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
            ClusterMucJoinOutcome::Full => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "service-unavailable",
                ));
            }
            ClusterMucJoinOutcome::RoomMissing
            | ClusterMucJoinOutcome::RoomDestroyed
            | ClusterMucJoinOutcome::RoomLocked
            | ClusterMucJoinOutcome::StaleRoom => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
        }
        cluster_event_id = Some(cluster_operation_id.to_string());
        if let Err(error) = state
            .wake_committed_muc_operation(cluster_operation_id)
            .await
        {
            tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                "federated MUC join committed; signed wake failed and PostgreSQL polling will catch up");
        }
        if state.federated_muc_redis_transport_enabled() {
            let cache = state
                .cache_committed_muc_join(&serializable, effective_capacity)
                .await?;
            if let Err(error) = cache.refresh {
                tracing::warn!(?error, %room_jid,
                    "PostgreSQL committed federated MUC join; Redis cache refresh failed");
            }
            match cache.registration {
                Ok(crate::cluster::MucRegistration::Joined) => {}
                Ok(crate::cluster::MucRegistration::Conflict)
                | Ok(crate::cluster::MucRegistration::Full) => {
                    tracing::warn!(%room_jid, %nick,
                        "Redis federated MUC cache disagreed with committed PostgreSQL occupancy");
                }
                Err(error) => tracing::warn!(?error, %room_jid,
                    "PostgreSQL committed federated MUC join; Redis cache update failed"),
            }
        }
    }
    // Snapshot local occupants for the joiner's roster. The committed
    // PostgreSQL event handles durable audience delivery.
    let local_existing = state.muc_occupants_for(&room_jid);
    let publication = state.publish_local_muc_join_if_vacant(&occupant);
    if publication != crate::xmpp::local_routes::muc::LocalMucJoinPublication::Published {
        if !state.federated_muc_pg_authority_enabled() {
            return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
        }
        if publication == crate::xmpp::local_routes::muc::LocalMucJoinPublication::Occupied {
            tracing::error!(room=%room_jid, %nick,
                "committed federated MUC join found another local incarnation; preserving it and compensating this claim");
            drop(local_join_guard);
            super::super::muc::compensate_unpublished_cluster_muc_join(state, &room, &occupant)
                .await;
            return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
        }
    }
    drop(local_join_guard);
    if state.federated_muc_redis_transport_enabled() {
        match project_federated_join(
            state,
            FederatedJoinProjectionRequest {
                committed: cluster_event_id.is_some(),
                room_jid: &room_jid,
                nick,
                exact_occupant_json: &exact_occupant_json,
                occupant: &serializable,
                created,
                id: request.stanza.id.as_deref(),
            },
        )
        .await?
        {
            FederatedJoinProjectionResult::Committed {
                room_join,
                registration,
            } => {
                if let Err(error) = room_join {
                    tracing::warn!(?error, room=%room_jid,
                        "PostgreSQL committed federated MUC join; Redis room index repair failed");
                }
                match registration {
                    Ok(true) => {}
                    Ok(false) => tracing::warn!(room=%room_jid, %nick,
                        "PostgreSQL committed federated MUC join; Redis rejected exact occupant repair"),
                    Err(error) => tracing::warn!(?error, room=%room_jid, %nick,
                        "PostgreSQL committed federated MUC join; Redis exact occupant repair failed"),
                }
            }
            FederatedJoinProjectionResult::Legacy => {}
        }
    }

    let global = if state.federated_muc_redis_transport_enabled() {
        state
            .federated_muc_global_occupants(&room_jid)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };
    let mut roster_nicks = std::collections::HashSet::new();
    for json in global.values() {
        if let Ok(present) = serde_json::from_str::<SerializableMucOccupant>(json) {
            if present.nick != nick && roster_nicks.insert(present.nick.clone()) {
                let roster_presence = muc_presence_stanza(
                    &present,
                    from,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                );
                let _ = state
                    .deliver_to_muc_occupant(&occupant, roster_presence)
                    .await;
            }
        }
    }
    for (_, present) in &local_existing {
        if roster_nicks.insert(present.nick.clone()) {
            let roster_presence = muc_presence_stanza(
                &SerializableMucOccupant::from(present),
                from,
                false,
                false,
                false,
                None,
                room.non_anonymous || occupant.role == "moderator",
            );
            let _ = state
                .deliver_to_muc_occupant(&occupant, roster_presence)
                .await;
        }
        if cluster_event_id.is_none() {
            let joined = muc_presence_stanza(
                &serializable,
                &present.full_jid,
                false,
                false,
                false,
                None,
                room.non_anonymous || present.role == "moderator",
            );
            let _ = state.deliver_to_muc_occupant(present, joined).await;
        }
    }
    let self_presence = muc_presence_stanza(
        &serializable,
        &actor_full_jid,
        false,
        true,
        created,
        request.stanza.id.as_deref().or(cluster_event_id.as_deref()),
        true,
    );
    let _ = state
        .deliver_to_muc_occupant(&occupant, self_presence)
        .await;
    let mut history = Vec::new();
    if history_request.max_stanzas != 0 && room.logging_enabled {
        for message in state
            .muc_service()
            .federated_history_since(room.id, 100, history_request.since)
            .await?
        {
            let stanza = federated_history_stanza(&room, &message.stanza, &message.sender_jid);
            history.push(set_to(
                &add_delay_from(&stanza, message.created_at, Some(&room_jid)),
                &actor_full_jid,
            ));
        }
    }
    for delivery in super::super::muc::apply_muc_history_bounds(history, history_request) {
        let _ = state.deliver_to_muc_occupant(&occupant, delivery).await;
    }
    let subject = super::super::muc::current_muc_subject_stanza(&room, &room_jid, &actor_full_jid);
    let _ = state.deliver_to_muc_occupant(&occupant, subject).await;
    Ok(None)
}
