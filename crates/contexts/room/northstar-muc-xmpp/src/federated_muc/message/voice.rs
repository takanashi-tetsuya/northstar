//! Handle federated voice requests and approvals.

use super::*;
use crate::muc::MucVoiceForm;

pub(super) async fn handle_voice_form<S: MucHost>(
    state: &S,
    authenticated_domain: &str,
    connection_id: &uuid::Uuid,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
    occupancy: &RoomOccupancy<S>,
    voice_form: Option<&MucVoiceForm>,
) -> Result<MessageStep<()>> {
    let &MessageAddress {
        from,
        ref to_jid,
        ref room_jid,
        ..
    } = address;
    let RoomOccupancy { own, room } = occupancy;
    if let Some(voice_form) = voice_form {
        if to_jid.resourcepart().is_some()
            || !matches!(request.stanza.kind.as_deref(), None | Some("normal"))
        {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            )));
        }
        let mut occupants = state
            .federated_muc_global_occupants(room_jid)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(nick, json)| {
                serde_json::from_str::<SerializableMucOccupant>(&json)
                    .ok()
                    .map(|occupant| (nick, occupant))
            })
            .collect::<std::collections::HashMap<_, _>>();
        for (_, occupant) in state.muc_occupants_for(room_jid) {
            occupants.insert(
                occupant.nick.clone(),
                SerializableMucOccupant::from(&occupant),
            );
        }
        match voice_form {
            crate::muc::MucVoiceForm::Request => {
                if !room.moderated || own.role != "visitor" {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                let voice_request =
                    crate::muc::muc_voice_request(room_jid, &own.full_jid, &own.nick);
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
                            room_jid,
                            &moderator.nick,
                            &voice_request,
                            &own.full_jid,
                        )
                        .await?;
                }
                return Ok(MessageStep::Done(None));
            }
            crate::muc::MucVoiceForm::Approval { jid, nick, allow } => {
                if own.role != "moderator" {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                let Some(target) = occupants.get(nick) else {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    )));
                };
                if target.full_jid != *jid || target.role != "visitor" {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "not-allowed",
                    )));
                }
                if !allow {
                    return Ok(MessageStep::Done(None));
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
                    let Some(current_room) =
                        service.federated_room_snapshot(localpart(room_jid)).await?
                    else {
                        return Ok(MessageStep::Done(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    if current_room.id != room.id || current_room.room_epoch != room.room_epoch {
                        return Ok(MessageStep::Done(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    }
                    let Some(current_actor) = state.local_muc_occupant_exact(own.into()) else {
                        return Ok(MessageStep::Done(federated_error(
                            &request.stanza,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    };
                    if current_actor.full_jid != own.full_jid
                        || current_actor.connection_id != own.connection_id
                        || current_actor.cluster_epoch != own.cluster_epoch
                        || current_actor.role != "moderator"
                        || !federated_endpoint_matches(&current_actor, authenticated_domain)
                    {
                        return Ok(MessageStep::Done(federated_error(
                            &request.stanza,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    }
                    let Some(updated_occupant) = state.set_local_muc_role_exact(
                        northstar_room_application::muc_service::LocalMucOccupantIdentity::from(
                            target,
                        ),
                        "visitor",
                        "participant",
                        None,
                    ) else {
                        return Ok(MessageStep::Done(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let updated = SerializableMucOccupant::from(&updated_occupant);
                    for (_, recipient) in state.muc_occupants_for(room_jid) {
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
                    return Ok(MessageStep::Done(None));
                }
                let service = state.muc_service();
                let Some(actor_target) = service
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                    .await?
                else {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "auth",
                        "forbidden",
                    )));
                };
                let Some(target_authority) = service
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &target.nick)
                    .await?
                else {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    )));
                };
                if actor_target.full_jid != own.full_jid
                    || actor_target.connection_uuid != own.connection_id
                    || target_authority.full_jid != target.full_jid
                    || target_authority.connection_uuid != target.connection_id
                {
                    return Ok(MessageStep::Done(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    )));
                }
                let operation_id =
                    northstar_room_application::muc_service::operation_id(&serde_json::json!({
                        "kind":"voice_approval","stream":*connection_id,
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
                        return Ok(MessageStep::Done(federated_error(
                            &request.stanza,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    }
                    _ => {
                        return Ok(MessageStep::Done(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    }
                }
                if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                    tracing::warn!(?error, %operation_id, "committed federated MUC voice approval wake failed; PostgreSQL outbox will catch up");
                }
                return Ok(MessageStep::Done(None));
            }
        }
    }
    Ok(MessageStep::Next(()))
}
