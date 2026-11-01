use super::*;

pub async fn handle_muc_unavailable_presence(
    session: &impl MucSession,
    root: Node<'_, '_>,
    full_jid: String,
    room_jid: String,
) -> Result<MucAction> {
    let Some(joined) = session
        .joined_rooms()
        .get(&room_jid)
        .map(|entry| entry.value().clone())
    else {
        return Ok(MucAction::None);
    };
    let mut local_departure_room = None;
    let local_departure_guard = if session.host().muc_pg_authority_enabled() {
        None
    } else {
        let Some(initial_room) = session
            .host()
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            session.joined_rooms().remove_if(&room_jid, |_, current| {
                current.cluster_epoch == joined.cluster_epoch
            });
            return Ok(MucAction::None);
        };
        let guard = session
            .host()
            .muc_service()
            .lock_local_room_mutation(initial_room.id)
            .await;
        let Some(refreshed_room) = session
            .host()
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            session.host().remove_local_muc_occupant_exact(
                northstar_room_application::muc_service::LocalMucOccupantIdentity {
                    room_jid: &room_jid,
                    nick: &joined.nick,
                    full_jid: &full_jid,
                    connection_id: session.connection_id(),
                    cluster_epoch: joined.cluster_epoch,
                },
            );
            session.joined_rooms().remove_if(&room_jid, |_, current| {
                current.cluster_epoch == joined.cluster_epoch
            });
            return Ok(MucAction::None);
        };
        if refreshed_room.room_epoch != initial_room.room_epoch {
            session.host().remove_local_muc_occupant_exact(
                northstar_room_application::muc_service::LocalMucOccupantIdentity {
                    room_jid: &room_jid,
                    nick: &joined.nick,
                    full_jid: &full_jid,
                    connection_id: session.connection_id(),
                    cluster_epoch: joined.cluster_epoch,
                },
            );
            session.joined_rooms().remove_if(&room_jid, |_, current| {
                current.cluster_epoch == joined.cluster_epoch
            });
            return Ok(MucAction::None);
        }
        local_departure_room = Some(refreshed_room);
        Some(guard)
    };
    let mut clustered_leave = false;
    let mut clustered_event_id = None;
    let mut clustered_room_id = None;
    if session.host().muc_pg_authority_enabled() {
        if let Some(room) = session
            .host()
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        {
            clustered_room_id = Some(room.id);
            if let Some(target) = session
                .host()
                .muc_service()
                .local_cluster_occupancy_target(
                    room.id,
                    joined.cluster_epoch,
                    session.connection_id(),
                )
                .await?
            {
                let cluster_operation_id = uuid::Uuid::new_v4();
                match session
                    .host()
                    .muc_service()
                    .transition_local_cluster_occupancy(
                        cluster_operation_id,
                        &target,
                        "leave",
                        session.host().muc_cluster_node_id(),
                        None,
                        None,
                        session.sm_db_id(),
                        std::time::Duration::from_secs(90),
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        clustered_leave = true;
                        clustered_event_id = Some(cluster_operation_id.to_string());
                    }
                    ClusterMucTransitionOutcome::Stale | ClusterMucTransitionOutcome::Destroyed => {
                    }
                    ClusterMucTransitionOutcome::Conflict
                    | ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(MucAction::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    }
                }
                if let Err(error) = session
                    .host()
                    .wake_committed_muc_operation(cluster_operation_id)
                    .await
                {
                    tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                            "MUC leave committed; signed wake failed and PostgreSQL polling will catch up");
                }
            }
        }
    }
    session
        .joined_rooms()
        .remove_if(&room_jid, |_, current| current == &joined);
    let Some(departed) = session.host().remove_local_muc_occupant_exact(
        northstar_room_application::muc_service::LocalMucOccupantIdentity {
            room_jid: &room_jid,
            nick: &joined.nick,
            full_jid: &full_jid,
            connection_id: session.connection_id(),
            cluster_epoch: joined.cluster_epoch,
        },
    ) else {
        return Ok(MucAction::None);
    };

    let serializable =
        northstar_room_application::muc_service::SerializableMucOccupant::from(&departed);
    let locally_empty = session.host().muc_occupants_for(&room_jid).is_empty();
    if locally_empty {
        if let Some(room) = local_departure_room.as_ref() {
            // Keep the room gate until the conditional temporary-room
            // delete commits. A concurrent join cannot otherwise
            // publish an occupant between the empty check and delete.
            session
                .host()
                .muc_service()
                .delete_temporary_room(room.id, room.room_epoch, room.config_version)
                .await?;
        }
    }
    drop(local_departure_guard);
    let removed_globally = session
        .host()
        .remove_exact_muc_soft_state(&departed)
        .await
        .unwrap_or(false);
    if locally_empty {
        session.host().leave_cluster_muc_room(&room_jid).await?;
    }
    if !clustered_leave {
        session
            .host()
            .publish_muc_cluster_presence_with_id(
                &room_jid,
                &serializable,
                true,
                false,
                root.attribute("id"),
            )
            .await?;
    }
    let remaining = session.host().muc_occupants_for(&room_jid);
    if !clustered_leave {
        for (_, target) in &remaining {
            let presence = muc_presence_stanza(
                &northstar_room_application::muc_service::SerializableMucOccupant::from(&departed),
                &target.full_jid,
                true,
                false,
                false,
                None,
                departed.room_non_anonymous || target.role == "moderator",
            );
            let _ = session
                .host()
                .deliver_to_muc_occupant(target, presence)
                .await;
        }
    }
    let self_presence = muc_presence_stanza(
        &northstar_room_application::muc_service::SerializableMucOccupant::from(&departed),
        &full_jid,
        true,
        true,
        false,
        root.attribute("id").or(clustered_event_id.as_deref()),
        true,
    );
    let globally_empty = if let Some(room_id) = clustered_room_id {
        session
            .host()
            .muc_service()
            .cluster_room_is_empty(room_id)
            .await?
    } else {
        removed_globally
            && session
                .host()
                .cached_muc_cluster_occupants(&room_jid)
                .await?
                .is_empty()
    };
    if session.host().muc_pg_authority_enabled() && remaining.is_empty() && globally_empty {
        if let Some(room) = session
            .host()
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        {
            session
                .host()
                .muc_service()
                .delete_temporary_room(room.id, room.room_epoch, room.config_version)
                .await?;
        }
    }
    Ok(MucAction::Send(self_presence))
}
