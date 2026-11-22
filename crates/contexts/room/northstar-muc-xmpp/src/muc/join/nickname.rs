//! Admission, commit and publication for an occupant changing nicknames.

use super::*;
use std::convert::Infallible;
use tokio::sync::OwnedMutexGuard;

pub(super) struct PreparedNicknameChange {
    pub(super) room: MucRoom,
    pub(super) local_rename_guard: Option<OwnedMutexGuard<()>>,
}

pub(super) async fn prepare_nickname_change<S: MucSession>(
    session: &S,
    request: &JoinRequest<'_, '_>,
    occupant: &mut Occupant<S::Host>,
) -> Result<JoinStep<PreparedNicknameChange>> {
    let JoinRequest {
        root,
        user,
        full_jid,
        room_jid,
        nick,
    } = *request;
    let Some(room) = session
        .host()
        .muc_service()
        .local_room_snapshot(localpart(room_jid))
        .await?
    else {
        session.joined_rooms().remove(room_jid);
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root,
            full_jid,
            "cancel",
            "item-not-found",
        ))));
    };
    if session
        .host()
        .muc_service()
        .local_nick_reserved_for_other(room.id, user.id, nick)
        .await?
    {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root, full_jid, "cancel", "conflict",
        ))));
    }

    let local_rename_guard = if session.host().muc_pg_authority_enabled() {
        None
    } else {
        Some(
            session
                .host()
                .muc_service()
                .lock_local_room_mutation(room.id)
                .await,
        )
    };

    if local_rename_guard.is_some() {
        let requested_payload = occupant.payload.clone();
        let Some(refreshed_room) = session
            .host()
            .muc_service()
            .local_room_snapshot(localpart(room_jid))
            .await?
        else {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "cancel",
                "item-not-found",
            ))));
        };
        if refreshed_room.room_epoch != room.room_epoch {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "cancel",
                "item-not-found",
            ))));
        }
        let Some(current) = validated_muc_occupant(session, room_jid) else {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "cancel",
                "not-acceptable",
            ))));
        };
        *occupant = current;
        occupant.payload = requested_payload;
        let affiliation = session
            .host()
            .muc_service()
            .local_affiliation(refreshed_room.id, user.id)
            .await?;
        if affiliation.as_deref() == Some("outcast") {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "auth",
                "forbidden",
            ))));
        }
        if refreshed_room.members_only && affiliation.is_none() {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "auth",
                "registration-required",
            ))));
        }
        let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
        if occupant.affiliation != affiliation {
            occupant.affiliation = affiliation;
            occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if refreshed_room.moderated {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();
        }
        occupant.room_non_anonymous = refreshed_room.non_anonymous;
        if session
            .host()
            .muc_service()
            .local_nick_reserved_for_other(refreshed_room.id, user.id, nick)
            .await?
        {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root, full_jid, "cancel", "conflict",
            ))));
        }
    }

    if !session.host().muc_pg_authority_enabled()
        && session
            .host()
            .local_muc_occupant_by_nick(room_jid, nick)
            .is_some()
    {
        return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
            root, full_jid, "cancel", "conflict",
        ))));
    }
    Ok(JoinStep::Next(PreparedNicknameChange {
        room,
        local_rename_guard,
    }))
}

pub(super) async fn apply_nickname_change<S: MucSession>(
    session: &S,
    request: &JoinRequest<'_, '_>,
    room: &MucRoom,
    occupant: &mut Occupant<S::Host>,
    joined_nick: &str,
    local_rename_guard: Option<OwnedMutexGuard<()>>,
) -> Result<JoinStep<Infallible>> {
    let JoinRequest {
        root,
        full_jid,
        room_jid,
        nick,
        ..
    } = *request;
    let old_occupant = occupant.clone();
    let old_serializable =
        northstar_room_application::muc_service::SerializableMucOccupant::from(&old_occupant);
    occupant.nick = nick.to_owned();
    let new_serializable =
        northstar_room_application::muc_service::SerializableMucOccupant::from(&*occupant);
    let old_json = serde_json::to_string(&old_serializable)?;
    let new_json = serde_json::to_string(&new_serializable)?;
    let mut cluster_operation = None;
    if session.host().muc_pg_authority_enabled() {
        session.host().admit_muc_pg_mutation()?;
        let Some(target) = session
            .host()
            .muc_service()
            .local_cluster_occupancy_target(room.id, occupant.cluster_epoch, occupant.connection_id)
            .await?
        else {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "cancel",
                "not-acceptable",
            ))));
        };
        let cluster_operation_id = uuid::Uuid::new_v4();
        match session
            .host()
            .muc_service()
            .rename_local_cluster_occupancy(
                cluster_operation_id,
                &target,
                session.host().muc_cluster_node_id(),
                nick,
            )
            .await?
        {
            ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                cluster_operation = Some(cluster_operation_id)
            }
            ClusterMucTransitionOutcome::Conflict => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root, full_jid, "cancel", "conflict",
                ))));
            }
            ClusterMucTransitionOutcome::Stale
            | ClusterMucTransitionOutcome::Destroyed
            | ClusterMucTransitionOutcome::Unauthorized => {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "cancel",
                    "not-acceptable",
                ))));
            }
        }
        if let Err(error) = session
            .host()
            .wake_committed_muc_operation(cluster_operation_id)
            .await
        {
            tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                    "MUC rename committed; signed wake failed and PostgreSQL polling will catch up");
        }
    }
    let redis_renamed = match session
        .host()
        .rename_cluster_muc_occupant_exact(
            room_jid,
            joined_nick,
            nick,
            occupant.cluster_epoch,
            &old_json,
            &new_json,
        )
        .await
    {
        Ok(northstar_room_core::occupancy::MucRename::Renamed) => true,
        Ok(northstar_room_core::occupancy::MucRename::Conflict) => {
            if cluster_operation.is_none() {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root, full_jid, "cancel", "conflict",
                ))));
            }
            tracing::warn!(%room_jid, old_nick=%joined_nick, new_nick=%nick,
                    "Redis MUC nickname cache conflicted after PostgreSQL committed; reconciliation will replace soft state");
            false
        }
        Ok(northstar_room_core::occupancy::MucRename::Stale) => {
            if cluster_operation.is_none() {
                return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                    root,
                    full_jid,
                    "cancel",
                    "not-acceptable",
                ))));
            }
            tracing::warn!(%room_jid, old_nick=%joined_nick, new_nick=%nick,
                    "Redis MUC nickname cache was stale after PostgreSQL committed");
            false
        }
        Err(error) => {
            if cluster_operation.is_none() {
                return Err(error);
            }
            session
                .host()
                .record_muc_cluster_control_plane_failure(&error);
            tracing::warn!(?error, %room_jid,
                    "PostgreSQL committed MUC rename; Redis wake/cache update will be reconciled");
            false
        }
    };
    let move_outcome = session.host().move_local_muc_nickname_exact(
        northstar_room_application::muc_service::LocalMucOccupantIdentity::from(&old_occupant),
        occupant,
        cluster_operation.is_some(),
    );
    match move_outcome {
        northstar_room_core::occupancy::LocalMucNicknameMove::Published
        | northstar_room_core::occupancy::LocalMucNicknameMove::AlreadyPublished => {}
        northstar_room_core::occupancy::LocalMucNicknameMove::DeferredToReconciliation
            if cluster_operation.is_some() =>
        {
            tracing::warn!(room=%room_jid, %nick,
                    "PG-authoritative MUC rename found another local incarnation; reconciliation will repair the cache");
        }
        northstar_room_core::occupancy::LocalMucNicknameMove::CollisionRestored
        | northstar_room_core::occupancy::LocalMucNicknameMove::CollisionRestoreFailed => {
            if move_outcome
                == northstar_room_core::occupancy::LocalMucNicknameMove::CollisionRestoreFailed
            {
                tracing::error!(room=%room_jid, old_nick=%joined_nick,
                        "could not restore local MUC actor after nickname collision");
            }
            if redis_renamed {
                let _ = session
                    .host()
                    .rename_cluster_muc_occupant_exact(
                        room_jid,
                        nick,
                        joined_nick,
                        occupant.cluster_epoch,
                        &new_json,
                        &old_json,
                    )
                    .await;
            }
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root, full_jid, "cancel", "conflict",
            ))));
        }
        _ => {
            session.joined_rooms().remove_if(room_jid, |_, current| {
                current.cluster_epoch == occupant.cluster_epoch
            });
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root,
                full_jid,
                "cancel",
                "not-acceptable",
            ))));
        }
    }
    session.joined_rooms().insert(
        room_jid.clone(),
        northstar_session_core::JoinedMucMembership {
            nick: nick.to_owned(),
            cluster_epoch: occupant.cluster_epoch,
        },
    );
    drop(local_rename_guard);
    if cluster_operation.is_some() {
        return Ok(JoinStep::Done(MucAction::None));
    }
    session
        .host()
        .publish_muc_cluster_nickname_change(
            room_jid,
            &old_serializable,
            &new_serializable,
            root.attribute("id"),
        )
        .await?;
    for (_, recipient) in session.host().muc_occupants_for(room_jid) {
        let recipient_serializable =
            northstar_room_application::muc_service::SerializableMucOccupant::from(&recipient);
        let unavailable = muc_nickname_change_presence(
            &old_serializable,
            &recipient_serializable,
            nick,
            root.attribute("id"),
        );
        let _ = session
            .host()
            .deliver_to_muc_occupant(&recipient, unavailable)
            .await;
        let self_presence = recipient.full_jid == *full_jid;
        let available = muc_presence_stanza(
            &new_serializable,
            &recipient.full_jid,
            false,
            self_presence,
            false,
            root.attribute("id"),
            new_serializable.room_non_anonymous || self_presence || recipient.role == "moderator",
        );
        let _ = session
            .host()
            .deliver_to_muc_occupant(&recipient, available)
            .await;
    }
    Ok(JoinStep::Done(MucAction::None))
}
