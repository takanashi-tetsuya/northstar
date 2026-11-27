//! Local join publication, initial roster and history replay.

use super::*;
use std::convert::Infallible;
use tokio::sync::OwnedMutexGuard;

mod replay_policy;
pub(super) use replay_policy::ReplayPolicy;

pub(super) async fn publish_join<S: MucSession>(
    session: &S,
    request: &JoinRequest<'_, '_>,
    room: &MucRoom,
    committed: &CommittedJoin<S::Host>,
    created: bool,
    local_join_guard: Option<OwnedMutexGuard<()>>,
    history_request: MucHistoryRequest,
) -> Result<JoinStep<Infallible>> {
    let JoinRequest {
        root,
        user,
        full_jid,
        room_jid,
        nick,
        ..
    } = *request;
    let CommittedJoin {
        occupant,
        serializable,
        cluster_event_id,
        projection,
    } = committed;
    let local_existing = if projection.is_none() {
        session.host().muc_occupants_for(room_jid)
    } else {
        Vec::new()
    };
    let publication = session.host().publish_local_muc_join_if_vacant(occupant);
    if publication != northstar_room_core::occupancy::LocalMucJoinPublication::Published {
        if !session.host().muc_pg_authority_enabled() {
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root, full_jid, "cancel", "conflict",
            ))));
        }
        if publication == northstar_room_core::occupancy::LocalMucJoinPublication::Occupied {
            tracing::error!(%room_jid, %nick,
                    "committed MUC join found another local incarnation; preserving it and compensating this claim");
            drop(local_join_guard);
            compensate_unpublished_cluster_muc_join(session.host(), room, occupant).await;
            return Ok(JoinStep::Done(MucAction::Send(muc_stanza_error(
                root, full_jid, "cancel", "conflict",
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
    drop(local_join_guard);
    if session.host().muc_redis_transport_enabled() {
        if let Ok(json) = serde_json::to_string(serializable) {
            let _ = session.host().join_cluster_muc_room(room_jid).await;
            let _ = session
                .host()
                .register_cluster_muc_occupant(room_jid, nick, &json)
                .await;
            if cluster_event_id.is_none() {
                let _ = session
                    .host()
                    .publish_muc_cluster_presence_with_id(
                        room_jid,
                        serializable,
                        false,
                        created,
                        root.attribute("id"),
                    )
                    .await;
            }
        }
    }

    let global_map = if projection.is_none() && session.host().muc_redis_transport_enabled() {
        session
            .host()
            .cached_muc_cluster_occupants(room_jid)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };
    let mut replay = ReplayPolicy::default();
    let legacy_roster;
    let roster = if let Some(projection) = projection {
        projection.roster.as_slice()
    } else {
        legacy_roster = global_map
            .values()
            .filter_map(|json| serde_json::from_str(json).ok())
            .collect::<Vec<_>>();
        &legacy_roster
    };
    for present in roster.iter().filter(|present| present.nick != nick) {
        replay.presence(
            room_jid,
            present,
            muc_presence_stanza(
                present,
                full_jid,
                false,
                false,
                false,
                None,
                room.non_anonymous || occupant.role == "moderator",
            ),
        );
    }
    for (_, target) in &local_existing {
        if target.nick != nick {
            let target =
                northstar_room_application::muc_service::SerializableMucOccupant::from(target);
            replay.presence(
                room_jid,
                &target,
                muc_presence_stanza(
                    &target,
                    full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                ),
            );
        }
        if cluster_event_id.is_none() {
            let joined = muc_presence_stanza(
                serializable,
                &target.full_jid,
                false,
                false,
                false,
                None,
                room.non_anonymous || target.role == "moderator",
            );
            let _ = session
                .host()
                .deliver_muc_from(target, joined, None, full_jid)
                .await;
        }
    }
    let mut self_join = muc_presence_stanza(
        serializable,
        full_jid,
        false,
        true,
        created,
        root.attribute("id").or(cluster_event_id.as_deref()),
        true,
    );
    if room.logging_enabled {
        self_join = add_muc_user_status(&self_join, 170);
    }
    tracing::info!(
        room = %room_jid, user = %user.username,
        "MUC join: success"
    );

    // XEP-0045 requires initial room presence first, then all selected
    // history, and only then the current subject.  Subject-only archive
    // records remain available through MAM but are not join history.
    let legacy_history;
    let history_candidates: &[_] = if let Some(projection) = projection {
        projection.history.as_slice()
    } else if history_request.max_stanzas == 0 || !room.logging_enabled {
        &[]
    } else {
        legacy_history = session
            .host()
            .muc_service()
            .local_history_since(room.id, 100, history_request.since)
            .await?;
        &legacy_history
    };
    for message in history_candidates {
        let occupant_id = muc_occupant_id(&room.occupant_id_secret, &message.sender_jid);
        let authoritative = set_muc_occupant_id(&message.stanza, &occupant_id);
        let history = if room.non_anonymous {
            add_muc_sender(&authoritative, &message.sender_jid)
        } else {
            authoritative
        };
        replay.history(
            room_jid,
            &message.stanza,
            &message.sender_jid,
            set_to(
                &add_delay_from(&history, message.created_at, Some(room_jid)),
                full_jid,
            ),
        );
    }
    let replies = replay
        .replies(
            session,
            user.id,
            full_jid,
            self_join,
            history_request,
            current_muc_subject_stanza(room, room_jid, full_jid),
        )
        .await;
    Ok(JoinStep::Done(MucAction::SendMany(replies)))
}
