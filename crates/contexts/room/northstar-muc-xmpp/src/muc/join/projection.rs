use anyhow::Result;
use northstar_room_application::muc_service::{MucJoinProjection, MucRoom};
use northstar_room_core::occupancy::{MucOccupant, MucOccupantRoute};

pub(crate) fn apply_committed_join<L, S>(
    occupant: &mut MucOccupant<L, S>,
    room: &mut MucRoom,
    projection: &MucJoinProjection,
) -> Result<()> {
    let actor = &projection.actor;
    let route = MucOccupantRoute {
        nick: actor.nick.clone(),
        full_jid: actor.full_jid.clone(),
        connection_id: actor.connection_uuid,
        cluster_epoch: actor.occupant_incarnation,
    };
    anyhow::ensure!(
        route.is_exact()
            && route.nick == occupant.nick
            && route.full_jid == occupant.full_jid
            && actor.bare_jid == northstar_xmpp_types::jid_text::bare_jid(&occupant.full_jid)
            && route.connection_id == occupant.connection_id
            && route.cluster_epoch == occupant.cluster_epoch
            && actor.room_id == room.id
            && actor.room_epoch == room.room_epoch
            && actor.config_version == room.config_version
            && actor.connection_epoch == 1
            && actor.sm_session_id == occupant.sm_session_id
            && actor.state == "active",
        "committed MUC join did not match the requested occupancy"
    );
    occupant.role.clone_from(&actor.role);
    occupant.affiliation.clone_from(&actor.affiliation);
    occupant.payload.clone_from(&actor.presence_payload);
    occupant.room_non_anonymous = projection.non_anonymous;
    occupant.occupant_id.clone_from(&projection.occupant_id);
    room.subject.clone_from(&projection.subject);
    room.subject_changed_at = projection.subject_changed_at;
    room.non_anonymous = projection.non_anonymous;
    room.logging_enabled = projection.logging_enabled;
    room.occupant_id_secret
        .clone_from(&projection.occupant_id_secret);
    Ok(())
}

#[cfg(test)]
mod tests;
