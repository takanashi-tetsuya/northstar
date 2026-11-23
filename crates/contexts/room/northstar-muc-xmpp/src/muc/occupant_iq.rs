use super::*;
use northstar_room_application::muc_service::{MucOccupancyProof, MucOccupantIqView};
use northstar_room_core::occupancy::MucOccupantRoute;

pub(crate) fn occupant_route<L, S>(occupant: &MucOccupant<L, S>) -> MucOccupantRoute {
    MucOccupantRoute {
        nick: occupant.nick.clone(),
        full_jid: occupant.full_jid.clone(),
        connection_id: occupant.connection_id,
        cluster_epoch: occupant.cluster_epoch,
    }
}

pub async fn refresh_muc_occupant_activity(
    session: &impl MucSession,
    room_jid: &str,
    nick: &str,
) -> Result<bool> {
    let Some((_, localpart)) = canonical_local_muc_room(room_jid, &muc_domain(session)) else {
        return Ok(false);
    };
    let Some(occupant) =
        validated_muc_occupant(session, room_jid).filter(|occupant| occupant.nick == nick)
    else {
        return Ok(false);
    };
    let route = occupant_route(&occupant);
    let host = session.host();
    let refreshed = host
        .muc_service()
        .refresh_muc_occupant_activity(
            &localpart,
            MucOccupancyProof {
                route: &route,
                authenticated_domain: None,
                node_id: host.muc_cluster_node_id(),
            },
        )
        .await?;
    if refreshed.is_none() {
        host.muc_telemetry().authority_rejected();
    }
    Ok(refreshed.is_some())
}

pub async fn occupant_iq_view(
    session: &impl MucSession,
    room_jid: &str,
    target_nick: &str,
) -> Result<MucOccupantIqView> {
    let Some((_, localpart)) = canonical_local_muc_room(room_jid, &muc_domain(session)) else {
        return Ok(MucOccupantIqView {
            room_visible: false,
            sender: None,
            target: None,
        });
    };
    let host = session.host();
    let node_id = host.muc_cluster_node_id();
    let route = validated_muc_occupant(session, room_jid)
        .as_ref()
        .map(occupant_route);
    host.muc_service()
        .occupant_iq(
            &localpart,
            route.as_ref().map(|route| MucOccupancyProof {
                route,
                authenticated_domain: None,
                node_id,
            }),
            target_nick,
            node_id,
            None,
        )
        .await
}
