use super::{addressed, MucHost};
use northstar_room_core::occupancy::MucOccupantRoute;

pub(crate) async fn deliver_voice_request(
    host: &impl MucHost,
    room: &str,
    requester: &MucOccupantRoute,
    moderators: Vec<MucOccupantRoute>,
    federated: bool,
) {
    let stanza_id = host.muc_time_sources().new_uuid();
    let request =
        crate::muc::muc_voice_request(room, &requester.full_jid, &requester.nick, stanza_id);
    let mut local = Vec::new();
    for route in moderators {
        if host
            .local_muc_occupant_exact(route.identity(room))
            .is_some()
        {
            local.push(route);
        } else if let Err(error) = addressed::publish(
            host,
            room,
            &route,
            &request,
            &requester.full_jid,
            true,
            federated,
        )
        .await
        {
            tracing::warn!(?error, "could not route MUC voice request");
        }
    }
    if local.is_empty() {
        return;
    }
    let Ok(moderators) = host
        .muc_service()
        .current_muc_moderators(crate::muc::localpart(room), &local)
        .await
    else {
        return;
    };
    for route in moderators {
        if let Some(endpoint) = host.local_muc_occupant_exact(route.identity(room)) {
            let stanza = crate::muc::set_to(&request, &route.full_jid);
            let _ = host
                .deliver_muc_from(&endpoint, stanza, Some(room), &requester.full_jid)
                .await;
        }
    }
}
