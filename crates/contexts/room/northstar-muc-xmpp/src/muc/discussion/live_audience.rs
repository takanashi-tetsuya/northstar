use super::*;
use northstar_room_core::occupancy::{LocalMucOccupantIdentity, MucOccupantRoute};

pub(crate) async fn publish_live_audience(
    host: &impl MucHost,
    room: &str,
    stanza: &str,
    real_sender: Option<&str>,
    audience: Option<&LiveAudience>,
    stage: &'static str,
) {
    if let Some(audience) = audience {
        if let Err(error) = host
            .publish_muc_live_audience(room, stanza, real_sender, audience)
            .await
        {
            record_muc_post_commit_failure(host, room, "*", stage);
            tracing::warn!(room, stage, ?error, "exact MUC post-commit fan-out failed");
        }
    } else {
        run_muc_cluster_fan_out(host, room, stanza, real_sender, stage).await;
    }
}

pub(crate) fn live_recipients<S: MucHost>(
    host: &S,
    room: &str,
    audience: Option<&LiveAudience>,
) -> Vec<Occupant<S>> {
    match audience {
        Some(audience) => exact_live_recipients(audience, host.muc_cluster_node_id(), |route| {
            host.local_muc_occupant_exact(route.identity(room))
        }),
        None => host
            .muc_occupants_for(room)
            .into_iter()
            .map(|(_, occupant)| occupant)
            .collect(),
    }
}

fn exact_live_recipients<T>(
    audience: &LiveAudience,
    local_node: &str,
    mut resolve: impl FnMut(&MucOccupantRoute) -> Option<T>,
) -> Vec<T> {
    audience
        .routes()
        .iter()
        .filter(|(node, _)| node == local_node)
        .filter_map(|(_, route)| resolve(route))
        .collect()
}

pub(crate) fn refresh_live_recipient<S: MucHost>(
    host: &S,
    recipient: &Occupant<S>,
    audience: Option<&LiveAudience>,
) -> Option<Occupant<S>> {
    if audience.is_none() {
        return Some(recipient.clone());
    }
    host.local_muc_occupant_exact(LocalMucOccupantIdentity {
        room_jid: &recipient.room_jid,
        nick: &recipient.nick,
        full_jid: &recipient.full_jid,
        connection_id: recipient.connection_id,
        cluster_epoch: recipient.cluster_epoch,
    })
}

#[cfg(test)]
mod tests;
