use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;

pub(super) struct FederatedReadActor<'a> {
    pub(super) full_jid: &'a str,
    pub(super) bare_jid: &'a str,
    pub(super) domain: &'a str,
    pub(super) node_id: &'a str,
    pub(super) route: Option<MucOccupantRoute>,
}

impl FederatedReadActor<'_> {
    pub(super) fn principal(&self) -> MucReadPrincipal<'_> {
        MucReadPrincipal::Federated {
            bare_jid: self.bare_jid,
            domain: self.domain,
        }
    }

    pub(super) fn proof(&self) -> Option<MucOccupancyProof<'_>> {
        self.route.as_ref().map(|route| MucOccupancyProof {
            route,
            authenticated_domain: Some(self.domain),
            node_id: self.node_id,
        })
    }

    pub(super) fn management_viewer(&self) -> MucManagementViewer<'_> {
        MucManagementViewer {
            principal: self.principal(),
            full_jid: self.full_jid,
            occupancy: self.proof(),
        }
    }

    fn own_ping(&self, ping: bool, nick: &str) -> Option<MucOccupancyProof<'_>> {
        self.proof()
            .filter(|proof| ping && proof.route.nick == nick)
    }
}

pub(super) fn federated_read_route(
    state: &impl MucHost,
    room_jid: &str,
    full_jid: &str,
    domain: &str,
) -> Option<MucOccupantRoute> {
    state
        .muc_occupants_for(room_jid)
        .into_iter()
        .find_map(|(_, occupant)| {
            (same_remote_actor(&occupant.full_jid, full_jid)
                && federated_endpoint_matches(&occupant, domain))
            .then(|| crate::muc::occupant_route(&occupant))
        })
}

pub(super) async fn deliver_occupant_iq(
    state: &impl MucHost,
    request: &FederatedIqRequest,
    room_jid: &str,
    target_nick: &str,
    actor: &FederatedReadActor<'_>,
) -> Result<Option<String>> {
    let stanza = &request.stanza;
    let from = &stanza.from;
    let ping = matches!(&request.payload, FederatedIqPayload::Ping);
    let localpart = localpart(room_jid);
    if let Some(proof) = actor.own_ping(ping, target_nick) {
        let refreshed = state
            .muc_service()
            .refresh_muc_occupant_activity(localpart, proof)
            .await?
            .is_some();
        return Ok(own_ping_reply(stanza, actor.full_jid, refreshed));
    }
    let view = state
        .muc_service()
        .occupant_iq(
            localpart,
            actor.proof(),
            target_nick,
            actor.node_id,
            Some(actor.full_jid),
        )
        .await?;
    let Some(sender) = view.sender else {
        return Ok(if ping {
            own_ping_reply(stanza, actor.full_jid, false)
        } else if !view.room_visible {
            federated_error(stanza, from, "cancel", "item-not-found")
        } else {
            federated_error(stanza, from, "auth", "not-authorized")
        });
    };
    let Some(route) = view.target else {
        return Ok(federated_error(stanza, from, "cancel", "item-not-found"));
    };
    let Some(target) = state.local_muc_occupant_exact(route.identity(room_jid)) else {
        return Ok(federated_error(stanza, from, "cancel", "item-not-found"));
    };
    let sender_address = format!("{room_jid}/{}", sender.nick);
    let forwarded = set_to(&set_from(&stanza.raw, &sender_address), &route.full_jid);
    let _ = state
        .deliver_muc_from(&target, forwarded, Some(&sender_address), actor.full_jid)
        .await;
    Ok(None)
}

pub(super) fn federated_liveness_reply(
    stanza: &FederatedStanza,
    address: &str,
    viewer: &str,
) -> String {
    federated_iq_result(stanza, address, viewer, "")
}

fn own_ping_reply(stanza: &FederatedStanza, viewer: &str, refreshed: bool) -> Option<String> {
    if refreshed {
        Some(federated_liveness_reply(stanza, &stanza.to, viewer))
    } else {
        federated_error(stanza, &stanza.from, "modify", "not-acceptable")
    }
}

pub(super) async fn committed_registration_reply(
    wake: impl std::future::Future<Output = Result<()>>,
    operation_id: uuid::Uuid,
    stanza: &FederatedStanza,
    room_jid: &str,
    actor_full_jid: &str,
) -> Option<String> {
    if let Err(error) = wake.await {
        tracing::warn!(%operation_id, %error, "committed federated MUC registration wake failed");
    }
    Some(federated_iq_result(stanza, room_jid, actor_full_jid, ""))
}

#[cfg(test)]
mod tests;
