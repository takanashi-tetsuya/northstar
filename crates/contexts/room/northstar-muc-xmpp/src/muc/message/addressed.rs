use super::*;
use northstar_room_application::muc_service::{MucAddressedActor, MucAddressedOutcome};
use northstar_room_core::occupancy::MucOccupantRoute;

pub(super) fn local_actor<'a>(
    session: &impl MucSession,
    room: &str,
    full_jid: &'a str,
) -> Option<MucAddressedActor<'a>> {
    Some(MucAddressedActor::Local {
        account_id: session.user()?.id,
        full_jid,
        connection_id: session.connection_id(),
        occupant_incarnation: session.joined_rooms().get(room)?.cluster_epoch,
    })
}

pub(crate) fn rejection(outcome: &MucAddressedOutcome) -> (&'static str, &'static str) {
    match outcome {
        MucAddressedOutcome::MissingRoom => ("cancel", "item-not-found"),
        MucAddressedOutcome::NotJoined => ("auth", "not-acceptable"),
        MucAddressedOutcome::NotAuthorized => ("auth", "not-authorized"),
        MucAddressedOutcome::Forbidden => ("auth", "forbidden"),
        _ => unreachable!("expected an addressed delivery refusal"),
    }
}

pub(crate) enum AddressedDeliveryKind<'a> {
    Private { sender_nick: &'a str },
    Decline,
}

pub(crate) async fn send_addressed(
    host: &impl MucHost,
    room: &str,
    route: &MucOccupantRoute,
    stanza: String,
    real_sender: &str,
    kind: AddressedDeliveryKind<'_>,
    federated: bool,
) -> Result<()> {
    if let Some(recipient) = host.local_muc_occupant_exact(route.identity(room)) {
        let senders = match kind {
            AddressedDeliveryKind::Private { sender_nick } => {
                vec![format!("{room}/{sender_nick}"), real_sender.to_owned()]
            }
            AddressedDeliveryKind::Decline => vec![room.to_owned()],
        };
        let blocked = host
            .blocked_muc_recipient_accounts(std::slice::from_ref(&recipient), &senders)
            .await;
        if !is_blocked(route, &blocked) {
            if let Some(current) = host.local_muc_occupant_exact(route.identity(room)) {
                let _ = host
                    .deliver_to_muc_occupant_unchecked(&current, stanza)
                    .await;
            }
        }
        return Ok(());
    }
    publish(host, room, route, &stanza, real_sender, false, federated).await
}

pub(super) fn is_blocked(
    route: &MucOccupantRoute,
    blocked: &std::collections::HashSet<String>,
) -> bool {
    northstar_xmpp_types::jid::canonical_bare_key(&route.full_jid)
        .is_ok_and(|owner| blocked.contains(&owner))
}

pub(super) async fn publish(
    host: &impl MucHost,
    room: &str,
    route: &MucOccupantRoute,
    stanza: &str,
    real_sender: &str,
    require_moderator: bool,
    federated: bool,
) -> Result<()> {
    if federated {
        host.federated_muc_publish_private_message(
            room,
            route,
            stanza,
            real_sender,
            require_moderator,
        )
        .await
    } else {
        host.publish_muc_cluster_private_message(
            room,
            route,
            stanza,
            real_sender,
            require_moderator,
        )
        .await
    }
}
