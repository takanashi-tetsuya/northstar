//! Route private messages sent to a room occupant.

use super::*;

pub(super) async fn handle_private_message<S: MucHost>(
    state: &S,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
    occupancy: &RoomOccupancy<S>,
) -> Result<MessageStep<()>> {
    let &MessageAddress {
        from,
        to,
        ref actor_full_jid,
        ref to_jid,
        ref room_jid,
        ..
    } = address;
    let RoomOccupancy { own, room } = occupancy;
    if to.contains('/') {
        if !room.allow_private_messages {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "auth",
                "forbidden",
            )));
        }
        if !matches!(
            request.stanza.kind.as_deref().unwrap_or("normal"),
            "chat" | "normal"
        ) {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            )));
        }
        let Some(target_nick) = to_jid.resourcepart() else {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            )));
        };
        let local_target = state.local_muc_occupant_by_nick(room_jid, target_nick);
        let (target_full_jid, route_via_cluster) = if let Some(target) = &local_target {
            (target.full_jid.clone(), false)
        } else {
            let global = state.federated_muc_global_occupants(room_jid).await?;
            let Some(target) = global
                .get(target_nick)
                .and_then(|json| serde_json::from_str::<SerializableMucOccupant>(json).ok())
            else {
                return Ok(MessageStep::Done(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            };
            (target.full_jid, true)
        };
        let private = set_muc_occupant_id(
            &add_stanza_id(
                &set_to(
                    &set_from(&request.stanza.raw, &format!("{room_jid}/{}", own.nick)),
                    &target_full_jid,
                ),
                room_jid,
                uuid::Uuid::new_v4(),
            ),
            &own.occupant_id,
        );
        if route_via_cluster {
            state
                .federated_muc_publish_private_message(
                    room_jid,
                    target_nick,
                    &private,
                    actor_full_jid,
                )
                .await?;
        } else if let Some(target) = local_target {
            let blocked = state
                .blocked_muc_recipient_accounts(
                    std::slice::from_ref(&target),
                    &[format!("{room_jid}/{}", own.nick), actor_full_jid.clone()],
                )
                .await;
            if !northstar_xmpp_types::jid::canonical_bare_key(&target.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                let _ = state
                    .deliver_to_muc_occupant_unchecked(&target, private)
                    .await;
            }
        }
        return Ok(MessageStep::Done(None));
    }
    Ok(MessageStep::Next(()))
}
