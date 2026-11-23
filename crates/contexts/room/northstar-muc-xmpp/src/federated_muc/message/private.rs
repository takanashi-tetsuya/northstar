//! Route private messages sent to a room occupant.

use super::*;
use crate::muc::message::addressed::{self, AddressedDeliveryKind};
use northstar_room_application::muc_service::{
    MucAddressedActor, MucAddressedOutcome, MucAddressedRequest,
};

pub(super) async fn handle_private_message<S: MucHost>(
    state: &S,
    request: &FederatedMessageRequest,
    address: &MessageAddress<'_>,
    authenticated_domain: &str,
) -> Result<MessageStep<()>> {
    let &MessageAddress {
        from,
        ref actor_full_jid,
        ref to_jid,
        ref room_jid,
        ..
    } = address;
    let Some(nick) = to_jid.resourcepart() else {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        )));
    };
    let authenticated_domain = canonical_authenticated_domain(authenticated_domain);
    let actor = MucAddressedActor::Federated {
        authenticated_domain: &authenticated_domain,
        full_jid: actor_full_jid,
    };
    let outcome = state
        .muc_service()
        .muc_addressed_authority(
            localpart(room_jid),
            MucAddressedRequest::Private { actor, nick },
        )
        .await?;
    let MucAddressedOutcome::Private {
        sender_nick,
        sender_occupant_id,
        target,
    } = outcome
    else {
        let (error_type, condition) = addressed::rejection(&outcome);
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            error_type,
            condition,
        )));
    };
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
    let Some(target) = target else {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        )));
    };
    let private = set_muc_occupant_id(
        &add_stanza_id(
            &set_to(
                &set_from(&request.stanza.raw, &format!("{room_jid}/{sender_nick}")),
                &target.full_jid,
            ),
            room_jid,
            address.facts.id,
        ),
        &sender_occupant_id,
    );
    addressed::send_addressed(
        state,
        room_jid,
        &target,
        private,
        actor_full_jid,
        AddressedDeliveryKind::Private {
            sender_nick: &sender_nick,
        },
        true,
    )
    .await?;
    Ok(MessageStep::Done(None))
}
