//! Validate the federated stanza and resolve the actor, room and occupant.

use super::*;
use crate::muc::MucVoiceForm;

pub(super) struct OccupantLookup<'a, S: MucHost> {
    pub(super) occupancy: RoomOccupancy<S>,
    pub(super) voice_form: Option<&'a MucVoiceForm>,
}

pub(super) fn validate_message<'a, S: MucHost>(
    state: &S,
    authenticated_domain: &str,
    request: &'a FederatedMessageRequest,
) -> Result<MessageStep<MessageAddress<'a>>> {
    let from = request.stanza.from.as_str();
    let to = request.stanza.to.as_str();
    if let Some((error_type, condition)) = request.validation_error {
        // RFC 6120 section 8.3.1 forbids reflecting an error in response to
        // another error stanza. Other malformed remote MUC messages get the
        // same bounded modern-message validation as local C2S messages before
        // any room/archive admission can observe them.
        if request.stanza.kind.as_deref() == Some("error") {
            return Ok(MessageStep::Done(None));
        }
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            error_type,
            condition,
        )));
    }
    if !authenticated_remote_actor(authenticated_domain, from) {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        )));
    }
    let actor_full_jid = northstar_xmpp_types::jid::canonicalize(from)
        .expect("authenticated_remote_actor already validated the full JID");
    // The clustered invitation authority is account scoped, while the exact
    // full JID remains independently bound to the authenticated occupancy.
    // Derive both from the already authenticated S2S actor; never reuse the
    // room JID, invitee JID or an unprepared `from` value as the principal.
    let actor_bare_jid = northstar_xmpp_types::jid::canonical_bare_key(&actor_full_jid)?;
    let Ok(to_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        )));
    };
    let room_jid = to_jid.bare();
    if to_jid.domainpart() != muc_domain(state) || to_jid.localpart().is_none() {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        )));
    }
    Ok(MessageStep::Next(MessageAddress {
        from,
        to,
        actor_full_jid,
        actor_bare_jid,
        to_jid,
        room_jid,
    }))
}

pub(super) async fn lookup_occupant<'a, S: MucHost>(
    state: &S,
    authenticated_domain: &str,
    request: &'a FederatedMessageRequest,
    address: &MessageAddress<'_>,
) -> Result<MessageStep<OccupantLookup<'a, S>>> {
    let &MessageAddress {
        from,
        ref actor_full_jid,
        ref room_jid,
        ..
    } = address;
    let Some((_, own)) = state
        .muc_occupants_for(room_jid)
        .into_iter()
        .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, actor_full_jid))
    else {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-acceptable",
        )));
    };
    if !federated_endpoint_matches(&own, authenticated_domain) {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        )));
    }
    // Only an available presence refresh may transfer the transport endpoint
    // of an existing federated occupant. Message traffic is authorized by the
    // authenticated domain but must not silently seize the occupant from the
    // connection/incarnation admitted by the room authority.
    let Some(room) = state
        .muc_service()
        .federated_room_snapshot(localpart(room_jid))
        .await?
    else {
        return Ok(MessageStep::Done(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        )));
    };
    let voice_form = match &request.voice_form {
        Ok(form) => form.as_ref(),
        Err(MalformedMucStanza) => {
            return Ok(MessageStep::Done(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            )));
        }
    };
    Ok(MessageStep::Next(OccupantLookup {
        occupancy: RoomOccupancy { own, room },
        voice_form,
    }))
}
