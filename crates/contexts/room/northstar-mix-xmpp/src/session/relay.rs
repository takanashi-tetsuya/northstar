use super::*;
use crate::relay::handle_channel_relay_request_for;
use northstar_room_core::mix::{MixChannelAddress, MixPamState};
use northstar_room_core::mix_iq_relay::{RelayReturnAuthority, RelayReturnRoute};

pub async fn try_mix_iq_relay(session: &impl MixSession, raw: &str) -> Result<Option<MixAction>> {
    let Some(request) = parse_relay_iq(raw)? else {
        return Ok(None);
    };
    if request.kind != "get" || request.request.is_none() {
        return Ok(None);
    }
    let target = match northstar_xmpp_types::jid::CanonicalJid::parse(&request.to) {
        Ok(target) if target.localpart().is_some() => target,
        _ => return Ok(None),
    };
    let (_target_id, channel_jid) = match decode_participant_jid(&target.bare()) {
        Ok(decoded) => decoded,
        Err(_) => return Ok(None),
    };
    let Some(user) = session.user() else {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            &request.from,
            "auth",
            "not-authorized",
        ))));
    };
    let Some(full_jid) = session.full_jid() else {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            &request.from,
            "auth",
            "not-authorized",
        ))));
    };
    if !request.from.is_empty() && request.from != full_jid {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            full_jid,
            "auth",
            "not-authorized",
        ))));
    }
    let channel_address = MixChannelAddress::parse(&channel_jid)?;
    let channel_domain = channel_address.domain();
    let exact_route = RelayReturnRoute::Local {
        jid: CanonicalJid::parse(full_jid)?,
        account: user.id,
        auth_generation: user.auth_generation,
        connection: session.connection_id(),
    };
    if channel_domain == mix_domain(session) {
        let response =
            handle_channel_relay_request_for(session.host(), &request, exact_route).await?;
        return Ok(Some(if response.is_empty() {
            MixAction::None
        } else {
            MixAction::Send(response)
        }));
    }
    let membership = session
        .host()
        .mix_service()
        .pam_membership(user.id, &channel_jid)
        .await?;
    let membership =
        membership.filter(|membership| membership.state == MixPamState::Joined.as_str());
    if membership.is_none()
        || session
            .host()
            .mix_service()
            .is_blocked(user.id, &channel_jid)
            .await?
        || !session.host().federation_domain_allowed(channel_domain)
    {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            full_jid,
            "auth",
            "forbidden",
        ))));
    }
    let relay_id = Uuid::new_v4().to_string();
    if !register_mix_iq_relay(
        session.host(),
        relay_id.clone(),
        MixIqRelayStage::Participant {
            requester_full_jid: full_jid.to_owned(),
            original_id: request.id.clone(),
            expected_from: request.to.clone(),
            channel_jid: channel_jid.clone(),
        },
        RelayReturnAuthority {
            exact_route,
            channel: channel_address.clone(),
            channel_incarnation: None,
            pam_incarnation: membership
                .as_ref()
                .map(PamMembership::relay_incarnation)
                .transpose()?,
        },
    ) {
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            full_jid,
            "wait",
            "resource-constraint",
        ))));
    }
    let outbound = relay_iq_xml(&request, &relay_id, full_jid, &request.to);
    if !session
        .host()
        .federation_outbox()
        .send(
            channel_domain,
            outbound,
            Some(CanonicalJid::parse(full_jid)?.bare()),
        )
        .await
    {
        session.host().pending_mix_iq().remove(&relay_id);
        return Ok(Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            full_jid,
            "wait",
            "remote-server-timeout",
        ))));
    }
    Ok(Some(MixAction::None))
}
