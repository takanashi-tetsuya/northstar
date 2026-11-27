use super::*;
use crate::relay::handle_channel_relay_request_for;
use northstar_room_application::room_delivery_policy::{
    MixRelayPolicyReader, PrivacyStanzaKind, RoomDeliveryPolicyQuery, RoomDeliveryPolicyReader,
    RoomPolicyLiveSession, RoomPolicySubject,
};
use northstar_room_core::mix::MixChannelAddress;
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
    let forbidden = || {
        Some(MixAction::Send(relay_error(
            &request.id,
            &request.to,
            full_jid,
            "auth",
            "forbidden",
        )))
    };
    let live_route = || {
        session
            .host()
            .session_entries_for(full_jid)
            .into_iter()
            .find_map(|(_, target)| {
                let route = RoomPolicyLiveSession::room_policy_route(&target);
                (route.account_id == user.id
                    && route.auth_generation == Some(user.auth_generation)
                    && matches!(route.subject, RoomPolicySubject::Connection { id, .. }
                    if id == session.connection_id()))
                .then_some(route)
            })
    };
    let Some(route) = live_route() else {
        return Ok(forbidden());
    };
    let policy = RoomDeliveryPolicyQuery {
        route,
        visible_peer: &request.to,
        real_peer: Some(&channel_jid),
        kind: Some(PrivacyStanzaKind::Iq),
        recipient_jid: full_jid,
    };
    if channel_domain == mix_domain(session) {
        let decisions = RoomDeliveryPolicyReader::read_room_delivery_policies(
            session.host().as_ref(),
            &[policy],
        )
        .await?;
        if !matches!(decisions.as_slice(), [decision] if decision.allows())
            || live_route() != Some(route)
        {
            return Ok(forbidden());
        }
        let response =
            handle_channel_relay_request_for(session.host(), &request, exact_route).await?;
        return Ok(Some(if response.is_empty() {
            MixAction::None
        } else {
            MixAction::Send(response)
        }));
    }
    if !session.host().federation_domain_allowed(channel_domain) {
        return Ok(forbidden());
    }
    let Some(pam_incarnation) = MixRelayPolicyReader::read_remote_mix_relay(
        session.host().as_ref(),
        &policy,
        &channel_address,
    )
    .await?
    else {
        return Ok(forbidden());
    };
    if live_route() != Some(route) {
        return Ok(forbidden());
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
            pam_incarnation: Some(pam_incarnation),
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
