//! ProtocolSession entry points for MIX IQs, messages and presence.

use super::*;

mod pam;
mod presence;
mod relay;
mod roster;

pub use self::presence::{
    forward_presence_to_mix_channels, mix_broadcast_presence_action, try_mix_presence,
};
pub use self::relay::try_mix_iq_relay;
pub use self::roster::push_mix_roster_update;

fn mix_domain(session: &impl MixSession) -> String {
    local_mix_domain(session.host().local_domain())
}

/// Intercept MIX/PAM IQs before ordinary entity and PubSub routing.
pub async fn try_mix_iq(session: &impl MixSession, raw: &str) -> Result<Option<MixAction>> {
    if let Some(action) = try_mix_iq_relay(session, raw).await? {
        return Ok(Some(action));
    }
    if !mix_iq_route_candidate(raw, &mix_domain(session)) {
        return Ok(None);
    }
    let Some(request) = parse_iq(raw)? else {
        return Ok(None);
    };
    let Some(user) = session.user() else {
        return Ok(Some(MixAction::Send(iq_error_to(
            &request.id,
            request
                .to
                .as_deref()
                .unwrap_or(session.host().local_domain()),
            request.from.as_deref().unwrap_or_default(),
            "auth",
            "not-authorized",
        ))));
    };
    let Some(full_jid) = session.full_jid() else {
        return Ok(Some(MixAction::Send(iq_error_to(
            &request.id,
            session.host().local_domain(),
            "",
            "auth",
            "not-authorized",
        ))));
    };
    let actor_bare = format!("{}@{}", user.username, session.host().local_domain());
    if let Some(asserted) = request.from.as_deref() {
        let asserted = northstar_xmpp_types::jid::canonicalize(asserted).ok();
        if asserted.as_deref() != Some(full_jid) && asserted.as_deref() != Some(actor_bare.as_str())
        {
            return Ok(Some(MixAction::Send(iq_error_to(
                &request.id,
                request
                    .to
                    .as_deref()
                    .unwrap_or(session.host().local_domain()),
                full_jid,
                "auth",
                "not-authorized",
            ))));
        }
    }
    let own_target = request.to.as_deref().is_some_and(|to| {
        CanonicalJid::parse_bare(to).is_ok_and(|target| target.to_string() == actor_bare)
    });
    if matches!(
        request.operation,
        IqOperation::PamJoin { .. } | IqOperation::PamLeave { .. }
    ) {
        if !own_target || request.kind != "set" {
            return Ok(Some(MixAction::Send(iq_error_to(
                &request.id,
                &actor_bare,
                full_jid,
                "modify",
                "bad-request",
            ))));
        }
        return handle_pam_request(
            session,
            request,
            user.id,
            user.username,
            &actor_bare,
            full_jid,
            Sha256::digest(raw.as_bytes()).into(),
        )
        .await
        .map(Some);
    }
    let to = request.to.as_deref().unwrap_or_default();
    if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == mix_domain(session)) {
        return Ok(None);
    }
    handle_local_mix_iq(session, request, user, &actor_bare, full_jid)
        .await
        .map(Some)
}

pub async fn handle_pam_request(
    session: &impl MixSession,
    request: OwnedIq,
    user_id: Uuid,
    username: &str,
    actor_bare: &str,
    full_jid: &str,
    request_digest: [u8; 32],
) -> Result<MixAction> {
    match request.operation {
        IqOperation::PamJoin { channel, join } => {
            pam::handle_pam_join(
                session,
                &request.id,
                user_id,
                username,
                actor_bare,
                full_jid,
                request_digest,
                channel,
                join,
            )
            .await
        }
        IqOperation::PamLeave { channel } => {
            pam::handle_pam_leave(
                session,
                &request.id,
                user_id,
                username,
                actor_bare,
                full_jid,
                request_digest,
                channel,
            )
            .await
        }
        _ => unreachable!("PAM dispatcher only passes PAM requests"),
    }
}

async fn handle_local_mix_iq(
    session: &impl MixSession,
    request: OwnedIq,
    user: MixSessionUser<'_>,
    actor_bare: &str,
    reply_to: &str,
) -> Result<MixAction> {
    let from = request
        .to
        .as_deref()
        .unwrap_or(&mix_domain(session))
        .to_owned();
    if is_mix_mam_request(&request) {
        let reply = MixMamReply {
            request: &request,
            addressed: &from,
            reply_to,
        };
        let actor = MixMamReadActor::Local {
            account_id: user.id,
            username: user.username.to_owned(),
            auth_generation: user.auth_generation,
            local_domain: session.host().local_domain().to_owned(),
        };
        let command = match reply.command(session.host().as_ref(), actor) {
            Ok(command) => command,
            Err(response) => return Ok(MixAction::SendMany(vec![response])),
        };
        let outcome = session.host().mix_service().read_mix_mam(command).await?;
        return Ok(MixAction::SendMany(reply.render(outcome)?));
    }
    let response =
        handle_channel_iq(session.host(), &request, actor_bare, &from, reply_to, None).await?;
    Ok(MixAction::Send(response))
}

pub async fn try_mix_message(
    session: &impl MixSession,
    root: Node<'_, '_>,
    raw: &str,
) -> Result<Option<MixAction>> {
    let Some(to) = root.attribute("to") else {
        return Ok(None);
    };
    if !CanonicalJid::parse(to).is_ok_and(|target| target.domainpart() == mix_domain(session)) {
        return Ok(None);
    }
    session.frame_observer().enter(MixFrameStage::Policy);
    let Some(user) = session.user() else {
        return Ok(Some(MixAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    };
    let Some(full_jid) = session.full_jid() else {
        return Ok(Some(MixAction::Send(stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    };
    let actor_bare = format!("{}@{}", user.username, session.host().local_domain());
    let result = process_channel_message(
        session.host(),
        &actor_bare,
        full_jid,
        raw,
        Some(session.frame_observer()),
    )
    .await?;
    Ok(Some(result.map_or(MixAction::None, MixAction::Send)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixBroadcastPresenceAction {
    Publish,
    Retract,
    Ignore,
}
