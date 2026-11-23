use super::*;
use crate::iq_parse::JoinData;
use northstar_room_application::mix_service::HostedMixOutcome;
use northstar_room_core::mix::{MixChannelId, MixRealJid};

pub(super) async fn join_channel(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor_bare: &str,
    reply_to: &str,
    join: &JoinData,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    if federated.is_none()
        && request
            .from
            .as_deref()
            .is_some_and(|from| from.contains('/'))
    {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "not-authorized",
        ));
    }
    let committed = match state
        .mix_service()
        .join_hosted_mix_committed(
            &MixChannelId::new(channel.id),
            JoinMixRequest {
                actor_jid: actor_bare.to_owned(),
                nick: join.nick.clone(),
                nodes: join.nodes.clone(),
                pam_user_id: None,
                invitation: join.invitation.clone(),
                preference: join.preference.clone(),
                anonymous_profile: join.anonymous_profile,
            },
            federated,
        )
        .await?
    {
        HostedMixOutcome::Present(committed) => committed,
        HostedMixOutcome::MissingChannel => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "cancel",
                "item-not-found",
            ));
        }
    };
    match committed.outcome {
        JoinChannelOutcome::Joined {
            participant,
            preference,
            subscriptions,
            ..
        } => Ok(iq_result_to(
            &request.id,
            &channel.jid(),
            reply_to,
            &core_join_payload(
                &participant,
                &subscriptions,
                join.preference.as_ref().map(|_| &preference),
                join.anonymous_profile,
            )?,
        )),
        outcome => Ok(join_error(&request.id, &channel.jid(), reply_to, outcome)),
    }
}

pub(super) async fn leave_channel(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor_bare: &str,
    reply_to: &str,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let left = match state
        .mix_service()
        .leave_mix_channel_committed(
            &MixChannelId::new(channel.id),
            &MixRealJid::parse(actor_bare)?,
            None,
            federated,
        )
        .await?
    {
        HostedMixOutcome::Present(left) if left.outcome.is_some() => left,
        _ => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "cancel",
                "item-not-found",
            ));
        }
    };
    for delta in &left.roster {
        push_mix_roster_update(state, delta).await?;
    }
    let payload = XmlElement::namespaced("leave", CORE_NS).finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &payload,
    ))
}

pub(super) async fn set_nick(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor_bare: &str,
    reply_to: &str,
    nick: &str,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    match HostedMixOutcome::classify(
        state
            .mix_service()
            .set_mix_nick(channel.id, actor_bare, nick, federated)
            .await,
    )? {
        HostedMixOutcome::Present(Ok(participant)) => {
            let payload = XmlElement::namespaced("setnick", CORE_NS)
                .child(XmlElement::new("nick").text(participant.nick.clone().unwrap_or_default()))
                .finish();
            Ok(iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &payload,
            ))
        }
        HostedMixOutcome::Present(Err(SetNickError::NotParticipant)) => Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        )),
        HostedMixOutcome::Present(Err(SetNickError::Conflict)) => Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "cancel",
            "conflict",
        )),
        HostedMixOutcome::MissingChannel => Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "cancel",
            "item-not-found",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn update_subscription(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor_bare: &str,
    reply_to: &str,
    subscribe: &[String],
    unsubscribe: &[String],
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let outcome = match HostedMixOutcome::classify(
        state
            .mix_service()
            .update_mix_subscriptions(channel.id, actor_bare, subscribe, unsubscribe, federated)
            .await,
    )? {
        HostedMixOutcome::Present(Some(outcome)) => outcome,
        HostedMixOutcome::Present(None) => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ))
        }
        HostedMixOutcome::MissingChannel => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "cancel",
                "item-not-found",
            ));
        }
    };
    let mut update = XmlElement::namespaced("update-subscription", CORE_NS);
    for node in &outcome.subscriptions {
        update.push_child(XmlElement::new("subscribe").attr("node", node));
    }
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &update.finish(),
    ))
}
