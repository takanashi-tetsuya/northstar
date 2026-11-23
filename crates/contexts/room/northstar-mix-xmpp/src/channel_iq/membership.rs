use super::*;
use crate::iq_parse::JoinData;

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
    match state
        .mix_service()
        .join_mix_channel(
            channel.id,
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
    let Some(left) = state
        .mix_service()
        .leave_mix_channel(channel.id, actor_bare, None, federated)
        .await?
    else {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "cancel",
            "item-not-found",
        ));
    };
    let _ = left;
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
    match state
        .mix_service()
        .set_mix_nick(channel.id, actor_bare, nick, federated)
        .await?
    {
        Ok(participant) => {
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
        Err(SetNickError::NotParticipant) => Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        )),
        Err(SetNickError::Conflict) => Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "cancel",
            "conflict",
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
    let Some(outcome) = state
        .mix_service()
        .update_mix_subscriptions(channel.id, actor_bare, subscribe, unsubscribe, federated)
        .await?
    else {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
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
