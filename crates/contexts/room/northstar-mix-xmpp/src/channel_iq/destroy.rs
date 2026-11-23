use super::*;

pub(super) async fn destroy_channel(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    mix_domain: &str,
    channel: &str,
    actor_bare: &str,
    reply_to: &str,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let Some(channel) = state.mix_service().mix_channel(mix_domain, channel).await? else {
        return Ok(iq_error_to(
            &request.id,
            mix_domain,
            reply_to,
            "cancel",
            "item-not-found",
        ));
    };
    let local_users = state
        .mix_service()
        .local_pam_users_for_channel(&channel.jid())
        .await?;
    if state
        .mix_service()
        .destroy_mix_channel(channel.id, actor_bare, federated)
        .await?
    {
        for user_id in local_users {
            if let Some(user) = state.mix_service().find_enabled_user_by_id(user_id).await? {
                push_mix_roster_update(state, &user, &channel.jid(), true).await?;
            }
        }
        let payload = XmlElement::namespaced("destroy", CORE_NS)
            .attr("channel", &channel.localpart)
            .finish();
        Ok(iq_result_to(&request.id, mix_domain, reply_to, &payload))
    } else {
        Ok(iq_error_to(
            &request.id,
            mix_domain,
            reply_to,
            "auth",
            "forbidden",
        ))
    }
}
