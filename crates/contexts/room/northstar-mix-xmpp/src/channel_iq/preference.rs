use super::*;

pub(super) async fn get_user_preference(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor_bare: &str,
    reply_to: &str,
) -> Result<String> {
    if state
        .mix_service()
        .mix_participant_preference(channel.id, actor_bare)
        .await?
        .is_none()
    {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    }
    let payload = XmlElement::namespaced("user-preference", ANON_NS)
        .validated_fragment(&preference_template_form())?
        .finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &payload,
    ))
}

pub(super) async fn set_user_preference(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor_bare: &str,
    reply_to: &str,
    fields: &BTreeMap<String, Vec<String>>,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let current = state
        .mix_service()
        .mix_participant_preference(channel.id, actor_bare)
        .await?
        .unwrap_or_default();
    let preference = parse_preference_submission(fields, Some(&current))?;
    let Some(outcome) = state
        .mix_service()
        .update_mix_participant_preference(channel.id, actor_bare, &preference, federated)
        .await?
    else {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "modify",
            "not-acceptable",
        ));
    };
    for (user_id, change) in &outcome.roster_changes {
        if let Some(user) = state
            .mix_service()
            .find_enabled_user_by_id(*user_id)
            .await?
        {
            state
                .deliver_roster_change(
                    *user_id,
                    &user.username,
                    change,
                    Some(&outcome.participant.participant_id.to_string()),
                )
                .await?;
        }
    }
    let preference_payload = XmlElement::namespaced("user-preference", ANON_NS)
        .validated_fragment(&preference_result_form(&preference))?
        .finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &preference_payload,
    ))
}
