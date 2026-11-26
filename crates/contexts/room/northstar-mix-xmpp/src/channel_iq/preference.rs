use super::*;
use crate::forms::parse_preference_patch;
use northstar_room_core::mix::{MixChannelId, MixRealJid};

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
    let patch = parse_preference_patch(fields)?;
    let Some(outcome) = state
        .mix_service()
        .update_preference(
            MixChannelId::new(channel.id),
            &MixRealJid::parse(actor_bare)?,
            patch,
            federated,
        )
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
    for delta in &outcome.roster_changes {
        crate::session::push_mix_roster_update(state, delta).await?;
    }
    let preference_payload = XmlElement::namespaced("user-preference", ANON_NS)
        .validated_fragment(&preference_result_form(&outcome.preference))?
        .finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &preference_payload,
    ))
}

#[cfg(test)]
mod tests;
