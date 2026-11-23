use super::*;
use northstar_room_core::mix::{MixChannelId, MixRealJid};

pub(super) async fn create_channel(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    mix_domain: &str,
    channel: &Option<String>,
    actor_bare: &str,
    reply_to: &str,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let (outcome, localpart) = state
        .mix_service()
        .create_mix_channel(
            mix_domain,
            channel.as_deref(),
            actor_bare,
            MAX_CHANNELS_PER_OWNER,
            federated,
        )
        .await?;
    if state.mix_muc_mirror_enabled() {
        if let CreateChannelOutcome::Created(channel_id) = outcome {
            let channel_id = MixChannelId::new(channel_id);
            match MixRealJid::parse(actor_bare) {
                Ok(owner) => {
                    northstar_room_application::mix_muc::link_created_mix(
                        state.mix_service(),
                        &channel_id,
                        &owner,
                        state.local_domain(),
                    )
                    .await
                }
                Err(error) => {
                    tracing::warn!(%channel_id, %error, "MIX channel created but mirror owner was invalid");
                }
            }
        }
    }
    Ok(create_reply(
        outcome,
        &localpart,
        &request.id,
        mix_domain,
        reply_to,
    ))
}

fn create_reply(
    outcome: CreateChannelOutcome,
    localpart: &str,
    id: &str,
    mix_domain: &str,
    reply_to: &str,
) -> String {
    match outcome {
        CreateChannelOutcome::Created(_) => {
            let payload = XmlElement::namespaced("create", CORE_NS)
                .attr("channel", localpart)
                .finish();
            iq_result_to(id, mix_domain, reply_to, &payload)
        }
        CreateChannelOutcome::Conflict => {
            iq_error_to(id, mix_domain, reply_to, "cancel", "conflict")
        }
        CreateChannelOutcome::QuotaExceeded => {
            iq_error_to(id, mix_domain, reply_to, "wait", "resource-constraint")
        }
    }
}

#[cfg(test)]
mod tests;
