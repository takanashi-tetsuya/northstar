use super::*;
use northstar_room_application::mix_service::HostedMixOutcome;
use northstar_room_core::mix::{MixChannelId, MixRealJid};

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
    let committed = match state
        .mix_service()
        .destroy_mix_channel_committed(
            &MixChannelId::new(channel.id),
            &MixRealJid::parse(actor_bare)?,
            federated,
        )
        .await?
    {
        HostedMixOutcome::Present(committed) => committed,
        HostedMixOutcome::MissingChannel => {
            return Ok(iq_error_to(
                &request.id,
                mix_domain,
                reply_to,
                "cancel",
                "item-not-found",
            ));
        }
    };
    if committed.outcome {
        for delta in &committed.roster {
            push_mix_roster_update(state, delta).await?;
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
