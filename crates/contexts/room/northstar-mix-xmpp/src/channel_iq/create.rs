use super::*;

pub(super) async fn create_channel(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    mix_domain: &str,
    channel: &Option<String>,
    actor_bare: &str,
    reply_to: &str,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    match state
        .mix_service()
        .create_mix_channel(
            mix_domain,
            channel.as_deref(),
            actor_bare,
            MAX_CHANNELS_PER_OWNER,
            federated,
        )
        .await?
    {
        (CreateChannelOutcome::Created(_), localpart) => {
            let _ = northstar_room_application::mix_muc::maybe_link_local_mirror(
                state.mix_muc_mirror_enabled(),
                state.mix_service(),
                state.local_domain(),
                &localpart,
                actor_bare,
            )
            .await?;
            let payload = XmlElement::namespaced("create", CORE_NS)
                .attr("channel", &localpart)
                .finish();
            Ok(iq_result_to(&request.id, mix_domain, reply_to, &payload))
        }
        (CreateChannelOutcome::Conflict, _) => Ok(iq_error_to(
            &request.id,
            mix_domain,
            reply_to,
            "cancel",
            "conflict",
        )),
        (CreateChannelOutcome::QuotaExceeded, _) => Ok(iq_error_to(
            &request.id,
            mix_domain,
            reply_to,
            "wait",
            "resource-constraint",
        )),
    }
}
