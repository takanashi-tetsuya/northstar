use super::*;

pub async fn federated_mix_disco_info(
    state: &Arc<impl MixHost>,
    request: &MixDiscoInfoRequest,
    requester: &AuthenticatedMixIqActor,
) -> Result<String> {
    if let Some(condition) = request.error {
        return Ok(iq_error_to(
            &request.id,
            &request.to,
            &requester.reply_to,
            stanza_error_type(condition),
            condition,
        ));
    }
    if request.node.is_some() {
        return Ok(iq_error_to(
            &request.id,
            &request.to,
            &requester.reply_to,
            "cancel",
            "item-not-found",
        ));
    }
    let target = match CanonicalJid::parse(&request.to) {
        Ok(target)
            if target.resourcepart().is_none()
                && same_jid_domain(
                    target.domainpart(),
                    &local_mix_domain(state.local_domain()),
                ) =>
        {
            target
        }
        _ => {
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        }
    };
    let muc_domain = local_muc_domain(state.local_domain());
    let mirror = if let Some(localpart) = target.localpart() {
        let Some(channel) = state
            .mix_service()
            .mix_channel(target.domainpart(), localpart)
            .await?
        else {
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        };
        if !state
            .mix_service()
            .mix_channel_discoverable_to(&channel, &requester.bare)
            .await?
        {
            // Hidden channels deliberately use item-not-found so disco does
            // not become an existence oracle for remote domains.
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        }
        let linked = state.mix_muc_mirror_enabled()
            && state
                .mix_service()
                .mix_muc_mirror_for_mix(channel.id)
                .await?
                .is_some();
        let mirror = northstar_room_application::mix_muc::conditional_mirror_discovery_form(
            state.mix_muc_mirror_enabled(),
            linked,
            northstar_room_application::mix_muc::MirrorDirection::Muc,
            &muc_domain,
        );
        mix_channel_disco_info_payload(
            channel.name.as_deref().unwrap_or(&channel.localpart),
            channel.allow_user_message_retraction
                || channel.administrator_retraction_rights != "nobody",
            channel.allow_private_messages,
            state.xmpp_extension_enabled(northstar_xep_0313::XEP_ID),
            &mirror,
        )?
    } else {
        let linked = state.mix_muc_mirror_enabled()
            && state
                .mix_service()
                .mix_muc_mirror_service_complete(target.domainpart())
                .await?;
        let mirror = northstar_room_application::mix_muc::conditional_mirror_discovery_form(
            state.mix_muc_mirror_enabled(),
            linked,
            northstar_room_application::mix_muc::MirrorDirection::Muc,
            &muc_domain,
        );
        mix_service_disco_info_payload(state.server_name(), &mirror)?
    };
    Ok(iq_result_to(
        &request.id,
        &target.to_string(),
        &requester.reply_to,
        &mirror,
    ))
}
