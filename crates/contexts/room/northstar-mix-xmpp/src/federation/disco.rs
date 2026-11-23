use super::*;
use northstar_room_application::mix_service::HostedDiscoView;
use northstar_room_core::mix::{MixAdministratorRetractionRights, MixChannelAddress};

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
    let mirror = if target.localpart().is_some() {
        let address = MixChannelAddress::parse(&target.bare())?;
        let actor = CanonicalJid::parse_bare(&requester.bare)?;
        let Some(view) = state
            .mix_service()
            .hosted_disco(&address, &actor)
            .await?
            .filter(|view| view.visible_to_actor)
        else {
            return Ok(iq_error_to(
                &request.id,
                &request.to,
                &requester.reply_to,
                "cancel",
                "item-not-found",
            ));
        };
        hosted_info_payload(
            &view,
            state.mix_muc_mirror_enabled(),
            state.xmpp_extension_enabled(northstar_xep_0313::XEP_ID),
            &muc_domain,
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

fn hosted_info_payload(
    view: &HostedDiscoView,
    mirror_enabled: bool,
    mam_enabled: bool,
    muc_domain: &str,
) -> Result<String> {
    let mirror = northstar_room_application::mix_muc::conditional_mirror_discovery_form(
        mirror_enabled,
        view.muc_room_id.is_some(),
        northstar_room_application::mix_muc::MirrorDirection::Muc,
        muc_domain,
    );
    mix_channel_disco_info_payload(
        view.name.as_deref().unwrap_or(view.address.localpart()),
        view.allow_user_message_retraction
            || view.administrator_retraction_rights != MixAdministratorRetractionRights::Nobody,
        view.allow_private_messages,
        mam_enabled,
        &mirror,
    )
}

#[cfg(test)]
mod tests;
