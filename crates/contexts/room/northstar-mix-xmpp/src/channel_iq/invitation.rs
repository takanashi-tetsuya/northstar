use super::*;
use northstar_room_application::mix_service::{IssueMixInvitation, PreparedMixInvitationToken};
use northstar_room_core::mix::{MixChannelAddress, MixChannelId, MixRealJid};

pub(super) async fn invite(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor_bare: &str,
    reply_to: &str,
    invitee: &MixRealJid,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let command = IssueMixInvitation {
        channel: MixChannelAddress::parse(&channel.jid())?,
        channel_id: MixChannelId::new(channel.id),
        inviter: MixRealJid::parse(actor_bare)?,
        invitee: invitee.clone(),
    };
    let token = PreparedMixInvitationToken::prepare(Uuid::new_v4);
    if !state
        .mix_service()
        .execute_mix_invitation(&command, &token, federated)
        .await?
    {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    }
    let payload = XmlElement::namespaced("invite", MISC_NS)
        .child(
            XmlElement::new("invitation")
                .child(XmlElement::new("inviter").text(actor_bare.to_owned()))
                .child(XmlElement::new("invitee").text(invitee.as_str()))
                .child(XmlElement::new("channel").text(channel.jid()))
                .child(XmlElement::new("token").text(token.secret())),
        )
        .finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &payload,
    ))
}
