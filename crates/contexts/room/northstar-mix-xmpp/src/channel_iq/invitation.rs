use super::*;

pub(super) async fn invite(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor_bare: &str,
    reply_to: &str,
    invitee: &str,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    if !state
        .mix_service()
        .issue_mix_invitation(
            channel.id,
            actor_bare,
            invitee,
            &token,
            northstar_time::Duration::hours(1),
            federated,
        )
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
                .child(XmlElement::new("invitee").text(invitee.to_owned()))
                .child(XmlElement::new("channel").text(channel.jid()))
                .child(XmlElement::new("token").text(token)),
        )
        .finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &payload,
    ))
}
