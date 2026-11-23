use super::*;
use northstar_room_application::mix_service::{
    LockedPublisher, PreparedMessage, PublicationRenderer,
};
use northstar_room_core::mix::{MixChannelAddress, MixJidVisibility, MixParticipantNick};

pub(super) enum MessagePayload<'a> {
    Rendered {
        payload: &'a str,
        publisher_identity: &'a MixPublisherIdentity,
        visible_jid: Option<&'a str>,
    },
    Locked {
        message: &'a PreparedMessage,
        renderer: PublicationRenderer,
    },
}

pub async fn publish_message(
    pool: &PgPool,
    message: &PreparedMessage,
    renderer: PublicationRenderer,
    identity: Option<MixBusinessIdentity<'_>>,
    payloads: &dyn MixEventPayloadRenderer,
    observation: Option<&northstar_room_application::mix::StoreRequest>,
) -> Result<StoreMixMessageAdmission> {
    admit_message(
        pool,
        &message.channel_id,
        &message.actor,
        message.item_id,
        MessagePayload::Locked { message, renderer },
        identity,
        &message.children,
        message.encrypted,
        payloads,
        observation,
    )
    .await
}

pub(super) async fn locked_message_payload<'a>(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannel,
    participant: &'a MixParticipant,
    message: &PreparedMessage,
    renderer: PublicationRenderer,
) -> Result<(String, Option<&'a str>)> {
    let visibility = MixJidVisibility::parse(&channel.jid_visibility)?;
    let publisher = LockedPublisher {
        channel: MixChannelAddress::parse(&channel.jid())?,
        nick: participant
            .nick
            .as_deref()
            .map(MixParticipantNick::parse)
            .transpose()?,
        archive_jid: (visibility == MixJidVisibility::Visible).then(|| message.actor.clone()),
    };
    let visible_jid = locked_live_jid_visible(transaction, channel, participant)
        .await?
        .then_some(participant.jid.as_str());
    Ok((renderer(message, &publisher)?, visible_jid))
}
