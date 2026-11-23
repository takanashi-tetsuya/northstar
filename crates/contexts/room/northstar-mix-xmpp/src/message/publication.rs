use super::*;
use northstar_room_application::mix_service::LockedPublisher;
use northstar_room_core::mix::MixParticipantNick;

pub(super) fn render_publication(
    message: &PreparedMessage,
    publisher: &LockedPublisher,
) -> Result<String> {
    mix_channel_message(MixChannelMessage {
        from: publisher.channel.as_str(),
        to: None,
        id: message.item_id,
        payload: Some(&message.children),
        nick: publisher.nick.as_ref().map(MixParticipantNick::as_str),
        jid: publisher.archive_jid.as_ref().map(MixRealJid::as_str),
    })
}
