use super::{MixChannel, MixParticipant};
use northstar_room_core::mix::MixJidVisibility;
use uuid::Uuid;

/// Publisher identity used to render an archive payload before admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixPublisherIdentity {
    pub archive_jid_visible: bool,
    pub nick: Option<String>,
    pub participant_id: Uuid,
}

impl MixPublisherIdentity {
    pub fn from_state(channel: &MixChannel, participant: &MixParticipant) -> Self {
        Self {
            archive_jid_visible: matches!(
                MixJidVisibility::parse(&channel.jid_visibility),
                Ok(MixJidVisibility::Visible)
            ),
            nick: participant.nick.clone(),
            participant_id: participant.participant_id,
        }
    }
}
