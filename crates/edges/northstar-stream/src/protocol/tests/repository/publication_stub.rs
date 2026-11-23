use anyhow::Result;
use northstar_abuse_policy::ContentIdentityAuthenticators;
use northstar_delivery_core::MixDelivery;
use northstar_room_application::mix_service::{
    foreground, MixPublicationRepository, MixRealJid, PreparedMessage, PublicationRenderer,
    StoreMixMessageAdmission,
};
use uuid::Uuid;

impl MixPublicationRepository for super::UnusedRepository {
    async fn publish_message(
        &self,
        _message: &PreparedMessage,
        _renderer: PublicationRenderer,
        _authenticators: Option<&ContentIdentityAuthenticators>,
        _observation: Option<&foreground::StoreRequest>,
    ) -> Result<StoreMixMessageAdmission> {
        panic!("unexpected repository call: publish_message")
    }

    async fn claimed_recipient_account(
        &self,
        _source: MixDelivery,
        _address: &MixRealJid,
    ) -> Result<Option<Uuid>> {
        panic!("unexpected repository call: claimed_recipient_account")
    }
}
