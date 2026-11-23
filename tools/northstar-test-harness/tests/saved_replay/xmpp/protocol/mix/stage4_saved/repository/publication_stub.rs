use super::*;
use northstar_abuse_policy::ContentIdentityAuthenticators;

impl MixPublicationRepository for ControlledRepository {
    async fn publish_message(
        &self,
        _message: &PreparedMessage,
        _renderer: PublicationRenderer,
        authenticators: Option<&ContentIdentityAuthenticators>,
        observation: Option<&foreground::StoreRequest>,
    ) -> Result<StoreMixMessageAdmission> {
        let request = observation.ok_or_else(|| self.unused("publish_message"))?;
        self.store_mix_message_observed(request, authenticators)
            .await
    }

    async fn claimed_recipient_account(
        &self,
        _source: northstar_delivery_core::MixDelivery,
        _address: &MixRealJid,
    ) -> Result<Option<Uuid>> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .account)
    }
}
