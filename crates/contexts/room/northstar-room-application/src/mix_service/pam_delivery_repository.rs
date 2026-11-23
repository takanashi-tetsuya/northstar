use super::{MixRepository, MixService, ReflectedMixArchiveOutcome, SourceArchiveAdmission};
use anyhow::Result;
use northstar_room_core::mix::{MixChannelAddress, MixPamState, MixRealJid};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PamDeliveryQuery<'a> {
    /// The recipient must already be verified as local by the caller.
    pub recipient: &'a MixRealJid,
    pub channel: &'a MixChannelAddress,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PamDeliveryAuthority {
    pub account_id: Uuid,
    pub enabled: bool,
    pub state: Option<MixPamState>,
    pub subscriptions: Vec<String>,
    pub blocked: bool,
}

impl PamDeliveryAuthority {
    pub fn receiving_account(&self, node: &str) -> Option<Uuid> {
        (self.enabled
            && self.state == Some(MixPamState::Joined)
            && !self.blocked
            && self
                .subscriptions
                .iter()
                .any(|subscription| subscription == node))
        .then_some(self.account_id)
    }
}

impl ReflectedMixArchiveOutcome {
    pub fn stored_original_account(&self) -> Option<Uuid> {
        match *self {
            Self::AdmittedOriginal {
                account_id,
                archive: SourceArchiveAdmission::Stored(_),
            } => Some(account_id),
            _ => None,
        }
    }
}

pub trait MixPamDeliveryRepository {
    fn pam_delivery_view(
        &self,
        query: PamDeliveryQuery<'_>,
    ) -> impl std::future::Future<Output = Result<Option<PamDeliveryAuthority>>> + Send;
}

impl<R: MixRepository> MixService<R> {
    pub async fn pam_delivery_view(
        &self,
        query: PamDeliveryQuery<'_>,
    ) -> Result<Option<PamDeliveryAuthority>> {
        self.repository.pam_delivery_view(query).await
    }
}
