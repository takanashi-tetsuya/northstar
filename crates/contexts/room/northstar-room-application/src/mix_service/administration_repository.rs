use super::*;
use northstar_room_core::mix::{
    MixAllowBlock, MixClock, MixJidVisibility, MixJidVisibilityPreference, MixLocalParticipantId,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PreferencePatch {
    pub jid_visibility: Option<MixJidVisibilityPreference>,
    pub private_messages: Option<MixAllowBlock>,
    pub vcard: Option<MixAllowBlock>,
    pub share_presence: Option<bool>,
}

impl PreferencePatch {
    pub fn apply(self, mut current: MixParticipantPreference) -> MixParticipantPreference {
        if let Some(value) = self.jid_visibility {
            current.jid_visibility = value.as_str().to_owned();
        }
        if let Some(value) = self.private_messages {
            current.private_messages = value.as_str().to_owned();
        }
        if let Some(value) = self.vcard {
            current.vcard = value.as_str().to_owned();
        }
        if let Some(value) = self.share_presence {
            current.share_presence = value;
        }
        current
    }
}

#[derive(Debug)]
pub struct CommittedPreference {
    pub participant_id: MixLocalParticipantId,
    pub preference: MixParticipantPreference,
    pub roster_changes: Vec<CommittedMixRosterDelta>,
}

#[derive(Clone, Debug, Default)]
pub struct InfoPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub visibility: Option<MixJidVisibility>,
}

#[derive(Clone, Debug)]
pub struct ConfigPatch {
    pub expected_revision: i64,
    /// Structurally validated form values. Interpret policy claims only after owner admission.
    pub fields: BTreeMap<String, Vec<String>>,
}

pub trait MixAdministrationRepository {
    fn update_preference(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: PreferencePatch,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<Option<CommittedPreference>>> + Send;

    fn update_info(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: InfoPatch,
        item_id: String,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<MixMutationOutcome>> + Send;

    fn update_config(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: ConfigPatch,
        item_id: String,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<MixMutationOutcome>> + Send;
}

impl<R> MixService<R> {
    #[must_use]
    pub fn with_item_clock(mut self, clock: impl MixClock + 'static) -> Self {
        self.item_clock = Arc::new(clock);
        self
    }

    pub fn prepare_item_timestamp(&self) -> DateTime<Utc> {
        self.item_clock.now_utc()
    }
}

impl<R: MixRepository> MixService<R> {
    pub async fn update_preference(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: PreferencePatch,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<CommittedPreference>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_preference(channel_id, actor, patch, federated)
            .await
    }

    pub async fn update_info(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: InfoPatch,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        let item_id = mix_timestamp_item_id(self.prepare_item_timestamp());
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_info(channel_id, actor, patch, item_id, federated)
            .await
    }

    pub async fn update_config(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: ConfigPatch,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        let item_id = mix_timestamp_item_id(self.prepare_item_timestamp());
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .update_config(channel_id, actor, patch, item_id, federated)
            .await
    }
}

#[cfg(test)]
mod tests;
