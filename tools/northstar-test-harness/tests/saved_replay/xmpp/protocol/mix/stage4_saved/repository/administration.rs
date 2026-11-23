use super::ControlledRepository;
use anyhow::Result;
use northstar_room_application::mix_service::{
    CommittedPreference, ConfigPatch, FederatedMixMutation, InfoPatch, MixAdministrationRepository,
    MixChannelId, MixMutationOutcome, MixRealJid, PreferencePatch,
};

impl MixAdministrationRepository for ControlledRepository {
    async fn update_preference(
        &self,
        _channel_id: MixChannelId,
        _actor: &MixRealJid,
        _patch: PreferencePatch,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<CommittedPreference>> {
        Err(self.unused("update_preference"))
    }

    async fn update_info(
        &self,
        _channel_id: MixChannelId,
        _actor: &MixRealJid,
        _patch: InfoPatch,
        _item_id: String,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        Err(self.unused("update_info"))
    }

    async fn update_config(
        &self,
        _channel_id: MixChannelId,
        _actor: &MixRealJid,
        _patch: ConfigPatch,
        _item_id: String,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        Err(self.unused("update_config"))
    }
}
