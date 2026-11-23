use super::Repository;
use crate::mix_service::{
    CommittedPreference, ConfigPatch, FederatedMixMutation, InfoPatch, MixAdministrationRepository,
    MixChannelId, MixMutationOutcome, MixRealJid, PreferencePatch,
};
use anyhow::Result;

impl MixAdministrationRepository for Repository {
    async fn update_preference(
        &self,
        _channel_id: MixChannelId,
        _actor: &MixRealJid,
        _patch: PreferencePatch,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<CommittedPreference>> {
        panic!("unexpected repository call: update_preference")
    }

    async fn update_info(
        &self,
        _channel_id: MixChannelId,
        _actor: &MixRealJid,
        _patch: InfoPatch,
        _item_id: String,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        panic!("unexpected repository call: update_info")
    }

    async fn update_config(
        &self,
        _channel_id: MixChannelId,
        _actor: &MixRealJid,
        _patch: ConfigPatch,
        _item_id: String,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        panic!("unexpected repository call: update_config")
    }
}
