use super::{Call, Repository};
use anyhow::Result;
use northstar_room_application::mix_service::{
    CommittedPreference, ConfigPatch, FederatedMixMutation, InfoPatch, MixAdministrationRepository,
    MixChannelId, MixMutationOutcome, MixRealJid, PreferencePatch,
};

impl MixAdministrationRepository for Repository {
    async fn update_preference(
        &self,
        channel_id: MixChannelId,
        actor: &MixRealJid,
        patch: PreferencePatch,
        _federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<CommittedPreference>> {
        self.0.record(Call::PreferenceWrite(
            channel_id.as_uuid(),
            actor.to_string(),
            patch,
        ));
        Ok(Some(
            self.0
                .preference_commit
                .lock()
                .unwrap()
                .take()
                .expect("unexpected repository call: update_preference"),
        ))
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
