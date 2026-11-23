use super::Repository;
use anyhow::Result;
use northstar_room_application::mix_service::{
    MixPresenceRecoveryRepository, PresenceOutcome, RecoveryEpoch, RecoveryEpochAndTargets,
    RecoveryPresenceSource, RecoveryProgress,
};
use northstar_room_core::mix::MixChannelId;

impl MixPresenceRecoveryRepository for Repository {
    async fn prepare_recovery(&self) -> Result<RecoveryEpochAndTargets> {
        panic!("prepare_recovery")
    }

    async fn refresh_recovery_presence(
        &self,
        _epoch: RecoveryEpoch,
        _channel: &MixChannelId,
        _source: &RecoveryPresenceSource,
    ) -> Result<PresenceOutcome> {
        panic!("refresh_recovery_presence")
    }

    async fn refresh_probe_presence_liveness(
        &self,
        _channel: &MixChannelId,
        _source: &RecoveryPresenceSource,
    ) -> Result<PresenceOutcome> {
        panic!("refresh_probe_presence_liveness")
    }

    async fn expire_recovery_presence_page(
        &self,
        _epoch: RecoveryEpoch,
        _budget: u32,
    ) -> Result<RecoveryProgress> {
        panic!("expire_recovery_presence_page")
    }
}
