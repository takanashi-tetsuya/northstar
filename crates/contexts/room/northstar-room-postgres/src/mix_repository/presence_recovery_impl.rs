use super::*;
use northstar_room_core::mix::MixChannelId;

impl<E: RoomEffects> MixPresenceRecoveryRepository for PostgresMixRepository<E> {
    async fn prepare_recovery(&self) -> Result<RecoveryEpochAndTargets> {
        crate::mix::prepare_recovery(&self.pool).await
    }

    async fn refresh_recovery_presence(
        &self,
        epoch: RecoveryEpoch,
        channel: &MixChannelId,
        source: &RecoveryPresenceSource,
    ) -> Result<PresenceOutcome> {
        Ok(presence_outcome(
            crate::mix::refresh_recovery_presence(&self.pool, epoch, channel, source, &MixPayloads)
                .await?,
        ))
    }

    async fn refresh_probe_presence_liveness(
        &self,
        channel: &MixChannelId,
        source: &RecoveryPresenceSource,
    ) -> Result<bool> {
        crate::mix::refresh_probe_presence_liveness(&self.pool, channel, source, &MixPayloads).await
    }

    async fn expire_recovery_presence_page(
        &self,
        epoch: RecoveryEpoch,
        budget: u32,
    ) -> Result<RecoveryProgress> {
        crate::mix::expire_recovery_presence_page(&self.pool, epoch, budget, &MixPayloads).await
    }
}
