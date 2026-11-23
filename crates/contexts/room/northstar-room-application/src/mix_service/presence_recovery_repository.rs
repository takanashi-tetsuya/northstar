use super::{MixRepository, MixService, PresenceOutcome};
use anyhow::Result;
use northstar_room_core::mix::{MixChannelAddress, MixChannelId, MixRealJid};
use northstar_time::{DateTime, Utc};
use northstar_xmpp_types::jid::CanonicalJid;

pub const RECOVERY_PRESENCE_PAGE_CAP: u32 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryEpoch {
    pub cutoff: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RecoveryProbeTarget {
    pub channel: MixChannelAddress,
    pub participant: MixRealJid,
}

#[derive(Clone, Debug)]
pub struct RecoveryEpochAndTargets {
    pub epoch: RecoveryEpoch,
    pub targets: Vec<RecoveryProbeTarget>,
}

#[derive(Clone, Debug)]
pub struct RecoveryPresenceSource {
    participant: MixRealJid,
    full: CanonicalJid,
}

impl RecoveryPresenceSource {
    pub fn parse(full: &str) -> Result<Self> {
        let full = CanonicalJid::parse(full)?;
        anyhow::ensure!(
            full.resourcepart().is_some(),
            "MIX presence requires a full JID"
        );
        let participant = MixRealJid::parse(&full.bare())?;
        Ok(Self { participant, full })
    }

    pub fn participant(&self) -> &MixRealJid {
        &self.participant
    }

    pub fn full(&self) -> &CanonicalJid {
        &self.full
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryProgress {
    pub expired: usize,
    pub has_remaining: bool,
}

pub trait MixPresenceRecoveryRepository {
    fn prepare_recovery(
        &self,
    ) -> impl std::future::Future<Output = Result<RecoveryEpochAndTargets>> + Send;

    fn refresh_recovery_presence(
        &self,
        epoch: RecoveryEpoch,
        channel: &MixChannelId,
        source: &RecoveryPresenceSource,
    ) -> impl std::future::Future<Output = Result<PresenceOutcome>> + Send;

    /// An authenticated empty available probe reply may refresh an existing row only.
    /// Returns whether that resource's known presence row was refreshed; nothing is
    /// written otherwise.
    fn refresh_probe_presence_liveness(
        &self,
        channel: &MixChannelId,
        source: &RecoveryPresenceSource,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;

    fn expire_recovery_presence_page(
        &self,
        epoch: RecoveryEpoch,
        budget: u32,
    ) -> impl std::future::Future<Output = Result<RecoveryProgress>> + Send;
}

impl<R: MixRepository> MixService<R> {
    pub async fn prepare_recovery(&self) -> Result<RecoveryEpochAndTargets> {
        self.repository.prepare_recovery().await
    }

    pub async fn refresh_recovery_presence(
        &self,
        epoch: RecoveryEpoch,
        channel: &MixChannelId,
        source: &RecoveryPresenceSource,
    ) -> Result<PresenceOutcome> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .refresh_recovery_presence(epoch, channel, source)
            .await
    }

    pub async fn refresh_probe_presence_liveness(
        &self,
        channel: &MixChannelId,
        source: &RecoveryPresenceSource,
    ) -> Result<bool> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .refresh_probe_presence_liveness(channel, source)
            .await
    }

    pub async fn expire_recovery_presence_page(
        &self,
        epoch: RecoveryEpoch,
        budget: u32,
    ) -> Result<RecoveryProgress> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .expire_recovery_presence_page(epoch, budget)
            .await
    }
}
