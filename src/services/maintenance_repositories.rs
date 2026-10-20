//! Repository ports of the retention and PubSub subscription cleanup workers, implemented by the database adapter.

use chrono::Utc;

/// A separately bounded retention source. These are intentionally the only
/// tables touched by automated history cleanup. In particular, reports,
/// appeals, copied report evidence, moderation state, and the audit log are
/// outside this enum and cannot be selected by a retention sweep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionStore {
    PersonalMam,
    MucMam,
    OfflineMessages,
    PersonalDeliveryAdmissions,
}

impl RetentionStore {
    pub fn label(self) -> &'static str {
        match self {
            Self::PersonalMam => "personal_mam",
            Self::MucMam => "muc_mam",
            Self::OfflineMessages => "offline_messages",
            Self::PersonalDeliveryAdmissions => "personal_delivery_admissions",
        }
    }
}

pub(crate) trait RetentionRepository: Send + Sync {
    fn purge_resolved_retention_batch(
        &self,
        store: RetentionStore,
        now: chrono::DateTime<Utc>,
        days: i64,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn purge_released_hold_snapshots_batch(
        &self,
        days: i64,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn purge_audit_log_batch(
        &self,
        days: i64,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn purge_governance_export_leases_batch(
        &self,
        days: i64,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn cleanup_omemo_recovery_transfers(
        &self,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
    fn purge_expired_retraction_intents(
        &self,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
}

pub(crate) trait SubscriptionCleanupRepository: Send + Sync {
    fn cleanup_expired_subscriptions(
        &self,
        batch_size: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<u64>> + Send;
}
