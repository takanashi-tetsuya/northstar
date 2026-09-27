//! Bounded, PostgreSQL-authoritative wake hints for committed direct spool rows.
//! A wake identifies an account to inspect; it never authorizes a delivery.

use crate::cluster::ClusterReadinessAuthority;
use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use std::{future::Future, time::Duration};
use uuid::Uuid;

pub(crate) const DIRECT_SPOOL_WAKE_PAGE: i32 = 256;
pub(crate) const DIRECT_SPOOL_WAKE_MAX_DEFER: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimedDirectSpoolWake {
    pub(crate) recipient_id: Uuid,
    pub(crate) revision: Uuid,
    pub(crate) claim_token: Uuid,
    /// PostgreSQL clock sampled after the committed wake became visible.
    pub(crate) cutoff: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectSpoolWakeRoute {
    pub(crate) full_jid: String,
    pub(crate) connection_id: Uuid,
}

pub(crate) trait DirectSpoolWakeRepository: Send + Sync {
    fn cleanup(&self, limit: i32) -> impl Future<Output = Result<i64>> + Send;

    fn claim(
        &self,
        authority: &ClusterReadinessAuthority,
        limit: i32,
    ) -> impl Future<Output = Result<Vec<ClaimedDirectSpoolWake>>> + Send;

    fn routes_page(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        after: Option<&str>,
        limit: i32,
    ) -> impl Future<Output = Result<Vec<DirectSpoolWakeRoute>>> + Send;

    /// Delete only when the exact revision/claim still owns the wake and no
    /// offline row remains for this recipient. The probe and CAS are atomic.
    fn acknowledge_if_empty(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        revision: Uuid,
        claim_token: Uuid,
    ) -> impl Future<Output = Result<bool>> + Send;

    /// Release the exact claim with a database-clock delay. A producer's newer
    /// revision must remain immediately due rather than inherit this delay.
    fn defer(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        revision: Uuid,
        claim_token: Uuid,
        delay: Duration,
    ) -> impl Future<Output = Result<bool>> + Send;
}

pub(crate) struct DirectSpoolWakeService<R> {
    repository: R,
}

impl<R: DirectSpoolWakeRepository> DirectSpoolWakeService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn cleanup(&self, limit: i32) -> Result<i64> {
        ensure!(
            (1..=DIRECT_SPOOL_WAKE_PAGE).contains(&limit),
            "invalid direct spool wake cleanup page"
        );
        self.repository.cleanup(limit).await
    }

    pub(crate) async fn claim(
        &self,
        authority: &ClusterReadinessAuthority,
        limit: i32,
    ) -> Result<Vec<ClaimedDirectSpoolWake>> {
        ensure!(
            (1..=DIRECT_SPOOL_WAKE_PAGE).contains(&limit),
            "invalid direct spool wake claim page"
        );
        self.repository.claim(authority, limit).await
    }

    pub(crate) async fn routes_page(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        after: Option<&str>,
        limit: i32,
    ) -> Result<Vec<DirectSpoolWakeRoute>> {
        ensure!(
            (1..=DIRECT_SPOOL_WAKE_PAGE).contains(&limit),
            "invalid direct spool route page"
        );
        self.repository
            .routes_page(authority, recipient_id, after, limit)
            .await
    }

    pub(crate) async fn acknowledge_if_empty(
        &self,
        authority: &ClusterReadinessAuthority,
        wake: &ClaimedDirectSpoolWake,
    ) -> Result<bool> {
        self.repository
            .acknowledge_if_empty(
                authority,
                wake.recipient_id,
                wake.revision,
                wake.claim_token,
            )
            .await
    }

    pub(crate) async fn defer(
        &self,
        authority: &ClusterReadinessAuthority,
        wake: &ClaimedDirectSpoolWake,
        delay: Duration,
    ) -> Result<bool> {
        ensure!(
            !delay.is_zero() && delay <= DIRECT_SPOOL_WAKE_MAX_DEFER,
            "invalid direct spool wake retry delay"
        );
        self.repository
            .defer(
                authority,
                wake.recipient_id,
                wake.revision,
                wake.claim_token,
                delay,
            )
            .await
    }
}
