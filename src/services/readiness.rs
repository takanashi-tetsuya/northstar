//! Persisted authorities required by the private readiness endpoint.
//! The HTTP adapter owns the short cache and live process checks; this service
//! orders the database checks and evaluates the cleanup convergence policy.

use crate::cluster::ClusterReadinessAuthority;
use crate::db::{
    AbuseKeyDeploymentIdentity, AdminSessionCleanupSnapshot, ClusterKeyDeploymentIdentity,
};
use anyhow::{ensure, Result};
use std::future::Future;

// Cleanup retries cap at a 300-second backoff. Allow one full capped interval
// plus recovery margin, but do not advertise readiness indefinitely.
pub(crate) const ADMIN_CLEANUP_MAX_READY_AGE_SECONDS: f64 = 600.0;
pub(crate) const ADMIN_CLEANUP_MAX_READY_ATTEMPTS: i64 = 9;

pub(crate) trait ReadinessRepository: Send + Sync {
    fn validate_abuse_key(
        &self,
        identity: &AbuseKeyDeploymentIdentity,
    ) -> impl Future<Output = Result<()>> + Send;

    fn validate_cluster_key(
        &self,
        identity: &ClusterKeyDeploymentIdentity,
    ) -> impl Future<Output = Result<()>> + Send;

    fn validate_cluster_instance(
        &self,
        authority: &ClusterReadinessAuthority,
    ) -> impl Future<Output = Result<()>> + Send;

    fn admin_session_cleanup_snapshot(
        &self,
    ) -> impl Future<Output = Result<AdminSessionCleanupSnapshot>> + Send;
}

pub(crate) struct ReadinessService<R> {
    repository: R,
}

impl<R: ReadinessRepository> ReadinessService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Keep the original probe order and unconditional final database query.
    /// Each repository call finishes before the next one starts; no transaction
    /// spans a process-local check or external I/O.
    pub(crate) async fn validate_persistence(
        &self,
        abuse_identity: Option<&AbuseKeyDeploymentIdentity>,
        cluster_authority: Option<&ClusterReadinessAuthority>,
    ) -> Result<()> {
        if let Some(identity) = abuse_identity {
            self.repository.validate_abuse_key(identity).await?;
        }
        if let Some(authority) = cluster_authority {
            self.repository
                .validate_cluster_key(&authority.key_identity)
                .await?;
            self.repository.validate_cluster_instance(authority).await?;
        }
        // This unconditional authority query also proves database connectivity.
        // A separate ping would add another pool wait to the same probe budget.
        let cleanup = self.repository.admin_session_cleanup_snapshot().await?;
        ensure!(
            admin_session_cleanup_ready(&cleanup),
            "administrator session-cleanup authority is inconsistent, full, or not converging"
        );
        Ok(())
    }
}

pub(crate) fn admin_session_cleanup_ready(cleanup: &AdminSessionCleanupSnapshot) -> bool {
    cleanup.pending >= 0
        && cleanup.running >= 0
        && cleanup.capacity > 0
        && cleanup.queued == cleanup.pending.saturating_add(cleanup.running)
        && cleanup.queued < cleanup.capacity
        && (cleanup.queued == 0
            || (cleanup.oldest_age_seconds <= ADMIN_CLEANUP_MAX_READY_AGE_SECONDS
                && cleanup.maximum_attempts < ADMIN_CLEANUP_MAX_READY_ATTEMPTS))
}
