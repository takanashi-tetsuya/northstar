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

#[derive(Clone)]
pub(crate) struct ReadinessService<R> {
    repository: R,
}

/// The critical periodic key guard can only request its one deployment check.
/// Its timeout and fail-closed worker policy remain with the worker.
#[derive(Clone)]
pub(crate) struct AbuseKeyAuthorityProbe<R> {
    repository: R,
}

impl<R: ReadinessRepository> AbuseKeyAuthorityProbe<R> {
    pub(crate) async fn validate(&self, identity: &AbuseKeyDeploymentIdentity) -> Result<()> {
        self.repository.validate_abuse_key(identity).await
    }
}

impl<R: ReadinessRepository> ReadinessService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) fn abuse_key_authority_probe(&self) -> AbuseKeyAuthorityProbe<R>
    where
        R: Clone,
    {
        AbuseKeyAuthorityProbe {
            repository: self.repository.clone(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;

    #[derive(Clone)]
    struct RecordingRepository {
        key_checks: Arc<AtomicUsize>,
        fail: bool,
    }

    impl ReadinessRepository for RecordingRepository {
        async fn validate_abuse_key(&self, identity: &AbuseKeyDeploymentIdentity) -> Result<()> {
            assert_eq!(identity.xmpp_domain, "example.test");
            self.key_checks.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                anyhow::bail!("key generation diverged");
            }
            Ok(())
        }

        async fn validate_cluster_key(&self, _: &ClusterKeyDeploymentIdentity) -> Result<()> {
            panic!("the periodic guard must not validate cluster keys")
        }

        async fn validate_cluster_instance(&self, _: &ClusterReadinessAuthority) -> Result<()> {
            panic!("the periodic guard must not validate cluster instances")
        }

        async fn admin_session_cleanup_snapshot(&self) -> Result<AdminSessionCleanupSnapshot> {
            panic!("the periodic guard must not run the readiness cleanup probe")
        }
    }

    #[tokio::test]
    async fn periodic_key_probe_runs_only_the_key_query_and_preserves_failure() {
        let identity = AbuseKeyDeploymentIdentity {
            xmpp_domain: "example.test".into(),
            epoch: 3,
            current_key_id: "current".into(),
            previous_key_id: None,
            retire_previous: false,
            minimum_overlap: Duration::from_secs(30),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        for fail in [false, true] {
            let service = ReadinessService::new(RecordingRepository {
                key_checks: Arc::clone(&calls),
                fail,
            });
            let probe = service.abuse_key_authority_probe();
            let result = probe.validate(&identity).await;
            assert_eq!(result.is_err(), fail);
            if fail {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("key generation diverged"));
            }
        }
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
}
