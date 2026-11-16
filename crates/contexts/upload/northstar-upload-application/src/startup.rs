//! Startup authority proofs and reconciliation for the upload context.

use std::{future::Future, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::safety::UploadSafetyGate;
use crate::store::UploadStore;
use crate::worker::StartupAuditHandoff;
use crate::UploadAuthorityGeneration;

/// Durable upload authority reads used once at startup.
pub trait UploadStartupRepository: Send + Sync {
    fn validate_storage_backend(
        &self,
        backend: &str,
        namespace_sha256: &[u8; 32],
    ) -> impl Future<Output = Result<i64>> + Send;
    fn validate_capacity_policy(
        &self,
        limits: UploadCapacityLimits,
    ) -> impl Future<Output = Result<(i64, bool)>> + Send;
    /// Number of catalog/ACL violations found.
    fn audit_capacity_authority(
        &self,
        limits: UploadCapacityLimits,
    ) -> impl Future<Output = Result<u64>> + Send;
    /// Number of ledger rows that differ from durable facts.
    fn reconcile_capacity_ledger(&self) -> impl Future<Output = Result<u64>> + Send;
    fn claim_is_live(
        &self,
        object_id: Uuid,
        claim_token: Uuid,
    ) -> impl Future<Output = Result<bool>> + Send;
}

#[derive(Clone, Copy, Debug)]
pub struct UploadCapacityLimits {
    pub max_pending_jobs: i64,
    pub max_retained_files: i64,
    pub max_retained_bytes: i64,
}

pub struct EstablishedUploadAuthority {
    pub generation: UploadAuthorityGeneration,
    pub startup_audits: StartupAuditHandoff,
}

pub async fn establish_upload_authority(
    repository: &impl UploadStartupRepository,
    gate: &UploadSafetyGate,
    backend: &str,
    namespace_sha256: &[u8; 32],
    limits: UploadCapacityLimits,
) -> Result<EstablishedUploadAuthority> {
    let startup_phase =
        northstar_telemetry::logging::StartupPhase::begin("upload_namespace_and_policy");
    let namespace_generation = repository
        .validate_storage_backend(backend, namespace_sha256)
        .await
        .context("upload storage backend does not match durable metadata")?;
    let (capacity_policy_generation, recovery_draining) = repository
        .validate_capacity_policy(limits)
        .await
        .context("upload capacity policy does not match durable deployment authority")?;
    let upload_authority_generation = UploadAuthorityGeneration {
        namespace: namespace_generation,
        capacity_policy: capacity_policy_generation,
    };
    startup_phase.complete();
    let startup_phase = northstar_telemetry::logging::StartupPhase::begin("upload_authority_audit");
    let authority_audit_started_at = tokio::time::Instant::now();
    let authority_audit = repository
        .audit_capacity_authority(limits)
        .await
        .context("could not prove upload authority catalog and ACL invariants")?;
    if authority_audit != 0 {
        gate.mark_capacity_authority_unsafe(Arc::<str>::from(format!(
            "upload authority catalog/ACL audit found {} violations",
            authority_audit
        )));
        anyhow::bail!(
            "upload authority catalog/ACL audit found {} violations",
            authority_audit
        );
    }
    startup_phase.complete();
    let startup_phase =
        northstar_telemetry::logging::StartupPhase::begin("upload_ledger_reconciliation");
    let ledger_audit_started_at = tokio::time::Instant::now();
    let capacity_reconciliation = repository
        .reconcile_capacity_ledger()
        .await
        .context("could not reconcile upload capacity facts before storage startup")?;
    if capacity_reconciliation != 0 {
        gate.mark_ledger_mismatch(Arc::<str>::from(format!(
            "upload capacity ledger differs from {} durable facts",
            capacity_reconciliation
        )));
        anyhow::bail!(
            "upload capacity ledger differs from {} durable facts",
            capacity_reconciliation
        );
    }
    startup_phase.complete();
    gate.establish(upload_authority_generation, recovery_draining);
    let startup_audits = StartupAuditHandoff::after_successful_audits(
        upload_authority_generation,
        [
            limits.max_pending_jobs,
            limits.max_retained_files,
            limits.max_retained_bytes,
        ],
        authority_audit_started_at,
        ledger_audit_started_at,
    );
    Ok(EstablishedUploadAuthority {
        generation: upload_authority_generation,
        startup_audits,
    })
}

pub async fn reconcile_abandoned_stages(
    repository: &impl UploadStartupRepository,
    store: &dyn UploadStore,
    staging_attempts: impl Future<Output = Result<Vec<(Uuid, Uuid)>>> + Send,
) -> Result<()> {
    // This bounded local enumeration is retained only for legacy
    // pre-0091 partials. S3 reconciliation never lists a bucket;
    // every stage is represented by a PostgreSQL job.
    let mut abandoned_stages = 0_u64;
    let startup_stages = tokio::time::timeout(Duration::from_secs(10), staging_attempts)
        .await
        .context("upload staging scan exceeded its startup time budget")?
        .context("failed to enumerate upload staging files")?;
    // Enumeration is bounded above, but every candidate still
    // needs an authoritative lease lookup and may need one exact
    // unlink. Keep the complete reconciliation phase under one
    // wall-clock budget so thousands of crash remnants cannot
    // hold readiness indefinitely through sequential queries.
    let startup_cleanup_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    for (object_id, claim_token) in startup_stages {
        let remaining = startup_cleanup_deadline
            .checked_duration_since(tokio::time::Instant::now())
            .context("upload staging reconciliation exceeded its startup time budget")?;
        if tokio::time::timeout(remaining, repository.claim_is_live(object_id, claim_token))
            .await
            .context("upload staging lease verification exceeded its startup time budget")?
            .context("failed to verify an upload staging lease")?
        {
            continue;
        }
        let remaining = startup_cleanup_deadline
            .checked_duration_since(tokio::time::Instant::now())
            .context("upload staging reconciliation exceeded its startup time budget")?;
        if tokio::time::timeout(
            remaining,
            store.abort(&object_id.to_string(), &claim_token.to_string(), None),
        )
        .await
        .context("upload staging deletion exceeded its startup time budget")?
        .context("failed to remove an abandoned upload stage")?
        {
            abandoned_stages = abandoned_stages.saturating_add(1);
        }
    }
    if abandoned_stages > 0 {
        tracing::warn!(
            abandoned_stages,
            "removed upload stages left by a previous process"
        );
    }
    Ok(())
}

pub async fn ensure_disabled_upload_state_empty(
    durable_state_exists: impl Future<Output = Result<bool>> + Send,
) -> Result<()> {
    let durable_upload_state_exists = durable_state_exists
        .await
        .context("could not verify that disabled upload storage is empty")?;
    anyhow::ensure!(
        !durable_upload_state_exists,
        "UPLOAD_MODE=disabled requires empty durable upload state; use drain_read_only until historical downloads and cleanup jobs have drained"
    );
    tracing::info!(
        "upload capability disabled; skipping storage authority, object-store and reconciliation initialization"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    use tokio::io::AsyncRead;
    use tracing::instrument::WithSubscriber;

    use crate::store::{StagedUpload, StoreFuture, StoredUpload, StoredUploadReader};
    use crate::{UploadIoClass, UploadSafetyState};

    const LIMITS: UploadCapacityLimits = UploadCapacityLimits {
        max_pending_jobs: 16,
        max_retained_files: 32,
        max_retained_bytes: 1024,
    };
    const GENERATION: UploadAuthorityGeneration = UploadAuthorityGeneration {
        namespace: 7,
        capacity_policy: 11,
    };

    struct LeaseCheck {
        result: Result<bool>,
        advance: Duration,
    }

    #[derive(Default)]
    struct FakeRepository {
        violations: u64,
        mismatches: u64,
        recovery_draining: bool,
        calls: Mutex<Vec<&'static str>>,
        claims: Mutex<Vec<(Uuid, Uuid)>>,
        leases: Mutex<VecDeque<LeaseCheck>>,
    }

    impl FakeRepository {
        fn with_leases(results: impl IntoIterator<Item = Result<bool>>) -> Self {
            Self {
                leases: Mutex::new(
                    results
                        .into_iter()
                        .map(|result| LeaseCheck {
                            result,
                            advance: Duration::ZERO,
                        })
                        .collect(),
                ),
                ..Self::default()
            }
        }
    }

    fn assert_limits(limits: UploadCapacityLimits) {
        assert_eq!(limits.max_pending_jobs, LIMITS.max_pending_jobs);
        assert_eq!(limits.max_retained_files, LIMITS.max_retained_files);
        assert_eq!(limits.max_retained_bytes, LIMITS.max_retained_bytes);
    }

    impl UploadStartupRepository for FakeRepository {
        async fn validate_storage_backend(
            &self,
            backend: &str,
            namespace_sha256: &[u8; 32],
        ) -> Result<i64> {
            assert_eq!(backend, "local");
            assert_eq!(namespace_sha256, &[3_u8; 32]);
            self.calls.lock().unwrap().push("backend");
            Ok(GENERATION.namespace)
        }

        async fn validate_capacity_policy(
            &self,
            limits: UploadCapacityLimits,
        ) -> Result<(i64, bool)> {
            assert_limits(limits);
            self.calls.lock().unwrap().push("policy");
            Ok((GENERATION.capacity_policy, self.recovery_draining))
        }

        async fn audit_capacity_authority(&self, limits: UploadCapacityLimits) -> Result<u64> {
            assert_limits(limits);
            self.calls.lock().unwrap().push("authority");
            Ok(self.violations)
        }

        async fn reconcile_capacity_ledger(&self) -> Result<u64> {
            self.calls.lock().unwrap().push("ledger");
            Ok(self.mismatches)
        }

        async fn claim_is_live(&self, object_id: Uuid, claim_token: Uuid) -> Result<bool> {
            self.claims.lock().unwrap().push((object_id, claim_token));
            let lease = self.leases.lock().unwrap().pop_front().unwrap();
            if !lease.advance.is_zero() {
                // Model a lease lookup that completes after the wall clock has
                // advanced. Timeout polls the result first; the next candidate
                // must still observe the original shared cleanup deadline.
                tokio::time::advance(lease.advance).await;
            }
            lease.result
        }
    }

    #[derive(Default)]
    struct FakeStore {
        aborts: Mutex<Vec<(String, String, Option<String>)>>,
        results: Mutex<VecDeque<Result<bool>>>,
    }

    impl UploadStore for FakeStore {
        fn backend(&self) -> &'static str {
            "local"
        }

        fn put<'a>(
            &'a self,
            _key: &'a str,
            _attempt: &'a str,
            _stream: Box<dyn AsyncRead + Send + Unpin + 'a>,
            _max_size: u64,
        ) -> StoreFuture<'a, StagedUpload> {
            Box::pin(async { anyhow::bail!("unused put") })
        }

        fn commit<'a>(
            &'a self,
            _key: &'a str,
            _attempt: &'a str,
            _expected_stage_version: Option<&'a str>,
            _expected_size: u64,
            _expected_sha256: &'a [u8; 32],
        ) -> StoreFuture<'a, StoredUpload> {
            Box::pin(async { anyhow::bail!("unused commit") })
        }

        fn abort<'a>(
            &'a self,
            key: &'a str,
            attempt: &'a str,
            stage_version: Option<&'a str>,
        ) -> StoreFuture<'a, bool> {
            Box::pin(async move {
                self.aborts.lock().unwrap().push((
                    key.to_owned(),
                    attempt.to_owned(),
                    stage_version.map(str::to_owned),
                ));
                self.results.lock().unwrap().pop_front().unwrap()
            })
        }

        fn get<'a>(
            &'a self,
            _object_key: &'a str,
            _object_version: Option<&'a str>,
        ) -> StoreFuture<'a, Option<StoredUploadReader>> {
            Box::pin(async { anyhow::bail!("unused get") })
        }

        fn delete<'a>(
            &'a self,
            _object_key: &'a str,
            _object_version: Option<&'a str>,
        ) -> StoreFuture<'a, bool> {
            Box::pin(async { anyhow::bail!("unused delete") })
        }

        fn clear<'a>(&'a self) -> StoreFuture<'a, u64> {
            Box::pin(async { anyhow::bail!("unused clear") })
        }
    }

    struct StageCounts(Arc<Mutex<Vec<u64>>>);

    impl tracing::field::Visit for StageCounts {
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            if field.name() == "abandoned_stages" {
                self.0.lock().unwrap().push(value);
            }
        }

        fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
    }

    impl tracing::Subscriber for StageCounts {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            event.record(&mut StageCounts(Arc::clone(&self.0)));
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    fn stages() -> Vec<(Uuid, Uuid)> {
        (0..3).map(|_| (Uuid::new_v4(), Uuid::new_v4())).collect()
    }

    #[tokio::test]
    async fn authority_violations_mark_the_gate_and_fail_before_ledger_reconciliation() {
        let repository = FakeRepository {
            violations: 2,
            ..FakeRepository::default()
        };
        let gate = UploadSafetyGate::new();
        let error = establish_upload_authority(&repository, &gate, "local", &[3_u8; 32], LIMITS)
            .await
            .err()
            .expect("authority violations must fail startup");
        assert_eq!(
            error.to_string(),
            "upload authority catalog/ACL audit found 2 violations",
        );
        assert_eq!(gate.state(), UploadSafetyState::CapacityAuthorityUnsafe);
        assert_eq!(gate.generation(), None);
        assert_eq!(
            *repository.calls.lock().unwrap(),
            ["backend", "policy", "authority"],
        );
        assert!(gate.permit(UploadIoClass::Recovery).is_err());
    }

    #[tokio::test]
    async fn ledger_mismatch_marks_the_gate_and_fails_before_establish() {
        let repository = FakeRepository {
            mismatches: 3,
            ..FakeRepository::default()
        };
        let gate = UploadSafetyGate::new();
        let error = establish_upload_authority(&repository, &gate, "local", &[3_u8; 32], LIMITS)
            .await
            .err()
            .expect("ledger mismatches must fail startup");
        assert_eq!(
            error.to_string(),
            "upload capacity ledger differs from 3 durable facts",
        );
        assert_eq!(gate.state(), UploadSafetyState::LedgerMismatch);
        assert_eq!(gate.generation(), None);
        assert_eq!(
            *repository.calls.lock().unwrap(),
            ["backend", "policy", "authority", "ledger"],
        );
        assert!(gate.permit(UploadIoClass::Recovery).is_err());
    }

    #[tokio::test]
    async fn clean_audits_establish_the_gate_with_the_validated_generation_and_draining_flag() {
        for recovery_draining in [false, true] {
            let repository = FakeRepository {
                recovery_draining,
                ..FakeRepository::default()
            };
            let gate = UploadSafetyGate::new();
            let authority =
                establish_upload_authority(&repository, &gate, "local", &[3_u8; 32], LIMITS)
                    .await
                    .unwrap();
            assert_eq!(authority.generation, GENERATION);
            assert_eq!(gate.generation(), Some(GENERATION));
            assert_eq!(
                gate.state(),
                if recovery_draining {
                    UploadSafetyState::RecoveryDraining
                } else {
                    UploadSafetyState::Healthy
                },
            );
            assert_eq!(
                *repository.calls.lock().unwrap(),
                ["backend", "policy", "authority", "ledger"],
            );
            assert!(gate.permit(UploadIoClass::Recovery).is_ok());
            assert_eq!(
                gate.permit(UploadIoClass::NewWrite).is_ok(),
                !recovery_draining,
            );
            assert!(authority.startup_audits.take().is_some());
            assert!(authority.startup_audits.take().is_none());
        }
    }

    #[tokio::test]
    async fn live_stage_is_kept_and_abandoned_stage_is_aborted_and_counted() {
        let repository = FakeRepository::with_leases([Ok(true), Ok(false), Ok(false)]);
        let store = FakeStore {
            results: Mutex::new(VecDeque::from([Ok(true), Ok(false)])),
            ..FakeStore::default()
        };
        let candidates = stages();
        let counts = Arc::new(Mutex::new(Vec::new()));
        reconcile_abandoned_stages(&repository, &store, async { Ok(candidates.clone()) })
            .with_subscriber(StageCounts(Arc::clone(&counts)))
            .await
            .unwrap();
        assert_eq!(*repository.claims.lock().unwrap(), candidates);
        assert_eq!(
            *store.aborts.lock().unwrap(),
            candidates[1..]
                .iter()
                .map(|(object_id, claim_token)| (
                    object_id.to_string(),
                    claim_token.to_string(),
                    None
                ))
                .collect::<Vec<_>>(),
        );
        assert_eq!(*counts.lock().unwrap(), [1]);
    }

    #[tokio::test]
    async fn abort_error_and_lease_error_stop_reconciliation() {
        for lease_error in [false, true] {
            let repository = FakeRepository::with_leases([if lease_error {
                Err(anyhow::anyhow!("injected lease error"))
            } else {
                Ok(false)
            }]);
            let store = FakeStore {
                results: Mutex::new(VecDeque::from([Err(anyhow::anyhow!(
                    "injected abort error"
                ))])),
                ..FakeStore::default()
            };
            let candidates = stages();
            let error =
                reconcile_abandoned_stages(&repository, &store, async { Ok(candidates.clone()) })
                    .await
                    .unwrap_err();
            assert_eq!(
                error.to_string(),
                if lease_error {
                    "failed to verify an upload staging lease"
                } else {
                    "failed to remove an abandoned upload stage"
                },
            );
            assert_eq!(
                error.root_cause().to_string(),
                if lease_error {
                    "injected lease error"
                } else {
                    "injected abort error"
                },
            );
            assert_eq!(*repository.claims.lock().unwrap(), candidates[..1]);
            assert_eq!(
                store.aborts.lock().unwrap().len(),
                usize::from(!lease_error)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stage_reconciliation_shares_one_thirty_second_deadline() {
        let repository = FakeRepository {
            leases: Mutex::new(VecDeque::from([LeaseCheck {
                result: Ok(true),
                advance: Duration::from_secs(31),
            }])),
            ..FakeRepository::default()
        };
        let store = FakeStore::default();
        let candidates = stages();
        let started = tokio::time::Instant::now();
        let error =
            reconcile_abandoned_stages(&repository, &store, async { Ok(candidates.clone()) })
                .await
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "upload staging reconciliation exceeded its startup time budget",
        );
        assert_eq!(started.elapsed(), Duration::from_secs(31));
        assert_eq!(*repository.claims.lock().unwrap(), candidates[..1]);
        assert!(store.aborts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn disabled_mode_rejects_existing_durable_state() {
        let error = ensure_disabled_upload_state_empty(async { Ok(true) })
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "UPLOAD_MODE=disabled requires empty durable upload state; use drain_read_only until historical downloads and cleanup jobs have drained",
        );
        ensure_disabled_upload_state_empty(async { Ok(false) })
            .await
            .unwrap();
        let error = ensure_disabled_upload_state_empty(async {
            Err(anyhow::anyhow!("injected durable state error"))
        })
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "could not verify that disabled upload storage is empty",
        );
        assert_eq!(
            error.root_cause().to_string(),
            "injected durable state error"
        );
    }
}
