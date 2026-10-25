//! The upload context as the composition root builds it: storage pool, durable authority, object
//! store, slot service and HTTP admission.

use super::construction::{AUXILIARY_POOL_ACQUIRE_TIMEOUT, AUXILIARY_POOL_STARTUP_BUDGET};
use super::*;
use crate::api::contexts::upload_admission::UploadAdmission;
use anyhow::Context;

/// The upload context's runtime parts, built once at startup.
pub(super) struct UploadModule {
    /// Upload persistence alone owns this pool. Disabled mode has no storage
    /// connection; the loopback development exception reuses the main pool.
    pub(super) storage_pool: Option<PgPool>,
    /// XEP-0363 bearer-token and capacity admission authority. Protocol code
    /// receives typed slot outcomes, never the PostgreSQL pool.
    pub(super) service: Option<UploadService>,
    pub(super) store: Option<Arc<dyn UploadStore>>,
    pub(super) namespace_sha256: [u8; 32],
    pub(super) authority_generation: UploadAuthorityGeneration,
    pub(super) safety_gate: Arc<UploadSafetyGate>,
    pub(super) startup_audits: Arc<northstar_upload_application::worker::StartupAuditHandoff>,
    /// Capability-owned upload runtime. Disabled mode contains no store,
    /// semaphore, per-IP map or upload-specific numeric state.
    pub(super) runtime: UploadRuntime,
}

impl UploadModule {
    /// Opens the upload storage pool, proves the durable upload authority, reconciles the ledger
    /// and staging files, and builds the store, the slot service and the HTTP admission.
    pub(super) async fn start(config: &Config, pool: &PgPool) -> anyhow::Result<Self> {
        let upload_startup_phase =
            northstar_telemetry::logging::StartupPhase::begin("upload_storage_initialization");
        anyhow::ensure!(
            !northstar_upload_postgres::migration::upload_migration_active(pool).await?,
            "offline upload migration is active; keep all nodes stopped"
        );
        let upload_storage_pool = match config.storage_pool_mode {
            StoragePoolMode::Disabled => None,
            StoragePoolMode::SharedUnsafeDevelopment => Some(pool.clone()),
            StoragePoolMode::DedicatedProductionRole => {
                let deadline = tokio::time::Instant::now() + AUXILIARY_POOL_STARTUP_BUDGET;
                let options = db::pin_public_application_schema(
                    PgPoolOptions::new()
                        .max_connections(STORAGE_POOL_MAX_CONNECTIONS)
                        .min_connections(0)
                        .acquire_timeout(AUXILIARY_POOL_ACQUIRE_TIMEOUT),
                );
                let storage_pool = startup_database_connect(
                    deadline,
                    AUXILIARY_POOL_ACQUIRE_TIMEOUT,
                    "upload storage",
                    |_| options.clone().connect(&config.storage_database_url),
                )
                .await?;
                tokio::time::timeout_at(deadline, db::attest_storage_role(&storage_pool))
                    .await
                    .context(
                        "storage role attestation exceeded its startup admission deadline",
                    )??;
                Some(storage_pool)
            }
        };
        let upload_startup_audits;
        let (upload_safety_gate, upload_namespace, upload_authority_generation, upload_store) =
            if config.upload_mode.keeps_storage_runtime() {
                let upload_db = upload_storage_pool
                    .as_ref()
                    .expect("enabled or draining uploads require an attested storage pool");
                let upload_safety_gate = UploadSafetyGate::new();
                let upload_namespace = upload_storage_namespace_id(config)?;
                let startup_phase = northstar_telemetry::logging::StartupPhase::begin(
                    "upload_namespace_and_policy",
                );
                let namespace_generation =
                    northstar_upload_postgres::validate_upload_storage_backend(
                        upload_db,
                        &config.upload_storage_backend,
                        &upload_namespace,
                    )
                    .await
                    .context("upload storage backend does not match durable metadata")?;
                let (capacity_policy_generation, recovery_draining) =
                    northstar_upload_postgres::validate_upload_capacity_policy(
                        upload_db,
                        config.upload_storage_max_pending_jobs,
                        config.upload_storage_max_retained_files,
                        config.upload_storage_max_retained_bytes,
                    )
                    .await
                    .context(
                        "upload capacity policy does not match durable deployment authority",
                    )?;
                let upload_authority_generation = UploadAuthorityGeneration {
                    namespace: namespace_generation,
                    capacity_policy: capacity_policy_generation,
                };
                startup_phase.complete();
                let startup_phase =
                    northstar_telemetry::logging::StartupPhase::begin("upload_authority_audit");
                let authority_audit_started_at = tokio::time::Instant::now();
                let authority_audit = northstar_upload_postgres::audit_upload_capacity_authority(
                    upload_db,
                    config.upload_storage_max_pending_jobs,
                    config.upload_storage_max_retained_files,
                    config.upload_storage_max_retained_bytes,
                )
                .await
                .context("could not prove upload authority catalog and ACL invariants")?;
                if authority_audit.violation_count() != 0 {
                    upload_safety_gate.mark_capacity_authority_unsafe(Arc::<str>::from(format!(
                        "upload authority catalog/ACL audit found {} violations",
                        authority_audit.violation_count()
                    )));
                    anyhow::bail!(
                        "upload authority catalog/ACL audit found {} violations",
                        authority_audit.violation_count()
                    );
                }
                startup_phase.complete();
                let startup_phase = northstar_telemetry::logging::StartupPhase::begin(
                    "upload_ledger_reconciliation",
                );
                let ledger_audit_started_at = tokio::time::Instant::now();
                let capacity_reconciliation =
                    northstar_upload_postgres::reconcile_upload_capacity_ledger(upload_db)
                        .await
                        .context(
                            "could not reconcile upload capacity facts before storage startup",
                        )?;
                if capacity_reconciliation.mismatch_count() != 0 {
                    upload_safety_gate.mark_ledger_mismatch(Arc::<str>::from(format!(
                        "upload capacity ledger differs from {} durable facts",
                        capacity_reconciliation.mismatch_count()
                    )));
                    anyhow::bail!(
                        "upload capacity ledger differs from {} durable facts",
                        capacity_reconciliation.mismatch_count()
                    );
                }
                startup_phase.complete();
                upload_safety_gate.establish(upload_authority_generation, recovery_draining);
                let upload_store: Arc<dyn UploadStore> = match config
                    .upload_storage_backend
                    .as_str()
                {
                    "local" => {
                        let local = Arc::new(
                            LocalUploadStore::new(config.upload_dir.clone())
                                .with_safety_gate(Arc::clone(&upload_safety_gate)),
                        );
                        let guarded = Arc::new(GuardedUploadStore::new(
                            local.clone(),
                            Arc::clone(&upload_safety_gate),
                        ));
                        // This bounded local enumeration is retained only for legacy
                        // pre-0091 partials. S3 reconciliation never lists a bucket;
                        // every stage is represented by a PostgreSQL job.
                        let mut abandoned_stages = 0_u64;
                        let startup_stages =
                            tokio::time::timeout(Duration::from_secs(10), local.staging_attempts())
                                .await
                                .context("upload staging scan exceeded its startup time budget")?
                                .context("failed to enumerate upload staging files")?;
                        // Enumeration is bounded above, but every candidate still
                        // needs an authoritative lease lookup and may need one exact
                        // unlink. Keep the complete reconciliation phase under one
                        // wall-clock budget so thousands of crash remnants cannot
                        // hold readiness indefinitely through sequential queries.
                        let startup_cleanup_deadline =
                            tokio::time::Instant::now() + Duration::from_secs(30);
                        for (object_id, claim_token) in startup_stages {
                            let remaining = startup_cleanup_deadline
                            .checked_duration_since(tokio::time::Instant::now())
                            .context(
                                "upload staging reconciliation exceeded its startup time budget",
                            )?;
                            if tokio::time::timeout(
                            remaining,
                            northstar_upload_postgres::upload_claim_is_live(upload_db, object_id, claim_token),
                        )
                        .await
                        .context(
                            "upload staging lease verification exceeded its startup time budget",
                        )?
                        .context("failed to verify an upload staging lease")?
                        {
                            continue;
                        }
                            let remaining = startup_cleanup_deadline
                            .checked_duration_since(tokio::time::Instant::now())
                            .context(
                                "upload staging reconciliation exceeded its startup time budget",
                            )?;
                            if tokio::time::timeout(
                                remaining,
                                guarded.abort(
                                    &object_id.to_string(),
                                    &claim_token.to_string(),
                                    None,
                                ),
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
                        guarded
                    }
                    "s3" => {
                        let inner: Arc<dyn UploadStore> = Arc::new(
                            S3UploadStore::new(S3UploadSettings {
                                endpoint: config.upload_s3_endpoint.clone(),
                                region: config.upload_s3_region.clone(),
                                bucket: config
                                    .upload_s3_bucket
                                    .clone()
                                    .context("S3 upload bucket is missing after validation")?,
                                prefix: config.upload_s3_prefix.clone(),
                                path_style: config.upload_s3_path_style,
                                allow_http: config.upload_s3_allow_http,
                                ambient_credentials: config.upload_s3_credential_mode == "ambient",
                                cleanup_mode: northstar_upload_storage::S3CleanupMode::parse(
                                    &config.upload_s3_cleanup_mode,
                                )?,
                                credential_bundle_file: config
                                    .upload_s3_credential_bundle_file
                                    .clone(),
                                access_key_id_file: config.upload_s3_access_key_id_file.clone(),
                                secret_access_key_file: config
                                    .upload_s3_secret_access_key_file
                                    .clone(),
                                session_token_file: config.upload_s3_session_token_file.clone(),
                                sse_kms_key_id_file: config.upload_s3_sse_kms_key_id_file.clone(),
                            })?
                            .with_safety_gate(Arc::clone(&upload_safety_gate)),
                        );
                        Arc::new(GuardedUploadStore::new(
                            inner,
                            Arc::clone(&upload_safety_gate),
                        ))
                    }
                    _ => unreachable!("upload backend was validated by Config"),
                };
                upload_startup_audits =
                    northstar_upload_application::worker::StartupAuditHandoff::after_successful_audits(
                        upload_authority_generation,
                        [
                            config.upload_storage_max_pending_jobs,
                            config.upload_storage_max_retained_files,
                            config.upload_storage_max_retained_bytes,
                        ],
                        authority_audit_started_at,
                        ledger_audit_started_at,
                    );
                (
                    upload_safety_gate,
                    upload_namespace,
                    upload_authority_generation,
                    Some(upload_store),
                )
            } else {
                let durable_upload_state_exists =
                    northstar_upload_postgres::durable_upload_state_exists(pool)
                        .await
                        .context("could not verify that disabled upload storage is empty")?;
                anyhow::ensure!(
                    !durable_upload_state_exists,
                    "UPLOAD_MODE=disabled requires empty durable upload state; use drain_read_only until historical downloads and cleanup jobs have drained"
                );
                tracing::info!(
                    "upload capability disabled; skipping storage authority, object-store and reconciliation initialization"
                );
                upload_startup_audits =
                    northstar_upload_application::worker::StartupAuditHandoff::default();
                (
                    UploadSafetyGate::disabled(),
                    [0_u8; 32],
                    UploadAuthorityGeneration {
                        namespace: 0,
                        capacity_policy: 0,
                    },
                    None,
                )
            };
        upload_startup_phase.complete();
        let runtime = UploadRuntime::from_config(config);
        let upload_service = config.upload_mode.keeps_storage_runtime().then(|| {
            northstar_upload_application::service::UploadService::new(
                northstar_upload_postgres::PostgresUploadRepository::new(
                    upload_storage_pool
                        .as_ref()
                        .expect("enabled or draining uploads require a storage pool")
                        .clone(),
                ),
                Arc::clone(&upload_safety_gate),
                config.upload_max_bytes,
            )
        });
        Ok(Self {
            storage_pool: upload_storage_pool,
            service: upload_service,
            store: upload_store,
            namespace_sha256: upload_namespace,
            authority_generation: upload_authority_generation,
            safety_gate: upload_safety_gate,
            startup_audits: Arc::new(upload_startup_audits),
            runtime,
        })
    }
}

/// Stable, non-secret identity for the physical upload namespace shared by
/// every node. PostgreSQL stores this digest so a node configured for a
/// different bucket/prefix cannot serve or delete another node's objects.
/// Credential material is deliberately excluded: rotating credentials must
/// not change storage authority.
pub(super) fn upload_storage_namespace_id(config: &Config) -> anyhow::Result<[u8; 32]> {
    let s3 = (config.upload_storage_backend == "s3")
        .then(|| -> anyhow::Result<S3UploadSettings> {
            Ok(S3UploadSettings {
                endpoint: config.upload_s3_endpoint.clone(),
                region: config.upload_s3_region.clone(),
                bucket: config.upload_s3_bucket.clone().unwrap_or_default(),
                prefix: config.upload_s3_prefix.clone(),
                path_style: config.upload_s3_path_style,
                allow_http: config.upload_s3_allow_http,
                ambient_credentials: config.upload_s3_credential_mode == "ambient",
                cleanup_mode: northstar_upload_storage::S3CleanupMode::parse(
                    &config.upload_s3_cleanup_mode,
                )?,
                credential_bundle_file: config.upload_s3_credential_bundle_file.clone(),
                access_key_id_file: config.upload_s3_access_key_id_file.clone(),
                secret_access_key_file: config.upload_s3_secret_access_key_file.clone(),
                session_token_file: config.upload_s3_session_token_file.clone(),
                sse_kms_key_id_file: config.upload_s3_sse_kms_key_id_file.clone(),
            })
        })
        .transpose()?;
    northstar_upload_storage::upload_storage_namespace_id(
        &config.upload_storage_backend,
        &config.upload_dir,
        s3.as_ref(),
    )
}

pub(super) enum UploadRuntime {
    Enabled {
        requests: UploadAdmission,
        downloads: UploadAdmission,
    },
    DrainReadOnly {
        downloads: UploadAdmission,
    },
    Disabled,
}

impl UploadRuntime {
    pub(super) fn from_config(config: &northstar_config::Config) -> Self {
        let downloads = || UploadAdmission {
            semaphore: Arc::new(Semaphore::new(config.upload_download_max_concurrent)),
            by_ip: Arc::new(DashMap::new()),
            max_per_ip: config.upload_download_max_per_ip,
        };
        match config.upload_mode {
            northstar_config::UploadMode::Enabled => Self::Enabled {
                requests: UploadAdmission {
                    semaphore: Arc::new(Semaphore::new(32)),
                    by_ip: Arc::new(DashMap::new()),
                    max_per_ip: 4,
                },
                downloads: downloads(),
            },
            northstar_config::UploadMode::DrainReadOnly => Self::DrainReadOnly {
                downloads: downloads(),
            },
            northstar_config::UploadMode::Disabled => Self::Disabled,
        }
    }

    pub(super) fn request_admission(&self) -> Option<&UploadAdmission> {
        match self {
            Self::Enabled { requests, .. } => Some(requests),
            Self::DrainReadOnly { .. } | Self::Disabled => None,
        }
    }

    pub(super) fn download_admission(&self) -> Option<&UploadAdmission> {
        match self {
            Self::Enabled { downloads, .. } | Self::DrainReadOnly { downloads } => Some(downloads),
            Self::Disabled => None,
        }
    }
}
