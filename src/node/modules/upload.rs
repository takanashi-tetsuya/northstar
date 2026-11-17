//! The upload context as the composition root builds it: storage pool, durable authority, object
//! store, slot service and HTTP admission.

use crate::node::construction::{AUXILIARY_POOL_ACQUIRE_TIMEOUT, AUXILIARY_POOL_STARTUP_BUDGET};
use crate::node::*;
use anyhow::Context;
use northstar_http::contexts::upload_admission::UploadRuntime;
use northstar_postgres::startup::startup_database_connect;
use northstar_upload_application::startup::{
    ensure_disabled_upload_state_empty, establish_upload_authority, UploadCapacityLimits,
};
use northstar_upload_postgres::PostgresUploadStartupRepository;
use northstar_upload_storage::config_settings::{namespace_id_from_config, start_upload_store};

/// The upload context's runtime parts, built once at startup.
pub(in crate::node) struct UploadModule {
    /// Upload persistence alone owns this pool. Disabled mode has no storage
    /// connection; the loopback development exception reuses the main pool.
    pub(in crate::node) storage_pool: Option<PgPool>,
    /// XEP-0363 bearer-token and capacity admission authority. Protocol code
    /// receives typed slot outcomes, never the PostgreSQL pool.
    pub(in crate::node) service: Option<UploadService>,
    pub(in crate::node) store: Option<Arc<dyn UploadStore>>,
    pub(in crate::node) namespace_sha256: [u8; 32],
    pub(in crate::node) authority_generation: UploadAuthorityGeneration,
    pub(in crate::node) safety_gate: Arc<UploadSafetyGate>,
    pub(in crate::node) startup_audits:
        Arc<northstar_upload_application::worker::StartupAuditHandoff>,
    /// Capability-owned upload runtime. Disabled mode contains no store,
    /// semaphore, per-IP map or upload-specific numeric state.
    pub(in crate::node) runtime: UploadRuntime,
}

impl UploadModule {
    pub(crate) fn upload_service(&self) -> &UploadService {
        self.service
            .as_ref()
            .expect("upload routes require an enabled or draining storage runtime")
    }

    /// Opens the upload storage pool, proves the durable upload authority, reconciles the ledger
    /// and staging files, and builds the store, the slot service and the HTTP admission.
    pub(in crate::node) async fn start(config: &Config, pool: &PgPool) -> anyhow::Result<Self> {
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
                let options = northstar_postgres::role_attestation::pin_public_application_schema(
                    northstar_postgres::pool::options()
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
                tokio::time::timeout_at(
                    deadline,
                    northstar_postgres::role_attestation::attest_storage_role(&storage_pool),
                )
                .await
                .context("storage role attestation exceeded its startup admission deadline")??;
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
                let upload_namespace = namespace_id_from_config(config)?;
                let startup = PostgresUploadStartupRepository::new(upload_db.clone());
                let limits = UploadCapacityLimits {
                    max_pending_jobs: config.upload_storage_max_pending_jobs,
                    max_retained_files: config.upload_storage_max_retained_files,
                    max_retained_bytes: config.upload_storage_max_retained_bytes,
                };
                let authority = establish_upload_authority(
                    &startup,
                    &upload_safety_gate,
                    &config.upload_storage_backend,
                    &upload_namespace,
                    limits,
                )
                .await?;
                let upload_authority_generation = authority.generation;
                let upload_store =
                    start_upload_store(config, &startup, &upload_safety_gate).await?;
                upload_startup_audits = authority.startup_audits;
                (
                    upload_safety_gate,
                    upload_namespace,
                    upload_authority_generation,
                    Some(upload_store),
                )
            } else {
                ensure_disabled_upload_state_empty(
                    northstar_upload_postgres::durable_upload_state_exists(pool),
                )
                .await?;
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

impl ServerNode {
    pub(crate) fn upload_store(&self) -> &dyn UploadStore {
        self.upload
            .store
            .as_deref()
            .expect("upload routes and workers require an enabled or draining runtime")
    }
}
