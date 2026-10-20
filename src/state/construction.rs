//! AppState construction: database pools, API keyrings, services, contexts and startup workers.

use super::*;

// Auxiliary pools retain their two-second acquisition policy while serving.
// Only initial handshakes may retry, within one shared admission window.
pub(super) const AUXILIARY_POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const AUXILIARY_POOL_STARTUP_BUDGET: Duration = Duration::from_secs(15);

pub(super) fn api_keyrings(
    current_secret: &[u8],
    previous_secret: Option<&[u8]>,
) -> anyhow::Result<(db::ApiControlKeyring, crate::api::cursor::CursorKeyring)> {
    let api_control = db::ApiControlKeyring::new(current_secret, previous_secret)
        .context("failed to derive API control keys")?;
    let api_cursor = crate::api::cursor::CursorKeyring::new(current_secret, previous_secret)
        .context("failed to derive API cursor keys")?;
    Ok((api_control, api_cursor))
}

pub(super) fn encode_api_control_entropy(mut entropy: [u8; 32]) -> [u8; 64] {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 64];
    for (index, byte) in entropy.iter().copied().enumerate() {
        encoded[index * 2] = LOWER_HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = LOWER_HEX[usize::from(byte & 0x0f)];
    }
    entropy.zeroize();
    encoded
}

pub(super) fn ephemeral_api_control_secret() -> [u8; 64] {
    use rand::RngCore;

    let mut entropy = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    encode_api_control_entropy(entropy)
}

impl AppState {
    pub async fn new(
        mut config: Config,
        pool: PgPool,
        federation: FederationRouter,
        components: crate::s2s::components::ComponentRegistry,
        runtime_control_connection: PoolConnection<Postgres>,
        worker_cancel: CancellationToken,
    ) -> anyhow::Result<Arc<Self>> {
        // This one-shot credential was consumed by ensure_bootstrap_admin
        // before AppState construction. Never retain it on shared state.
        if let Some(mut password) = config.raw.bootstrap_admin_password.take() {
            password.zeroize();
        }
        let metrics_bearer_token = config.metrics_bearer_token.take();
        let web_admin_gateway_token = config.web_admin_gateway_token.take();
        let component_credentials: Arc<[crate::platform::config::ComponentCredential]> =
            std::mem::take(&mut config.components).into();
        config.components = component_credentials
            .iter()
            .cloned()
            .map(|mut credential| {
                credential.secret_value = None;
                credential.secret_file = None;
                credential.secret_sha256.zeroize();
                credential
            })
            .collect();
        let mut previous_api_control_secret = config.api_control_previous_secret.take();
        let (api_control, api_cursor) = if let Some(mut current_secret) =
            config.api_control_secret.take()
        {
            let keyrings = api_keyrings(
                current_secret.as_bytes(),
                previous_api_control_secret.as_deref().map(str::as_bytes),
            );
            current_secret.zeroize();
            if let Some(previous_secret) = &mut previous_api_control_secret {
                previous_secret.zeroize();
            }
            keyrings?
        } else {
            anyhow::ensure!(
                config.api_control_allow_ephemeral
                    && config.redis_url.is_none()
                    && config.http_bind.ip().is_loopback()
                    && (!config.web_admin_enabled || config.web_admin_bind.ip().is_loopback())
                    && (config.domain == "localhost"
                        || config.domain.ends_with(".localhost")
                        || config.domain.ends_with(".test")),
                "API_CONTROL_SECRET_FILE is required outside an explicitly opted-in single-node loopback development deployment"
            );
            tracing::warn!(
                "API_CONTROL_SECRET_FILE is unset; REST idempotency and pagination cursors use a process-local key, so encrypted replays and issued cursors will not survive restart"
            );
            // Generate exactly one process-local root secret, then derive the
            // independent API-control and cursor subkeys from it. Generating
            // inside either keyring would make their lifetimes diverge. Encode
            // the 256-bit entropy as lowercase hex because mounted text
            // secrets and both keyrings deliberately reject NUL bytes.
            let mut process_secret = ephemeral_api_control_secret();
            let keyrings = api_keyrings(&process_secret, None);
            process_secret.zeroize();
            keyrings?
        };
        let api_control = Arc::new(api_control);
        let startup_phase =
            crate::platform::logging::StartupPhase::begin("mix_delivery_capacity_audit");
        db::audit_mix_delivery_capacity_ledger(&pool)
            .await
            .context("MIX delivery capacity ledger failed startup reconciliation")?;
        startup_phase.complete();
        let startup_phase = crate::platform::logging::StartupPhase::begin("mix_pam_capacity_audit");
        db::audit_mix_pam_operation_capacity(&pool)
            .await
            .context("MIX-PAM operation capacity authority failed startup audit")?;
        startup_phase.complete();
        let upload_startup_phase =
            crate::platform::logging::StartupPhase::begin("upload_storage_initialization");
        anyhow::ensure!(
            !db::upload_migration_active(&pool).await?,
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
                let upload_namespace = upload_storage_namespace_id(&config)?;
                let startup_phase =
                    crate::platform::logging::StartupPhase::begin("upload_namespace_and_policy");
                let namespace_generation = db::validate_upload_storage_backend(
                    upload_db,
                    &config.upload_storage_backend,
                    &upload_namespace,
                )
                .await
                .context("upload storage backend does not match durable metadata")?;
                let (capacity_policy_generation, recovery_draining) =
                    db::validate_upload_capacity_policy(
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
                    crate::platform::logging::StartupPhase::begin("upload_authority_audit");
                let authority_audit_started_at = tokio::time::Instant::now();
                let authority_audit = db::audit_upload_capacity_authority(
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
                let startup_phase =
                    crate::platform::logging::StartupPhase::begin("upload_ledger_reconciliation");
                let ledger_audit_started_at = tokio::time::Instant::now();
                let capacity_reconciliation = db::reconcile_upload_capacity_ledger(upload_db)
                    .await
                    .context("could not reconcile upload capacity facts before storage startup")?;
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
                            db::upload_claim_is_live(upload_db, object_id, claim_token),
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
                                cleanup_mode: crate::storage::S3CleanupMode::parse(
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
                    crate::runtime::upload_worker::StartupAuditHandoff::after_successful_audits(
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
                let durable_upload_state_exists = db::durable_upload_state_exists(&pool)
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
                    crate::runtime::upload_worker::StartupAuditHandoff::default();
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
        let extdisco_service = crate::services::extdisco::ExtDiscoService::new(
            config.domain.clone(),
            config.stun_service.clone(),
            config.turn_service.clone(),
            config.raw.turn_shared_secret.take(),
            config.turn_credentials_ttl_seconds,
            config.turn_credential_requests_per_minute,
        );
        let abuse_state_hmac_key = config.raw.abuse_state_hmac_key.take().map(Zeroizing::new);
        let abuse_state_hmac_previous_key = config
            .raw
            .abuse_state_hmac_previous_key
            .take()
            .map(Zeroizing::new);
        if abuse_state_hmac_key.is_none() {
            let listeners_are_loopback = [
                config.xmpp_bind,
                config.xmpps_bind,
                config.http_bind,
                config.metrics_bind,
                config.s2s_bind,
                config.s2s_tls_bind,
                config.component_bind,
            ]
            .iter()
            .all(|address| address.ip().is_loopback())
                && (!config.web_admin_enabled || config.web_admin_bind.ip().is_loopback());
            anyhow::ensure!(
                config.abuse_state_allow_ephemeral
                    && config.redis_url.is_none()
                    && listeners_are_loopback
                    && (config.domain == "localhost"
                        || config.domain.ends_with(".localhost")
                        || config.domain.ends_with(".test")),
                "ABUSE_STATE_HMAC_KEY_FILE is required unless every listener is loopback-only and ABUSE_STATE_ALLOW_EPHEMERAL=true explicitly enables single-node development mode"
            );
        }
        // The overlap phase deliberately keeps the previous generation as the
        // primary durable writer so old-only nodes can verify challenges and
        // deduplicate admissions.  `retire_previous` is the DB-authorized
        // fence after which every node switches its primary to the new key.
        let write_abuse_artifacts_with_previous =
            abuse_state_hmac_previous_key.is_some() && !config.abuse_state_hmac_retire_previous;
        let abuse = Arc::new(AbuseGuard::new_persistent_for_deployment(
            AbuseConfig {
                base_work_factor: config.pow_base_work_factor,
                max_work_factor: config.pow_max_work_factor,
                window: Duration::from_secs(config.abuse_window_seconds),
                cooldown_step: Duration::from_secs(config.abuse_cooldown_seconds),
                max_wait: Duration::from_secs(config.abuse_max_wait_seconds),
                message_free_burst: config.abuse_message_free_burst,
                approximate_max_device_seconds: config.pow_max_device_seconds,
            },
            pool.clone(),
            abuse_state_hmac_key
                .as_ref()
                .map(|secret| secret.as_bytes()),
            abuse_state_hmac_previous_key
                .as_ref()
                .map(|secret| secret.as_bytes()),
            write_abuse_artifacts_with_previous,
            config.pow_v1_compatibility_until,
        ));
        // Inline key material is accepted only by the explicit disposable
        // loopback development profile. Mounted persistent keys, including
        // every Redis/non-loopback deployment, participate in DB authority.
        let abuse_key_deployment = config.abuse_state_hmac_key_file.as_ref().map(|_| {
            let (current_key_id, previous_key_id) = abuse.deployment_key_ids();
            db::AbuseKeyDeploymentIdentity {
                xmpp_domain: config.domain.clone(),
                epoch: config.abuse_state_hmac_key_epoch,
                current_key_id: current_key_id.to_owned(),
                previous_key_id: previous_key_id.map(str::to_owned),
                retire_previous: config.abuse_state_hmac_retire_previous,
                minimum_overlap: abuse.minimum_key_rotation_overlap(),
            }
        });
        let tls = crate::security::tls::ReloadableTlsConfig::new(
            &config.tls_cert_path,
            &config.tls_key_path,
            &config.domain,
            crate::security::tls::TlsPolicyFiles {
                extra_root: config.federation_extra_root_cert_path.as_deref(),
                c2s_client_trust_root: config.c2s_client_trust_root_cert_path.as_deref(),
                federation_crl: config.federation_crl_path.as_deref(),
                c2s_client_crl: config.c2s_client_crl_path.as_deref(),
                ocsp_response: config.tls_ocsp_response_path.as_deref(),
            },
        )
        .context("failed to load and validate TLS identity")?;
        let open_registration = config.open_registration;
        let dialback_secret = if let Some(secret) =
            config.raw.dialback_secret.take().map(Zeroizing::new)
        {
            Zeroizing::new(secret.as_bytes().to_vec())
        } else {
            use rand::RngCore;
            let mut secret = Zeroizing::new(vec![0_u8; 32]);
            rand::thread_rng().fill_bytes(&mut secret);
            if config.dialback_enabled {
                tracing::warn!(
                    "DIALBACK_SECRET is unset; using a process-local secret (set a mounted secret for deterministic multi-node operation)"
                );
            }
            secret
        };
        let fast_token_secret = Arc::new(
            if let Some(secret) = config.raw.fast_token_secret.take().map(Zeroizing::new) {
                Zeroizing::new(secret.as_bytes().to_vec())
            } else {
                anyhow::ensure!(
                    config.fast_token_enabled
                        && config.raw.fast_token_allow_ephemeral_for_development,
                    "FAST key is unavailable after configuration validation"
                );
                use rand::RngCore;
                let mut secret = Zeroizing::new(vec![0_u8; 32]);
                rand::thread_rng().fill_bytes(&mut secret);
                tracing::warn!(
                    "explicit loopback development mode is using an ephemeral FAST key; XEP-0484 tokens change on restart"
                );
                secret
            },
        );
        let dummy_scram_secret = Arc::new(if let Some(secret) = config.dummy_scram_secret.take() {
            Zeroizing::new(secret.as_bytes().to_vec())
        } else {
            anyhow::ensure!(
                config.raw.dummy_scram_allow_ephemeral_for_development,
                "dummy SCRAM key is unavailable after configuration validation"
            );
            use rand::RngCore;
            let mut secret = Zeroizing::new(vec![0_u8; 32]);
            rand::thread_rng().fill_bytes(&mut secret);
            tracing::warn!(
                "explicit loopback development mode is using an independent ephemeral dummy SCRAM key; unknown-account challenge material changes on restart"
            );
            secret
        });
        anyhow::ensure!(
            !crate::auth::constant_time_bytes_eq(
                fast_token_secret.as_slice(),
                dummy_scram_secret.as_slice(),
            ),
            "FAST and dummy SCRAM master keys must be independent"
        );
        let client_connections = Arc::new(Semaphore::new(config.max_client_connections));
        let s2s_connections = Arc::new(Semaphore::new(config.max_s2s_connections));
        let s2s_connection_attempts = Arc::new(Semaphore::new(config.max_s2s_connections));
        let component_connections = Arc::new(Semaphore::new(config.max_component_connections));
        let connection_actors =
            crate::platform::connection_actors::ConnectionActorRegistry::for_transport_limits(
                config.max_client_connections,
                config.max_s2s_connections,
                config.max_component_connections,
            )
            .context("configured connection actor capacity is invalid")?;
        let sm_capacity_metrics =
            Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
        let sm_memory_governor = crate::services::sm_capacity::SmMemoryGovernor::new(
            config.sm_memory_budget_bytes,
            config.sm_recovery_max_bytes,
            config.sm_recovery_max_jobs,
            config.sm_max_snapshot_bytes,
            Arc::clone(&sm_capacity_metrics),
        )?;
        let (resolver_config, mut resolver_options) =
            read_system_conf().context("failed to read the system DNS resolver configuration")?;
        resolver_options.try_tcp_on_error = true;
        resolver_options.server_ordering_strategy = ServerOrderingStrategy::RoundRobin;
        resolver_options.cache_size = 1024;
        let mut dnssec_options = resolver_options.clone();
        dnssec_options.validate = true;
        dnssec_options.use_hosts_file = ResolveHosts::Never;
        dnssec_options.preserve_intermediates = true;
        dnssec_options.positive_max_ttl = Some(Duration::from_secs(24 * 60 * 60));
        dnssec_options.negative_max_ttl = Some(Duration::from_secs(5 * 60));
        let s2s_dns_resolver = TokioResolver::builder_with_config(
            resolver_config.clone(),
            TokioRuntimeProvider::default(),
        )
        .with_options(resolver_options)
        .build()
        .context("failed to initialize the asynchronous DNS resolver")?;
        let lab_dnssec_anchor = config
            .federation_dnssec_lab_trust_anchor_path
            .as_deref()
            .map(crate::security::lab_dnssec::load_anchor)
            .transpose()?;
        let s2s_dnssec_resolver = (config.federation_dane_mode
            != crate::security::dane::DaneMode::Off)
            .then(|| {
                let mut builder = TokioResolver::builder_with_config(
                    resolver_config,
                    TokioRuntimeProvider::default(),
                )
                .with_options(dnssec_options);
                if let Some(anchor) = lab_dnssec_anchor {
                    builder = builder.with_trust_anchor(Arc::new(anchor));
                }
                builder
                    .build()
                    .context("failed to initialize the locally validating DNSSEC resolver")
            })
            .transpose()?;

        // Transfer the Redis endpoint and signing capability out of the
        // broadly shared Config before constructing AppState.  ClusterManager
        // is their sole runtime owner; keeping a second copy in `state.config`
        // would let unrelated protocol code regain a long-lived secret by
        // reaching through configuration.
        let mut redis_url = config.raw.redis_url.take();
        let cluster_security = config.cluster_security.take();
        let cluster = crate::cluster::ClusterManager::new(
            redis_url.as_deref(),
            &config.domain,
            config.raw.redis_tls_ca_cert_path.as_deref(),
            config.raw.redis_tls_client_cert_path.as_deref(),
            config.raw.redis_tls_client_key_path.as_deref(),
            cluster_security,
        )
        .await
        .context("failed to connect to Redis for cluster manager")?;
        if let Some(redis_url) = &mut redis_url {
            redis_url.zeroize();
            redis_url.clear();
        }
        cluster.configure_authority_pool(&pool)?;
        if let Some(identity) = cluster.key_authority_identity() {
            db::reconcile_cluster_key_deployment_before_instance_claim(&pool, &identity)
                .await
                .context("cluster signing-key authority preparation failed")?;
            for peer in cluster.peer_key_authority_identities() {
                db::reconcile_cluster_peer_key_deployment(&pool, &peer)
                    .await
                    .with_context(|| {
                        format!(
                            "configured cluster peer {} key authority is inconsistent",
                            peer.node_id
                        )
                    })?;
            }
            cluster
                .claim_instance_authority(&pool)
                .await
                .context("cluster node ID is already owned by another live process")?;
            db::reconcile_cluster_key_deployment(&pool, &identity)
                .await
                .context("cluster signing-key authority finalization failed")?;
            cluster
                .refresh_instance_authority(&pool)
                .await
                .context("could not load peer cluster instance authority")?;
        }
        cluster
            .activate()
            .await
            .context("failed to publish the initial signed cluster node lease")?;
        db::initialize_admin_runtime_settings(
            &pool,
            false,
            !open_registration,
            config.registration_dependency_locked(),
        )
        .await?;
        let (island_mode, registration_closed) = db::admin_runtime_settings(&pool).await?;
        let registration_closed = Arc::new(AtomicBool::new(registration_closed));
        let process_started_at = db::admin_service_control_startup_time(&pool).await?;
        let (runtime_blacklist, runtime_whitelist) = db::federation_runtime_rules(&pool).await?;

        db::recover_remote_pam_after_restart(&pool)
            .await
            .context("failed to recover pending MIX-PAM federation operations")?;
        let mix_presence_recovery = db::prepare_mix_presence_after_restart(&pool, &config.domain)
            .await
            .context("failed to prepare XEP-0403 presence recovery")?;
        if config.mix_muc_mirror_enabled {
            let mix_domain = format!("mix.{}", config.domain);
            let linked = db::reconcile_mix_muc_mirrors(&pool, &mix_domain, &config.domain)
                .await
                .context("failed to reconcile XEP-0408 MIX/MUC mirror associations")?;
            tracing::info!(linked, "XEP-0408 partial MIX/MUC mirror mode enabled");
        }

        if let Some(identity) = &abuse_key_deployment {
            db::reconcile_abuse_key_deployment(&pool, identity)
                .await
                .context("anti-abuse HMAC deployment consistency check failed")?;
        }

        let bosh = config.bosh_enabled.then(|| {
            crate::bosh::BoshManager::new(
                config.bosh_max_sessions,
                config.bosh_max_concurrent_body_reads,
            )
        });
        let upload_runtime = UploadRuntime::from_config(&config);
        let sm_recovery_max_jobs = config.sm_recovery_max_jobs;
        let sm_recovery_max_bytes = config.sm_recovery_max_bytes;
        let message_content_identity = abuse.personal_message_content_keyring();
        let retraction_content_identity = abuse.personal_retraction_content_keyring();
        let mix_message_content_identity = abuse.mix_message_content_keyring();
        let mix_retraction_content_identity = abuse.mix_retraction_content_keyring();
        // Durable outbox workers share one application-owned admission
        // capability. This leaves a primary-pool connection for foreground
        // protocol traffic even during simultaneous MIX, PubSub and MUC
        // recovery.
        let durable_outbox_database_admission =
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(
                config.database_max_connections,
            );
        let message_service = crate::services::messaging::MessageService::new(
            db::messaging::PostgresMessageRepository::new(
                pool.clone(),
                message_content_identity,
                config.domain.clone(),
                config.offline_max_messages_per_account,
                config.offline_max_bytes_per_account,
                config.offline_message_ttl_days,
            )
            .with_cluster_admission(cluster.admission()),
            config.require_encrypted_archive,
        );
        let retraction_service = crate::services::retractions::RetractionService::new(
            db::retractions::PostgresRetractionRepository::new(pool.clone())
                .with_cluster_admission(cluster.admission()),
            retraction_content_identity,
            config.domain.clone(),
        );
        let metrics = Arc::new(Metrics::default());
        let account_service = crate::services::account::AccountService::new(
            db::account_repository::PostgresAccountRepository::new(
                pool.clone(),
                config.domain.clone(),
                Arc::clone(&abuse),
            )
            .with_api_control(Arc::clone(&api_control)),
            config.configured_registration_mode()
                == crate::platform::config::RegistrationMode::InvitationOnly,
            config.registration_rate_per_hour,
            config.scram_iterations,
            config.scram_sha1_enabled,
        );
        let login_service = crate::services::http_login::HttpLoginService::new(
            db::http_login_repository::PostgresHttpLoginRepository::new(
                pool.clone(),
                Arc::clone(&abuse),
                Arc::clone(&api_control),
                crate::services::http_login::HttpLoginPolicy {
                    domain: config.domain.clone(),
                    scram_iterations: config.scram_iterations,
                    scram_sha1_enabled: config.scram_sha1_enabled,
                    session_ttl_hours: config.session_ttl_hours,
                },
                metrics.clone() as Arc<dyn crate::services::http_login::LoginFailureMetrics>,
            ),
        );
        let password_change_service = crate::services::password_change::PasswordChangeService::new(
            db::password_change_repository::PostgresPasswordChangeRepository::new(
                pool.clone(),
                Arc::clone(&api_control),
                Arc::clone(&abuse),
            ),
            config.scram_iterations,
            config.scram_sha1_enabled,
        );
        let dummy_scram_iteration_profiles =
            crate::db::scram_iteration_profiles(&pool, config.scram_iterations)
                .await
                .context("failed to load dummy SCRAM iteration profiles")?;
        let authentication_service = crate::services::authentication::AuthenticationService::new_with_dummy_scram_iteration_profiles(
                db::authentication::PostgresAuthenticationRepository::new(pool.clone(), Arc::clone(&fast_token_secret)),
                dummy_scram_secret,
                config.scram_iterations,
                dummy_scram_iteration_profiles,
                config.scram_sha1_enabled,
            );
        let pubsub_service =
            crate::services::pubsub::PubSubService::new_with_durable_outbox_database_admission(
                db::pubsub_repository::PostgresPubSubRepository::new(pool.clone(), &config.domain),
                pool.options().get_max_connections(),
                durable_outbox_database_admission.clone(),
            );
        let profile_service = crate::services::profile::ProfileService::with_mutation_admission(
            db::profile::PostgresProfileRepository::new(pool.clone(), config.domain.clone()),
            pubsub_service.mutation_admission(),
        );
        let mam_service = crate::services::mam::MamService::new(
            db::mam::PostgresMamRepository::new(pool.clone()),
            crate::services::mam::FederatedMamOutboxLimits {
                ttl_seconds: config.s2s_outbox_ttl_seconds,
                max_rows: config.s2s_outbox_max_rows,
                max_bytes: config.s2s_outbox_max_bytes,
                max_per_domain: config.s2s_outbox_max_per_domain,
            },
            federation.outbox_wakeup(),
        );
        let upload_service = config.upload_mode.keeps_storage_runtime().then(|| {
            crate::services::upload::UploadService::new(
                db::upload::PostgresUploadRepository::new(
                    upload_storage_pool
                        .as_ref()
                        .expect("enabled or draining uploads require a storage pool")
                        .clone(),
                ),
                Arc::clone(&upload_safety_gate),
                config.upload_max_bytes,
            )
        });
        let privacy_service = crate::services::privacy::PrivacyService::new(
            db::privacy::PostgresPrivacyRepository::new(pool.clone()),
        );
        let replay_service = crate::services::replay::ReplayService::new(
            db::replay_repository::PostgresReplayRepository::new(pool.clone()),
            &config.domain,
            config.offline_message_ttl_days,
        );
        let passkey_service = Arc::new(PasskeyService::new(
            db::passkeys::PostgresPasskeyRepository::new(pool.clone(), fast_token_secret.clone()),
            crate::services::passkeys::PasskeyConfig {
                enabled: config.web_client_enabled && config.fast_token_enabled,
                public_url: config.public_url.clone(),
                domain: config.domain.clone(),
                scram_iterations: config.scram_iterations,
                scram_sha1_enabled: config.scram_sha1_enabled,
                fast_token_ttl_days: config.fast_token_ttl_days,
                fast_strong_reauth_max_days: config.fast_strong_reauth_max_days,
                session_ttl_hours: config.session_ttl_hours,
            },
        ));
        let roster_service =
            RosterService::new(db::roster::PostgresRosterRepository::new(pool.clone()));
        let private_storage_service = crate::services::private_storage::PrivateStorageService::new(
            db::private::PostgresPrivateStorageRepository::new(pool.clone()),
            config.pep_max_nodes_per_account,
            config.pep_max_storage_bytes_per_account,
        );
        let auxiliary_pool_deadline = tokio::time::Instant::now() + AUXILIARY_POOL_STARTUP_BUDGET;
        let command_pool = match config.admin_command_pool_mode {
            // The explicit loopback-only exception has no independent
            // PostgreSQL principal.  A second PgPool with the same unsafe
            // credential would add pressure without adding a capability
            // boundary, so share the already-attested primary pool instead.
            AdminCommandPoolMode::SharedUnsafeDevelopment => pool.clone(),
            AdminCommandPoolMode::DedicatedProductionRole => {
                let command_pool_options = crate::db::pin_public_application_schema(
                    PgPoolOptions::new()
                        .max_connections(4)
                        .min_connections(0)
                        .acquire_timeout(AUXILIARY_POOL_ACQUIRE_TIMEOUT),
                );
                let command_pool = startup_database_connect(
                    auxiliary_pool_deadline,
                    AUXILIARY_POOL_ACQUIRE_TIMEOUT,
                    "XEP-0133 command",
                    |_| {
                        command_pool_options
                            .clone()
                            .connect(&config.admin_command_database_url)
                    },
                )
                .await?;
                tokio::time::timeout_at(auxiliary_pool_deadline, async {
                    crate::db::attest_admin_command_role(&command_pool).await?;
                    anyhow::Ok(())
                })
                .await
                .context("command role attestation exceeded its startup admission deadline")??;
                command_pool
            }
        };
        let omemo_recovery_pool_options = PgPoolOptions::new()
            .max_connections(OMEMO_RECOVERY_POOL_MAX_CONNECTIONS)
            .min_connections(0)
            .acquire_timeout(AUXILIARY_POOL_ACQUIRE_TIMEOUT);
        let omemo_recovery_pool_options = if config.database_allow_unsafe_role_for_development {
            omemo_recovery_pool_options
        } else {
            crate::db::pin_public_application_schema(omemo_recovery_pool_options)
        };
        let omemo_recovery_poll_pool = startup_database_connect(
            auxiliary_pool_deadline,
            AUXILIARY_POOL_ACQUIRE_TIMEOUT,
            "OMEMO recovery poll",
            |_| {
                omemo_recovery_pool_options
                    .clone()
                    .connect(&config.database_url)
            },
        )
        .await?;
        let sm_authority_schema = db::current_application_schema(&pool)
            .await
            .context("could not determine the SM authority schema")?;
        let mut sm_authority_connect_options = config
            .database_url
            .parse::<PgConnectOptions>()
            .context("could not parse the SM authority listener database URL")?;
        if !config.database_allow_unsafe_role_for_development {
            sm_authority_connect_options =
                sm_authority_connect_options.options([("search_path", "public")]);
        }
        let sm_service = crate::services::sm::SmService::new(
            db::sm_repository::PostgresSmRepository::new(
                pool.clone(),
                Arc::clone(&fast_token_secret),
            ),
            sm_authority_schema.clone(),
        )?;
        // The MIX wake broker validates the same schema identity that the
        // dedicated PostgreSQL listener attests below.  It never trusts a
        // notification as delivery authority; schema matching only prevents
        // a shared database's unrelated schema from creating local scan load.
        let mix_service = crate::services::mix::MixService::new_with_outbox_database_admission(
            db::mix_repository::PostgresMixRepository::new(pool.clone()),
            config.domain.clone(),
            mix_message_content_identity,
            mix_retraction_content_identity,
            durable_outbox_database_admission.clone(),
            sm_authority_schema,
        )?;
        config.raw.database_url.zeroize();
        config.raw.database_url.clear();
        config.raw.admin_command_database_url.zeroize();
        config.raw.admin_command_database_url.clear();
        config.raw.storage_database_url.zeroize();
        config.raw.storage_database_url.clear();
        let muc_service = crate::services::muc::MucService::new(
            db::room::PostgresMucRepository::new(pool.clone()),
            config.domain.clone(),
        );
        let sessions = Arc::new(DashMap::new());
        let muc_occupants = Arc::new(DashMap::new());
        let started_at = Instant::now();
        let api_cursor = Arc::new(api_cursor);
        let federation_write_policy = Arc::new(FederationWritePolicy::new(island_mode));
        let public_discovery_context = PublicDiscoveryContext::new(
            http_policy::PublicDiscoveryPolicy {
                domain: config.domain.clone(),
                public_url: config.public_url.clone(),
                trusted_proxy_ips: config.trusted_proxy_ips.clone(),
                websocket_allowed_origins: config.websocket_allowed_origins.clone(),
                configured_registration_mode: config.configured_registration_mode(),
                registration_dependency_locked: config.registration_dependency_locked(),
                require_encrypted_archive: config.require_encrypted_archive,
                federation_configured: config.federation_enabled,
                rest_api_enabled: config.rest_api_enabled,
                websocket_enabled: config.websocket_enabled,
                bosh_enabled: config.bosh_enabled,
                web_client_enabled: config.web_client_enabled,
                passkeys_enabled: config.web_client_enabled
                    && config.fast_token_enabled
                    && crate::services::passkeys::relying_party(&config.public_url).is_ok(),
                web_admin_enabled: config.web_admin_enabled,
                upload_mode: config.upload_mode,
                upload_max_bytes: config.upload_max_bytes,
                upload_download_max_bytes: config.upload_download_max_bytes,
                pow_max_work_factor: config.pow_max_work_factor,
                pow_max_device_seconds: config.pow_max_device_seconds,
                xep_0487_ips: config.xep_0487_ips.clone(),
                xep_0487_ttl_seconds: config.xep_0487_ttl_seconds,
                xep_0487_priority: config.xep_0487_priority,
                xep_0487_weight: config.xep_0487_weight,
                xmpps_port: config.xmpps_bind.port(),
                s2s_tls_port: config.s2s_tls_bind.port(),
            },
            Arc::clone(&registration_closed),
            Arc::clone(&federation_write_policy.island_mode),
        );
        let api_query_context = api_queries::ApiQueryContext::new(
            crate::services::api_queries::ApiQueryService::new(
                db::api_queries::PostgresApiQueryRepository::new(pool.clone()),
            ),
            Arc::clone(&api_cursor),
            api_queries::ApiQueryRuntime {
                domain: config.domain.clone(),
                node_id: cluster.node_id.clone(),
                require_encrypted_archive: config.require_encrypted_archive,
                federation_configured: config.federation_enabled,
                configured_registration_mode: config.configured_registration_mode(),
                registration_dependency_locked: config.registration_dependency_locked(),
                registration_closed: Arc::clone(&registration_closed),
                island_mode: Arc::clone(&federation_write_policy.island_mode),
                sessions: Arc::clone(&sessions),
                occupants: Arc::clone(&muc_occupants),
                metrics: Arc::clone(&metrics),
                started_at,
            },
        );
        let omemo_recovery_poll_context = omemo_poll::OmemoRecoveryPollContext::new(
            crate::services::omemo_recovery::OmemoRecoveryPollService::new(
                db::omemo_recovery_repository::PostgresOmemoRecoveryPollRepository::new(
                    omemo_recovery_poll_pool,
                ),
            ),
            config.domain.clone(),
            config.trusted_proxy_ips.clone(),
            omemo_poll::OmemoRecoveryPollCounters::from_metrics(&metrics),
        );
        let admin_mutations = db::admin_mutations::AdminMutationStore::new(
            pool.clone(),
            Arc::clone(&api_control),
            cluster.admission(),
        );
        let account_admin_service = crate::services::account_admin::AccountAdminService::new(
            db::account_admin_repository::PostgresAccountAdminRepository::new(
                admin_mutations.clone(),
            ),
        );
        let registration_admin_service =
            crate::services::account_admin::RegistrationAdminService::new(
                db::account_admin_repository::PostgresRegistrationAdminRepository::new(
                    db::admin_dispatch_repository::AdminCommandStore::new(
                        command_pool.clone(),
                        Arc::clone(&api_control),
                        cluster.admission(),
                    ),
                    pool.clone(),
                ),
                account_admin::LocalRegistrationCache::new(
                    config.registration_dependency_locked(),
                    Arc::clone(&registration_closed),
                ),
            );
        let session_admin_service = crate::services::account_admin::SessionAdminService::new(
            db::account_admin_repository::PostgresSessionAdminRepository::new(
                admin_mutations.clone(),
            ),
            account_admin::LocalAdminSessions::new(Arc::clone(&sessions)),
        );
        let operation_admin_service = crate::services::operations::OperationAdminService::new(
            db::operation_admin_repository::PostgresOperationAdminRepository::new(
                admin_mutations.clone(),
            ),
        );
        let operation_muc_destroy_service = Arc::new(
            crate::services::operation_muc_destroy::MucDestroyService::new(
                db::operation_muc_destroy_repository::PostgresMucDestroyRepository::new(
                    pool.clone(),
                ),
                config.domain.clone(),
            ),
        );
        let locked_muc_expiry_service =
            crate::services::locked_muc_expiry::LockedMucExpiryService::new(
                db::locked_muc_expiry_repository::PostgresLockedMucExpiryRepository::new(
                    pool.clone(),
                ),
            );
        let operation_effect_fence_service =
            crate::services::operation_effect_fence::OperationEffectFenceService::new(
                db::operation_effect_fence_repository::PostgresOperationEffectFenceRepository::new(
                    pool.clone(),
                ),
            );
        let operation_journal_worker_service =
            crate::services::operation_journal_worker::OperationJournalWorkerService::new(
                db::operation_journal_worker_repository::PostgresOperationJournalWorkerRepository::new(
                    pool.clone(),
                ),
            );
        let s2s_outbox_dispatch_service =
            crate::services::s2s_outbox_dispatch::S2sOutboxDispatchService::new(
                db::s2s_outbox_dispatch_repository::PostgresS2sOutboxDispatchRepository::new(
                    pool.clone(),
                ),
                crate::services::s2s_outbox_dispatch::S2sOutboxDispatchPolicy {
                    claim_batch: config.s2s_outbox_claim_batch,
                    lease_seconds: config.s2s_outbox_lease_seconds,
                    retry_base_seconds: config.s2s_outbox_retry_base_seconds,
                    retry_max_seconds: config.s2s_outbox_retry_max_seconds,
                    max_attempts: config.s2s_outbox_max_attempts,
                },
            );
        let admin_session_cleanup_worker_service =
            crate::services::admin_session_cleanup_worker::AdminSessionCleanupWorkerService::new(
                db::admin_session_cleanup_worker_repository::PostgresAdminSessionCleanupRepository::new(pool.clone()),
            );
        let admin_dispatch_service = crate::services::admin_dispatch::AdminDispatchService::new(
            db::admin_dispatch_repository::PostgresAdminDispatchRepository::new(
                admin_mutations.clone(),
                command_pool.clone(),
                Arc::clone(&api_control),
                cluster.admission(),
            ),
            config.domain.clone(),
        );
        let upload_admin_service = crate::services::upload_admin::UploadAdminService::new(
            db::upload_admin_repository::PostgresUploadAdminRepository::new(
                admin_mutations.clone(),
            ),
        );
        let report_moderation_service =
            crate::services::report_moderation::ReportModerationService::new(
                db::report_moderation_repository::PostgresReportModerationRepository::new(
                    admin_mutations.clone(),
                ),
            );
        let retention_policy_context = retention_policy::RetentionPolicyContext::new(
            crate::services::retention_policy::RetentionPolicyService::new(
                db::retention_policy_repository::PostgresRetentionPolicyRepository::new(
                    pool.clone(),
                    Arc::clone(&api_control),
                ),
                crate::services::retention_policy::RetentionPolicyLimits {
                    personal_mam_days: config.mam_retention_days,
                    offline_message_days: config.offline_message_ttl_days,
                    moderation_evidence_days: config.moderation_retention_days,
                },
                config.muc_mam_retention_days,
            ),
            Arc::clone(&metrics),
        );
        let governance_context = governance::GovernanceContext::new(
            crate::services::governance::GovernanceService::new(
                db::governance_repository::PostgresGovernanceRepository::new(
                    pool.clone(),
                    admin_mutations.clone(),
                    Arc::clone(&api_control),
                    crate::api::governance_cursor::SignedGovernanceCursors::new(Arc::clone(
                        &api_cursor,
                    )),
                ),
            ),
            Arc::clone(&metrics),
        );
        let invitation_admin_service =
            crate::services::invitation_admin::InvitationAdminService::new(
                db::invitation_admin_repository::PostgresInvitationAdminRepository::new(
                    admin_mutations,
                ),
            );
        let report_service = crate::services::reports::ReportService::new(
            db::report_repository::PostgresReportRepository::new(
                pool.clone(),
                Arc::clone(&api_control),
                Arc::clone(&abuse),
            ),
        );
        let message_admission_service =
            crate::services::message_admission::MessageAdmissionService::new(
                db::message_admission_repository::PostgresMessageAdmissionRepository::new(
                    Arc::clone(&abuse),
                    pool.clone(),
                ),
            );
        let account_revocation_consumer_service =
            crate::services::account_revocation_consumer::AccountRevocationConsumerService::new(
                db::account_revocation_repository::PostgresAccountRevocationRepository::new(
                    pool.clone(),
                ),
            );
        let state = Arc::new(Self {
            config,
            api_query_context,
            metrics_snapshot_service:
                crate::services::metrics_snapshot::MetricsSnapshotService::new(
                    db::metrics_snapshot_repository::PostgresMetricsSnapshotRepository::new(
                        pool.clone(),
                    ),
                ),
            readiness_service: crate::services::readiness::ReadinessService::new(
                db::readiness_repository::PostgresReadinessRepository::new(pool.clone()),
            ),
            public_discovery_context,
            omemo_recovery_service: crate::services::omemo_recovery::OmemoRecoveryService::new(
                db::omemo_recovery_repository::PostgresOmemoRecoveryRepository::new(pool.clone()),
            ),
            pubsub_service,
            profile_service,
            extdisco_service,
            muc_service,
            message_service,
            message_admission_service,
            retraction_service,
            mam_service,
            mix_service,
            sm_service,
            blocking_service: crate::services::blocking::BlockingService::new(
                db::roster::PostgresBlockingRepository::new(pool.clone()),
            ),
            presence_service: crate::services::presence::PresenceService::new(
                db::presence_repository::PostgresPresenceRepository::new(pool.clone()),
            ),
            replay_service,
            roster_service,
            s2s_roster_authorization_service:
                crate::services::s2s_roster_authorization::FederatedRosterAuthorizationService::new(
                    db::s2s_roster_authorization_repository::PostgresFederatedRosterRepository::new(
                        pool.clone(),
                    ),
                ),
            s2s_outbox_dispatch_service,
            s2s_sm_outbox_service: crate::services::s2s_sm_outbox::SmOutboxService::new(
                db::s2s_sm_outbox_repository::PostgresSmOutboxRepository::new(pool.clone()),
            ),
            passkey_service,
            privacy_service,
            private_storage_service,
            account_service,
            login_service,
            password_change_service,
            authentication_service,
            admin_command_service: crate::services::admin_commands::AdminCommandService::new(
                db::admin_command_repository::PostgresAdminCommandRepository::new(
                    pool.clone(),
                    command_pool,
                ),
            ),
            push_service: crate::services::push::PushService::new(
                db::push::PostgresPushRepository::new(pool.clone()),
            ),
            pool,
            cluster,
            account_revocation_consumer_service,
            bosh,
            sessions,
            muc_occupants,
            suspended_muc_sessions: Arc::new(DashMap::new()),
            sm_suspension_recovery:
                crate::services::session_cleanup::SmSuspensionRecoveryQueue::new(
                    sm_recovery_max_jobs,
                    sm_recovery_max_bytes,
                    Arc::clone(&sm_capacity_metrics),
                    Arc::clone(&sm_memory_governor),
                ),
            sm_memory_governor,
            metrics,
            metrics_bearer_token,
            web_admin_gateway_token,
            omemo_recovery_poll_context,
            durable_outbox_database_admission,
            report_service,
            account_admin_service,
            registration_admin_service,
            session_admin_service,
            operation_admin_service,
            operation_muc_destroy_service,
            locked_muc_expiry_service,
            locked_muc_expiry_context: std::sync::OnceLock::new(),
            operation_effect_fence_service,
            operation_journal_worker_service,
            admin_session_cleanup_worker_service,
            admin_dispatch_service,
            upload_admin_service,
            report_moderation_service,
            invitation_admin_service,
            retention_policy_context,
            governance_context,
            upload_service,
            upload_storage_pool,
            upload_store,
            upload_storage_namespace_sha256: upload_namespace,
            upload_authority_generation,
            upload_safety_gate,
            upload_startup_audits: Arc::new(upload_startup_audits),
            federation_outbox: federation,
            component_credentials,
            components,
            s2s_connection_registry: Arc::new(crate::s2s::S2sConnectionRegistry::default()),
            s2s_dns_resolver,
            s2s_dnssec_resolver,
            pending_mix_iq: Arc::new(northstar_protocol_runtime::mix::MixIqRelayIndex::new()),
            caps_cache: Arc::new(northstar_protocol_runtime::caps::CapsCacheIndex::new()),
            caps_by_jid: Arc::new(northstar_protocol_runtime::caps::CapsResourceIndex::new()),
            pending_caps: Arc::new(northstar_protocol_runtime::caps::PendingCapsIndex::new()),
            federated_caps_gates: Arc::new(
                northstar_protocol_runtime::caps::FederatedCapsGateIndex::new(),
            ),
            caps_effect_dispatcher: northstar_protocol_runtime::caps::CapsEffectDispatcher::new(),
            dialback_secret,
            dialback_verifications: Arc::new(Semaphore::new(64)),
            http_body_admission: Arc::new(http_body_admission::HttpBodyAdmission::default()),
            client_connections,
            client_connections_by_ip: DashMap::new(),
            upload_runtime,
            s2s_connections,
            s2s_connection_attempts,
            component_connections,
            connection_actors,
            challenge_issue_service:
                crate::services::challenge_issuance::ChallengeIssueService::new(
                    db::challenge_issuance_repository::PostgresChallengeRepository::new(
                        Arc::clone(&abuse),
                    ),
                ),
            challenge_cleanup_service:
                crate::services::challenge_issuance::ChallengeCleanupService::new(
                    db::challenge_issuance_repository::PostgresChallengeRepository::new(
                        Arc::clone(&abuse),
                    ),
                ),
            sasl_login_abuse_service: crate::services::login_abuse::SaslLoginAbuseService::new(
                db::login_abuse_repository::PostgresSaslLoginAbuseRepository::new(Arc::clone(
                    &abuse,
                )),
            ),
            passkey_login_abuse_service: Arc::new(
                crate::services::login_abuse::PasskeyLoginAbuseService::new(
                    db::login_abuse_repository::PostgresPasskeyLoginAbuseRepository::new(
                        Arc::clone(&abuse),
                    ),
                ),
            ),
            abuse_key_deployment,
            started_at,
            process_started_at,
            tls_context: crate::security::tls::TlsContext::new(tls),
            federation_write_policy,
            registration_closed,
            federation_runtime_policy: Arc::new(arc_swap::ArcSwap::from_pointee(
                RuntimeFederationPolicy {
                    blacklist: runtime_blacklist.into_iter().collect(),
                    whitelist: runtime_whitelist.into_iter().collect(),
                },
            )),
            service_shutdown: Arc::new(std::sync::OnceLock::new()),
            runtime_control_liveness: Arc::new(()),
            workers: crate::platform::workers::WorkerRegistry::new(),
        });
        state.worker_registry().register_observer(
            "session-cleanup",
            crate::platform::workers::WorkerCriticality::Restartable,
        );
        db::authority_listener::start_database_authority_listener(
            state.sm_service().authority_broker(),
            state.mix_service().delivery_wake_broker(),
            state.cluster.account_revocation_notify(),
            state.cluster.direct_spool_notify(),
            sm_authority_connect_options,
            Arc::clone(state.worker_registry()),
            worker_cancel.clone(),
        );
        if state
            .config
            .xmpp_extensions
            .enabled(northstar_xep_0115::XEP_ID)
        {
            crate::xmpp::protocol::caps::start_caps_effect_dispatcher(
                Arc::new(state.caps_effect_dispatch_context()),
                Arc::clone(state.worker_registry()),
                worker_cancel.clone(),
            );
        }
        crate::services::session_cleanup::start_sm_suspension_recovery(
            Arc::new(state.sm_suspension_context()),
            Arc::clone(state.worker_registry()),
            Arc::clone(&state.sm_suspension_recovery),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::mix::start_mix_presence_recovery(
            Arc::new(state.mix_presence_recovery_context()),
            Arc::clone(state.worker_registry()),
            mix_presence_recovery.0,
            mix_presence_recovery.1,
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::mix::start_mix_iq_relay_expiry(
            Arc::new(state.mix_iq_relay_expiry_context()),
            Arc::clone(state.worker_registry()),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::mix::start_mix_delivery_outbox(
            Arc::new(state.mix_outbox_context()),
            Arc::clone(state.worker_registry()),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::pubsub::start_pubsub_digest_delivery(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::pubsub::start_pubsub_event_outbox_delivery(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::cluster::start_muc_outbox_delivery(Arc::clone(&state), worker_cancel.clone());
        assert!(state
            .locked_muc_expiry_context
            .set(Arc::new(
                locked_muc_expiry::LockedMucExpiryContext::from_state(&state)
            ))
            .is_ok());
        Self::start_locked_muc_expiry(Arc::clone(&state), worker_cancel.clone());
        // Both durable policy snapshots deliberately share the single reserved
        // control-plane connection.  They must therefore be refreshed by one
        // sequential worker: two independently supervised workers can turn a
        // CPU-saturated process into its own connection-pool contention.
        Self::start_runtime_control_refresh(
            Arc::clone(&state),
            runtime_control_connection,
            worker_cancel,
        );
        Ok(state)
    }
}
