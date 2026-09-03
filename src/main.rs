#![forbid(unsafe_code)]

mod abuse;
mod account_recovery;
mod api;
mod auth;
mod bosh;
mod cluster;
mod cluster_security;
mod components;
mod config;
mod connection_actors;
mod crl;
mod db;
mod error;
mod identity_audit;
mod jid;
mod mam_pubsub_parsing;
mod metrics;
mod operation_runtime;
mod outbound;
mod password_work;
mod pie;
mod retention;
mod s2s;
mod services;
mod state;
mod storage;
mod tls;
mod transport_parsing;
mod upload_worker;
mod workers;
mod xmpp;

use anyhow::{Context, Result};
use config::Config;
use futures::FutureExt;
use sqlx::postgres::PgPoolOptions;
use state::AppState;
use std::{any::Any, future::Future, panic::AssertUnwindSafe, path::PathBuf, sync::Arc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use workers::{WorkerCriticality, WorkerMode};
use zeroize::Zeroizing;

const ABUSE_KEY_AUTHORITY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const CAPACITY_AUTHORITY_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const SERVICE_TASK_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const SERVICE_TASK_ABORT_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

const fn version_line() -> &'static str {
    concat!("xmpp-server ", env!("CARGO_PKG_VERSION"))
}

enum ServiceTaskExit {
    Finished {
        name: &'static str,
        result: Result<()>,
    },
    Panicked {
        name: &'static str,
        message: String,
    },
}

#[derive(Debug, Default)]
struct ServiceTaskDrainReport {
    joined: usize,
    aborted: usize,
    failures: Vec<String>,
}

fn spawn_service_task<F>(tasks: &mut JoinSet<ServiceTaskExit>, name: &'static str, future: F)
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    tasks.spawn(async move {
        match AssertUnwindSafe(future).catch_unwind().await {
            Ok(result) => ServiceTaskExit::Finished { name, result },
            Err(panic) => ServiceTaskExit::Panicked {
                name,
                message: panic_payload(panic),
            },
        }
    });
}

struct MigrationEnvironment {
    database_url: Zeroizing<String>,
    domain: String,
    allow_unsafe_role_for_development: bool,
}

fn migration_environment_from_values(
    database_url: Option<String>,
    database_url_file: Option<PathBuf>,
    domain: Option<String>,
    allow_unsafe_role_for_development: Option<String>,
) -> Result<MigrationEnvironment> {
    anyhow::ensure!(
        database_url.is_none() || database_url_file.is_none(),
        "set only one of MIGRATOR_DATABASE_URL and MIGRATOR_DATABASE_URL_FILE"
    );
    let database_url = match (database_url, database_url_file) {
        (Some(value), None) => Zeroizing::new(value),
        (None, Some(path)) => Zeroizing::new(config::read_secret_file(
            &path,
            "MIGRATOR_DATABASE_URL_FILE",
        )?),
        (None, None) => anyhow::bail!(
            "set MIGRATOR_DATABASE_URL_FILE (preferred) or MIGRATOR_DATABASE_URL for `xmpp-server migrate`"
        ),
        (Some(_), Some(_)) => unreachable!("exclusive migrator URL inputs checked above"),
    };
    anyhow::ensure!(
        !database_url.trim().is_empty(),
        "migrator database URL must not be empty"
    );
    let domain = domain.context("XMPP_DOMAIN is required for `xmpp-server migrate`")?;
    let domain = jid::prepare_domainpart(domain.trim()).context("XMPP_DOMAIN is invalid")?;
    let allow_unsafe_role_for_development = match allow_unsafe_role_for_development.as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => anyhow::bail!(
            "MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT must be exactly true or false"
        ),
    };
    if allow_unsafe_role_for_development {
        anyhow::ensure!(
            domain == "localhost"
                || domain.ends_with(".localhost")
                || domain.ends_with(".test"),
            "MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT is restricted to reserved development domains"
        );
    }
    Ok(MigrationEnvironment {
        database_url,
        domain,
        allow_unsafe_role_for_development,
    })
}

async fn run_migrations() -> Result<()> {
    let environment = migration_environment_from_values(
        std::env::var("MIGRATOR_DATABASE_URL").ok(),
        std::env::var_os("MIGRATOR_DATABASE_URL_FILE").map(PathBuf::from),
        std::env::var("XMPP_DOMAIN").ok(),
        std::env::var("MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT").ok(),
    )?;
    let pool_options = PgPoolOptions::new().max_connections(2).min_connections(0);
    let pool_options = if environment.allow_unsafe_role_for_development {
        pool_options
    } else {
        db::pin_public_application_schema(pool_options)
    };
    let pool = pool_options
        .connect(environment.database_url.as_str())
        .await
        .context("could not connect to PostgreSQL with the migrator role")?;
    if environment.allow_unsafe_role_for_development {
        db::attest_development_database_is_loopback(&pool).await?;
        eprintln!(
            "warning: explicit loopback development override skips PostgreSQL migrator role attestation"
        );
    } else {
        db::attest_migrator_role(&pool).await?;
    }
    db::migrate_for_domain(&pool, &environment.domain).await?;
    pool.close().await;
    Ok(())
}

fn install_crypto_provider() -> Result<()> {
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("could not install the rustls AWS-LC crypto provider"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(
        arguments.first().map(String::as_str),
        Some("--version" | "-V")
    ) {
        if arguments.len() != 1 {
            anyhow::bail!("usage: xmpp-server --version");
        }
        println!("{}", version_line());
        return Ok(());
    }
    if arguments.first().map(String::as_str) == Some("--healthcheck") {
        let address = arguments
            .get(1)
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:8080".into());
        if arguments.len() > 2 {
            anyhow::bail!("usage: xmpp-server --healthcheck [IP:PORT]");
        }
        return container_healthcheck(&address).await;
    }

    // SQLx may need TLS before normal logging/configuration exists (explicit
    // migrations and the read-only identity audit both connect early).
    install_crypto_provider()?;

    // Hermetic integration/deployment environments can explicitly prevent a
    // developer .env file in the working directory from filling unset secret
    // variables. Normal foreground startup keeps the convenient default.
    if std::env::var("NORTHSTAR_DISABLE_DOTENV").as_deref() != Ok("true") {
        dotenvy::dotenv().ok();
    }
    if let Some(outcome) = identity_audit::maybe_run(&arguments).await? {
        return match outcome {
            identity_audit::AuditOutcome::Clean | identity_audit::AuditOutcome::Help => Ok(()),
            identity_audit::AuditOutcome::Dirty => anyhow::bail!(
                "identity audit found issues requiring operator review; the complete JSON report was written to stdout and the database was not modified"
            ),
        };
    }
    if arguments.first().map(String::as_str) == Some("migrate") {
        if arguments.len() != 1 {
            anyhow::bail!("usage: xmpp-server migrate");
        }
        return run_migrations().await;
    }
    let config = Config::from_env()?;
    let _log_guard = init_logging(&config)?;
    if config.invitation_policy_disabled_with_web_client {
        tracing::warn!(
            open_registration = config.open_registration,
            "invitation-only registration was resolved fail-closed because WEB_CLIENT_ENABLED=false; effective registration mode is closed"
        );
    }
    if arguments.first().map(String::as_str) == Some("pie") {
        return pie::run(&config, &arguments[1..]).await;
    }
    let pool_options = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .min_connections(config.database_min_connections);
    let pool_options = if config.database_allow_unsafe_role_for_development {
        pool_options
    } else {
        db::pin_public_application_schema(pool_options)
    };
    let pool = pool_options
        .connect(&config.database_url)
        .await
        .context("could not connect to PostgreSQL")?;
    if config.database_allow_unsafe_role_for_development {
        db::attest_development_database_is_loopback(&pool).await?;
        tracing::warn!(
            "explicit loopback development override skips PostgreSQL runtime role attestation"
        );
    } else {
        db::attest_runtime_role(&pool).await?;
    }
    db::verify_schema(&pool, &config.domain)
        .await
        .context("database schema verification failed")?;
    tokio::time::timeout(
        CAPACITY_AUTHORITY_QUERY_TIMEOUT,
        db::reconcile_deployment_capacity(
            &pool,
            db::DeploymentCapacityConfiguration::from_config(&config)?,
        ),
    )
    .await
    .context("deployment-wide capacity authority reconciliation timed out")??;
    if !config.scram_sha1_enabled {
        let removed = db::clear_scram_sha1_credentials(&pool).await?;
        if removed > 0 {
            tracing::info!(removed, "cleared disabled SCRAM-SHA-1 verifier material");
        }
    }
    db::ensure_bootstrap_admin(&pool, &config).await?;
    let components = components::registry();
    let (federation, federation_rx) =
        s2s::FederationRouter::channel(pool.clone(), &config, components.clone());
    let cancel = CancellationToken::new();
    let state = AppState::new(config, pool, federation, components, cancel.clone()).await?;
    state.install_service_shutdown(cancel.clone())?;

    let worker_registry = Arc::clone(state.worker_registry());
    if let Some(authority_identity) = state.abuse_key_deployment().cloned() {
        tracing::info!(
            poll_seconds = ABUSE_KEY_AUTHORITY_POLL_INTERVAL.as_secs(),
            query_timeout_seconds = ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT.as_secs(),
            "enabled fail-closed PostgreSQL anti-abuse key authority guard"
        );
        let authority_pool = state.pool.clone();
        let authority_cancel = cancel.clone();
        worker_registry.supervise(
            "abuse-key-deployment-authority",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            Some(ABUSE_KEY_AUTHORITY_POLL_INTERVAL.saturating_mul(2)),
            cancel.clone(),
            move |heartbeat| {
                let authority_pool = authority_pool.clone();
                let authority_identity = authority_identity.clone();
                let authority_cancel = authority_cancel.clone();
                async move {
                    let mut interval = tokio::time::interval(ABUSE_KEY_AUTHORITY_POLL_INTERVAL);
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tokio::select! {
                            _ = authority_cancel.cancelled() => return Ok(()),
                            _ = interval.tick() => {
                                let validation = tokio::time::timeout(
                                    ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT,
                                    db::validate_abuse_key_deployment(
                                        &authority_pool,
                                        &authority_identity,
                                    ),
                                ).await;
                                match validation {
                                    Ok(Ok(())) => heartbeat.ok(),
                                    Ok(Err(error)) => {
                                        heartbeat.error(&error);
                                        tracing::error!(
                                            ?error,
                                            poll_seconds = ABUSE_KEY_AUTHORITY_POLL_INTERVAL.as_secs(),
                                            "anti-abuse key authority diverged; cancelling every listener"
                                        );
                                        return Err(error).context(
                                            "PostgreSQL rejected this process's anti-abuse key generation",
                                        );
                                    }
                                    Err(error) => {
                                        heartbeat.error(&error);
                                        tracing::error!(
                                            ?error,
                                            query_timeout_seconds = ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT.as_secs(),
                                            "anti-abuse key authority could not be verified in time; cancelling every listener"
                                        );
                                        anyhow::bail!(
                                            "PostgreSQL anti-abuse key authority validation exceeded the {} second fail-closed timeout",
                                            ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT.as_secs(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            },
        );
    }
    let capacity_state = Arc::clone(&state);
    let capacity_cancel = cancel.clone();
    let capacity_interval =
        std::time::Duration::from_secs(state.config.capacity_session_heartbeat_seconds);
    worker_registry.supervise(
        "deployment-capacity-session-leases",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        Some(capacity_interval.saturating_mul(2)),
        cancel.clone(),
        move |heartbeat| {
            let capacity_state = Arc::clone(&capacity_state);
            let capacity_cancel = capacity_cancel.clone();
            async move {
                let mut interval = tokio::time::interval(capacity_interval);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = capacity_cancel.cancelled() => return Ok(()),
                        _ = interval.tick() => {
                            let local = capacity_state.sessions.iter()
                                .filter(|session| session.routable.load(std::sync::atomic::Ordering::Acquire))
                                .map(|session| (session.connection_id, session.disconnect.clone()))
                                .collect::<Vec<_>>();
                            let ids = local.iter().map(|(id, _)| *id).collect::<Vec<_>>();
                            let refreshed = tokio::select! {
                                _ = capacity_cancel.cancelled() => return Ok(()),
                                result = tokio::time::timeout(
                                    CAPACITY_AUTHORITY_QUERY_TIMEOUT,
                                    db::refresh_live_session_leases(
                                        &capacity_state.pool,
                                        &ids,
                                        capacity_state.config.capacity_session_lease_seconds,
                                    ),
                                ) => result
                                    .context("deployment live-session lease refresh timed out")?
                                    .context("could not refresh deployment live-session capacity leases")?,
                            };
                            for (connection_id, disconnect) in local {
                                if !refreshed.contains(&connection_id) {
                                    capacity_state.metrics.capacity_session_lease_losses_total.fetch_add(
                                        1,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                    tracing::error!(%connection_id, "committed route lost its PostgreSQL capacity lease; disconnecting fail closed");
                                    disconnect.cancel();
                                }
                            }
                            tokio::select! {
                                _ = capacity_cancel.cancelled() => return Ok(()),
                                result = tokio::time::timeout(
                                    CAPACITY_AUTHORITY_QUERY_TIMEOUT,
                                    db::cleanup_expired_live_session_leases(&capacity_state.pool, 1024),
                                ) => result
                                    .context("deployment live-session lease cleanup timed out")?
                                    .context("could not reap expired deployment live-session capacity leases")?,
                            };
                            heartbeat.ok();
                        }
                    }
                }
            }
        },
    );
    let bg_state = state.clone();
    let bg_cancel = cancel.clone();
    worker_registry.supervise(
        "background-maintenance",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        Some(std::time::Duration::from_secs(180)),
        cancel.clone(),
        move |heartbeat| {
            let bg_state = Arc::clone(&bg_state);
            let bg_cancel = bg_cancel.clone();
            async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                _ = bg_cancel.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    let failures_before = bg_state
                        .metrics
                        .background_maintenance_failures_total
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if let Err(error) = bg_state.abuse.cleanup_challenges().await {
                        tracing::warn!(?error, "anti-abuse cleanup failed");
                        bg_state.metrics.background_maintenance_failures_total.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    match db::purge_resolved_moderation_batch(
                        &bg_state.pool,
                        bg_state.config.moderation_retention_days,
                        bg_state.config.retention_cleanup_batch_size,
                    ).await {
                        Ok(deleted) if deleted > 0 => {
                            bg_state.metrics.retention_moderation_cases_deleted_total.fetch_add(
                                deleted,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            tracing::info!(
                                deleted,
                                retention_days = bg_state.config.moderation_retention_days,
                                "expired resolved moderation cases and evidence"
                            );
                        },
                        Ok(_) => {},
                        Err(error) => {
                            tracing::error!(?error, "moderation retention cleanup failed");
                            bg_state.metrics.background_maintenance_failures_total.fetch_add(
                                1,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                        }
                    }
                    if let Err(e) = db::cleanup_expired_sessions(&bg_state.pool).await {
                        tracing::error!("failed to cleanup expired sessions: {e}");
                        bg_state.metrics.background_maintenance_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Err(e) = db::cleanup_expired_idempotency(&bg_state.pool, 1000).await {
                        tracing::error!("failed to cleanup expired API idempotency records: {e}");
                        bg_state.metrics.background_maintenance_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Err(e) = db::cleanup_fast_tokens(&bg_state.pool).await {
                        tracing::error!("failed to cleanup expired FAST tokens: {e}");
                        bg_state.metrics.background_maintenance_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Err(e) =
                        db::cleanup_expired_user_agent_login_epoch_stages(&bg_state.pool, 1000)
                            .await
                    {
                        tracing::error!("failed to cleanup staged user-agent login epochs: {e}");
                        bg_state
                            .metrics
                            .background_maintenance_failures_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Err(e) = bg_state.admin_command_service().cleanup_sessions().await {
                        tracing::error!("failed to cleanup expired admin command sessions: {e}");
                        bg_state.metrics.background_maintenance_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    match bg_state.cleanup_expired_sm_sessions().await {
                        Ok(expired) => {
                            if expired > 0 {
                                tracing::info!(expired, "tore down expired SM resume sessions");
                            }
                        }
                        Err(e) => {
                            tracing::error!("failed to cleanup expired SM resume sessions: {e}");
                            bg_state.metrics.background_maintenance_failures_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    let now = std::time::Instant::now();
                    bg_state.caps_cache().sweep(now);
                    let failures_after = bg_state
                        .metrics
                        .background_maintenance_failures_total
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if failures_after == failures_before {
                        heartbeat.ok();
                    } else {
                        heartbeat.error("one or more background maintenance operations failed");
                    }
                }
            }
                }
            }
        },
    );

    let deletion_state = Arc::clone(&state);
    let deletion_cancel = cancel.clone();
    worker_registry.supervise(
        "account-deletion-recovery",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        // One SM teardown/storage reconciliation can legitimately consume most
        // of the 900-second recovery lease. Do not abort a healthy attempt.
        Some(std::time::Duration::from_secs(1_200)),
        cancel.clone(),
        move |heartbeat| {
            account_recovery::serve(
                Arc::clone(&deletion_state),
                deletion_cancel.clone(),
                heartbeat,
            )
        },
    );

    if state.config.upload_mode.keeps_storage_runtime() {
        let upload_state = Arc::clone(&state);
        let upload_cancel = cancel.clone();
        worker_registry.supervise(
            "upload-storage-reconciliation",
            // Namespace drift can make a node write or delete objects in the
            // wrong bucket/prefix. The worker treats a proven authority mismatch
            // as fatal; transient inability to query PostgreSQL skips object I/O
            // and reports an unhealthy heartbeat without returning.
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            // One provider operation may legitimately occupy 180 seconds. Silence
            // detection therefore includes a margin and cannot kill a healthy
            // critical worker mid-operation.
            Some(std::time::Duration::from_secs(600)),
            cancel.clone(),
            move |heartbeat| {
                let upload_state = Arc::clone(&upload_state);
                let upload_cancel = upload_cancel.clone();
                async move { upload_worker::serve(upload_state, upload_cancel, heartbeat).await }
            },
        );
    }

    let retention_state = Arc::clone(&state);
    let retention_cancel = cancel.clone();
    let retention_max_silence = std::time::Duration::from_secs(
        state
            .config
            .retention_cleanup_interval_seconds
            .saturating_mul(2)
            .saturating_add(60),
    );
    worker_registry.supervise(
        "archive-retention",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        Some(retention_max_silence),
        cancel.clone(),
        move |heartbeat| {
            let retention_state = Arc::clone(&retention_state);
            let retention_cancel = retention_cancel.clone();
            async move { retention::serve(retention_state, retention_cancel, heartbeat).await }
        },
    );

    let mut service_tasks = JoinSet::new();
    spawn_service_task(
        &mut service_tasks,
        "XMPP",
        xmpp::serve_tcp(state.clone(), cancel.clone()),
    );
    spawn_service_task(
        &mut service_tasks,
        "XMPPS",
        xmpp::serve_xmpps_tcp(state.clone(), cancel.clone()),
    );
    spawn_service_task(
        &mut service_tasks,
        "S2S",
        s2s::serve(state.clone(), federation_rx, cancel.clone()),
    );
    spawn_service_task(
        &mut service_tasks,
        "S2S TLS",
        s2s::serve_s2s_tls(state.clone(), cancel.clone()),
    );
    spawn_service_task(
        &mut service_tasks,
        "external component",
        components::serve(state.clone(), cancel.clone()),
    );
    spawn_service_task(
        &mut service_tasks,
        "durable operation worker",
        operation_runtime::serve(state.clone(), cancel.clone()),
    );

    // Credential-generation and exact-connection cleanup is a security
    // authority, not ordinary administrator background work. Keep it on an
    // independently supervised worker so a large broadcast cannot delay a
    // committed revocation. One attempt owns a 60-second renewable database
    // lease; the watchdog includes a bounded margin for delivery and cleanup.
    let admin_cleanup_state = Arc::clone(&state);
    let admin_cleanup_cancel = cancel.clone();
    worker_registry.supervise(
        "admin-session-cleanup",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        Some(std::time::Duration::from_secs(90)),
        cancel.clone(),
        move |heartbeat| {
            operation_runtime::serve_admin_session_cleanup(
                Arc::clone(&admin_cleanup_state),
                admin_cleanup_cancel.clone(),
                heartbeat,
            )
        },
    );

    if state.cluster.is_enabled() {
        let state_pubsub = state.clone();
        let pubsub_cancel = cancel.clone();
        worker_registry.supervise(
            "redis-pubsub",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            Some(std::time::Duration::from_secs(45)),
            cancel.clone(),
            move |heartbeat| {
                cluster::run_pubsub_listener(
                    Arc::clone(&state_pubsub),
                    pubsub_cancel.clone(),
                    heartbeat,
                )
            },
        );

        let state_maintenance = state.clone();
        let maintenance_cancel = cancel.clone();
        worker_registry.supervise(
            "cluster-maintenance",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            Some(std::time::Duration::from_secs(90)),
            cancel.clone(),
            move |heartbeat| {
                let state_maintenance = Arc::clone(&state_maintenance);
                let maintenance_cancel = maintenance_cancel.clone();
                async move {
                    cluster::run_maintenance(state_maintenance, maintenance_cancel, heartbeat).await
                }
            },
        );

        let state_policy = state.clone();
        let policy_cancel = cancel.clone();
        worker_registry.supervise(
            "cluster-failure-policy",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            Some(std::time::Duration::from_secs(15)),
            cancel.clone(),
            move |heartbeat| {
                cluster::run_failure_supervisor(
                    Arc::clone(&state_policy),
                    policy_cancel.clone(),
                    heartbeat,
                )
            },
        );
    }

    let shutdown_state = state.clone();
    spawn_service_task(
        &mut service_tasks,
        "metrics",
        api::serve_metrics(state.clone(), cancel.clone()),
    );
    spawn_service_task(
        &mut service_tasks,
        "HTTP",
        api::serve(state.clone(), cancel.clone()),
    );
    if state.config.web_admin_enabled {
        spawn_service_task(
            &mut service_tasks,
            "Web administration",
            api::serve_administration(state, cancel.clone()),
        );
    }

    let mut shutdown_error = None;
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            shutdown_error = worker_registry
                .critical_failure()
                .map(anyhow::Error::msg);
        },
        _ = api::shutdown_signal() => {
            tracing::info!("shutdown signal received; stopping listeners and draining HTTP requests");
        },
        result = service_tasks.join_next() => {
            shutdown_error = Some(unexpected_service_task_exit(result));
        },
    }

    // Close connection admission before signalling any child. Every accepted
    // transport is now owned by the bounded registry and must finalize before
    // the abort-and-reap deadline below.
    shutdown_state.connection_actors().begin_shutdown();
    shutdown_state.cluster.begin_shutdown();
    cancel.cancel();
    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        shutdown_state.cluster.quiesce_publication(),
    )
    .await
    {
        Ok(_publication_fence) => {
            if let Err(error) = shutdown_state
                .cluster
                .release_instance_authority(&shutdown_state.pool)
                .await
            {
                tracing::warn!(
                    ?error,
                    "could not audit the final cluster node-instance lease release"
                );
            }
        }
        Err(_) => tracing::error!(
            "signed cluster publications did not drain; leaving the instance fenced until its database lease expires"
        ),
    }
    let notified_muc_occupants = shutdown_state.notify_muc_system_shutdown().await;
    if notified_muc_occupants > 0 {
        tracing::info!(
            notified_muc_occupants,
            "sent XEP-0045 system-shutdown presence"
        );
    }
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let (worker_report, service_report, connection_report) = tokio::join!(
        worker_registry.shutdown_and_join(&cancel, SERVICE_TASK_DRAIN_TIMEOUT),
        drain_service_tasks(&mut service_tasks, SERVICE_TASK_DRAIN_TIMEOUT),
        shutdown_state
            .connection_actors()
            .join_or_abort(SERVICE_TASK_DRAIN_TIMEOUT, SERVICE_TASK_ABORT_DRAIN_TIMEOUT,),
    );
    if !worker_report.is_clean() {
        let error = anyhow::anyhow!("background worker shutdown was incomplete: {worker_report:?}");
        tracing::error!(?error);
        shutdown_error.get_or_insert(error);
    }
    if service_report.aborted > 0 || !service_report.failures.is_empty() {
        let error = anyhow::anyhow!("listener shutdown was incomplete: {service_report:?}");
        tracing::error!(?error);
        shutdown_error.get_or_insert(error);
    }
    if connection_report.remaining > 0 {
        let error =
            anyhow::anyhow!("connection actor shutdown was incomplete: {connection_report:?}");
        tracing::error!(?error);
        shutdown_error.get_or_insert(error);
    }
    tracing::info!(
        worker_supervisors_joined = worker_report.joined,
        service_tasks_joined = service_report.joined,
        connection_actors_aborted = connection_report.aborted,
        "shutdown complete"
    );

    match shutdown_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn unexpected_service_task_exit(
    result: Option<std::result::Result<ServiceTaskExit, tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok(ServiceTaskExit::Finished {
            name,
            result: Ok(()),
        })) => anyhow::anyhow!("{name} task exited unexpectedly before service shutdown"),
        Some(Ok(ServiceTaskExit::Finished {
            name,
            result: Err(error),
        })) => error.context(format!("{name} task failed")),
        Some(Ok(ServiceTaskExit::Panicked { name, message })) => {
            anyhow::anyhow!("{name} task panicked: {message}")
        }
        Some(Err(error)) => anyhow::Error::from(error).context("unnamed service task failed"),
        None => anyhow::anyhow!("every service task exited unexpectedly"),
    }
}

async fn drain_service_tasks(
    tasks: &mut JoinSet<ServiceTaskExit>,
    grace: std::time::Duration,
) -> ServiceTaskDrainReport {
    let mut report = ServiceTaskDrainReport::default();
    let deadline = tokio::time::Instant::now() + grace;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok(ServiceTaskExit::Finished { result: Ok(()), .. }))) => report.joined += 1,
            Ok(Some(Ok(ServiceTaskExit::Finished {
                name,
                result: Err(error),
            }))) => {
                report.joined += 1;
                report
                    .failures
                    .push(format!("{name} task failed during shutdown: {error:#}"));
            }
            Ok(Some(Ok(ServiceTaskExit::Panicked { name, message }))) => {
                report.joined += 1;
                report
                    .failures
                    .push(format!("{name} task panicked during shutdown: {message}"));
            }
            Ok(Some(Err(error))) => report
                .failures
                .push(format!("service task join failed during shutdown: {error}")),
            Ok(None) => break,
            Err(_) => {
                report.aborted = tasks.len();
                tasks.abort_all();
                break;
            }
        }
    }
    if !tasks.is_empty() {
        let deadline = tokio::time::Instant::now() + SERVICE_TASK_ABORT_DRAIN_TIMEOUT;
        while !tasks.is_empty() {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(error))) if error.is_cancelled() => {}
                Ok(Some(Err(error))) => report
                    .failures
                    .push(format!("service task failed after abort: {error}")),
                Ok(None) => break,
                Err(_) => {
                    report.failures.push(format!(
                        "{} service tasks did not terminate after abort",
                        tasks.len()
                    ));
                    tasks.abort_all();
                    break;
                }
            }
        }
    }
    report
}

fn panic_payload(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

#[cfg(test)]
async fn unexpected_task_exit(
    name: &'static str,
    task: tokio::task::JoinHandle<Result<()>>,
) -> Result<()> {
    match task.await {
        Ok(Ok(())) => anyhow::bail!("{name} task exited unexpectedly before service shutdown"),
        Ok(Err(error)) => Err(error).with_context(|| format!("{name} task failed")),
        Err(error) => Err(error).with_context(|| format!("{name} task panicked")),
    }
}

async fn container_healthcheck(address: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let address: std::net::SocketAddr = address
        .parse()
        .context("healthcheck address must be a literal IP:PORT")?;
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(address),
    )
    .await
    .context("healthcheck connection timed out")?
    .context("healthcheck connection failed")?;
    stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .context("healthcheck request failed")?;
    let response = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut response = Vec::with_capacity(128);
        let mut chunk = [0_u8; 128];
        loop {
            let bytes = stream
                .read(&mut chunk)
                .await
                .context("healthcheck response failed")?;
            if bytes == 0 {
                anyhow::bail!("healthcheck response ended before the HTTP status line");
            }
            response.extend_from_slice(&chunk[..bytes]);
            if response.windows(2).any(|bytes| bytes == b"\r\n") {
                return Ok::<_, anyhow::Error>(response);
            }
            if response.len() >= 512 {
                anyhow::bail!("healthcheck HTTP status line is too long");
            }
        }
    })
    .await
    .context("healthcheck response timed out")??;
    if response.starts_with(b"HTTP/1.1 200 ") || response.starts_with(b"HTTP/1.0 200 ") {
        Ok(())
    } else {
        anyhow::bail!("readiness endpoint did not return HTTP 200")
    }
}

fn init_logging(config: &Config) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let rotation = match config.log_rotation.to_lowercase().as_str() {
        "hourly" => tracing_appender::rolling::Rotation::HOURLY,
        "minutely" => tracing_appender::rolling::Rotation::MINUTELY,
        "never" => tracing_appender::rolling::Rotation::NEVER,
        _ => tracing_appender::rolling::Rotation::DAILY,
    };

    let file_appender = tracing_appender::rolling::Builder::new()
        .rotation(rotation)
        .filename_prefix("server.log")
        .max_log_files(config.log_retention_files)
        .build(&config.log_dir)
        .context("failed to build rolling file appender")?;

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    if config.log_format.eq_ignore_ascii_case("json") {
        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_ansi(false);
        let console_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .with_ansi(false);
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .with(console_layer)
            .init();
    } else {
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false);
        let console_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .with(console_layer)
            .init();
    }

    Ok(Some(guard))
}

#[cfg(test)]
mod container_healthcheck_tests {
    use super::{
        container_healthcheck, drain_service_tasks, migration_environment_from_values,
        spawn_service_task, unexpected_task_exit, version_line,
    };
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn version_output_matches_the_cargo_package_version() {
        assert_eq!(
            version_line(),
            concat!("xmpp-server ", env!("CARGO_PKG_VERSION"))
        );
    }

    async fn endpoint(status: &'static str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 256];
            let bytes = stream.read(&mut request).await.unwrap();
            assert!(request[..bytes].starts_with(b"GET /readyz HTTP/1.1\r\n"));
            stream
                .write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .await
                .unwrap();
        });
        (address, task)
    }

    #[tokio::test]
    async fn container_probe_requires_the_readiness_endpoint_to_return_exactly_200() {
        let (address, server) = endpoint("200 OK").await;
        container_healthcheck(&address.to_string()).await.unwrap();
        server.await.unwrap();

        let (address, server) = endpoint("503 Service Unavailable").await;
        assert!(container_healthcheck(&address.to_string()).await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn container_probe_rejects_hostnames_and_malformed_addresses() {
        assert!(container_healthcheck("localhost:8080").await.is_err());
        assert!(container_healthcheck("127.0.0.1").await.is_err());
    }

    #[tokio::test]
    async fn successful_service_task_exit_is_an_error_with_its_name() {
        let error = unexpected_task_exit("test listener", tokio::spawn(async { Ok(()) }))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("test listener task exited unexpectedly"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn failed_service_task_preserves_its_error_and_context() {
        let error = unexpected_task_exit(
            "test listener",
            tokio::spawn(async { anyhow::bail!("injected listener failure") }),
        )
        .await
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("test listener task failed"), "{rendered}");
        assert!(rendered.contains("injected listener failure"), "{rendered}");
    }

    #[tokio::test]
    async fn panicked_service_task_preserves_join_error_and_context() {
        let error = unexpected_task_exit(
            "test listener",
            tokio::spawn(async { panic!("injected listener panic") }),
        )
        .await
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("test listener task panicked"),
            "{rendered}"
        );
        assert!(rendered.contains("injected listener panic"), "{rendered}");
    }

    #[tokio::test]
    async fn service_task_drain_joins_completed_tasks_without_leaking_handles() {
        let mut tasks = tokio::task::JoinSet::new();
        spawn_service_task(&mut tasks, "test listener", async { Ok(()) });

        let report = drain_service_tasks(&mut tasks, std::time::Duration::from_secs(1)).await;

        assert_eq!(report.joined, 1);
        assert_eq!(report.aborted, 0);
        assert!(report.failures.is_empty(), "{report:?}");
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn service_task_drain_aborts_and_reaps_a_non_cooperative_task() {
        let mut tasks = tokio::task::JoinSet::new();
        spawn_service_task(&mut tasks, "stuck listener", async {
            std::future::pending::<anyhow::Result<()>>().await
        });

        let report = drain_service_tasks(&mut tasks, std::time::Duration::from_millis(10)).await;

        assert_eq!(report.joined, 0);
        assert_eq!(report.aborted, 1);
        assert!(report.failures.is_empty(), "{report:?}");
        assert!(tasks.is_empty());
    }

    #[test]
    fn migration_environment_is_minimal_and_requires_an_exclusive_url() {
        let environment = migration_environment_from_values(
            Some("postgresql://migrator@db/xmpp".into()),
            None,
            Some("Example.COM".into()),
            None,
        )
        .unwrap();
        assert_eq!(environment.domain, "example.com");
        assert_eq!(
            environment.database_url.as_str(),
            "postgresql://migrator@db/xmpp"
        );
        assert!(
            migration_environment_from_values(None, None, Some("example.test".into()), None)
                .is_err()
        );
        assert!(migration_environment_from_values(
            Some("postgresql://migrator@db/xmpp".into()),
            Some(PathBuf::from("unused")),
            Some("example.test".into()),
            None,
        )
        .is_err());
        assert!(migration_environment_from_values(
            Some(String::new()),
            None,
            Some("example.test".into()),
            None,
        )
        .is_err());
        assert!(migration_environment_from_values(
            Some("postgresql://migrator@db/xmpp".into()),
            None,
            None,
            None,
        )
        .is_err());
        assert!(
            migration_environment_from_values(
                Some("postgresql://owner@127.0.0.1/xmpp".into()),
                None,
                Some("fixture.localhost".into()),
                Some("true".into()),
            )
            .unwrap()
            .allow_unsafe_role_for_development
        );
        assert!(migration_environment_from_values(
            Some("postgresql://owner@127.0.0.1/xmpp".into()),
            None,
            Some("example.com".into()),
            Some("true".into()),
        )
        .is_err());
        assert!(migration_environment_from_values(
            Some("postgresql://owner@127.0.0.1/xmpp".into()),
            None,
            Some("fixture.test".into()),
            Some("TRUE".into()),
        )
        .is_err());
    }
}
