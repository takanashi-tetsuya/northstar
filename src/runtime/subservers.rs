//! Independent process roles over the existing PostgreSQL authority.
//!
//! The core is the sole owner of live sessions and transport delivery. The
//! maintenance process receives only a retention policy, a bounded database
//! pool and metrics; it never constructs ServerNode or loads protocol secrets.

use anyhow::{Context, Result};
use northstar_config::maintenance::MaintenanceConfig;
use northstar_operations_application::maintenance_process::supervise_maintenance;
use northstar_operations_application::retention_worker::RetentionContext;
use northstar_operations_postgres::maintenance_ownership;
use northstar_runtime::workers::WorkerCriticality;
use northstar_runtime::workers::WorkerMode;
use northstar_runtime::workers::WorkerRegistry;
use northstar_telemetry::metrics::Metrics;
use sqlx::{postgres::PgConnectOptions, PgPool};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub(crate) const MAINTENANCE_POOL_MAX_CONNECTIONS: u32 = 3;
pub(crate) const MAX_CORE_PRIMARY_CONNECTIONS: u32 =
    northstar_config::DATABASE_MAX_CONNECTIONS_LIMIT - MAINTENANCE_POOL_MAX_CONNECTIONS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessRole {
    Standalone,
    Core,
    Maintenance,
}

impl ProcessRole {
    pub(crate) fn parse(arguments: &[String]) -> Result<Self> {
        match arguments
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            [] | ["serve", "standalone"] => Ok(Self::Standalone),
            ["serve", "core"] => Ok(Self::Core),
            ["serve", "maintenance"] => Ok(Self::Maintenance),
            _ => {
                anyhow::bail!("usage: xmpp-server [serve standalone|core|maintenance]; see --help")
            }
        }
    }

    pub(crate) fn embeds_retention(self) -> bool {
        self == Self::Standalone
    }
}

pub(crate) fn print_inventory() -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": 1,
            "database_model": "shared-postgresql",
            "processes": [
                {"role":"core", "command":["serve","core"], "owns":["client-transports","federation","live-sessions","realtime-delivery","public-http","administration","session-bound-recovery","upload-storage"]},
                {"role":"maintenance", "command":["serve","maintenance"], "owns":["archive-retention","completed-retraction-retention","expired-governance-artifacts","expired-pubsub-subscriptions"], "public_listeners":false}
            ],
            "compatibility_command":["serve","standalone"]
        }))?
    );
    Ok(())
}

/// Exclusive per-schema ownership survives neither connection loss nor process
/// exit. Different isolated test schemas do not contend on this lock.
pub(crate) async fn claim_maintenance(
    pool: &PgPool,
) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
    let mut connection = pool
        .acquire()
        .await
        .context("could not reserve maintenance ownership connection")?;
    claim_maintenance_on_connection(&mut connection).await?;
    Ok(connection)
}

/// Standalone uses its already-reserved runtime-control connection, whose
/// critical worker cancels the process on failure. Maintenance probes its own
/// exact connection. This startup guard has bounded loss detection; it is not
/// a transaction fence for work already submitted on another connection.
pub(crate) async fn claim_maintenance_on_connection(
    connection: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
) -> Result<()> {
    maintenance_ownership::claim_exact(connection).await
}

pub(crate) async fn run_maintenance() -> Result<()> {
    let mut config = MaintenanceConfig::from_env()?;
    let url = config.take_database_url()?;
    let (console, console_guard) = northstar_telemetry::logging::console(std::io::stdout());
    let _log_guard = northstar_telemetry::logging::LogGuards::new(vec![console_guard]);
    tracing_subscriber::fmt()
        .with_writer(console)
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init()
        .map_err(|_| anyhow::anyhow!("could not initialize maintenance logging"))?;

    // This budget includes the dedicated ownership/health connection. No
    // migrator, administrator-command or runtime-control pool is constructed.
    let options = northstar_postgres::pool::options()
        .max_connections(MAINTENANCE_POOL_MAX_CONNECTIONS)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(5));
    let options = if config.database_allow_unsafe_role_for_development {
        options
    } else {
        northstar_postgres::role_attestation::pin_public_application_schema(options)
    };
    let connect_options = PgConnectOptions::from_str(&url)
        .map_err(|_| anyhow::anyhow!("invalid maintenance PostgreSQL URL"))?
        .application_name("northstar-maintenance")
        .options([
            ("statement_timeout", "30s"),
            ("lock_timeout", "3s"),
            ("idle_in_transaction_session_timeout", "30s"),
        ]);
    let pool = options
        .connect_with(connect_options)
        .await
        .context("maintenance PostgreSQL connection failed")?;
    if config.database_allow_unsafe_role_for_development {
        northstar_postgres::role_attestation::attest_development_database_is_loopback(&pool)
            .await?;
    } else {
        northstar_postgres::role_attestation::attest_runtime_role(&pool).await?;
    }
    northstar_postgres::schema::verify_schema(&pool, &config.xmpp_domain)
        .await
        .context("maintenance schema verification failed")?;
    let ownership = claim_maintenance(&pool).await?;
    let listener = TcpListener::bind(config.maintenance_bind)
        .await
        .context("maintenance health listener bind failed")?;
    let cancel = CancellationToken::new();
    let workers = WorkerRegistry::new();
    let metrics = Arc::new(Metrics::default());
    let policy = config.policy();
    let silence = policy.max_silence();
    let retention = Arc::new(RetentionContext::new(
        northstar_workflows::maintenance_repository::PostgresMaintenanceRepository::new(
            pool.clone(),
        ),
        policy,
        northstar_operations_application::retention_worker::RetentionCounters::from_metrics(
            &metrics,
        ),
    ));
    let retention_readiness = retention.readiness();
    let worker_cancel = cancel.clone();
    workers.supervise(
        "archive-retention",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        Some(silence),
        cancel.clone(),
        move |heartbeat| {
            northstar_operations_application::retention_worker::serve_context(
                Arc::clone(&retention),
                worker_cancel.clone(),
                heartbeat,
            )
        },
    );
    let subscriptions = Arc::new(
        northstar_pubsub_application::subscription_cleanup::SubscriptionCleanupContext::new(
            northstar_pubsub_postgres::subscription_cleanup::PostgresSubscriptionCleanupRepository::new(
                pool.clone(),
            ),
            Arc::clone(&metrics.subscription_cleanup),
        ),
    );
    let subscription_readiness = subscriptions.readiness();
    let subscription_cancel = cancel.clone();
    workers.supervise(
        "pubsub-subscription-cleanup",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        Some(northstar_pubsub_application::subscription_cleanup::MAX_SILENCE),
        cancel.clone(),
        move |heartbeat| {
            northstar_pubsub_application::subscription_cleanup::serve_context(
                Arc::clone(&subscriptions),
                subscription_cancel.clone(),
                heartbeat,
            )
        },
    );
    workers.register_observer("maintenance-ownership", WorkerCriticality::Critical);
    workers.observer_ok("maintenance-ownership");
    let health = tokio::spawn(northstar_http::maintenance_health::private_health(
        listener,
        Arc::clone(&workers),
        metrics,
        retention_readiness,
        subscription_readiness,
        cancel.clone(),
    ));
    tracing::info!(role="maintenance", address=%config.maintenance_bind, "maintenance subserver started");
    supervise_maintenance(
        maintenance_ownership::MaintenanceOwnershipConnection::new(ownership, pool),
        &workers,
        &cancel,
        health,
        northstar_http::shutdown_signal(),
    )
    .await
}

#[cfg(test)]
mod tests;
