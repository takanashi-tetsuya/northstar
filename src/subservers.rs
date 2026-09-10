//! Independent process roles over the existing PostgreSQL authority.
//!
//! The core is the sole owner of live sessions and transport delivery. The
//! maintenance process receives only a retention policy, a bounded database
//! pool and metrics; it never constructs AppState or loads protocol secrets.

use crate::{
    db,
    metrics::Metrics,
    retention::{RetentionContext, RetentionPolicy, RetentionReadiness},
    workers::{WorkerCriticality, WorkerMode, WorkerRegistry},
};
use anyhow::{Context, Result};
use serde::Deserialize;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

pub(crate) const MAINTENANCE_POOL_MAX_CONNECTIONS: u32 = 3;
pub(crate) const MAX_CORE_PRIMARY_CONNECTIONS: u32 =
    crate::config::DATABASE_MAX_CONNECTIONS_LIMIT - MAINTENANCE_POOL_MAX_CONNECTIONS;

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
                {"role":"maintenance", "command":["serve","maintenance"], "owns":["archive-retention","completed-retraction-retention","expired-governance-artifacts"], "public_listeners":false}
            ],
            "compatibility_command":["serve","standalone"]
        }))?
    );
    Ok(())
}

#[derive(Deserialize)]
struct MaintenanceConfig {
    xmpp_domain: String,
    #[serde(default)]
    database_url: String,
    database_url_file: Option<PathBuf>,
    #[serde(default)]
    database_allow_unsafe_role_for_development: bool,
    #[serde(default = "default_bind")]
    maintenance_bind: SocketAddr,
    #[serde(default = "default_mam_days")]
    mam_retention_days: i64,
    #[serde(default = "default_mam_days")]
    muc_mam_retention_days: i64,
    #[serde(default = "default_offline_days")]
    offline_message_ttl_days: i64,
    #[serde(default = "default_audit_days")]
    audit_log_retention_days: i64,
    #[serde(default = "default_batch")]
    retention_cleanup_batch_size: i64,
    #[serde(default = "default_interval")]
    retention_cleanup_interval_seconds: u64,
}

fn default_bind() -> SocketAddr {
    ([127, 0, 0, 1], 9092).into()
}
fn default_mam_days() -> i64 {
    365
}
fn default_offline_days() -> i64 {
    30
}
fn default_audit_days() -> i64 {
    730
}
fn default_batch() -> i64 {
    1000
}
fn default_interval() -> u64 {
    60
}

impl MaintenanceConfig {
    fn policy(&self) -> RetentionPolicy {
        RetentionPolicy {
            mam_retention_days: self.mam_retention_days,
            muc_mam_retention_days: self.muc_mam_retention_days,
            offline_message_ttl_days: self.offline_message_ttl_days,
            audit_log_retention_days: self.audit_log_retention_days,
            retention_cleanup_batch_size: self.retention_cleanup_batch_size,
            retention_cleanup_interval_seconds: self.retention_cleanup_interval_seconds,
        }
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.maintenance_bind.ip().is_loopback(),
            "MAINTENANCE_BIND must use a loopback IP; the maintenance process has no public API"
        );
        anyhow::ensure!(
            self.maintenance_bind.port() != 0,
            "MAINTENANCE_BIND must use a nonzero port"
        );
        self.policy().validate()?;
        if self.database_allow_unsafe_role_for_development {
            anyhow::ensure!(
                self.xmpp_domain == "localhost"
                    || self.xmpp_domain.ends_with(".localhost")
                    || self.xmpp_domain.ends_with(".test"),
                "development database override requires a reserved development domain"
            );
        }
        Ok(())
    }
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
    // Even an early startup failure must close the physical session rather
    // than return an advisory-lock owner to a still-live pool.
    connection.close_on_drop();
    let claimed: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended(current_database() || ':' || current_schema() || ':northstar:archive-maintenance:v1', 0))")
        .fetch_one(&mut **connection).await?;
    anyhow::ensure!(claimed, "archive maintenance is already owned by another process; stop it before changing process topology");
    Ok(())
}

pub(crate) async fn run_maintenance() -> Result<()> {
    let mut config: MaintenanceConfig =
        envy::from_env().context("invalid maintenance configuration")?;
    config.xmpp_domain =
        crate::jid::prepare_domainpart(config.xmpp_domain.trim()).context("invalid XMPP_DOMAIN")?;
    config.validate()?;
    anyhow::ensure!(
        config.database_url.is_empty() || config.database_url_file.is_none(),
        "set only one of DATABASE_URL and DATABASE_URL_FILE"
    );
    let url = zeroize::Zeroizing::new(match config.database_url_file.as_ref() {
        Some(path) => crate::config::read_secret_file(path, "DATABASE_URL_FILE")?,
        None => std::mem::take(&mut config.database_url),
    });
    anyhow::ensure!(
        !url.trim().is_empty(),
        "maintenance requires DATABASE_URL_FILE or DATABASE_URL"
    );
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init()
        .map_err(|_| anyhow::anyhow!("could not initialize maintenance logging"))?;

    // This budget includes the dedicated ownership/health connection. No
    // migrator, administrator-command or runtime-control pool is constructed.
    let options = PgPoolOptions::new()
        .max_connections(MAINTENANCE_POOL_MAX_CONNECTIONS)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(5));
    let options = if config.database_allow_unsafe_role_for_development {
        options
    } else {
        db::pin_public_application_schema(options)
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
        db::attest_development_database_is_loopback(&pool).await?;
    } else {
        db::attest_runtime_role(&pool).await?;
    }
    db::verify_schema(&pool, &config.xmpp_domain)
        .await
        .context("maintenance schema verification failed")?;
    let mut ownership = claim_maintenance(&pool).await?;
    let listener = TcpListener::bind(config.maintenance_bind)
        .await
        .context("maintenance health listener bind failed")?;
    let cancel = CancellationToken::new();
    let workers = WorkerRegistry::new();
    let metrics = Arc::new(Metrics::default());
    let policy = config.policy();
    let silence = Duration::from_secs(
        policy
            .retention_cleanup_interval_seconds
            .saturating_mul(2)
            .saturating_add(60),
    );
    let retention = Arc::new(RetentionContext::new(
        pool.clone(),
        policy,
        Arc::clone(&metrics),
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
            crate::retention::serve_context(
                Arc::clone(&retention),
                worker_cancel.clone(),
                heartbeat,
            )
        },
    );
    workers.register_observer("maintenance-ownership", WorkerCriticality::Critical);
    workers.observer_ok("maintenance-ownership");
    let mut health = tokio::spawn(private_health(
        listener,
        Arc::clone(&workers),
        metrics,
        retention_readiness,
        cancel.clone(),
    ));
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let shutdown = crate::api::shutdown_signal();
    tokio::pin!(shutdown);
    tracing::info!(role="maintenance", address=%config.maintenance_bind, "maintenance subserver started");
    let outcome = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Err(anyhow::anyhow!("maintenance worker authority failed")),
            _ = &mut shutdown => break Ok(()),
            result = &mut health => break match result {
                Ok(Err(error)) => Err(error).context("maintenance health listener failed"),
                Ok(Ok(())) => Err(anyhow::anyhow!("maintenance health listener stopped unexpectedly")),
                Err(error) => Err(error).context("maintenance health listener panicked"),
            },
            _ = interval.tick() => {
                // The exact locked connection is probed; substituting a pool
                // connection would conceal loss of exclusive ownership.
                let probe = tokio::time::timeout(Duration::from_secs(3), sqlx::query("SELECT 1").execute(&mut *ownership)).await;
                if !matches!(probe, Ok(Ok(_))) {
                    workers.observer_error("maintenance-ownership", "database ownership connection failed");
                    break Err(anyhow::anyhow!("maintenance database ownership connection failed"));
                }
                workers.observer_ok("maintenance-ownership");
            }
        }
    };
    cancel.cancel();
    let report = workers
        .shutdown_and_join(&cancel, Duration::from_secs(15))
        .await;
    if !health.is_finished()
        && tokio::time::timeout(Duration::from_secs(1), &mut health)
            .await
            .is_err()
    {
        health.abort();
        let _ = health.await;
    }
    // Closing the physical connection releases the session-level advisory
    // lock; returning it to a live pool would retain the lock invisibly.
    ownership.close().await?;
    pool.close().await;
    anyhow::ensure!(
        report.is_clean(),
        "maintenance worker shutdown was incomplete"
    );
    outcome
}

async fn private_health(
    listener: TcpListener,
    workers: Arc<WorkerRegistry>,
    metrics: Arc<Metrics>,
    retention_readiness: RetentionReadiness,
    cancel: CancellationToken,
) -> Result<()> {
    anyhow::ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "maintenance health listener must remain loopback-only"
    );
    let permits = Arc::new(Semaphore::new(16));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            connection = listener.accept() => {
                let (mut stream, _) = connection?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let workers = Arc::clone(&workers);
                let metrics = Arc::clone(&metrics);
                let retention_readiness = retention_readiness.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(Duration::from_secs(2), async {
                        let mut buffer = [0u8; 4096];
                        let mut used = 0;
                        loop {
                            let count = stream.read(&mut buffer[used..]).await?;
                            if count == 0 { return Ok::<(), std::io::Error>(()); }
                            used += count;
                            if buffer[..used].windows(4).any(|part| part == b"\r\n\r\n") { break; }
                            if used == buffer.len() { return Ok(()); }
                        }
                        let first = std::str::from_utf8(&buffer[..used]).unwrap_or_default().lines().next().unwrap_or_default();
                        let (status, body) = match first {
                            "GET /healthz HTTP/1.1" | "GET /healthz HTTP/1.0" => ("200 OK", "ok\n".to_owned()),
                            "GET /readyz HTTP/1.1" | "GET /readyz HTTP/1.0" if retention_readiness.is_ready() && workers.readiness_error().is_none() => ("200 OK", "ready\n".to_owned()),
                            "GET /readyz HTTP/1.1" | "GET /readyz HTTP/1.0" => ("503 Service Unavailable", "maintenance-not-ready\n".to_owned()),
                            "GET /metrics HTTP/1.1" | "GET /metrics HTTP/1.0" => ("200 OK", metrics.render()),
                            _ => ("404 Not Found", "not-found\n".to_owned()),
                        };
                        stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}", body.len()).as_bytes()).await?;
                        stream.shutdown().await
                    }).await;
                });
            }
        }
    }
    connections.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests;
