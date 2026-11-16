#![forbid(unsafe_code)]

use northstar_cluster as cluster;
mod db;
#[cfg(test)]
mod direct_replay;
mod runtime;
#[cfg(test)]
mod stage4_replay;
mod state;
mod xmpp;

use anyhow::{Context, Result};
use northstar_config::Config;
use runtime::service_tasks::{
    await_shutdown_notifications, drain_service_tasks, spawn_service_task,
    unexpected_service_task_exit, SERVICE_TASK_ABORT_DRAIN_TIMEOUT, SERVICE_TASK_DRAIN_TIMEOUT,
};
use sqlx::PgPool;
use state::AppState;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

const fn version_line() -> &'static str {
    concat!("xmpp-server ", env!("CARGO_PKG_VERSION"))
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
        (None, Some(path)) => Zeroizing::new(northstar_security::secret_files::read_secret_file(
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
    let domain = northstar_xmpp_types::jid::prepare_domainpart(domain.trim())
        .context("XMPP_DOMAIN is invalid")?;
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

fn migration_environment() -> Result<MigrationEnvironment> {
    migration_environment_from_values(
        std::env::var("MIGRATOR_DATABASE_URL").ok(),
        std::env::var_os("MIGRATOR_DATABASE_URL_FILE").map(PathBuf::from),
        std::env::var("XMPP_DOMAIN").ok(),
        std::env::var("MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT").ok(),
    )
}

async fn connect_migrator_pool(environment: &MigrationEnvironment) -> Result<PgPool> {
    let pool_options = northstar_postgres::pool::options()
        .max_connections(2)
        .min_connections(0);
    let pool_options = if environment.allow_unsafe_role_for_development {
        pool_options
    } else {
        northstar_postgres::role_attestation::pin_public_application_schema(pool_options)
    };
    let pool = pool_options
        .connect(environment.database_url.as_str())
        .await
        .context("could not connect to PostgreSQL with the migrator role")?;
    if environment.allow_unsafe_role_for_development {
        northstar_postgres::role_attestation::attest_development_database_is_loopback(&pool)
            .await?;
        eprintln!(
            "warning: explicit loopback development override skips PostgreSQL migrator role attestation"
        );
    } else {
        northstar_postgres::role_attestation::attest_migrator_role(&pool).await?;
    }
    Ok(pool)
}

async fn run_migrations() -> Result<()> {
    let environment = migration_environment()?;
    let pool = connect_migrator_pool(&environment).await?;
    northstar_workflows::identity_migration::migrate_for_domain(&pool, &environment.domain).await?;
    pool.close().await;
    Ok(())
}

fn install_crypto_provider() -> Result<()> {
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("could not install the rustls AWS-LC crypto provider"))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    northstar_telemetry::logging::report_result(run().await)
}

async fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(arguments.first().map(String::as_str), Some("--help" | "-h")) {
        anyhow::ensure!(arguments.len() == 1, "usage: xmpp-server --help");
        println!("Northstar XMPP server\n\n  xmpp-server serve core         Start protocol/session/administration server\n  xmpp-server serve maintenance  Start isolated retention and subscription maintenance server\n  xmpp-server serve standalone   Start the compatible combined server (default)\n  xmpp-server --subservers       Show process responsibility inventory\n  xmpp-server migrate           Apply migrations with explicit migrator credentials\n  xmpp-server storage migrate --from local|s3 --to s3|local --all-nodes-stopped\n  xmpp-server storage backup-object export|import ...\n  xmpp-server --healthcheck [IP:PORT]\n  xmpp-server --version");
        return Ok(());
    }
    if arguments.first().map(String::as_str) == Some("--subservers") {
        anyhow::ensure!(arguments.len() == 1, "usage: xmpp-server --subservers");
        return runtime::subservers::print_inventory();
    }
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
    if arguments.first().map(String::as_str) == Some("--runtime-connection-budget") {
        if arguments.len() != 1 {
            anyhow::bail!("usage: xmpp-server --runtime-connection-budget");
        }
        println!(
            "{}",
            serde_json::to_string(&northstar_config::runtime_connection_budget_manifest())?
        );
        return Ok(());
    }
    if arguments.first().map(String::as_str) == Some("--storage-connection-budget") {
        if arguments.len() != 1 {
            anyhow::bail!("usage: xmpp-server --storage-connection-budget");
        }
        println!(
            "{}",
            serde_json::to_string(&northstar_config::storage_connection_budget_manifest())?
        );
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
    // Maintenance has a separate configuration boundary: never populate its
    // environment from a core .env file containing protocol/signing secrets.
    if arguments != ["serve", "maintenance"]
        && std::env::var("NORTHSTAR_DISABLE_DOTENV").as_deref() != Ok("true")
    {
        northstar_config::load_dotenv()?;
    }
    if let Some(outcome) = northstar_data_tools::identity_audit::maybe_run(&arguments).await? {
        return match outcome {
            northstar_data_tools::identity_audit::AuditOutcome::Clean | northstar_data_tools::identity_audit::AuditOutcome::Help => Ok(()),
            northstar_data_tools::identity_audit::AuditOutcome::Dirty => anyhow::bail!(
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
    if arguments.first().map(String::as_str) == Some("storage") {
        match arguments.get(1).map(String::as_str) {
            Some("migrate") => {
                let environment = migration_environment()?;
                let pool = connect_migrator_pool(&environment).await?;
                let repository =
                    northstar_upload_postgres::PostgresUploadRepository::new(pool.clone());
                let result = northstar_upload_storage::storage_migration::run_cli(
                    &repository,
                    &arguments[2..],
                )
                .await;
                pool.close().await;
                return result;
            }
            Some("backup-object") => {
                return northstar_upload_storage::backup::run_cli(&arguments[2..]).await
            }
            _ => anyhow::bail!("usage: xmpp-server storage migrate|backup-object ..."),
        }
    }
    let process_role = if arguments.first().map(String::as_str) == Some("pie") {
        runtime::subservers::ProcessRole::Standalone
    } else {
        runtime::subservers::ProcessRole::parse(&arguments)?
    };
    if process_role == runtime::subservers::ProcessRole::Maintenance {
        return runtime::subservers::run_maintenance().await;
    }
    let config = Config::from_env()?;
    let _log_guard = init_logging(&config)?;
    if process_role == runtime::subservers::ProcessRole::Core {
        anyhow::ensure!(config.database_max_connections <= runtime::subservers::MAX_CORE_PRIMARY_CONNECTIONS,
            "core subserver DATABASE_MAX_CONNECTIONS must be at most {}, reserving shared-role capacity for maintenance",
            runtime::subservers::MAX_CORE_PRIMARY_CONNECTIONS);
        tracing::info!(
            role = "core",
            "core subserver selected; archive retention is owned by the maintenance process"
        );
    }
    if config.invitation_policy_disabled_with_web_client {
        tracing::warn!(
            open_registration = config.open_registration,
            "invitation-only registration was resolved fail-closed because WEB_CLIENT_ENABLED=false; effective registration mode is closed"
        );
    }
    if arguments.first().map(String::as_str) == Some("pie") {
        return northstar_data_tools::pie::run(&config, &arguments[1..]).await;
    }
    // This reservation deliberately precedes primary-pool construction and
    // every startup database operation.  Runtime policy and service-control
    // authority must survive a cold-start cohort that would otherwise fill
    // the traffic pool before it can establish its own isolated connection.
    let startup_phase =
        northstar_telemetry::logging::StartupPhase::begin("runtime_control_reservation");
    let mut runtime_control_connection = state::reserve_runtime_control_connection(&config).await?;
    if process_role.embeds_retention() {
        // Retention ownership shares this already-reserved physical session;
        // it consumes no primary-pool slot. Its existing critical supervisor
        // cancels this process if the exact connection stops making progress.
        runtime::subservers::claim_maintenance_on_connection(&mut runtime_control_connection)
            .await?;
    }
    startup_phase.complete();
    let startup_phase =
        northstar_telemetry::logging::StartupPhase::begin("primary_pool_and_role_attestation");
    let pool_options = northstar_postgres::pool::options()
        .max_connections(config.database_max_connections)
        .min_connections(config.database_min_connections);
    let pool_options = if config.database_allow_unsafe_role_for_development {
        pool_options
    } else {
        northstar_postgres::role_attestation::pin_public_application_schema(pool_options)
    };
    let pool = pool_options
        .connect(&config.database_url)
        .await
        .context("could not connect to PostgreSQL")?;
    if config.database_allow_unsafe_role_for_development {
        northstar_postgres::role_attestation::attest_development_database_is_loopback(&pool)
            .await?;
        tracing::warn!(
            "explicit loopback development override skips PostgreSQL runtime role attestation"
        );
    } else {
        northstar_postgres::role_attestation::attest_runtime_role(&pool).await?;
    }
    startup_phase.complete();
    let startup_phase = northstar_telemetry::logging::StartupPhase::begin("schema_verification");
    northstar_postgres::schema::verify_schema(&pool, &config.domain)
        .await
        .context("database schema verification failed")?;
    startup_phase.complete();
    // Startup reconciliation owns a PostgreSQL advisory lock with its own
    // transaction-local 30-second bound. Do not wrap that authoritative
    // serialization in the much shorter runtime lease-I/O budget: a peer may
    // be legitimately committing the same epoch while this process has not
    // yet received CPU time. The database lock remains fail-closed and is
    // released automatically if its owner dies.
    let startup_phase =
        northstar_telemetry::logging::StartupPhase::begin("deployment_capacity_reconciliation");
    northstar_session_postgres::capacity::reconcile_deployment_capacity(
        &pool,
        northstar_session_postgres::capacity::DeploymentCapacityConfiguration::from_config(
            &config,
        )?,
    )
    .await
    .context("could not establish deployment-wide capacity authority")?;
    startup_phase.complete();
    let startup_phase = northstar_telemetry::logging::StartupPhase::begin("credential_maintenance");
    if !config.scram_sha1_enabled {
        let removed = northstar_auth_postgres::users::clear_scram_sha1_credentials(&pool).await?;
        if removed > 0 {
            tracing::info!(removed, "cleared disabled SCRAM-SHA-1 verifier material");
        }
    }
    northstar_auth_postgres::users::ensure_bootstrap_admin(&pool, &config).await?;
    startup_phase.complete();
    let components = northstar_federation_application::components::ComponentRegistry::default();
    let (federation, federation_rx) = northstar_federation_application::outbox::FederationOutboxService::channel(
        northstar_federation_postgres::outbox_repository::PostgresFederationOutboxRepository::new(pool.clone()),
        northstar_federation_core::S2sOutboxPolicy::new(
            config.s2s_outbox_ttl_seconds,
            config.s2s_outbox_max_rows,
            config.s2s_outbox_max_bytes,
            config.s2s_outbox_max_per_domain,
        ),
        Arc::new(components.clone()),
        config
            .components
            .iter()
            .flat_map(|credential| credential.allowed_domains.iter().cloned())
            .collect(),
    );
    let cancel = CancellationToken::new();
    let startup_phase = northstar_telemetry::logging::StartupPhase::begin("application_state");
    let listeners = config.runtime_listener_policy();
    let test_listener_activation = config.test_listener_activation;
    let test_readiness_file = config.test_readiness_file.clone();
    let test_readiness_nonce = config.test_readiness_nonce.clone();
    let state = AppState::new(
        config,
        pool,
        federation,
        components,
        runtime_control_connection,
        cancel.clone(),
    )
    .await?;
    startup_phase.complete();
    state.install_service_shutdown(cancel.clone())?;

    let worker_registry = Arc::clone(state.worker_registry());
    state.start_workers(&cancel, process_role);

    // Listener ownership belongs to this process before any service task is
    // spawned. Test fixtures can therefore use `127.0.0.1:0` and consume a
    // nonce-bound readiness record instead of racing a port-number allocator.
    let xmpp_listener = bind_runtime_listener("XMPP", listeners.xmpp).await?;
    let xmpps_listener = bind_runtime_listener("XMPPS", listeners.xmpps).await?;
    let http_listener = bind_runtime_listener("HTTP", listeners.http).await?;
    let metrics_listener = bind_runtime_listener("metrics", listeners.metrics).await?;
    let admin_listener = match listeners.admin {
        Some(bind) => Some(bind_runtime_listener("web administration", bind).await?),
        None => None,
    };
    let s2s_listener = match listeners.s2s {
        Some(bind) => Some(bind_runtime_listener("S2S", bind).await?),
        None => None,
    };
    let s2s_tls_listener = match listeners.s2s_tls {
        Some(bind) => Some(bind_runtime_listener("S2S Direct TLS", bind).await?),
        None => None,
    };
    let component_listener = if state.accepts_component_connections() {
        Some(bind_runtime_listener("external component", listeners.component).await?)
    } else {
        None
    };
    let listener_addresses = runtime_listener_addresses(RuntimeListeners {
        xmpp: &xmpp_listener,
        xmpps: &xmpps_listener,
        http: &http_listener,
        metrics: &metrics_listener,
        admin: admin_listener.as_ref(),
        s2s: s2s_listener.as_ref(),
        s2s_tls: s2s_tls_listener.as_ref(),
        component: component_listener.as_ref(),
    })?;

    let mut service_tasks = JoinSet::new();
    spawn_service_task(
        &mut service_tasks,
        "XMPP",
        northstar_c2s::serve_tcp(state.clone(), cancel.clone(), xmpp_listener),
    );
    spawn_service_task(
        &mut service_tasks,
        "XMPPS",
        northstar_c2s::serve_xmpps_tcp(state.clone(), cancel.clone(), xmpps_listener),
    );
    spawn_service_task(
        &mut service_tasks,
        "S2S",
        northstar_s2s::inbound::serve(state.clone(), federation_rx, cancel.clone(), s2s_listener),
    );
    spawn_service_task(
        &mut service_tasks,
        "S2S TLS",
        northstar_s2s::inbound::serve_s2s_tls(state.clone(), cancel.clone(), s2s_tls_listener),
    );
    spawn_service_task(
        &mut service_tasks,
        "external component",
        northstar_s2s::components::serve(state.clone(), cancel.clone(), component_listener),
    );
    let operation_worker_runtime = state.operation_worker_runtime();
    spawn_service_task(
        &mut service_tasks,
        "durable operation worker",
        northstar_operations_xmpp::operation_runtime::serve(
            operation_worker_runtime,
            cancel.clone(),
        ),
    );

    let shutdown_state = state.clone();
    spawn_service_task(
        &mut service_tasks,
        "metrics",
        northstar_http::serve_metrics(state.metrics_context(), cancel.clone(), metrics_listener),
    );
    spawn_service_task(
        &mut service_tasks,
        "HTTP",
        northstar_http::serve(
            state.clone(),
            state::http_host::xmpp_transport_routes(&state),
            cancel.clone(),
            http_listener,
        ),
    );
    if listeners.admin.is_some() {
        let Some(listener) = admin_listener else {
            unreachable!("web admin listener should be present when web_admin_enabled is true")
        };
        spawn_service_task(
            &mut service_tasks,
            "Web administration",
            northstar_http::serve_administration(state.clone(), cancel.clone(), listener),
        );
    }
    runtime::test_activation::publish_if_enabled(
        runtime::test_activation::TestActivationPolicy {
            enabled: test_listener_activation,
            destination: test_readiness_file.as_deref(),
            nonce: test_readiness_nonce.as_deref(),
        },
        &listener_addresses,
        std::process::id(),
    )?;

    let mut shutdown_error = None;
    let graceful_signal = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            shutdown_error = worker_registry
                .critical_failure()
                .map(anyhow::Error::msg);
            false
        },
        _ = northstar_http::shutdown_signal() => {
            tracing::info!("shutdown signal received; stopping listeners and draining HTTP requests");
            true
        },
        result = service_tasks.join_next() => {
            shutdown_error = Some(unexpected_service_task_exit(result));
            false
        },
    };

    // Close connection admission before signalling any child. Every accepted
    // transport is now owned by the bounded registry and must finalize before
    // the abort-and-reap deadline below.
    shutdown_state.connection_actors().close_admission();
    if graceful_signal {
        let muc_delivery = shutdown_state.muc_delivery_context();
        match await_shutdown_notifications(
            &cancel,
            &mut service_tasks,
            northstar_muc_xmpp::shutdown::notify_muc_system_shutdown(&muc_delivery),
            tokio::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        {
            Ok(Some(notified_muc_occupants)) if notified_muc_occupants > 0 => {
                tracing::info!(notified_muc_occupants, "confirmed XEP-0045 shutdown notification transport writes or BOSH response acknowledgements");
            }
            Ok(_) => {}
            Err(error) => {
                shutdown_error.get_or_insert(error);
            }
        }
        if let Some(error) = worker_registry.critical_failure() {
            shutdown_error.get_or_insert_with(|| anyhow::Error::msg(error));
        }
    }
    shutdown_state.begin_cluster_shutdown();
    shutdown_state.connection_actors().begin_shutdown();
    cancel.cancel();
    match shutdown_state
        .release_cluster_instance_after_publication_quiescence(std::time::Duration::from_secs(15))
        .await
    {
        Some(Ok(())) => {}
        Some(Err(error)) => tracing::warn!(
            ?error,
            "could not audit the final cluster node-instance lease release"
        ),
        None => tracing::error!(
            "signed cluster publications did not drain; leaving the instance fenced until its database lease expires"
        ),
    }
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

    if let Some(error) = worker_registry.critical_failure() {
        shutdown_error.get_or_insert_with(|| anyhow::Error::msg(error));
    }
    match shutdown_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn bind_runtime_listener(
    purpose: &'static str,
    address: SocketAddr,
) -> Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("could not bind {purpose} listener to {address}"))
}

struct RuntimeListeners<'a> {
    xmpp: &'a tokio::net::TcpListener,
    xmpps: &'a tokio::net::TcpListener,
    http: &'a tokio::net::TcpListener,
    metrics: &'a tokio::net::TcpListener,
    admin: Option<&'a tokio::net::TcpListener>,
    s2s: Option<&'a tokio::net::TcpListener>,
    s2s_tls: Option<&'a tokio::net::TcpListener>,
    component: Option<&'a tokio::net::TcpListener>,
}

fn runtime_listener_addresses(
    listeners: RuntimeListeners<'_>,
) -> Result<BTreeMap<String, SocketAddr>> {
    let mut addresses = BTreeMap::new();
    for (purpose, listener) in [
        ("xmpp", listeners.xmpp),
        ("xmpps", listeners.xmpps),
        ("http", listeners.http),
        ("metrics", listeners.metrics),
    ] {
        addresses.insert(
            purpose.to_owned(),
            listener
                .local_addr()
                .with_context(|| format!("could not inspect {purpose} listener"))?,
        );
    }
    for (purpose, listener) in [
        ("web-admin", listeners.admin),
        ("s2s", listeners.s2s),
        ("s2s-tls", listeners.s2s_tls),
        ("component", listeners.component),
    ] {
        if let Some(listener) = listener {
            addresses.insert(
                purpose.to_owned(),
                listener
                    .local_addr()
                    .with_context(|| format!("could not inspect {purpose} listener"))?,
            );
        }
    }
    Ok(addresses)
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

fn init_logging(config: &Config) -> Result<northstar_telemetry::logging::LogGuards> {
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

    let (non_blocking, file_guard) = tracing_appender::non_blocking(file_appender);
    let (console, console_guard) = northstar_telemetry::logging::console(std::io::stderr());
    let guards = northstar_telemetry::logging::LogGuards::new(vec![file_guard, console_guard]);

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    if config.log_format.eq_ignore_ascii_case("json") {
        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_ansi(false);
        let console_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(console)
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
        let console_layer = tracing_subscriber::fmt::layer().with_writer(console);
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .with(console_layer)
            .init();
    }

    Ok(guards)
}

#[cfg(test)]
mod container_healthcheck_tests {
    use super::{container_healthcheck, migration_environment_from_values, version_line};
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
    async fn runtime_listener_inventory_uses_bound_ephemeral_addresses() {
        let xmpp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let xmpps = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let metrics = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addresses = super::runtime_listener_addresses(super::RuntimeListeners {
            xmpp: &xmpp,
            xmpps: &xmpps,
            http: &http,
            metrics: &metrics,
            admin: None,
            s2s: None,
            s2s_tls: None,
            component: None,
        })
        .unwrap();
        assert_eq!(addresses.len(), 4);
        for (purpose, address) in addresses {
            assert!(address.ip().is_loopback(), "{purpose} must remain loopback");
            assert_ne!(
                address.port(),
                0,
                "{purpose} must be resolved before readiness"
            );
        }
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
