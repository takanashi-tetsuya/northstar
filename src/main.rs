#![forbid(unsafe_code)]

#[cfg(test)]
mod direct_replay;
mod node;
mod runtime;
#[cfg(test)]
mod stage4_replay;
#[cfg(test)]
mod xmpp;

use anyhow::{Context, Result};
use node::ServerNode;
use northstar_config::Config;
use northstar_runtime::listeners::{runtime_listener_addresses, RuntimeListeners};
use northstar_runtime::process_shutdown::supervise_process_shutdown;
use northstar_runtime::service_tasks::spawn_service_task;
use northstar_telemetry::logging::{init_process_logging, ProcessLogSettings};
use sqlx::PgPool;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
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
        return northstar_http::container_probe::container_healthcheck(&address).await;
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
    let _log_guard = init_process_logging(ProcessLogSettings {
        log_rotation: &config.log_rotation,
        log_dir: &config.log_dir,
        log_retention_files: config.log_retention_files,
        log_format: &config.log_format,
    })?;
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
    let mut runtime_control_connection = node::reserve_runtime_control_connection(&config).await?;
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
    let state = ServerNode::new(
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
            node::hosts::http::xmpp_transport_routes(&state),
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
    northstar_runtime::test_activation::publish_if_enabled(
        northstar_runtime::test_activation::TestActivationPolicy {
            enabled: test_listener_activation,
            destination: test_readiness_file.as_deref(),
            nonce: test_readiness_nonce.as_deref(),
        },
        &listener_addresses,
        std::process::id(),
    )?;

    supervise_process_shutdown(
        shutdown_state.as_ref(),
        &cancel,
        &worker_registry,
        shutdown_state.connection_actors(),
        &mut service_tasks,
        northstar_http::shutdown_signal(),
    )
    .await
}

async fn bind_runtime_listener(
    purpose: &'static str,
    address: SocketAddr,
) -> Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("could not bind {purpose} listener to {address}"))
}

#[cfg(test)]
mod container_healthcheck_tests {
    use super::{migration_environment_from_values, version_line};
    use std::path::PathBuf;

    #[test]
    fn version_output_matches_the_cargo_package_version() {
        assert_eq!(
            version_line(),
            concat!("xmpp-server ", env!("CARGO_PKG_VERSION"))
        );
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
