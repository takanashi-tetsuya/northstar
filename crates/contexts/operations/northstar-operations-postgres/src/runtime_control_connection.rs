//! Startup admission and reservation of the runtime-control database connection.

use anyhow::Context;
use northstar_config::{Config, SERVICE_CONTROL_POOL_MAX_CONNECTIONS};
use northstar_postgres::startup::startup_database_connect;
use sqlx::{
    pool::PoolConnection,
    postgres::{PgConnectOptions, PgPoolOptions},
    Postgres,
};
use std::time::Duration;

/// Durable runtime policy is a safety boundary, not ordinary background work.
/// Reserve one runtime-role connection so traffic workers cannot prevent the
/// process from observing committed administration settings under a saturated
/// main pool. XEP-0133 uses the same control-plane capability when enabled,
/// but does not own the capability itself.
// This is an initial connection/SCRAM handshake budget, not the runtime
// policy polling interval. Repeatedly cancelling half-second handshakes under
// a cold-start cohort can prevent any of them from reaching authentication.
const RUNTIME_CONTROL_STARTUP_CONNECT_ATTEMPT_BUDGET: Duration = Duration::from_secs(3);
/// A process has no traffic listeners while this bounded admission window is
/// active.  It exists specifically to de-correlate a cold-start cohort from a
/// short, per-attempt pool deadline; it is not a runtime worker retry policy.
const RUNTIME_CONTROL_STARTUP_RETRY_BUDGET: Duration = Duration::from_secs(15);

fn runtime_control_pool_options(config: &Config, attempt_budget: Duration) -> PgPoolOptions {
    let options = northstar_postgres::pool::options()
        .max_connections(SERVICE_CONTROL_POOL_MAX_CONNECTIONS)
        .min_connections(SERVICE_CONTROL_POOL_MAX_CONNECTIONS)
        .acquire_timeout(attempt_budget);
    if config.database_allow_unsafe_role_for_development {
        options
    } else {
        northstar_postgres::role_attestation::pin_public_application_schema(options)
    }
}

fn runtime_control_connect_options(database_url: &str) -> Result<PgConnectOptions, sqlx::Error> {
    Ok(database_url
        .parse::<PgConnectOptions>()?
        .application_name("northstar-runtime-control"))
}

async fn runtime_control_startup_connect<T, Connect, ConnectFuture>(
    deadline: tokio::time::Instant,
    connect: Connect,
) -> anyhow::Result<T>
where
    Connect: FnMut(Duration) -> ConnectFuture,
    ConnectFuture: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    startup_database_connect(
        deadline,
        RUNTIME_CONTROL_STARTUP_CONNECT_ATTEMPT_BUDGET,
        "runtime-control",
        connect,
    )
    .await
}

/// Establish the one process-owned control-plane connection before the
/// traffic pool or any startup reconciliation can take database capacity.
///
/// Keeping this at the application boundary makes the ordering explicit:
/// `main` owns startup sequencing, while `ServerNode` only owns the connection
/// after startup transfers it into the coordinated runtime worker.  The
/// connection remains separate from traffic for its whole lifetime.
pub async fn reserve_runtime_control_connection(
    config: &Config,
) -> anyhow::Result<PoolConnection<Postgres>> {
    let deadline = tokio::time::Instant::now() + RUNTIME_CONTROL_STARTUP_RETRY_BUDGET;
    let connect_options = runtime_control_connect_options(&config.database_url)?;
    let runtime_control_pool = runtime_control_startup_connect(deadline, |attempt_budget| {
        runtime_control_pool_options(config, attempt_budget).connect_with(connect_options.clone())
    })
    .await?;
    // Attestation and final ownership transfer share the same absolute startup
    // deadline. A completed handshake alone never authorizes serving traffic.
    tokio::time::timeout_at(deadline, async {
        if config.database_allow_unsafe_role_for_development {
            northstar_postgres::role_attestation::attest_development_database_is_loopback(
                &runtime_control_pool,
            )
            .await?;
        } else {
            northstar_postgres::role_attestation::attest_runtime_role(&runtime_control_pool)
                .await?;
        }
        runtime_control_pool
            .acquire()
            .await
            .context("could not reserve the runtime-control database connection")
    })
    .await
    .context(
        "runtime-control role attestation/reservation exceeded its startup admission deadline",
    )?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    };

    #[test]
    fn control_connection_identification_preserves_url_transport_and_schema_options() {
        let url = "postgres://fixture_user@127.0.0.1:6543/fixture_db?sslmode=verify-full&application_name=caller-name&options=-csearch_path%3Dfixture_schema%2Cpublic%20-cstatement_timeout%3D5000";
        let original = url.parse::<sqlx::postgres::PgConnectOptions>().unwrap();
        let control = runtime_control_connect_options(url).unwrap();
        assert_eq!(
            control.get_application_name(),
            Some("northstar-runtime-control")
        );
        assert_eq!(original.get_application_name(), Some("caller-name"));
        assert_eq!(control.get_host(), original.get_host());
        assert_eq!(control.get_port(), original.get_port());
        assert_eq!(control.get_username(), original.get_username());
        assert_eq!(control.get_database(), original.get_database());
        assert!(matches!(
            control.get_ssl_mode(),
            sqlx::postgres::PgSslMode::VerifyFull
        ));
        assert_eq!(control.get_options(), original.get_options());
        assert_eq!(
            control.get_options(),
            Some("-csearch_path=fixture_schema,public -cstatement_timeout=5000")
        );
        assert!(runtime_control_connect_options("not a database URL").is_err());
    }

    #[tokio::test]
    async fn slow_initial_handshake_finishes_without_half_second_cancellation() {
        let attempts = AtomicU32::new(0);
        let result = runtime_control_startup_connect(
            tokio::time::Instant::now() + Duration::from_secs(15),
            |budget| {
                attempts.fetch_add(1, Ordering::Relaxed);
                assert!(budget > Duration::from_millis(500));
                assert!(budget <= Duration::from_secs(3));
                async {
                    tokio::time::sleep(Duration::from_millis(750)).await;
                    Ok(7_u32)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result, 7);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn remaining_admission_budget_cancels_an_incomplete_handshake() {
        struct CancellationWitness(Arc<AtomicBool>);
        impl Drop for CancellationWitness {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let attempts = AtomicU32::new(0);
        let result: anyhow::Result<()> = runtime_control_startup_connect(
            tokio::time::Instant::now() + Duration::from_secs(1),
            |budget| {
                attempts.fetch_add(1, Ordering::Relaxed);
                assert!(budget <= Duration::from_secs(1));
                let witness = CancellationWitness(Arc::clone(&cancelled));
                async move {
                    let _witness = witness;
                    std::future::pending().await
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert!(cancelled.load(Ordering::Relaxed));
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn admission_retries_pool_timeouts_but_never_authentication_or_protocol_errors() {
        let attempts = AtomicU32::new(0);
        runtime_control_startup_connect(
            tokio::time::Instant::now() + Duration::from_secs(2),
            |_| {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt == 0 {
                        Err(sqlx::Error::PoolTimedOut)
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        attempts.store(0, Ordering::Relaxed);
        let result: anyhow::Result<()> = runtime_control_startup_connect(
            tokio::time::Instant::now() + Duration::from_secs(2),
            |_| {
                attempts.fetch_add(1, Ordering::Relaxed);
                async {
                    Err(sqlx::Error::Protocol(
                        "fixture authentication rejected".into(),
                    ))
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn expired_admission_never_starts_a_new_connection() {
        let result: anyhow::Result<()> = runtime_control_startup_connect(
            tokio::time::Instant::now() - Duration::from_millis(1),
            |_| async { panic!("connection was attempted after its admission deadline") },
        )
        .await;
        assert!(result.is_err());
    }
}
