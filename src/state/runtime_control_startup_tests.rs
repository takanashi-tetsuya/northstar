use super::{
    runtime_control_connect_options, runtime_control_startup_connect, startup_database_connect,
};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};
use std::time::Duration;

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
    runtime_control_startup_connect(tokio::time::Instant::now() + Duration::from_secs(2), |_| {
        let attempt = attempts.fetch_add(1, Ordering::Relaxed);
        async move {
            if attempt == 0 {
                Err(sqlx::Error::PoolTimedOut)
            } else {
                Ok(())
            }
        }
    })
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

#[tokio::test]
async fn auxiliary_pools_share_the_remaining_deadline_and_cancel_inflight_connect() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    startup_database_connect(deadline, Duration::from_secs(2), "command", |_| async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok(())
    })
    .await
    .unwrap();
    let result: anyhow::Result<()> =
        startup_database_connect(deadline, Duration::from_secs(2), "OMEMO", |budget| {
            assert!(budget < Duration::from_secs(2));
            std::future::pending()
        })
        .await;
    assert!(result.unwrap_err().to_string().contains("OMEMO"));
    let result: anyhow::Result<()> =
        startup_database_connect(deadline, Duration::from_secs(2), "command", |_| async {
            panic!("a later pool must not reset an exhausted shared deadline")
        })
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn auxiliary_pool_retry_preserves_its_acquisition_limit() {
    let attempts = AtomicU32::new(0);
    startup_database_connect(
        tokio::time::Instant::now() + Duration::from_secs(15),
        Duration::from_secs(2),
        "OMEMO",
        |budget| {
            assert_eq!(budget, Duration::from_secs(2));
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
}
