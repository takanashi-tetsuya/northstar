#[cfg(test)]
mod health_regressions {
    use super::super::*;
    use tokio::{net::TcpStream, task::JoinHandle};

    struct HealthFixture {
        address: SocketAddr,
        workers: Arc<WorkerRegistry>,
        readiness: RetentionReadiness,
        cancel: CancellationToken,
        task: Option<JoinHandle<Result<()>>>,
    }

    impl HealthFixture {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let workers = WorkerRegistry::new();
            let cancel = CancellationToken::new();
            let readiness = RetentionReadiness::for_test(true);
            let task = tokio::spawn(private_health(
                listener,
                Arc::clone(&workers),
                Arc::new(Metrics::default()),
                readiness.clone(),
                cancel.clone(),
            ));
            Self {
                address,
                workers,
                readiness,
                cancel,
                task: Some(task),
            }
        }

        async fn request(&self, request: &[u8]) -> Vec<u8> {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut client = TcpStream::connect(self.address).await.unwrap();
                client.write_all(request).await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                response
            })
            .await
            .expect("private health request did not finish")
        }

        async fn stop(mut self) {
            self.cancel.cancel();
            tokio::time::timeout(Duration::from_secs(1), self.task.take().unwrap())
                .await
                .expect("health cancellation did not join its connections")
                .expect("health listener panicked")
                .unwrap();
            assert!(
                TcpStream::connect(self.address).await.is_err(),
                "health listener survived shutdown"
            );
        }
    }

    impl Drop for HealthFixture {
        fn drop(&mut self) {
            self.cancel.cancel();
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }

    fn response_body(response: &[u8], status: &str) -> String {
        let response = std::str::from_utf8(response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        assert_eq!(
            headers.lines().next().unwrap(),
            format!("HTTP/1.1 {status}")
        );
        assert!(headers.contains("Connection: close"));
        assert!(headers.contains("Cache-Control: no-store"));
        assert!(headers.contains(&format!("Content-Length: {}", body.len())));
        body.to_owned()
    }

    #[test]
    fn process_roles_have_explicit_non_overlapping_retention_ownership() {
        assert!(ProcessRole::parse(&[]).unwrap().embeds_retention());
        assert!(ProcessRole::parse(&["serve".into(), "standalone".into()])
            .unwrap()
            .embeds_retention());
        for role in ["core", "maintenance"] {
            assert!(!ProcessRole::parse(&["serve".into(), role.into()])
                .unwrap()
                .embeds_retention());
        }
        for args in [
            vec!["serve"],
            vec!["serve", "worker"],
            vec!["serve", "core", "extra"],
            vec!["typo"],
        ] {
            assert!(
                ProcessRole::parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>())
                    .is_err()
            );
        }
    }

    #[test]
    fn maintenance_configuration_needs_no_transport_or_signing_credentials() {
        let mut config: MaintenanceConfig =
            serde_json::from_value(serde_json::json!({"xmpp_domain":"example.com"})).unwrap();
        config.validate().unwrap();
        for address in [
            "0.0.0.0:9092",
            "192.0.2.1:9092",
            "[::]:9092",
            "[2001:db8::1]:9092",
            "127.0.0.1:0",
        ] {
            config.maintenance_bind = address.parse().unwrap();
            assert!(
                config.validate().is_err(),
                "accepted public or non-owned bind {address}"
            );
        }
        config.maintenance_bind = "[::1]:9092".parse().unwrap();
        config.validate().unwrap();
        config.database_allow_unsafe_role_for_development = true;
        assert!(config.validate().is_err());
        config.xmpp_domain = "fixture.localhost".into();
        config.validate().unwrap();
    }

    #[test]
    fn split_process_budget_includes_all_physical_runtime_role_connections() {
        let budget = crate::config::runtime_connection_budget_manifest();
        assert_eq!(
            MAX_CORE_PRIMARY_CONNECTIONS
                + MAINTENANCE_POOL_MAX_CONNECTIONS
                + budget.auxiliary_connections,
            budget.runtime_role_connection_limit
        );
        assert!(MAX_CORE_PRIMARY_CONNECTIONS >= budget.primary_pool_min_connections);
    }

    #[tokio::test]
    async fn private_health_serves_exact_health_and_metrics_routes_and_closes_responses() {
        let fixture = HealthFixture::start().await;
        assert_eq!(
            response_body(
                &fixture
                    .request(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .await,
                "200 OK"
            ),
            "ok\n"
        );
        assert_eq!(
            response_body(
                &fixture.request(b"GET /readyz HTTP/1.0\r\n\r\n").await,
                "200 OK"
            ),
            "ready\n"
        );
        let metrics = response_body(
            &fixture
                .request(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await,
            "200 OK",
        );
        assert!(metrics.contains("xmpp_retention_cleanup_failures_total 0"));
        fixture.stop().await;
    }

    #[tokio::test]
    async fn private_health_requires_completed_retention_and_reflects_a_failed_pass_immediately() {
        let fixture = HealthFixture::start().await;
        fixture.readiness.set_for_test(false);
        assert_eq!(
            response_body(
                &fixture.request(b"GET /readyz HTTP/1.1\r\n\r\n").await,
                "503 Service Unavailable"
            ),
            "maintenance-not-ready\n"
        );
        fixture.readiness.set_for_test(true);
        assert_eq!(
            response_body(
                &fixture.request(b"GET /readyz HTTP/1.1\r\n\r\n").await,
                "200 OK"
            ),
            "ready\n"
        );
        fixture.readiness.set_for_test(false);
        assert_eq!(
            response_body(
                &fixture.request(b"GET /readyz HTTP/1.1\r\n\r\n").await,
                "503 Service Unavailable"
            ),
            "maintenance-not-ready\n"
        );
        fixture.stop().await;
    }

    #[tokio::test]
    async fn private_health_reports_unready_without_leaking_details_and_recovers() {
        let fixture = HealthFixture::start().await;
        fixture
            .workers
            .register_observer("test-private-retention", WorkerCriticality::Restartable);
        for _ in 0..3 {
            fixture
                .workers
                .observer_error("test-private-retention", "private-fixture-error-detail");
        }
        assert!(fixture.workers.readiness_error().is_some());
        let response = fixture.request(b"GET /readyz HTTP/1.1\r\n\r\n").await;
        assert_eq!(
            response_body(&response, "503 Service Unavailable"),
            "maintenance-not-ready\n"
        );
        assert!(!String::from_utf8(response)
            .unwrap()
            .contains("private-fixture-error-detail"));
        assert_eq!(
            response_body(
                &fixture.request(b"GET /healthz HTTP/1.1\r\n\r\n").await,
                "200 OK"
            ),
            "ok\n"
        );
        fixture.workers.observer_ok("test-private-retention");
        assert_eq!(
            response_body(
                &fixture.request(b"GET /readyz HTTP/1.1\r\n\r\n").await,
                "200 OK"
            ),
            "ready\n"
        );
        fixture.stop().await;
    }

    #[tokio::test]
    async fn private_health_has_no_administration_or_mutating_routes() {
        let fixture = HealthFixture::start().await;
        for request in [
            "GET /admin HTTP/1.1\r\n\r\n",
            "POST /readyz HTTP/1.1\r\n\r\n",
            "GET /readyz?detail=1 HTTP/1.1\r\n\r\n",
            "GET /healthz/ HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                response_body(&fixture.request(request.as_bytes()).await, "404 Not Found"),
                "not-found\n"
            );
        }
        fixture.stop().await;
    }

    #[tokio::test]
    async fn private_health_closes_a_bounded_oversize_header_and_keeps_serving() {
        let fixture = HealthFixture::start().await;
        // One bounded local fixture, without an end-of-header marker, proves
        // that the fixed header budget terminates admission without a response.
        let request = vec![b'x'; 4096];
        assert!(fixture.request(&request).await.is_empty());
        assert_eq!(
            response_body(
                &fixture.request(b"GET /healthz HTTP/1.1\r\n\r\n").await,
                "200 OK"
            ),
            "ok\n"
        );
        fixture.stop().await;
    }

    #[tokio::test]
    async fn private_health_cancellation_closes_incomplete_requests_without_waiting_for_their_deadline(
    ) {
        let fixture = HealthFixture::start().await;
        let mut client = TcpStream::connect(fixture.address).await.unwrap();
        client
            .write_all(b"GET /readyz HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        // A completed request establishes that the listener is actively serving.
        fixture.request(b"GET /healthz HTTP/1.1\r\n\r\n").await;
        fixture.stop().await;
        let mut response = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("an accepted connection outlived its cancelled listener");
        assert!(
            read.is_ok()
                || read.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
        );
        assert!(
            response.is_empty(),
            "shutdown fabricated a response to an incomplete request"
        );
    }
}
