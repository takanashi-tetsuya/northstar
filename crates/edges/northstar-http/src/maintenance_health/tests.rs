use super::*;
use crate::test_support::socket_close_guard;
use northstar_runtime::workers::WorkerCriticality;
use std::net::SocketAddr;
use tokio::{
    net::{TcpSocket, TcpStream},
    sync::RwLockReadGuard,
    task::JoinHandle,
};

struct HealthFixture {
    address: SocketAddr,
    /// Keeps `address` bound until the fixture is dropped; see `reserved_loopback_listener`.
    _port_reservation: TcpSocket,
    workers: Arc<WorkerRegistry>,
    readiness: RetentionReadiness,
    subscription_readiness: SubscriptionCleanupReadiness,
    cancel: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
    /// Keeps child processes of other tests from holding copies of this fixture's sockets, so
    /// dropping a socket closes it; see `crate::test_support`.
    _socket_close_guard: RwLockReadGuard<'static, ()>,
}

/// Binds the loopback health listener together with a second socket on the same port that is
/// bound but never listens. A non-listening socket receives no connections, so while the
/// listener is open it gets every connection; after the listener closes, a connection to the
/// port is refused. Because the second socket keeps the port bound, no other socket can bind the
/// freed port (only another `SO_REUSEPORT` socket of the same user could, and nothing else in the
/// workspace sets it), and an outgoing connection cannot take it as its source port and connect
/// to itself, so a refused connection in `stop` proves that this listener is closed.
fn reserved_loopback_listener() -> (TcpListener, TcpSocket) {
    let listener = TcpSocket::new_v4().unwrap();
    listener.set_reuseport(true).unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let reservation = TcpSocket::new_v4().unwrap();
    reservation.set_reuseport(true).unwrap();
    reservation.bind(listener.local_addr().unwrap()).unwrap();
    (listener.listen(1024).unwrap(), reservation)
}

impl HealthFixture {
    async fn start() -> Self {
        let socket_close_guard = socket_close_guard().await;
        let (listener, port_reservation) = reserved_loopback_listener();
        let address = listener.local_addr().unwrap();
        let workers = WorkerRegistry::new();
        let cancel = CancellationToken::new();
        let readiness = RetentionReadiness::for_test(true);
        let subscription_readiness = SubscriptionCleanupReadiness::default();
        subscription_readiness.complete_pass();
        let task = tokio::spawn(private_health(
            listener,
            Arc::clone(&workers),
            Arc::new(Metrics::default()),
            readiness.clone(),
            subscription_readiness.clone(),
            cancel.clone(),
        ));
        Self {
            address,
            _port_reservation: port_reservation,
            workers,
            readiness,
            subscription_readiness,
            cancel,
            task: Some(task),
            _socket_close_guard: socket_close_guard,
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
        // `_port_reservation` still holds the port, so no other socket can be listening on it,
        // and `_socket_close_guard` keeps every child process from holding a copy of the
        // listener, so the joined task's drop has closed it.
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

#[tokio::test]
async fn private_health_requires_both_independent_cleanup_passes() {
    let fixture = HealthFixture::start().await;
    for (archive, subscriptions, expected) in [
        (false, false, "503 Service Unavailable"),
        (true, false, "503 Service Unavailable"),
        (false, true, "503 Service Unavailable"),
        (true, true, "200 OK"),
        (false, true, "503 Service Unavailable"),
        (true, false, "503 Service Unavailable"),
    ] {
        fixture.readiness.set_for_test(archive);
        if subscriptions {
            fixture.subscription_readiness.complete_pass();
        } else {
            fixture.subscription_readiness.begin_pass();
        }
        response_body(
            &fixture.request(b"GET /readyz HTTP/1.1\r\n\r\n").await,
            expected,
        );
    }
    // Neither cleanup readiness is a liveness or administration authority.
    response_body(
        &fixture.request(b"GET /healthz HTTP/1.1\r\n\r\n").await,
        "200 OK",
    );
    fixture.stop().await;
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
async fn private_health_cancellation_closes_incomplete_requests_without_waiting_for_their_deadline()
{
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

#[tokio::test]
async fn private_health_rejects_public_binds_and_bounds_incomplete_connections() {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let result = private_health(
        listener,
        WorkerRegistry::new(),
        Arc::new(Metrics::default()),
        RetentionReadiness::for_test(true),
        SubscriptionCleanupReadiness::default(),
        CancellationToken::new(),
    )
    .await;
    assert_eq!(
        result.unwrap_err().to_string(),
        "maintenance health listener must remain loopback-only",
        "loopback authority"
    );

    let fixture = HealthFixture::start().await;
    let mut clients = Vec::new();
    for _ in 0..16 {
        let mut client = TcpStream::connect(fixture.address).await.unwrap();
        client
            .write_all(b"GET /readyz HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        clients.push(client);
    }
    // Accepts are ordered on this one listener. The next connection must be
    // closed before the two second request deadline can free an existing slot.
    let mut extra = TcpStream::connect(fixture.address).await.unwrap();
    let mut rejected = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), extra.read_to_end(&mut rejected))
        .await
        .expect("sixteen connection budget did not reject immediately")
        .unwrap();
    assert!(rejected.is_empty(), "sixteen connection budget");
    tokio::time::timeout(Duration::from_secs(3), async {
        for mut client in clients {
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(
                response.is_empty(),
                "incomplete request expires without a response"
            );
        }
    })
    .await
    .expect("two second request deadline did not release incomplete connections");
    assert_eq!(
        response_body(
            &fixture.request(b"GET /healthz HTTP/1.1\r\n\r\n").await,
            "200 OK",
        ),
        "ok\n",
        "expired requests release connection permits"
    );
    fixture.stop().await;
}
