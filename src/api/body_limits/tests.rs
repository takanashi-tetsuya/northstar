use super::*;
use crate::{
    api::{ApiEmpty, ApiJson},
    state::http_body_admission::HttpBodyAdmission,
};
use axum::{
    routing::{delete, post, put},
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    net::IpAddr,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};

struct Fixture {
    address: SocketAddr,
    admission: Arc<HttpBodyAdmission>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fixture {
    async fn start(admission: Arc<HttpBodyAdmission>, trusted: Vec<IpAddr>) -> Self {
        let policy =
            HttpTransportPolicy::new(trusted, Arc::new(AtomicU64::new(0)), admission.clone());
        let router = Router::new()
            .route(
                "/api/v1/login",
                post(|body: ApiJson<Value>| async move { Json(body.value) }),
            )
            .route("/api/v1/empty", delete(|_: ApiEmpty| async { "empty" }))
            .route(
                "/api/v1/passkeys/login/start",
                post(|Json(body): Json<Value>| async { Json(body) }),
            )
            .route(
                "/api/v1/upload/{id}",
                put(raw_body).delete(|_: ApiEmpty| async { "empty" }),
            )
            .route("/http-bind", post(raw_body))
            .route("/bosh", post(raw_body))
            .route(
                "/api/v1/slow-handler",
                post(|_: ApiJson<Value>| async {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    "handler completed"
                }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = crate::api::common_http_layers(router, policy, true);
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            address,
            admission,
            task,
        }
    }

    async fn open(
        &self,
        method: &str,
        path: &str,
        headers: &str,
        body: &[u8],
        source: &str,
    ) -> TcpStream {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
        let mut socket = socket.connect(self.address).await.unwrap();
        socket.set_nodelay(true).unwrap();
        socket.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{headers}\r\n").as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
        socket
    }

    async fn active(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.admission.active().0 != expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        if expected == 0 {
            assert_eq!(self.admission.active(), (0, 0));
        }
    }
}

async fn raw_body(body: Body) -> Json<Value> {
    Json(json!({"bytes": to_bytes(body, 1024 * 1024).await.unwrap().len()}))
}

async fn response(mut socket: TcpStream, status: u16) -> String {
    let mut bytes = Vec::new();
    // EOF is part of the assertion: a response followed by a retained slow
    // HTTP/1 body is not successful mitigation.
    tokio::time::timeout(Duration::from_secs(4), socket.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(bytes).unwrap();
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status} ")),
        "{response}"
    );
    response
}

fn limits(total: usize, per_ip: usize, milliseconds: u64) -> Arc<HttpBodyAdmission> {
    Arc::new(HttpBodyAdmission::new(
        total,
        per_ip,
        Duration::from_millis(milliseconds),
    ))
}

#[tokio::test]
async fn incomplete_unauthenticated_bodies_expire_for_all_rest_extractors() {
    let fixture = Fixture::start(limits(4, 2, 200), vec![]).await;
    for (method, path) in [
        ("POST", "/api/v1/login"),
        ("POST", "/api/v1/passkeys/login/start"),
        ("DELETE", "/api/v1/empty"),
        ("DELETE", "/api/v1/upload/test"),
    ] {
        let socket = fixture
            .open(method, path, "Content-Length: 128\r\n", b"{", "127.0.0.1")
            .await;
        let result = response(socket, 408).await;
        assert!(result.contains("\"code\":\"request_timeout\""));
        assert!(result.contains("connection: close"));
        assert!(result.contains("x-request-id:"));
        assert!(result.contains("cache-control: no-store"));
        fixture.active(0).await;
    }
}

#[tokio::test]
async fn trickled_chunks_cannot_extend_the_absolute_deadline() {
    let fixture = Fixture::start(limits(2, 1, 250), vec![]).await;
    let socket = fixture
        .open(
            "POST",
            "/api/v1/login",
            "Transfer-Encoding: chunked\r\n",
            b"1\r\n[\r\n",
            "127.0.0.1",
        )
        .await;
    let (mut read, mut write) = socket.into_split();
    let writer = tokio::spawn(async move {
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if write.write_all(b"1\r\n \r\n").await.is_err() {
                break;
            }
        }
    });
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), read.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    writer.abort();
    assert!(bytes.starts_with(b"HTTP/1.1 408 "));
    fixture.active(0).await;
}

#[tokio::test]
async fn fragmented_json_and_chunked_empty_bodies_succeed() {
    let fixture = Fixture::start(limits(2, 1, 1000), vec![]).await;
    for path in ["/api/v1/login", "/api/v1/passkeys/login/start"] {
        let mut socket = fixture
            .open(
                "POST",
                path,
                "Transfer-Encoding: chunked\r\nConnection: close\r\n",
                b"1\r\n{\r\n",
                "127.0.0.1",
            )
            .await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        socket
            .write_all(b"9\r\n\"ok\":true\r\n1\r\n}\r\n0\r\n\r\n")
            .await
            .unwrap();
        assert!(response(socket, 200).await.contains("\"ok\":true"));
    }
    let mut socket = fixture
        .open(
            "DELETE",
            "/api/v1/empty",
            "Transfer-Encoding: chunked\r\nConnection: close\r\n",
            b"",
            "127.0.0.1",
        )
        .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    socket.write_all(b"0\r\n\r\n").await.unwrap();
    response(socket, 200).await;
    fixture.active(0).await;
}

#[tokio::test]
async fn global_and_source_limits_reject_without_waiting_and_disconnect_releases_them() {
    let admission = limits(2, 1, 3000);
    let fixture = Fixture::start(admission.clone(), vec![]).await;
    // The second listener shares the same process budget.
    let second = Fixture::start(admission, vec![]).await;
    let first = fixture
        .open(
            "POST",
            "/api/v1/login",
            "Content-Length: 128\r\n",
            b"{",
            "127.0.0.1",
        )
        .await;
    fixture.active(1).await;
    let denied = second
        .open(
            "POST",
            "/api/v1/login",
            "Content-Length: 128\r\nX-Forwarded-For: 198.51.100.2\r\n",
            b"{",
            "127.0.0.1",
        )
        .await;
    let result = tokio::time::timeout(Duration::from_secs(1), response(denied, 429))
        .await
        .unwrap();
    assert!(result.contains("retry-after: 1"));
    let other = second
        .open(
            "POST",
            "/api/v1/login",
            "Content-Length: 128\r\n",
            b"{",
            "127.0.0.2",
        )
        .await;
    fixture.active(2).await;
    let denied = fixture
        .open(
            "POST",
            "/api/v1/login",
            "Content-Length: 128\r\n",
            b"{",
            "127.0.0.3",
        )
        .await;
    tokio::time::timeout(Duration::from_secs(1), response(denied, 429))
        .await
        .unwrap();
    drop(first);
    drop(other);
    fixture.active(0).await;
    let socket = second
        .open(
            "POST",
            "/api/v1/login",
            "Content-Length: 2\r\nConnection: close\r\n",
            b"{}",
            "127.0.0.1",
        )
        .await;
    response(socket, 200).await;
}

#[tokio::test]
async fn trusted_proxy_identity_is_used_but_duplicate_forwarding_cannot_split_a_source() {
    let fixture = Fixture::start(limits(4, 1, 3000), vec!["127.0.0.1".parse().unwrap()]).await;
    let first = fixture
        .open(
            "POST",
            "/api/v1/login",
            "Content-Length: 128\r\nX-Forwarded-For: 198.51.100.1\r\n",
            b"{",
            "127.0.0.1",
        )
        .await;
    fixture.active(1).await;
    let other = fixture
        .open(
            "POST",
            "/api/v1/login",
            "Content-Length: 128\r\nX-Forwarded-For: 198.51.100.2\r\n",
            b"{",
            "127.0.0.1",
        )
        .await;
    fixture.active(2).await;
    let ambiguous = fixture.open("POST", "/api/v1/login", "Content-Length: 128\r\nX-Forwarded-For: 198.51.100.3\r\nX-Forwarded-For: 198.51.100.4\r\n", b"{", "127.0.0.1").await;
    fixture.active(3).await;
    let denied = fixture.open("POST", "/api/v1/login", "Content-Length: 128\r\nX-Forwarded-For: 198.51.100.5\r\nX-Forwarded-For: 198.51.100.6\r\n", b"{", "127.0.0.1").await;
    response(denied, 429).await;
    drop((first, other, ambiguous));
    fixture.active(0).await;
}

#[tokio::test]
async fn body_errors_reclaim_admission_and_oversized_streams_close() {
    let fixture = Fixture::start(limits(2, 1, 3000), vec![]).await;
    let mut socket = fixture
        .open(
            "POST",
            "/api/v1/login",
            "Transfer-Encoding: chunked\r\n",
            b"40001\r\n",
            "127.0.0.1",
        )
        .await;
    socket
        .write_all(&vec![b'x'; super::super::API_BODY_LIMIT_BYTES + 1])
        .await
        .unwrap();
    response(socket, 413).await;
    fixture.active(0).await;
    for (path, body) in [("/api/v1/login", "bad"), ("/api/v1/empty", "x")] {
        let method = if path.ends_with("empty") {
            "DELETE"
        } else {
            "POST"
        };
        let socket = fixture
            .open(
                method,
                path,
                &format!("Content-Length: {}\r\nConnection: close\r\n", body.len()),
                body.as_bytes(),
                "127.0.0.1",
            )
            .await;
        response(socket, 400).await;
        fixture.active(0).await;
    }
}

#[tokio::test]
async fn streaming_routes_and_handler_work_are_not_given_the_rest_read_deadline() {
    let fixture = Fixture::start(limits(1, 1, 100), vec![]).await;
    for (method, path) in [
        ("PUT", "/api/v1/upload/test"),
        ("POST", "/http-bind"),
        ("POST", "/bosh"),
    ] {
        let mut socket = fixture
            .open(
                method,
                path,
                "Content-Length: 300000\r\nConnection: close\r\n",
                b"",
                "127.0.0.1",
            )
            .await;
        tokio::time::sleep(Duration::from_millis(180)).await;
        assert_eq!(fixture.admission.active(), (0, 0));
        socket.write_all(&vec![b'x'; 300000]).await.unwrap();
        assert!(response(socket, 200).await.contains("300000"));
    }
    let socket = fixture
        .open(
            "POST",
            "/api/v1/slow-handler",
            "Content-Length: 2\r\nConnection: close\r\n",
            b"{}",
            "127.0.0.1",
        )
        .await;
    assert!(response(socket, 200).await.contains("handler completed"));
}

#[tokio::test]
async fn cancelled_task_and_ipv4_mapped_sources_do_not_leak_or_bypass_permits() {
    let admission = limits(2, 1, 1000);
    let permit = admission.try_acquire("127.0.0.1".parse().unwrap()).unwrap();
    assert!(admission
        .try_acquire("::ffff:127.0.0.1".parse().unwrap())
        .is_none());
    let task = tokio::spawn(async move {
        let _permit = permit;
        std::future::pending::<()>().await;
    });
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(admission.active(), (0, 0));
    let response = reject(Version::HTTP_2, AppError::RequestTimeout);
    assert!(!response.headers().contains_key(header::CONNECTION));
}
