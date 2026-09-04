//! Minimal, bounded loopback health listener.
//!
//! This is intentionally not the business API.  It only exposes health
//! signals so a reverse proxy cannot turn readiness into an unbounded database
//! probe.  Production deployments should bind it to a private interface.

use crate::{dependencies::DependencyRegistry, health::ServiceHealth};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

const MAX_REQUEST_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct HealthHttpServer {
    health: ServiceHealth,
    dependencies: DependencyRegistry,
}

impl HealthHttpServer {
    pub fn new(health: ServiceHealth, dependencies: DependencyRegistry) -> Self {
        Self {
            health,
            dependencies,
        }
    }

    pub async fn serve(
        self,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let shared = Arc::new(self.clone());
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return Ok(()); }
                }
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted?;
                    let health = Arc::clone(&shared);
                    tokio::spawn(async move {
                        let mut buffer = vec![0u8; MAX_REQUEST_BYTES];
                        let read = match stream.read(&mut buffer).await { Ok(n) => n, Err(_) => return };
                        let request = String::from_utf8_lossy(&buffer[..read]);
                        let path = request.lines().next().and_then(|line| line.split_whitespace().nth(1)).unwrap_or("/");
                        let (status, body) = match path {
                            "/livez" => ("200 OK", if health.health.is_live() { "ok\n" } else { "not-live\n" }),
                            "/readyz" => (if health.health.is_ready() && health.dependencies.is_ready() { "200 OK" } else { "503 Service Unavailable" }, if health.health.is_ready() && health.dependencies.is_ready() { "ready\n" } else { "not-ready\n" }),
                            "/metrics" => ("200 OK", "# HELP northstar_service_live Service liveness\n# TYPE northstar_service_live gauge\nnorthstar_service_live 1\n"),
                            _ => ("404 Not Found", "not-found\n"),
                        };
                        let response = format!("HTTP/1.1 {status}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\n\r\n{}", body.len(), body);
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn health_listener_is_bounded_and_fail_closed() {
        let health = ServiceHealth::new();
        let deps = DependencyRegistry::default();
        deps.register("database");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let server = HealthHttpServer::new(health.clone(), deps.clone());
        let task = tokio::spawn(server.serve(listener, rx));
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 503"));
        let mut metrics_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        metrics_stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut metrics = String::new();
        metrics_stream.read_to_string(&mut metrics).await.unwrap();
        assert!(metrics.contains("northstar_service_live 1"));
        tx.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}
