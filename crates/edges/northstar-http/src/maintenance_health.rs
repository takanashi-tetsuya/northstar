//! The maintenance subserver's private loopback health listener: `/healthz`, `/readyz` and
//! `/metrics` with bounded concurrency, header size and request deadline.

use anyhow::Result;
use northstar_operations_application::retention_worker::RetentionReadiness;
use northstar_pubsub_application::subscription_cleanup::SubscriptionCleanupReadiness;
use northstar_runtime::workers::WorkerRegistry;
use northstar_telemetry::metrics::Metrics;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

pub async fn private_health(
    listener: TcpListener,
    workers: Arc<WorkerRegistry>,
    metrics: Arc<Metrics>,
    retention_readiness: RetentionReadiness,
    subscription_readiness: SubscriptionCleanupReadiness,
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
                let subscription_readiness = subscription_readiness.clone();
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
                            "GET /readyz HTTP/1.1" | "GET /readyz HTTP/1.0" if retention_readiness.is_ready() && subscription_readiness.is_ready() && workers.readiness_error().is_none() => ("200 OK", "ready\n".to_owned()),
                            "GET /readyz HTTP/1.1" | "GET /readyz HTTP/1.0" => ("503 Service Unavailable", "maintenance-not-ready\n".to_owned()),
                            "GET /metrics HTTP/1.1" | "GET /metrics HTTP/1.0" => ("200 OK", metrics.render() + &northstar_telemetry::logging::render_metrics()),
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
