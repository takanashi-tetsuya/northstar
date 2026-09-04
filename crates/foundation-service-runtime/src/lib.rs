//! Northstar standard microservice runtime, configuration and health lifecycle.
//!
//! Defined per `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, Section 5).

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub service_id: String,
    pub host: String,
    pub port: u16,
    pub database_url: Option<String>,
    pub kafka_brokers: Option<String>,
    pub environment: String,
}

impl ServiceConfig {
    pub fn new(service_id: impl Into<String>, port: u16) -> Self {
        Self {
            service_id: service_id.into(),
            host: "0.0.0.0".to_string(),
            port,
            database_url: std::env::var("DATABASE_URL").ok(),
            kafka_brokers: std::env::var("KAFKA_BROKERS").ok(),
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServiceHealth {
    is_live: Arc<AtomicBool>,
    is_ready: Arc<AtomicBool>,
}

impl ServiceHealth {
    pub fn new() -> Self {
        Self {
            is_live: Arc::new(AtomicBool::new(true)),
            is_ready: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn set_ready(&self, ready: bool) {
        self.is_ready.store(ready, Ordering::SeqCst);
    }

    pub fn set_live(&self, live: bool) {
        self.is_live.store(live, Ordering::SeqCst);
    }

    pub fn is_ready(&self) -> bool {
        self.is_ready.load(Ordering::SeqCst)
    }

    pub fn is_live(&self) -> bool {
        self.is_live.load(Ordering::SeqCst)
    }
}

impl Default for ServiceHealth {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ServiceRuntime {
    pub config: ServiceConfig,
    pub health: ServiceHealth,
    shutdown_tx: broadcast::Sender<()>,
}

impl ServiceRuntime {
    pub fn new(config: ServiceConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            config,
            health: ServiceHealth::new(),
            shutdown_tx,
        }
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub async fn wait_for_shutdown_signal(&self) {
        // Wait for OS shutdown signal (SIGINT / Ctrl+C)
        let _ = tokio::signal::ctrl_c().await;
        self.health.set_ready(false);
        tracing::info!(service = %self.config.service_id, "Shutdown signal received, initiating graceful drain");
        self.trigger_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runtime_health_and_shutdown() {
        let config = ServiceConfig::new("test-service", 8080);
        let runtime = ServiceRuntime::new(config);

        assert!(runtime.health.is_live());
        assert!(runtime.health.is_ready());

        let mut sub = runtime.subscribe_shutdown();
        runtime.health.set_ready(false);
        assert!(!runtime.health.is_ready());

        runtime.trigger_shutdown();
        assert!(sub.recv().await.is_ok());
    }
}
