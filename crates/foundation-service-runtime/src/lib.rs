//! Northstar standard microservice runtime, configuration and health lifecycle.
//!
//! Defined per `northstar_progress_and_next_plan_2026-09-04.md` and
//! `northstar_progress_revalidation_and_next_plan_2026-09-04_85109d4.md` (Section 3.4).

pub mod admin_http;
pub mod authz;
pub mod client;
pub mod config;
pub mod dependencies;
pub mod health;
pub mod limits;
pub mod server;
pub mod shutdown;
pub mod signal;
pub mod task_group;
pub mod tls;
pub mod workload_identity;

pub use authz::{
    AuthorizationDecision, AuthorizationError, AuthorizationInput, AuthorizationRegistry,
    RpcMethodPolicy,
};
pub use client::{CircuitBreaker, CircuitState, ClientPolicyError, RetryPolicy};
pub use config::ServiceConfig;
pub use config::{ConfigError, ServiceProfile};
pub use dependencies::{DependencyRegistry, DependencyState};
pub use health::ServiceHealth;
pub use shutdown::ShutdownCoordinator;
pub use task_group::{WorkerCriticality, WorkerGroup};
pub use tls::{MtlsPolicy, MtlsPolicyError};
pub use workload_identity::{SpiffeId, TrustDomain, VerifiedWorkload, WorkloadIdentityError};

use std::time::Duration;
use tokio::sync::broadcast;

pub struct ServiceRuntime {
    pub config: ServiceConfig,
    pub health: ServiceHealth,
    shutdown_coordinator: ShutdownCoordinator,
}

impl ServiceRuntime {
    pub fn new(config: ServiceConfig) -> Self {
        let drain_timeout = Duration::from_secs(config.drain_timeout_secs);
        Self {
            config,
            health: ServiceHealth::new(),
            shutdown_coordinator: ShutdownCoordinator::new(drain_timeout),
        }
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_coordinator.subscribe()
    }

    pub fn trigger_shutdown(&self) {
        self.health.set_ready(false);
        self.shutdown_coordinator.trigger();
    }

    pub async fn wait_for_shutdown_signal(&self) {
        signal::wait_for_termination_signal().await;
        // Drop readiness immediately on shutdown initiation so load balancers divert new traffic
        self.health.set_ready(false);
        tracing::info!(service = %self.config.service_id, "Shutdown signal received, initiating graceful drain");
        self.trigger_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runtime_health_and_shutdown_lifecycle() {
        let config = ServiceConfig::new("test-service", 8080);
        let runtime = ServiceRuntime::new(config);

        assert!(runtime.health.is_live());
        assert!(!runtime.health.is_ready());

        // Component marks readiness when started
        runtime.health.set_ready(true);
        assert!(runtime.health.is_ready());

        let mut sub = runtime.subscribe_shutdown();
        runtime.trigger_shutdown();

        // Readiness must drop to false on shutdown
        assert!(!runtime.health.is_ready());
        assert!(sub.recv().await.is_ok());
    }
}
