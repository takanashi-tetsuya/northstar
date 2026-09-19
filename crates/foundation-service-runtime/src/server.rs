//! Transport-neutral server assembly hooks.

use crate::{
    admin_http::HealthHttpServer, dependencies::DependencyRegistry, health::ServiceHealth,
};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcServerOptions {
    pub max_concurrent_streams: u32,
    pub request_timeout: Duration,
    pub max_decoding_message_size: usize,
    pub max_encoding_message_size: usize,
}

impl GrpcServerOptions {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.max_concurrent_streams == 0 {
            return Err("max_concurrent_streams must be non-zero");
        }
        if self.request_timeout.is_zero() {
            return Err("request_timeout must be non-zero");
        }
        if self.max_decoding_message_size == 0 || self.max_encoding_message_size == 0 {
            return Err("message limits must be non-zero");
        }
        Ok(self)
    }

    /// Apply protocol-neutral safety limits to a Tonic transport builder.
    /// Service-specific generated handlers are added by the owning binary.
    pub fn apply(self, builder: tonic::transport::Server) -> tonic::transport::Server {
        builder
            .timeout(self.request_timeout)
            .max_concurrent_streams(self.max_concurrent_streams)
    }
}

impl Default for GrpcServerOptions {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 256,
            request_timeout: Duration::from_secs(5),
            max_decoding_message_size: 1024 * 1024,
            max_encoding_message_size: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    request_id: String,
    deadline: Option<std::time::SystemTime>,
}

impl RequestContext {
    pub fn new(
        request_id: impl Into<String>,
        deadline: Option<std::time::SystemTime>,
    ) -> Option<Self> {
        let request_id = request_id.into();
        (!request_id.trim().is_empty() && request_id.len() <= 128).then_some(Self {
            request_id,
            deadline,
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn deadline(&self) -> Option<std::time::SystemTime> {
        self.deadline
    }

    pub fn is_expired(&self, now: std::time::SystemTime) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }
}

/// The runtime owns listener and lifecycle wiring; a service supplies its
/// protocol handler separately.  This prevents handlers from opening ad-hoc
/// listeners or bypassing readiness/drain state.
pub struct ServerBuilder {
    health: ServiceHealth,
    dependencies: DependencyRegistry,
    admin_listener: Option<TcpListener>,
}

impl ServerBuilder {
    pub fn new(health: ServiceHealth, dependencies: DependencyRegistry) -> Self {
        Self {
            health,
            dependencies,
            admin_listener: None,
        }
    }

    pub fn with_admin_listener(mut self, listener: TcpListener) -> Self {
        self.admin_listener = Some(listener);
        self
    }

    pub fn build(self) -> Result<Server, std::io::Error> {
        Ok(Server {
            health_server: HealthHttpServer::new(self.health, self.dependencies),
            admin_listener: self.admin_listener,
        })
    }
}

pub struct Server {
    health_server: HealthHttpServer,
    admin_listener: Option<TcpListener>,
}

pub fn tonic_builder(options: GrpcServerOptions) -> Result<tonic::transport::Server, &'static str> {
    options
        .validate()
        .map(|validated| validated.apply(tonic::transport::Server::builder()))
}

impl Server {
    pub async fn serve_health(self, shutdown: watch::Receiver<bool>) -> std::io::Result<()> {
        match self.admin_listener {
            Some(listener) => self.health_server.serve(listener, shutdown).await,
            None => {
                let _ = shutdown;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_options_fail_closed_and_context_is_bounded() {
        assert!(GrpcServerOptions {
            max_concurrent_streams: 0,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(GrpcServerOptions::default().validate().is_ok());
        assert!(RequestContext::new("", None).is_none());
        assert!(RequestContext::new("req-1", None).is_some());
        let deadline = std::time::SystemTime::now();
        let context = RequestContext::new("req-2", Some(deadline)).unwrap();
        assert!(context.is_expired(deadline));
    }
}
