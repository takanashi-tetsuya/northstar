//! Microservice configuration loader with secret file and environment support.

use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Clone)]
pub struct ServiceConfig {
    pub service_id: String,
    pub host: String,
    pub port: u16,
    pub database_url: Option<String>,
    pub kafka_brokers: Option<String>,
    pub environment: String,
    pub drain_timeout_secs: u64,
}

impl ServiceConfig {
    pub fn new(service_id: impl Into<String>, default_port: u16) -> Self {
        let service_id = service_id.into();
        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);

        let database_url = Self::read_secret("DATABASE_URL", "DATABASE_URL_FILE");
        let kafka_brokers = Self::read_secret("KAFKA_BROKERS", "KAFKA_BROKERS_FILE");
        let environment =
            std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let drain_timeout_secs = std::env::var("DRAIN_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(15);

        Self {
            service_id,
            host,
            port,
            database_url,
            kafka_brokers,
            environment,
            drain_timeout_secs,
        }
    }

    fn read_secret(direct_var: &str, file_var: &str) -> Option<String> {
        if let Ok(val) = std::env::var(direct_var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        if let Ok(file_path) = std::env::var(file_var) {
            let p = Path::new(&file_path);
            if p.is_file() {
                if let Ok(content) = fs::read_to_string(p) {
                    let trimmed = content.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
        None
    }
}

impl fmt::Debug for ServiceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_db = self.database_url.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("ServiceConfig")
            .field("service_id", &self.service_id)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database_url", &redacted_db)
            .field("kafka_brokers", &self.kafka_brokers)
            .field("environment", &self.environment)
            .field("drain_timeout_secs", &self.drain_timeout_secs)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_port_and_secret_redaction() {
        let config = ServiceConfig::new("test-svc", 8080);
        assert_eq!(config.service_id, "test-svc");
        assert_eq!(config.port, 8080);
        let debug_str = format!("{config:?}");
        assert!(!debug_str.contains("password"));
        if config.database_url.is_some() {
            assert!(debug_str.contains("[REDACTED]"));
        }
    }
}
