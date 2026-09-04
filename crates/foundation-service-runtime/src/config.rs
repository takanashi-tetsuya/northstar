//! Microservice configuration loader with secret file and environment support.

use std::fmt;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceProfile {
    Development,
    Production,
}

impl ServiceProfile {
    pub fn from_environment() -> Self {
        match std::env::var("ENVIRONMENT").ok().as_deref() {
            Some("production") | Some("prod") => Self::Production,
            _ => Self::Development,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{0} and {1} cannot both be configured")]
    SecretConflict(&'static str, &'static str),
    #[error("{0} must be a valid non-zero port")]
    InvalidPort(&'static str),
    #[error("{0} must be between 1 and 300 seconds")]
    InvalidDrainTimeout(&'static str),
    #[error("{0} is required in production profile")]
    MissingProductionValue(&'static str),
    #[error("secret file configured by {0} cannot be read")]
    UnreadableSecretFile(&'static str),
    #[error("{0} is not a valid service bind address")]
    InvalidHost(&'static str),
}

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
    /// Load configuration with explicit profile semantics.  Development keeps
    /// ergonomic defaults; production rejects malformed values and never
    /// invents a secret or endpoint.
    pub fn load(
        service_id: impl Into<String>,
        default_port: u16,
        profile: ServiceProfile,
    ) -> Result<Self, ConfigError> {
        let service_id = service_id.into();
        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        if host.trim().is_empty() {
            return Err(ConfigError::InvalidHost("HOST"));
        }
        let port = match std::env::var("PORT") {
            Ok(value) => value
                .parse::<u16>()
                .map_err(|_| ConfigError::InvalidPort("PORT"))?,
            Err(_) if default_port != 0 => default_port,
            Err(_) => return Err(ConfigError::InvalidPort("PORT")),
        };
        if port == 0 {
            return Err(ConfigError::InvalidPort("PORT"));
        }
        let database_url = Self::read_secret_checked("DATABASE_URL", "DATABASE_URL_FILE")?;
        let kafka_brokers = Self::read_secret_checked("KAFKA_BROKERS", "KAFKA_BROKERS_FILE")?;
        let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| {
            if profile == ServiceProfile::Production {
                "production"
            } else {
                "development"
            }
            .to_string()
        });
        let drain_timeout_secs = match std::env::var("DRAIN_TIMEOUT_SECS") {
            Ok(value) => value
                .parse::<u64>()
                .map_err(|_| ConfigError::InvalidDrainTimeout("DRAIN_TIMEOUT_SECS"))?,
            Err(_) => 15,
        };
        if !(1..=300).contains(&drain_timeout_secs) {
            return Err(ConfigError::InvalidDrainTimeout("DRAIN_TIMEOUT_SECS"));
        }
        if profile == ServiceProfile::Production
            && !matches!(environment.as_str(), "production" | "prod")
        {
            return Err(ConfigError::MissingProductionValue(
                "ENVIRONMENT=production",
            ));
        }
        Ok(Self {
            service_id,
            host,
            port,
            database_url,
            kafka_brokers,
            environment,
            drain_timeout_secs,
        })
    }

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

    fn read_secret_checked(
        direct_var: &'static str,
        file_var: &'static str,
    ) -> Result<Option<String>, ConfigError> {
        let direct = std::env::var(direct_var)
            .ok()
            .filter(|v| !v.trim().is_empty());
        let file = std::env::var(file_var)
            .ok()
            .filter(|v| !v.trim().is_empty());
        if direct.is_some() && file.is_some() {
            return Err(ConfigError::SecretConflict(direct_var, file_var));
        }
        if let Some(path) = file {
            let content = fs::read_to_string(path)
                .map_err(|_| ConfigError::UnreadableSecretFile(file_var))?;
            if content.trim().is_empty() {
                return Err(ConfigError::UnreadableSecretFile(file_var));
            }
            return Ok(Some(content.trim().to_string()));
        }
        Ok(direct.map(|value| value.trim().to_owned()))
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
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn config_port_and_secret_redaction() {
        let _guard = env_lock().lock().unwrap();
        let config = ServiceConfig::new("test-svc", 8080);
        assert_eq!(config.service_id, "test-svc");
        assert_eq!(config.port, 8080);
        let debug_str = format!("{config:?}");
        assert!(!debug_str.contains("password"));
        if config.database_url.is_some() {
            assert!(debug_str.contains("[REDACTED]"));
        }
    }

    #[test]
    fn profile_loader_rejects_invalid_port_and_secret_conflict() {
        let _guard = env_lock().lock().unwrap();
        let original_port = std::env::var("PORT").ok();
        let original_url = std::env::var("DATABASE_URL").ok();
        let original_file = std::env::var("DATABASE_URL_FILE").ok();
        std::env::set_var("PORT", "not-a-port");
        assert!(matches!(
            ServiceConfig::load("test-svc", 8080, ServiceProfile::Development),
            Err(ConfigError::InvalidPort("PORT"))
        ));
        std::env::set_var("PORT", "8080");
        std::env::set_var("DATABASE_URL", "postgres://example");
        std::env::set_var("DATABASE_URL_FILE", "C:/does-not-matter");
        assert!(matches!(
            ServiceConfig::load("test-svc", 8080, ServiceProfile::Development),
            Err(ConfigError::SecretConflict(
                "DATABASE_URL",
                "DATABASE_URL_FILE"
            ))
        ));
        match original_port {
            Some(v) => std::env::set_var("PORT", v),
            None => std::env::remove_var("PORT"),
        }
        match original_url {
            Some(v) => std::env::set_var("DATABASE_URL", v),
            None => std::env::remove_var("DATABASE_URL"),
        }
        match original_file {
            Some(v) => std::env::set_var("DATABASE_URL_FILE", v),
            None => std::env::remove_var("DATABASE_URL_FILE"),
        }
    }
}
