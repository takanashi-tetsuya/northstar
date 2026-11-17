use crate::Config;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};
use zeroize::Zeroizing;

/// The complete retention policy. This value carries no listener, identity,
/// cryptographic key or live-session authority.
#[derive(Clone, Debug)]
pub struct RetentionPolicy {
    pub mam_retention_days: i64,
    pub muc_mam_retention_days: i64,
    pub offline_message_ttl_days: i64,
    pub audit_log_retention_days: i64,
    pub retention_cleanup_batch_size: i64,
    pub retention_cleanup_interval_seconds: u64,
}

impl RetentionPolicy {
    pub fn max_silence(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.retention_cleanup_interval_seconds
                .saturating_mul(2)
                .saturating_add(60),
        )
    }

    pub fn from_config(config: &Config) -> Self {
        Self {
            mam_retention_days: config.mam_retention_days,
            muc_mam_retention_days: config.muc_mam_retention_days,
            offline_message_ttl_days: config.offline_message_ttl_days,
            audit_log_retention_days: config.audit_log_retention_days,
            retention_cleanup_batch_size: config.retention_cleanup_batch_size,
            retention_cleanup_interval_seconds: config.retention_cleanup_interval_seconds,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (0..=3650).contains(&self.offline_message_ttl_days)
                && (0..=36_500).contains(&self.mam_retention_days)
                && (0..=36_500).contains(&self.muc_mam_retention_days),
            "retention days must be zero (disabled) or within the documented maximum"
        );
        anyhow::ensure!(
            (30..=36_500).contains(&self.audit_log_retention_days),
            "AUDIT_LOG_RETENTION_DAYS must be between 30 and 36500"
        );
        anyhow::ensure!(
            (1..=10_000).contains(&self.retention_cleanup_batch_size)
                && (60..=86_400).contains(&self.retention_cleanup_interval_seconds),
            "retention cleanup batch size must be 1..10000 and interval 60..86400 seconds"
        );
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct MaintenanceConfig {
    pub xmpp_domain: String,
    #[serde(default)]
    database_url: String,
    database_url_file: Option<PathBuf>,
    #[serde(default)]
    pub database_allow_unsafe_role_for_development: bool,
    #[serde(default = "default_bind")]
    pub maintenance_bind: SocketAddr,
    #[serde(default = "default_mam_days")]
    mam_retention_days: i64,
    #[serde(default = "default_mam_days")]
    muc_mam_retention_days: i64,
    #[serde(default = "default_offline_days")]
    offline_message_ttl_days: i64,
    #[serde(default = "default_audit_days")]
    audit_log_retention_days: i64,
    #[serde(default = "default_batch")]
    retention_cleanup_batch_size: i64,
    #[serde(default = "default_interval")]
    retention_cleanup_interval_seconds: u64,
}

fn default_bind() -> SocketAddr {
    ([127, 0, 0, 1], 9092).into()
}
fn default_mam_days() -> i64 {
    365
}
fn default_offline_days() -> i64 {
    30
}
fn default_audit_days() -> i64 {
    730
}
fn default_batch() -> i64 {
    1000
}
fn default_interval() -> u64 {
    60
}

impl MaintenanceConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut config: MaintenanceConfig =
            envy::from_env().context("invalid maintenance configuration")?;
        config.xmpp_domain =
            northstar_xmpp_types::jid::prepare_domainpart(config.xmpp_domain.trim())
                .context("invalid XMPP_DOMAIN")?;
        config.validate()?;
        Ok(config)
    }

    pub fn take_database_url(&mut self) -> anyhow::Result<Zeroizing<String>> {
        anyhow::ensure!(
            self.database_url.is_empty() || self.database_url_file.is_none(),
            "set only one of DATABASE_URL and DATABASE_URL_FILE"
        );
        let url = Zeroizing::new(match self.database_url_file.as_ref() {
            Some(path) => {
                northstar_security::secret_files::read_secret_file(path, "DATABASE_URL_FILE")?
            }
            None => std::mem::take(&mut self.database_url),
        });
        anyhow::ensure!(
            !url.trim().is_empty(),
            "maintenance requires DATABASE_URL_FILE or DATABASE_URL"
        );
        Ok(url)
    }

    pub fn policy(&self) -> RetentionPolicy {
        RetentionPolicy {
            mam_retention_days: self.mam_retention_days,
            muc_mam_retention_days: self.muc_mam_retention_days,
            offline_message_ttl_days: self.offline_message_ttl_days,
            audit_log_retention_days: self.audit_log_retention_days,
            retention_cleanup_batch_size: self.retention_cleanup_batch_size,
            retention_cleanup_interval_seconds: self.retention_cleanup_interval_seconds,
        }
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.maintenance_bind.ip().is_loopback(),
            "MAINTENANCE_BIND must use a loopback IP; the maintenance process has no public API"
        );
        anyhow::ensure!(
            self.maintenance_bind.port() != 0,
            "MAINTENANCE_BIND must use a nonzero port"
        );
        self.policy().validate()?;
        if self.database_allow_unsafe_role_for_development {
            anyhow::ensure!(
                crate::reserved_development_domain(&self.xmpp_domain),
                "development database override requires a reserved development domain"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_max_silence_saturates() {
        let config: MaintenanceConfig =
            serde_json::from_value(serde_json::json!({"xmpp_domain":"example.com"})).unwrap();
        let mut policy = config.policy();
        assert_eq!(policy.max_silence(), std::time::Duration::from_secs(180));
        policy.retention_cleanup_interval_seconds = u64::MAX;
        assert_eq!(
            policy.max_silence(),
            std::time::Duration::from_secs(u64::MAX)
        );
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
    fn maintenance_database_url_is_exclusive_and_nonempty() {
        let mut config = MaintenanceConfig {
            xmpp_domain: "example.com".into(),
            database_url: "postgres://localhost/northstar".into(),
            database_url_file: Some(PathBuf::from("database-url")),
            database_allow_unsafe_role_for_development: false,
            maintenance_bind: default_bind(),
            mam_retention_days: default_mam_days(),
            muc_mam_retention_days: default_mam_days(),
            offline_message_ttl_days: default_offline_days(),
            audit_log_retention_days: default_audit_days(),
            retention_cleanup_batch_size: default_batch(),
            retention_cleanup_interval_seconds: default_interval(),
        };
        assert_eq!(
            config.take_database_url().unwrap_err().to_string(),
            "set only one of DATABASE_URL and DATABASE_URL_FILE"
        );

        config.database_url.clear();
        config.database_url_file = None;
        assert_eq!(
            config.take_database_url().unwrap_err().to_string(),
            "maintenance requires DATABASE_URL_FILE or DATABASE_URL"
        );

        config.database_url = " \t\n".into();
        assert_eq!(
            config.take_database_url().unwrap_err().to_string(),
            "maintenance requires DATABASE_URL_FILE or DATABASE_URL"
        );

        config.database_url = "postgres://localhost/northstar".into();
        let url = config.take_database_url().unwrap();
        assert_eq!(url.as_str(), "postgres://localhost/northstar");
        assert!(config.database_url.is_empty());
    }
}
