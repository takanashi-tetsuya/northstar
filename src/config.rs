use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

#[derive(Clone, Deserialize)]
pub struct RawConfig {
    #[serde(default = "default_domain")]
    pub xmpp_domain: String,

    #[serde(default)]
    pub database_url: String,

    pub database_url_file: Option<PathBuf>,

    #[serde(default = "default_db_max_connections")]
    pub database_max_connections: u32,

    #[serde(default = "default_db_min_connections")]
    pub database_min_connections: u32,

    #[serde(default = "default_scram_iterations")]
    pub scram_iterations: u32,

    #[serde(default = "default_sm_resume_timeout")]
    pub sm_resume_timeout_seconds: u64,

    #[serde(default = "default_offline_message_ttl")]
    pub offline_message_ttl_days: i64,

    #[serde(default = "default_xmpp_bind")]
    pub xmpp_bind: SocketAddr,

    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,

    #[serde(default = "default_tls_cert_path")]
    pub tls_cert_path: PathBuf,

    #[serde(default = "default_tls_key_path")]
    pub tls_key_path: PathBuf,

    #[serde(default = "default_true")]
    pub open_registration: bool,

    #[serde(default = "default_true")]
    pub require_encrypted_archive: bool,

    #[serde(default = "default_registration_rate")]
    pub registration_rate_per_hour: u32,

    #[serde(default = "default_false")]
    pub invitation_required: bool,

    #[serde(default = "default_pow_base")]
    pub pow_base_work_factor: u64,

    #[serde(default = "default_pow_max")]
    pub pow_max_work_factor: u64,

    #[serde(default = "default_abuse_window")]
    pub abuse_window_seconds: u64,

    #[serde(default = "default_abuse_cooldown")]
    pub abuse_cooldown_seconds: u64,

    #[serde(default = "default_abuse_wait")]
    pub abuse_max_wait_seconds: u64,

    #[serde(default = "default_trusted_ips")]
    pub trusted_proxy_ips: String,

    #[serde(default = "default_session_ttl")]
    pub session_ttl_hours: i64,

    pub bootstrap_admin_username: Option<String>,
    pub bootstrap_admin_password: Option<String>,
    pub bootstrap_admin_password_file: Option<PathBuf>,

    pub public_url: Option<String>,

    #[serde(default = "default_upload_dir")]
    pub upload_dir: PathBuf,

    #[serde(default = "default_upload_max")]
    pub upload_max_bytes: u64,

    #[serde(default = "default_s2s_bind")]
    pub s2s_bind: SocketAddr,

    #[serde(default = "default_true")]
    pub federation_enabled: bool,

    #[serde(default)]
    pub federation_allowlist: String,

    #[serde(default)]
    pub federation_denylist: String,

    #[serde(default = "default_false")]
    pub federation_allow_private_ips: bool,

    #[serde(default)]
    pub federation_dns_overrides: String,

    pub federation_extra_root_cert_path: Option<PathBuf>,

    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,

    #[serde(default = "default_log_rotation")]
    pub log_rotation: String,

    #[serde(default = "default_log_format")]
    pub log_format: String,

    #[serde(default = "default_log_retention")]
    pub log_retention_files: usize,
}

// Defaults
fn default_domain() -> String {
    "localhost".to_string()
}
fn default_db_max_connections() -> u32 {
    32
}
fn default_db_min_connections() -> u32 {
    2
}
fn default_scram_iterations() -> u32 {
    crate::auth::DEFAULT_SCRAM_ITERATIONS
}
fn default_sm_resume_timeout() -> u64 {
    300
}
fn default_offline_message_ttl() -> i64 {
    30
}
fn default_xmpp_bind() -> SocketAddr {
    "0.0.0.0:5222".parse().unwrap()
}
fn default_http_bind() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}
fn default_tls_cert_path() -> PathBuf {
    PathBuf::from("certs/server.crt")
}
fn default_tls_key_path() -> PathBuf {
    PathBuf::from("certs/server.key")
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_registration_rate() -> u32 {
    20
}
fn default_pow_base() -> u64 {
    1024
}
fn default_pow_max() -> u64 {
    524288
}
fn default_abuse_window() -> u64 {
    60
}
fn default_abuse_cooldown() -> u64 {
    60
}
fn default_abuse_wait() -> u64 {
    900
}
fn default_trusted_ips() -> String {
    "127.0.0.1,::1".to_string()
}
fn default_session_ttl() -> i64 {
    168
}
fn default_upload_dir() -> PathBuf {
    PathBuf::from("data/uploads")
}
fn default_upload_max() -> u64 {
    26214400
}
fn default_s2s_bind() -> SocketAddr {
    "0.0.0.0:5269".parse().unwrap()
}
fn default_log_dir() -> PathBuf {
    PathBuf::from("logs")
}
fn default_log_rotation() -> String {
    "daily".to_string()
}
fn default_log_format() -> String {
    "text".to_string()
}
fn default_log_retention() -> usize {
    30
}

#[derive(Clone)]
pub struct Config {
    pub raw: RawConfig,
    pub domain: String,
    pub public_url: String,
    pub trusted_proxy_ips: Vec<IpAddr>,
    pub federation_allowlist: Vec<String>,
    pub federation_denylist: Vec<String>,
    pub federation_dns_overrides: Vec<(String, SocketAddr)>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let mut raw: RawConfig =
            envy::from_env().context("Failed to parse config from environment")?;
        raw.database_url_file = non_empty_path(raw.database_url_file.take());
        if let Some(path) = &raw.database_url_file {
            if !raw.database_url.trim().is_empty() {
                anyhow::bail!("set only one of DATABASE_URL and DATABASE_URL_FILE");
            }
            raw.database_url = read_secret_file(path, "DATABASE_URL_FILE")?;
        }
        raw.bootstrap_admin_username = raw
            .bootstrap_admin_username
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.bootstrap_admin_password = raw
            .bootstrap_admin_password
            .take()
            .filter(|value| !value.is_empty());
        raw.bootstrap_admin_password_file =
            non_empty_path(raw.bootstrap_admin_password_file.take());
        if let Some(path) = &raw.bootstrap_admin_password_file {
            if raw.bootstrap_admin_password.is_some() {
                anyhow::bail!(
                    "set only one of BOOTSTRAP_ADMIN_PASSWORD and BOOTSTRAP_ADMIN_PASSWORD_FILE"
                );
            }
            raw.bootstrap_admin_password =
                Some(read_secret_file(path, "BOOTSTRAP_ADMIN_PASSWORD_FILE")?);
        }
        raw.public_url = raw
            .public_url
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.federation_extra_root_cert_path = raw
            .federation_extra_root_cert_path
            .take()
            .filter(|path| !path.as_os_str().is_empty());

        let domain = raw.xmpp_domain.to_ascii_lowercase();
        if !valid_domain(&domain) {
            anyhow::bail!("XMPP_DOMAIN is invalid");
        }
        if raw.database_url.trim().is_empty() {
            anyhow::bail!("DATABASE_URL must not be empty");
        }
        if raw.database_max_connections == 0
            || raw.database_min_connections > raw.database_max_connections
        {
            anyhow::bail!(
                "DATABASE_MAX_CONNECTIONS must be positive and not smaller than DATABASE_MIN_CONNECTIONS"
            );
        }
        if !(crate::auth::MIN_SCRAM_ITERATIONS..=crate::auth::MAX_SCRAM_ITERATIONS)
            .contains(&raw.scram_iterations)
        {
            anyhow::bail!(
                "SCRAM_ITERATIONS must be between {} and {}",
                crate::auth::MIN_SCRAM_ITERATIONS,
                crate::auth::MAX_SCRAM_ITERATIONS
            );
        }
        if !(1..=86_400).contains(&raw.sm_resume_timeout_seconds) {
            anyhow::bail!("SM_RESUME_TIMEOUT_SECONDS must be between 1 and 86400");
        }
        if !(1..=3650).contains(&raw.offline_message_ttl_days) {
            anyhow::bail!("OFFLINE_MESSAGE_TTL_DAYS must be between 1 and 3650");
        }
        if !(1..=8760).contains(&raw.session_ttl_hours) {
            anyhow::bail!("SESSION_TTL_HOURS must be between 1 and 8760");
        }
        if raw.upload_max_bytes == 0 || raw.upload_max_bytes > i64::MAX as u64 {
            anyhow::bail!("UPLOAD_MAX_BYTES must be between 1 and i64::MAX");
        }
        if raw.pow_base_work_factor == 0 || raw.pow_max_work_factor < raw.pow_base_work_factor {
            anyhow::bail!("PoW maximum work factor must be at least the positive base factor");
        }
        if raw.abuse_window_seconds == 0
            || raw.abuse_cooldown_seconds == 0
            || raw.abuse_max_wait_seconds == 0
        {
            anyhow::bail!("anti-abuse window, cooldown and maximum wait must be positive");
        }
        if raw.log_retention_files == 0
            || !matches!(
                raw.log_rotation.to_ascii_lowercase().as_str(),
                "daily" | "hourly" | "minutely" | "never"
            )
        {
            anyhow::bail!("LOG_ROTATION or LOG_RETENTION_FILES is invalid");
        }
        if !matches!(
            raw.log_format.to_ascii_lowercase().as_str(),
            "text" | "json"
        ) {
            anyhow::bail!("LOG_FORMAT must be text or json");
        }
        if raw.bootstrap_admin_username.is_some() != raw.bootstrap_admin_password.is_some() {
            anyhow::bail!(
                "BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD must be set together"
            );
        }

        let default_public_url = if domain == "localhost" {
            format!("http://localhost:{}", raw.http_bind.port())
        } else {
            format!("https://{domain}")
        };
        let public_url = raw
            .public_url
            .clone()
            .unwrap_or(default_public_url)
            .trim_end_matches('/')
            .to_owned();
        if !(public_url.starts_with("http://") || public_url.starts_with("https://"))
            || public_url.chars().any(char::is_whitespace)
        {
            anyhow::bail!("PUBLIC_URL must be an absolute HTTP(S) URL without whitespace");
        }

        if raw.registration_rate_per_hour == 0 {
            anyhow::bail!("REGISTRATION_RATE_PER_HOUR must be greater than zero");
        }

        let trusted_proxy_ips = raw
            .trusted_proxy_ips
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse())
            .collect::<Result<Vec<IpAddr>, _>>()
            .context("invalid trusted proxy IPs")?;

        let federation_allowlist = domain_list(&raw.federation_allowlist);
        let federation_denylist = domain_list(&raw.federation_denylist);
        for pattern in federation_allowlist.iter().chain(&federation_denylist) {
            let candidate = pattern.strip_prefix("*.").unwrap_or(pattern);
            if !valid_domain(candidate) {
                anyhow::bail!("federation allow/deny list contains an invalid domain pattern");
            }
        }

        let mut federation_dns_overrides = Vec::new();
        for entry in raw.federation_dns_overrides.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (d, addr) = entry.split_once('=').context("invalid DNS override")?;
            let d = d.trim().to_ascii_lowercase();
            if !valid_domain(&d) {
                anyhow::bail!("invalid domain in override");
            }
            federation_dns_overrides.push((d, addr.trim().parse().context("invalid address")?));
        }

        Ok(Self {
            raw,
            domain,
            public_url,
            trusted_proxy_ips,
            federation_allowlist,
            federation_denylist,
            federation_dns_overrides,
        })
    }

    pub fn federation_domain_allowed(&self, domain: &str) -> bool {
        if !self.raw.federation_enabled {
            return false;
        }
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if !valid_domain(&domain) || domain == self.domain {
            return false;
        }

        if self
            .federation_denylist
            .iter()
            .any(|pattern| domain_pattern_matches(pattern, &domain))
        {
            return false;
        }
        self.federation_allowlist.is_empty()
            || self
                .federation_allowlist
                .iter()
                .any(|pattern| domain_pattern_matches(pattern, &domain))
    }
}

fn non_empty_path(path: Option<PathBuf>) -> Option<PathBuf> {
    path.filter(|path| !path.as_os_str().is_empty())
}

fn read_secret_file(path: &PathBuf, variable: &str) -> Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("cannot read secret file configured by {variable}"))?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        anyhow::bail!("secret file configured by {variable} must be a regular file under 64 KiB");
    }
    let value = fs::read_to_string(path)
        .with_context(|| format!("cannot read secret file configured by {variable}"))?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.is_empty() || value.contains('\0') {
        anyhow::bail!("secret file configured by {variable} is empty or invalid");
    }
    Ok(value)
}

// Forward raw fields for convenience
impl std::ops::Deref for Config {
    type Target = RawConfig;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn domain_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn domain_pattern_matches(pattern: &str, domain: &str) -> bool {
    pattern == domain
        || pattern
            .strip_prefix("*.")
            .is_some_and(|suffix| domain != suffix && domain.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::read_secret_file;

    #[test]
    fn secret_files_drop_only_the_line_ending() {
        let path = std::env::temp_dir().join(format!(
            "northstar-config-secret-{}.txt",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, "  keep surrounding spaces  \r\n").unwrap();
        let value = read_secret_file(&path, "TEST_SECRET_FILE").unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(value, "  keep surrounding spaces  ");
    }

    #[test]
    fn empty_secret_files_are_rejected() {
        let path = std::env::temp_dir().join(format!(
            "northstar-empty-secret-{}.txt",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, "\r\n").unwrap();
        let error = read_secret_file(&path, "TEST_SECRET_FILE").unwrap_err();
        std::fs::remove_file(path).unwrap();
        assert!(error.to_string().contains("empty or invalid"));
    }
}
