//! Runtime pool budget, Redis transport and shared cluster and authentication secret validation.

use super::*;
use subtle::ConstantTimeEq;

pub(super) fn validate_runtime_pool_budget(
    max_connections: u32,
    min_connections: u32,
) -> Result<()> {
    if !(DATABASE_PRIMARY_POOL_MIN_CONNECTIONS..=DATABASE_MAX_CONNECTIONS_LIMIT)
        .contains(&max_connections)
        || min_connections > max_connections
    {
        anyhow::bail!(
            "DATABASE_MAX_CONNECTIONS must be between {DATABASE_PRIMARY_POOL_MIN_CONNECTIONS} and {DATABASE_MAX_CONNECTIONS_LIMIT}; \
             the remaining {RUNTIME_ROLE_RESERVED_CONNECTIONS} of the runtime role's \
             {RUNTIME_ROLE_CONNECTION_LIMIT} connection limit are reserved for OMEMO recovery, \
             SM authority LISTEN, and durable service control, and DATABASE_MIN_CONNECTIONS \
             must not exceed DATABASE_MAX_CONNECTIONS"
        );
    }
    Ok(())
}

pub(super) fn validate_redis_transport(
    redis_url: Option<&str>,
    ca_cert: Option<&std::path::Path>,
    client_cert: Option<&std::path::Path>,
    client_key: Option<&std::path::Path>,
) -> Result<()> {
    if client_cert.is_some() != client_key.is_some() {
        anyhow::bail!(
            "REDIS_TLS_CLIENT_CERT_PATH and REDIS_TLS_CLIENT_KEY_PATH must be set together"
        );
    }
    let tls_files = ca_cert.is_some() || client_cert.is_some();
    let Some(redis_url) = redis_url else {
        if tls_files {
            anyhow::bail!("Redis TLS certificate paths require REDIS_URL");
        }
        return Ok(());
    };
    let url = redis::parse_redis_url(redis_url)
        .context("REDIS_URL must be a valid redis, rediss, or local Unix-socket URL")?;
    if url.fragment().is_some() {
        anyhow::bail!("REDIS_URL fragments, including insecure TLS mode, are forbidden");
    }
    match url.scheme() {
        "rediss" | "valkeys" => Ok(()),
        "redis" | "valkey" => {
            if tls_files {
                anyhow::bail!("Redis TLS certificate paths require a rediss:// URL");
            }
            let host = url
                .host_str()
                .context("REDIS_URL TCP endpoints require a host")?;
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host
                    .to_ascii_lowercase()
                    .strip_suffix(".localhost")
                    .is_some_and(|prefix| !prefix.is_empty())
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
            if !loopback {
                anyhow::bail!(
                    "unencrypted redis:// is permitted only for an explicit loopback host; use rediss://"
                );
            }
            Ok(())
        }
        "redis+unix" | "valkey+unix" | "unix" => {
            if tls_files {
                anyhow::bail!("Redis TLS certificate paths cannot be used with a Unix socket");
            }
            Ok(())
        }
        _ => anyhow::bail!("REDIS_URL uses an unsupported scheme"),
    }
}

pub(super) fn redis_endpoint_is_local(redis_url: Option<&str>) -> Result<bool> {
    let Some(redis_url) = redis_url else {
        return Ok(true);
    };
    let url = redis::parse_redis_url(redis_url)
        .context("REDIS_URL must be a valid redis, rediss, or local Unix-socket URL")?;
    match url.scheme() {
        "redis" | "rediss" | "valkey" | "valkeys" => {
            Ok(url.host_str().is_some_and(web_origin_host_is_loopback))
        }
        "redis+unix" | "valkey+unix" | "unix" => Ok(true),
        _ => anyhow::bail!("REDIS_URL uses an unsupported scheme"),
    }
}

pub(super) fn validate_cluster_dialback_secret(
    clustered: bool,
    dialback_enabled: bool,
    secret_file: Option<&std::path::Path>,
) -> Result<()> {
    if clustered && dialback_enabled && secret_file.is_none() {
        anyhow::bail!(
            "Redis cluster mode with DIALBACK_ENABLED requires DIALBACK_SECRET_FILE so every node verifies the same callback key"
        );
    }
    Ok(())
}

pub(super) fn validate_cluster_fast_secret(
    clustered: bool,
    secret_file: Option<&std::path::Path>,
) -> Result<()> {
    if clustered && secret_file.is_none() {
        anyhow::bail!(
            "Redis cluster mode requires FAST_TOKEN_SECRET_FILE so every node verifies the same XEP-0484 tokens"
        );
    }
    Ok(())
}

pub(super) fn validate_shared_runtime_secret(name: &str, secret: Option<&str>) -> Result<()> {
    if secret
        .is_some_and(|secret| secret.len() < 32 || secret.len() > 4096 || secret.contains('\0'))
    {
        anyhow::bail!("{name} must contain 32 to 4096 bytes without NUL");
    }
    Ok(())
}

pub(super) fn ephemeral_development_secret_allowed(
    opted_in: bool,
    redis_configured: bool,
    listeners_are_loopback: bool,
    reserved_development_domain: bool,
) -> bool {
    opted_in && !redis_configured && listeners_are_loopback && reserved_development_domain
}

pub(super) fn authentication_master_secrets_are_independent(
    fast: Option<&str>,
    dummy_scram: Option<&str>,
) -> bool {
    !fast.is_some_and(|fast| {
        dummy_scram.is_some_and(|dummy| bool::from(fast.as_bytes().ct_eq(dummy.as_bytes())))
    })
}
