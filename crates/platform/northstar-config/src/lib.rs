//! Process configuration for Northstar: loading and validating the environment, secret files, listener plans,
//! component credentials, connection budgets and the configured XEP extension switches.

#![forbid(unsafe_code)]

mod components;
mod defaults;
mod domain_policy;
mod environment;
mod listeners;
mod loading;
mod parsing;
mod raw;
mod runtime_validation;
mod web_origin;

pub use environment::load_dotenv;

pub use self::components::*;
use self::defaults::*;
pub use self::defaults::{DEFAULT_SCRAM_ITERATIONS, MAX_SCRAM_ITERATIONS, MIN_SCRAM_ITERATIONS};
pub use self::domain_policy::*;
use self::listeners::*;
use self::parsing::*;
pub use self::raw::*;
use self::runtime_validation::*;
pub use self::web_origin::*;
use northstar_security::secret_files::{read_protected_utf8_file, read_secret_file};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};

use northstar_web_surface::{
    DownloadCeiling, ListenerConfiguration, RegistrationDependencyLock, RequestedWebCapabilities,
    ResolvedWebCapabilities, UploadRuntimeFacts,
};
pub use northstar_web_surface::{RegistrationMode, UploadMode};

/// PostgreSQL enforces this limit for the shared production runtime role, not
/// for an individual pool.  The primary pool must leave room for every
/// long-lived runtime-role connection owned by this process.
pub const RUNTIME_ROLE_CONNECTION_LIMIT: u32 = 64;
/// The browser OMEMO recovery pool is deliberately separate from traffic so a
/// long poll cannot monopolize normal request connections.
pub const OMEMO_RECOVERY_POOL_MAX_CONNECTIONS: u32 = 2;
/// The SM authority listener owns one dedicated PostgreSQL connection.
pub const SM_AUTHORITY_LISTENER_MAX_CONNECTIONS: u32 = 1;
/// Durable restart/shutdown observation owns one dedicated runtime connection.
pub const SERVICE_CONTROL_POOL_MAX_CONNECTIONS: u32 = 1;
/// Fixed runtime-role reservations outside `DATABASE_MAX_CONNECTIONS`.
pub const RUNTIME_ROLE_RESERVED_CONNECTIONS: u32 = OMEMO_RECOVERY_POOL_MAX_CONNECTIONS
    + SM_AUTHORITY_LISTENER_MAX_CONNECTIONS
    + SERVICE_CONTROL_POOL_MAX_CONNECTIONS;
/// One primary slot remains available to foreground work while one bounded
/// outbox database turn is in progress.  Accepting a one-connection primary
/// pool would make that service guarantee impossible.
pub const DATABASE_PRIMARY_POOL_MIN_CONNECTIONS: u32 = 2;
/// Largest primary-pool size that cannot exceed the runtime role's physical
/// PostgreSQL connection limit on a single process.
pub const DATABASE_MAX_CONNECTIONS_LIMIT: u32 =
    RUNTIME_ROLE_CONNECTION_LIMIT - RUNTIME_ROLE_RESERVED_CONNECTIONS;
/// Upload persistence has a separate PostgreSQL login. A small pool leaves
/// headroom below its role limit for overlapping process shutdown/startup.
pub const STORAGE_POOL_MAX_CONNECTIONS: u32 = 2;
pub const STORAGE_ROLE_CONNECTION_LIMIT: u32 = 16;
pub const STORAGE_MAX_ENABLED_NODES: u32 =
    STORAGE_ROLE_CONNECTION_LIMIT / STORAGE_POOL_MAX_CONNECTIONS;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct StorageConnectionBudgetManifest {
    pub schema_version: u8,
    pub storage_role_connection_limit: u32,
    pub enabled_pool_max_connections_per_node: u32,
    pub disabled_pool_max_connections_per_node: u32,
    pub max_enabled_nodes_at_pool_limit: u32,
}

pub const fn storage_connection_budget_manifest() -> StorageConnectionBudgetManifest {
    StorageConnectionBudgetManifest {
        schema_version: 1,
        storage_role_connection_limit: STORAGE_ROLE_CONNECTION_LIMIT,
        enabled_pool_max_connections_per_node: STORAGE_POOL_MAX_CONNECTIONS,
        disabled_pool_max_connections_per_node: 0,
        max_enabled_nodes_at_pool_limit: STORAGE_MAX_ENABLED_NODES,
    }
}

/// Stable, machine-readable facts for isolated capacity fixtures.
///
/// This is deliberately derived from the same constants that constrain a
/// running server.  Test harnesses must not maintain a second hand-written
/// total for the long-lived runtime pools.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeConnectionBudgetManifest {
    pub schema_version: u8,
    pub runtime_role_connection_limit: u32,
    pub primary_pool_min_connections: u32,
    pub primary_pool_max_connections: u32,
    pub omemo_recovery_pool_max_connections: u32,
    pub sm_authority_listener_max_connections: u32,
    pub service_control_pool_max_connections: u32,
    pub auxiliary_connections: u32,
}

pub const fn runtime_connection_budget_manifest() -> RuntimeConnectionBudgetManifest {
    RuntimeConnectionBudgetManifest {
        schema_version: 1,
        runtime_role_connection_limit: RUNTIME_ROLE_CONNECTION_LIMIT,
        primary_pool_min_connections: DATABASE_PRIMARY_POOL_MIN_CONNECTIONS,
        primary_pool_max_connections: DATABASE_MAX_CONNECTIONS_LIMIT,
        omemo_recovery_pool_max_connections: OMEMO_RECOVERY_POOL_MAX_CONNECTIONS,
        sm_authority_listener_max_connections: SM_AUTHORITY_LISTENER_MAX_CONNECTIONS,
        service_control_pool_max_connections: SERVICE_CONTROL_POOL_MAX_CONNECTIONS,
        auxiliary_connections: RUNTIME_ROLE_RESERVED_CONNECTIONS,
    }
}

/// The command-session capability has a separate PostgreSQL principal in
/// production.  The explicit loopback-only development exception deliberately
/// has no such principal, so it must share the already-attested primary pool
/// rather than create a second pool with the same credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminCommandPoolMode {
    DedicatedProductionRole,
    SharedUnsafeDevelopment,
}

fn resolve_admin_command_pool_mode(
    unsafe_development: bool,
    configured_database_url: &str,
) -> Result<AdminCommandPoolMode> {
    let configured = !configured_database_url.trim().is_empty();
    if unsafe_development {
        anyhow::ensure!(
            !configured,
            "DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT reuses the primary pool and must not set ADMIN_COMMAND_DATABASE_URL or ADMIN_COMMAND_DATABASE_URL_FILE"
        );
        return Ok(AdminCommandPoolMode::SharedUnsafeDevelopment);
    }
    anyhow::ensure!(
        configured,
        "production XEP-0133 commands require ADMIN_COMMAND_DATABASE_URL_FILE (preferred) or ADMIN_COMMAND_DATABASE_URL for the bounded northstar_commands role"
    );
    Ok(AdminCommandPoolMode::DedicatedProductionRole)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoragePoolMode {
    Disabled,
    DedicatedProductionRole,
    SharedUnsafeDevelopment,
}

fn resolve_storage_pool_mode(
    unsafe_development: bool,
    keeps_storage_runtime: bool,
    configured_database_url: &str,
) -> Result<StoragePoolMode> {
    let configured = !configured_database_url.trim().is_empty();
    if unsafe_development {
        anyhow::ensure!(
            !configured,
            "DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT shares the primary pool and must not set STORAGE_DATABASE_URL or STORAGE_DATABASE_URL_FILE"
        );
        return Ok(if keeps_storage_runtime {
            StoragePoolMode::SharedUnsafeDevelopment
        } else {
            StoragePoolMode::Disabled
        });
    }
    if !keeps_storage_runtime {
        return Ok(StoragePoolMode::Disabled);
    }
    anyhow::ensure!(
        configured,
        "enabled or draining uploads require STORAGE_DATABASE_URL_FILE (preferred) or STORAGE_DATABASE_URL for the bounded northstar_storage role"
    );
    Ok(StoragePoolMode::DedicatedProductionRole)
}

pub struct Config {
    pub raw: RawConfig,
    pub admin_command_pool_mode: AdminCommandPoolMode,
    pub storage_pool_mode: StoragePoolMode,
    pub domain: String,
    pub public_url: String,
    pub websocket_allowed_origins: Vec<String>,
    pub trusted_proxy_ips: Vec<IpAddr>,
    pub xep_0487_ips: Vec<IpAddr>,
    pub xmpp_extensions: Arc<northstar_xep_catalog::ExtensionRuntime>,
    pub federation_allowlist: Vec<String>,
    pub federation_denylist: Vec<String>,
    /// Test/private-network endpoint overrides. The boolean selects Direct TLS.
    pub federation_dns_overrides: Vec<(String, SocketAddr, bool)>,
    pub federation_dane_mode: northstar_security::dane::DaneMode,
    pub stun_service: Option<(String, u16)>,
    pub turn_service: Option<(String, u16)>,
    pub components: Vec<ComponentCredential>,
    pub cluster_security: Option<Arc<northstar_security::cluster_bus::ClusterSecurityConfig>>,
    /// True only when FAST has a mounted deployment key or the explicit
    /// loopback-only ephemeral development policy was accepted.
    pub fast_token_enabled: bool,
    pub dummy_scram_secret: Option<Zeroizing<String>>,
    pub api_control_secret: Option<String>,
    pub api_control_previous_secret: Option<String>,
    pub metrics_bearer_token: Option<Arc<Zeroizing<String>>>,
    pub web_admin_gateway_token: Option<Arc<Zeroizing<String>>>,
    /// Immutable result of the deployment-surface capability resolver.  All
    /// route, listener and registration decisions derive from this plan.
    pub web_capabilities: Arc<ResolvedWebCapabilities>,
    /// Compatibility projection for older call sites.  The authority is the
    /// registration dependency lock in `web_capabilities`.
    pub invitation_policy_disabled_with_web_client: bool,
    pub pow_v1_compatibility_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl Config {
    pub fn configured_registration_mode(&self) -> RegistrationMode {
        self.web_capabilities.registration.mode
    }

    pub fn registration_dependency_locked(&self) -> bool {
        self.web_capabilities.registration.lock.is_locked()
    }

    pub fn federation_domain_allowed(&self, domain: &str) -> bool {
        federation_domain_allowed_in(
            domain,
            &self.domain,
            self.raw.federation_enabled,
            &self.federation_allowlist,
            &self.federation_denylist,
        )
    }

    pub fn external_route_domain_policy(&self) -> ExternalRouteDomainPolicy {
        ExternalRouteDomainPolicy {
            local_domain: self.domain.clone(),
            federation_enabled: self.raw.federation_enabled,
            federation_allowlist: self.federation_allowlist.clone(),
            federation_denylist: self.federation_denylist.clone(),
            component_domains: self
                .components
                .iter()
                .flat_map(|component| component.allowed_domains.iter().cloned())
                .collect(),
        }
    }

    /// Returns whether a client-originated stanza may leave the local XMPP
    /// service through either a configured external component or S2S.
    ///
    /// Components are an independent routing transport: disabling Internet
    /// federation must not make an explicitly configured XEP-0114/XEP-0225
    /// component domain unreachable.  Keep this separate from
    /// `federation_domain_allowed`, because an inbound S2S peer must never
    /// gain authority merely because the same domain is assigned to a local
    /// component.
    pub fn external_route_domain_allowed(&self, domain: &str) -> bool {
        self.component_domain_configured(domain) || self.federation_domain_allowed(domain)
    }

    pub fn component_credential(&self, domain: &str) -> Option<&ComponentCredential> {
        let domain = northstar_xmpp_types::jid::prepare_domainpart(domain).ok()?;
        self.components.iter().find(|credential| {
            credential
                .allowed_domains
                .iter()
                .any(|allowed| allowed == &domain)
        })
    }

    pub fn component_domain_configured(&self, domain: &str) -> bool {
        self.component_credential(domain).is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmIpPolicy {
    None,
    Exact,
    Subnet,
}

impl SmIpPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "exact" => Some(Self::Exact),
            "subnet" => Some(Self::Subnet),
            _ => None,
        }
    }
}

// Forward raw fields for convenience
impl std::ops::Deref for Config {
    type Target = RawConfig;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

#[cfg(test)]
mod tests;
