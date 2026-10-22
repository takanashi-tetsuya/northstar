//! Listener roles, security contexts, and bind address validation.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::surface::SurfaceId;

/// Listener role identifying the network binding purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ListenerRole {
    /// Public listener serving user REST, WebSocket, BOSH, Web client, and HTTP upload routes.
    Public,
    /// Dedicated administrative listener serving admin API and admin SPA.
    Admin,
    /// Dedicated or multiplexed observability listener serving health/metrics.
    Observability,
}

impl ListenerRole {
    /// Returns the stable string identifier for this listener role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Admin => "admin",
            Self::Observability => "observability",
        }
    }
}

impl fmt::Display for ListenerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Security context for administrative surface exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdminSecurityContext {
    /// Whether incoming connections have verified trusted-proxy provenance.
    pub trusted_proxy: bool,
    /// Whether a secure gateway / admin credential is explicitly configured.
    pub gateway_credential_present: bool,
}

impl AdminSecurityContext {
    /// Create a new administrative security context.
    pub const fn new(trusted_proxy: bool, gateway_credential_present: bool) -> Self {
        Self {
            trusted_proxy,
            gateway_credential_present,
        }
    }

    /// Returns true if both trusted-proxy provenance and gateway credentials are present.
    pub const fn is_non_loopback_allowed(&self) -> bool {
        self.trusted_proxy && self.gateway_credential_present
    }
}

/// Configuration for listener bind addresses and administrative security settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerConfiguration {
    /// Public listener bind address (default 0.0.0.0:5280).
    pub public_addr: SocketAddr,
    /// Admin listener bind address (default 127.0.0.1:8081).
    pub admin_addr: SocketAddr,
    /// Dedicated observability listener bind address. If `None`, observability is multiplexed onto the public listener.
    pub observability_addr: Option<SocketAddr>,
    /// Security context for administrative interface.
    pub admin_security: AdminSecurityContext,
}

impl Default for ListenerConfiguration {
    fn default() -> Self {
        Self {
            public_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 5280),
            admin_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
            observability_addr: None,
            admin_security: AdminSecurityContext::default(),
        }
    }
}

impl ListenerConfiguration {
    /// Create a new listener configuration with the specified public and admin bind addresses.
    pub const fn new(public_addr: SocketAddr, admin_addr: SocketAddr) -> Self {
        Self {
            public_addr,
            admin_addr,
            observability_addr: None,
            admin_security: AdminSecurityContext {
                trusted_proxy: false,
                gateway_credential_present: false,
            },
        }
    }

    /// Set an optional dedicated observability listener address.
    pub fn with_observability_addr(mut self, addr: Option<SocketAddr>) -> Self {
        self.observability_addr = addr;
        self
    }

    /// Set the administrative security context.
    pub fn with_admin_security(mut self, security: AdminSecurityContext) -> Self {
        self.admin_security = security;
        self
    }
}

/// Description of an active resolved network listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedListener {
    /// Role of this listener.
    pub role: ListenerRole,
    /// Bound socket address.
    pub bind_addr: SocketAddr,
    /// List of surfaces hosted on this listener.
    pub surfaces: Vec<SurfaceId>,
}

/// Resolved listeners after capability resolution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedListeners {
    /// Active public listener, if any public surface is enabled.
    pub public: Option<ResolvedListener>,
    /// Active admin listener, if admin surface is enabled.
    pub admin: Option<ResolvedListener>,
    /// Active dedicated observability listener, if dedicated observability is configured and enabled.
    pub observability: Option<ResolvedListener>,
}

impl ResolvedListeners {
    /// Returns an iterator over all active resolved listeners.
    pub fn active_listeners(&self) -> impl Iterator<Item = &ResolvedListener> {
        self.public
            .as_ref()
            .into_iter()
            .chain(self.admin.as_ref())
            .chain(self.observability.as_ref())
    }
}
