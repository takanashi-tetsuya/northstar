//! Typed error definitions for web surface capability resolution, listener
//! configuration, upload safety validation, and asset ownership.

use std::fmt;
use std::net::SocketAddr;

use crate::asset::AssetScope;
use crate::capability::{CapabilityId, RegistrationDependencyLock, RegistrationMode};
use crate::listener::ListenerRole;
use crate::surface::SurfaceId;

/// Errors that can occur during web surface capability resolution and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionError {
    /// Web client was explicitly requested, but a required underlying capability is disabled.
    MissingWebClientDependency {
        /// The missing capability that caused this error.
        missing: CapabilityId,
        /// Human-readable detail explaining the missing dependency.
        detail: &'static str,
    },
    /// Non-loopback admin listener exposure attempted without required security provenance.
    UnsafeNonLoopbackAdminExposure {
        /// The attempted bind address.
        bind_addr: SocketAddr,
        /// Whether trusted-proxy provenance is missing.
        missing_trusted_proxy: bool,
        /// Whether a gateway credential is missing.
        missing_gateway_credential: bool,
    },
    /// Two or more active listeners collide on the same socket address.
    ListenerAddressCollision {
        /// First colliding listener role.
        first: ListenerRole,
        /// Second colliding listener role.
        second: ListenerRole,
        /// The colliding socket address.
        addr: SocketAddr,
    },
    /// Attempted to resolve `UploadMode::Disabled` with retained historical objects, pending jobs, or unproven facts.
    CannotDisableUploadWithRetainedData {
        /// Known count of retained objects in storage, if known.
        retained_objects: Option<u64>,
        /// Known count of pending jobs in background queue, if known.
        pending_jobs: Option<u64>,
        /// Known backlog count of unprocessed attachment operations, if known.
        backlog: Option<u64>,
        /// Recommended remediation (e.g. use `UploadMode::DrainReadOnly`).
        recommendation: &'static str,
    },
    /// A private or admin-only asset was assigned to or requested on a public/client surface.
    AssetOwnershipViolation {
        /// Asset URI path.
        path: String,
        /// Declared asset scope.
        scope: AssetScope,
        /// Surface on which exposure was attempted.
        attempted_surface: SurfaceId,
        /// Detail explaining the ownership violation.
        reason: &'static str,
    },
    /// Ambiguous route identity or duplicate asset path registered on the same surface.
    AmbiguousAssetRoute {
        /// The ambiguous asset path.
        path: String,
        /// The surface with duplicate registrations.
        surface: SurfaceId,
    },
    /// Route identity conflict between two endpoints on the same surface.
    RouteCollision {
        /// Surface where collision occurred.
        surface: SurfaceId,
        /// Route path that collided.
        route_path: String,
    },
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingWebClientDependency { missing, detail } => {
                write!(
                    f,
                    "Web client capability dependency error: missing required capability '{}' ({})",
                    missing.as_str(),
                    detail
                )
            }
            Self::UnsafeNonLoopbackAdminExposure {
                bind_addr,
                missing_trusted_proxy,
                missing_gateway_credential,
            } => {
                write!(
                    f,
                    "Unsafe non-loopback admin exposure at {}: this release requires WEB_ADMIN_BIND to use a loopback address; forwarded transport assertions and gateway credentials do not relax that boundary (legacy_flags={}, {})",
                    bind_addr, missing_trusted_proxy, missing_gateway_credential
                )
            }
            Self::ListenerAddressCollision {
                first,
                second,
                addr,
            } => {
                write!(
                    f,
                    "Listener address collision at {}: {} and {} cannot share the same bind address",
                    addr,
                    first.as_str(),
                    second.as_str()
                )
            }
            Self::CannotDisableUploadWithRetainedData {
                retained_objects,
                pending_jobs,
                backlog,
                recommendation,
            } => {
                write!(
                    f,
                    "Cannot disable upload subsystem with unproven or non-empty state (retained_objects={:?}, pending_jobs={:?}, backlog={:?}): {}",
                    retained_objects, pending_jobs, backlog, recommendation
                )
            }
            Self::AssetOwnershipViolation {
                path,
                scope,
                attempted_surface,
                reason,
            } => {
                write!(
                    f,
                    "Asset ownership violation for '{}' ({:?}): cannot be exposed on {} ({})",
                    path,
                    scope,
                    attempted_surface.as_str(),
                    reason
                )
            }
            Self::AmbiguousAssetRoute { path, surface } => {
                write!(
                    f,
                    "Ambiguous asset route '{}' registered multiple times on surface {}",
                    path,
                    surface.as_str()
                )
            }
            Self::RouteCollision {
                surface,
                route_path,
            } => {
                write!(
                    f,
                    "Route collision on surface {}: duplicate path '{}'",
                    surface.as_str(),
                    route_path
                )
            }
        }
    }
}

impl std::error::Error for ResolutionError {}

/// Errors that can occur during runtime registration policy transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationTransitionError {
    /// Attempted transition to an active registration mode while locked to Closed due to disabled Web Client.
    LockedByMissingDependency {
        /// Current registration mode.
        current: RegistrationMode,
        /// Attempted target registration mode.
        attempted: RegistrationMode,
        /// Dependency lock currently in effect.
        lock: RegistrationDependencyLock,
        /// Detail explaining why transition was rejected.
        reason: &'static str,
    },
}

impl fmt::Display for RegistrationTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LockedByMissingDependency {
                current,
                attempted,
                lock,
                reason,
            } => {
                write!(
                    f,
                    "Registration transition from {:?} to {:?} rejected due to lock {:?}: {}",
                    current, attempted, lock, reason
                )
            }
        }
    }
}

impl std::error::Error for RegistrationTransitionError {}
