//! Deployment-surface capability model, upload mode lifecycle, and deterministic
//! dependency resolution for Northstar.
//!
//! This crate deliberately has no dependency on Axum, Tokio, SQLx, AppState, sockets,
//! or filesystem I/O. It provides a pure, auditable domain model for web surface
//! capabilities, listener ownership, and asset boundaries.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod asset;
pub mod capability;
pub mod error;
pub mod listener;
pub mod resolver;
pub mod surface;

pub use asset::{default_static_assets, AssetScope, ResolvedAssets, StaticAsset};
pub use capability::{
    AdjustmentReason, CapabilityId, DownloadCeiling, EffectiveAdjustment,
    RegistrationDependencyLock, RegistrationMode, RequestedWebCapabilities,
    RequestedWebCapabilitiesBuilder, ResolvedRegistrationPolicy, ResolvedWebCapabilities,
    UploadMode, UploadRuntimeFacts, UploadSubsystems,
};
pub use error::{RegistrationTransitionError, ResolutionError};
pub use listener::{
    AdminSecurityContext, ListenerConfiguration, ListenerRole, ResolvedListener, ResolvedListeners,
};
pub use resolver::resolve_web_surface;
pub use surface::SurfaceId;
