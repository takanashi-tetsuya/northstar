//! Capability definitions, upload mode structures, registration authority,
//! request structures, and resolved state models.

use std::fmt;

use crate::asset::{default_static_assets, ResolvedAssets, StaticAsset};
use crate::error::{RegistrationTransitionError, ResolutionError};
use crate::listener::{ListenerConfiguration, ResolvedListeners};
use crate::surface::SurfaceId;

/// Stable capability identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CapabilityId {
    /// End-user REST API capability.
    UserRest,
    /// WebSocket bidirectional transport capability.
    WebSocket,
    /// BOSH HTTP binding transport capability.
    Bosh,
    /// Web client SPA hosting capability.
    WebClient,
    /// Web admin UI and control API capability.
    WebAdmin,
    /// HTTP File Upload service capability.
    HttpUpload,
    /// Health checks, readiness probes, and metrics capability.
    Observability,
    /// User account registration authority.
    Registration,
}

impl CapabilityId {
    /// All base web capabilities in stable order.
    pub const ALL: [CapabilityId; 8] = [
        CapabilityId::UserRest,
        CapabilityId::WebSocket,
        CapabilityId::Bosh,
        CapabilityId::WebClient,
        CapabilityId::WebAdmin,
        CapabilityId::HttpUpload,
        CapabilityId::Observability,
        CapabilityId::Registration,
    ];

    /// Returns the stable string identifier for this capability.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserRest => "user-rest",
            Self::WebSocket => "websocket",
            Self::Bosh => "bosh",
            Self::WebClient => "web-client",
            Self::WebAdmin => "web-admin",
            Self::HttpUpload => "http-upload",
            Self::Observability => "observability",
            Self::Registration => "registration",
        }
    }

    /// Returns the primary deployment surface ID associated with this capability, if directly mapped.
    pub const fn associated_surface(self) -> Option<SurfaceId> {
        match self {
            Self::UserRest => Some(SurfaceId::UserRest),
            Self::WebSocket => Some(SurfaceId::WebSocket),
            Self::Bosh => Some(SurfaceId::Bosh),
            Self::WebClient => Some(SurfaceId::WebClientAssets),
            Self::WebAdmin => Some(SurfaceId::WebAdmin),
            Self::HttpUpload => Some(SurfaceId::HttpUpload),
            Self::Observability => Some(SurfaceId::Observability),
            Self::Registration => Some(SurfaceId::UserRest),
        }
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Operational mode for the HTTP File Upload subsystem (XEP-0363).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadMode {
    /// Full upload capability enabled: new slot/IQ admission, PUT, bounded GET,
    /// cleanup/reconciliation workers, and XMPP discovery are enabled.
    #[default]
    Enabled,
    /// Drain read-only: reject new slots and PUT; do not advertise upload;
    /// preserve bounded GET for retained historical attachments and keep
    /// cleanup and reconciliation workers running.
    DrainReadOnly,
    /// Fully disabled: no upload routes, no background workers, no XMPP discovery.
    /// Only resolvable when explicit runtime facts prove no retained objects,
    /// pending jobs, or backlog remain.
    Disabled,
}

impl UploadMode {
    /// Returns the stable string identifier for this upload mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::DrainReadOnly => "drain-read-only",
            Self::Disabled => "disabled",
        }
    }

    /// Whether this mode accepts new upload slot requests and PUT uploads.
    pub const fn permits_new_uploads(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Compatibility spelling used by the application layer.
    pub const fn admits_new_uploads(self) -> bool {
        self.permits_new_uploads()
    }

    /// Whether this mode permits reading historical attachments.
    pub const fn permits_reads(self) -> bool {
        matches!(self, Self::Enabled | Self::DrainReadOnly)
    }

    /// Whether the object store, bounded readers and cleanup workers must be
    /// constructed for this lifecycle phase.
    pub const fn keeps_storage_runtime(self) -> bool {
        self.permits_reads()
    }
}

impl fmt::Display for UploadMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Explicit runtime facts concerning the state of the storage backend and background worker queues.
///
/// These facts are required to prove that no retained historical attachments or uncommitted
/// queue operations remain before `UploadMode::Disabled` is allowed to resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UploadRuntimeFacts {
    /// Known count of retained attachments/objects in object store or filesystem.
    /// `None` indicates unverified or unknown state.
    pub retained_objects_count: Option<u64>,
    /// Known count of pending jobs in background work queue.
    /// `None` indicates unverified or unknown state.
    pub pending_jobs_count: Option<u64>,
    /// Known backlog count of unprocessed attachment operations.
    /// `None` indicates unverified or unknown state.
    pub backlog_count: Option<u64>,
}

impl UploadRuntimeFacts {
    /// Runtime facts explicitly proven to be completely empty.
    pub const fn empty() -> Self {
        Self {
            retained_objects_count: Some(0),
            pending_jobs_count: Some(0),
            backlog_count: Some(0),
        }
    }

    /// Unknown or unverified runtime facts.
    pub const fn unknown() -> Self {
        Self {
            retained_objects_count: None,
            pending_jobs_count: None,
            backlog_count: None,
        }
    }

    /// Create verified facts with known counts.
    pub const fn with_counts(retained_objects: u64, pending_jobs: u64, backlog: u64) -> Self {
        Self {
            retained_objects_count: Some(retained_objects),
            pending_jobs_count: Some(pending_jobs),
            backlog_count: Some(backlog),
        }
    }

    /// Returns true if and only if all storage and queue counts are explicitly verified to be zero.
    pub const fn has_proven_clean(&self) -> bool {
        matches!(self.retained_objects_count, Some(0))
            && matches!(self.pending_jobs_count, Some(0))
            && matches!(self.backlog_count, Some(0))
    }
}

/// Immutable download ceiling ownership for attachment retrieval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DownloadCeiling {
    /// Maximum allowable download size in bytes per attachment slot.
    pub max_bytes: u64,
    /// Maximum concurrent download streams allowed, if bounded.
    pub max_concurrent_streams: Option<u32>,
}

impl Default for DownloadCeiling {
    fn default() -> Self {
        Self {
            max_bytes: 100 * 1024 * 1024, // 100 MiB default ceiling
            max_concurrent_streams: None,
        }
    }
}

impl DownloadCeiling {
    /// Create a download ceiling with the specified maximum byte limit.
    pub const fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            max_concurrent_streams: None,
        }
    }

    /// Create a download ceiling with byte and concurrent stream limits.
    pub const fn with_concurrency(max_bytes: u64, max_concurrent_streams: u32) -> Self {
        Self {
            max_bytes,
            max_concurrent_streams: Some(max_concurrent_streams),
        }
    }
}

/// Detailed resolved upload subsystems and route permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadSubsystems {
    /// Admission of new slot requests via IQ or REST.
    pub slot_admission: bool,
    /// HTTP PUT upload route active.
    pub put: bool,
    /// Bounded HTTP GET download route active for historical/new attachments.
    pub get: bool,
    /// Background expiration and cleanup worker active.
    pub cleanup_worker: bool,
    /// Storage reconciliation and audit worker active.
    pub reconciliation_worker: bool,
    /// Service Discovery (XEP-0030) disco feature advertisement enabled.
    pub xmpp_advertisement: bool,
    /// Immutable download ceiling ownership.
    pub download_ceiling: DownloadCeiling,
}

impl UploadSubsystems {
    /// Construct resolved subsystems according to the requested upload mode and ceiling.
    pub const fn from_mode(mode: UploadMode, ceiling: DownloadCeiling) -> Self {
        match mode {
            UploadMode::Enabled => Self {
                slot_admission: true,
                put: true,
                get: true,
                cleanup_worker: true,
                reconciliation_worker: true,
                xmpp_advertisement: true,
                download_ceiling: ceiling,
            },
            UploadMode::DrainReadOnly => Self {
                slot_admission: false,
                put: false,
                get: true,
                cleanup_worker: true,
                reconciliation_worker: true,
                xmpp_advertisement: false,
                download_ceiling: ceiling,
            },
            UploadMode::Disabled => Self {
                slot_admission: false,
                put: false,
                get: false,
                cleanup_worker: false,
                reconciliation_worker: false,
                xmpp_advertisement: false,
                download_ceiling: ceiling,
            },
        }
    }
}

/// Single authority for account registration policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum RegistrationMode {
    /// Registration is completely closed. No public registrations or invitations accepted.
    #[default]
    Closed,
    /// Open public account registration is permitted without an invitation token.
    Open,
    /// Account registration is strictly permitted only with a valid invitation token.
    InvitationOnly,
}

impl RegistrationMode {
    /// Returns the stable string identifier for this registration mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::InvitationOnly => "invitation-only",
        }
    }

    /// Whether this mode permits public account creation.
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Whether this mode requires an invitation token.
    pub const fn is_invitation_only(self) -> bool {
        matches!(self, Self::InvitationOnly)
    }

    /// Whether registration is completely closed.
    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }
}

impl fmt::Display for RegistrationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Immutable dependency lock state for user registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum RegistrationDependencyLock {
    /// Unlocked: runtime and administrative transitions to any valid mode are permitted.
    #[default]
    Unlocked,
    /// Locked to Closed because the Web Client SPA is disabled while InvitationOnly was requested.
    /// Transitions to Open or InvitationOnly are forbidden at runtime; only Closed is permitted.
    LockedWebClientDisabled,
}

impl RegistrationDependencyLock {
    /// Whether registration is locked due to missing dependencies.
    pub const fn is_locked(self) -> bool {
        matches!(self, Self::LockedWebClientDisabled)
    }
}

/// Resolved registration policy carrying the effective mode and an immutable dependency lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRegistrationPolicy {
    /// Effective registration mode.
    pub mode: RegistrationMode,
    /// Immutable dependency lock.
    pub lock: RegistrationDependencyLock,
}

impl ResolvedRegistrationPolicy {
    /// Create a new resolved registration policy.
    pub const fn new(mode: RegistrationMode, lock: RegistrationDependencyLock) -> Self {
        Self { mode, lock }
    }

    /// Pure transition validator used by runtime/admin control.
    ///
    /// While dependency-locked, attempts to transition to `Open` or `InvitationOnly`
    /// are rejected with `RegistrationTransitionError::LockedByMissingDependency`.
    /// Transitioning to or clamping at `Closed` is always permitted.
    pub fn validate_transition(
        &self,
        target_mode: RegistrationMode,
    ) -> Result<ResolvedRegistrationPolicy, RegistrationTransitionError> {
        if self.lock.is_locked() && target_mode != RegistrationMode::Closed {
            return Err(RegistrationTransitionError::LockedByMissingDependency {
                current: self.mode,
                attempted: target_mode,
                lock: self.lock,
                reason: "Registration is dependency-locked to Closed because the Web Client is disabled. Enable Web Client and restart before opening registration.",
            });
        }

        Ok(ResolvedRegistrationPolicy {
            mode: target_mode,
            lock: self.lock,
        })
    }

    /// Clamp registration mode to `Closed` (e.g. for refresh/admission/discovery callers).
    /// Clamping to `Closed` is always valid regardless of lock state.
    pub const fn clamp_to_closed(&self) -> ResolvedRegistrationPolicy {
        ResolvedRegistrationPolicy {
            mode: RegistrationMode::Closed,
            lock: self.lock,
        }
    }
}

/// Structured reason for an automatic resolution adjustment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjustmentReason {
    /// Invitation-only registration requested, but Web client is disabled.
    /// Security rule: fail-closed by clamping registration mode to Closed with an immutable dependency lock.
    InvitationRegistrationClosedBecauseWebClientDisabled,
    /// Upload capability in drain read-only mode: new slots and PUT rejected, XMPP advertisement disabled,
    /// while GET and cleanup/reconciliation workers remain active for historical attachments.
    UploadDrainingReadOnly,
    /// XEP-0363 is disabled, so new slot/PUT admission is removed while
    /// retained objects remain readable and cleanup stays active.
    UploadProtocolDisabled,
    /// Upload capability completely disabled after verifying clean runtime facts.
    UploadFullyDisabled,
    /// Admin surface disabled: admin listener and admin routes deactivated independently.
    AdminDeactivated,
    /// Explicit override or product constraint.
    ExplicitAdjustment(&'static str),
}

impl fmt::Display for AdjustmentReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvitationRegistrationClosedBecauseWebClientDisabled => {
                write!(
                    f,
                    "Invitation-only registration requested but Web client is disabled; registration closed fail-closed with immutable dependency lock (effective mode=Closed)"
                )
            }
            Self::UploadDrainingReadOnly => {
                write!(
                    f,
                    "Upload subsystem in DrainReadOnly mode: rejecting new slots and PUT, preserving GET and cleanup/reconciliation workers"
                )
            }
            Self::UploadProtocolDisabled => {
                write!(
                    f,
                    "XEP-0363 disabled: rejecting new slots and PUT while preserving retained-object GET and cleanup/reconciliation"
                )
            }
            Self::UploadFullyDisabled => {
                write!(
                    f,
                    "Upload subsystem fully disabled after verifying zero retained objects and clean queues"
                )
            }
            Self::AdminDeactivated => {
                write!(
                    f,
                    "Administration capability disabled; admin listener and management API deactivated independently"
                )
            }
            Self::ExplicitAdjustment(msg) => write!(f, "{}", msg),
        }
    }
}

/// An auditable, structured record of an effective adjustment made during capability resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveAdjustment {
    /// The capability that was adjusted.
    pub capability: CapabilityId,
    /// The state initially requested.
    pub requested: bool,
    /// The effective resolved state.
    pub effective: bool,
    /// The structured reason explaining why this adjustment was made.
    pub reason: AdjustmentReason,
}

impl EffectiveAdjustment {
    /// Create a new effective adjustment entry.
    pub const fn new(
        capability: CapabilityId,
        requested: bool,
        effective: bool,
        reason: AdjustmentReason,
    ) -> Self {
        Self {
            capability,
            requested,
            effective,
            reason,
        }
    }
}

impl fmt::Display for EffectiveAdjustment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Adjustment for {}: requested={}, effective={} ({})",
            self.capability.as_str(),
            self.requested,
            self.effective,
            self.reason
        )
    }
}

/// Requested capabilities and deployment surface configuration prior to resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedWebCapabilities {
    /// End-user REST API requested.
    pub user_rest: bool,
    /// WebSocket real-time transport requested.
    pub websocket: bool,
    /// BOSH HTTP-bind transport requested.
    pub bosh: bool,
    /// Web client SPA hosting requested.
    pub web_client: bool,
    /// Web administration interface requested.
    pub web_admin: bool,
    /// HTTP File Upload operational mode requested.
    pub upload_mode: UploadMode,
    /// Whether the XEP-0363 protocol adapter is requested.
    pub upload_protocol: bool,
    /// Storage and queue runtime facts for upload validation.
    pub upload_facts: UploadRuntimeFacts,
    /// Immutable download ceiling ownership requested.
    pub upload_ceiling: DownloadCeiling,
    /// Health/metrics observability requested.
    pub observability: bool,
    /// Single authority registration mode requested.
    pub registration: RegistrationMode,
    /// Listener configuration requested.
    pub listeners: ListenerConfiguration,
    /// Static assets catalog requested.
    pub assets: Vec<StaticAsset>,
}

impl Default for RequestedWebCapabilities {
    /// Standard production default graph:
    /// - All core capabilities enabled
    /// - Upload mode enabled with default ceiling
    /// - Closed registration
    /// - Default listeners (Admin on 127.0.0.1:8081)
    /// - Default static asset catalog
    fn default() -> Self {
        Self {
            user_rest: true,
            websocket: true,
            bosh: true,
            web_client: true,
            web_admin: true,
            upload_mode: UploadMode::Enabled,
            upload_protocol: true,
            upload_facts: UploadRuntimeFacts::unknown(),
            upload_ceiling: DownloadCeiling::default(),
            observability: true,
            registration: RegistrationMode::Closed,
            listeners: ListenerConfiguration::default(),
            assets: default_static_assets(),
        }
    }
}

impl RequestedWebCapabilities {
    /// Create a new builder for configuring requested web capabilities.
    pub fn builder() -> RequestedWebCapabilitiesBuilder {
        RequestedWebCapabilitiesBuilder::default()
    }

    /// Resolve this capability request deterministically.
    pub fn resolve(&self) -> Result<ResolvedWebCapabilities, ResolutionError> {
        crate::resolver::resolve_web_surface(self)
    }

    /// Builder-style method to set user REST.
    pub fn with_user_rest(mut self, enabled: bool) -> Self {
        self.user_rest = enabled;
        self
    }

    /// Builder-style method to set WebSocket.
    pub fn with_websocket(mut self, enabled: bool) -> Self {
        self.websocket = enabled;
        self
    }

    /// Builder-style method to set BOSH.
    pub fn with_bosh(mut self, enabled: bool) -> Self {
        self.bosh = enabled;
        self
    }

    /// Builder-style method to set Web Client.
    pub fn with_web_client(mut self, enabled: bool) -> Self {
        self.web_client = enabled;
        self
    }

    /// Builder-style method to set Web Admin.
    pub fn with_web_admin(mut self, enabled: bool) -> Self {
        self.web_admin = enabled;
        self
    }

    /// Builder-style method to set Upload mode.
    pub fn with_upload_mode(mut self, mode: UploadMode) -> Self {
        self.upload_mode = mode;
        self
    }

    /// Builder-style method to enable or disable the XEP-0363 protocol adapter.
    pub fn with_upload_protocol(mut self, enabled: bool) -> Self {
        self.upload_protocol = enabled;
        self
    }

    /// Builder-style method to set Upload runtime facts.
    pub fn with_upload_facts(mut self, facts: UploadRuntimeFacts) -> Self {
        self.upload_facts = facts;
        self
    }

    /// Builder-style method to set Download ceiling.
    pub fn with_upload_ceiling(mut self, ceiling: DownloadCeiling) -> Self {
        self.upload_ceiling = ceiling;
        self
    }

    /// Builder-style method to set Observability.
    pub fn with_observability(mut self, enabled: bool) -> Self {
        self.observability = enabled;
        self
    }

    /// Builder-style method to set Registration Mode.
    pub fn with_registration(mut self, mode: RegistrationMode) -> Self {
        self.registration = mode;
        self
    }

    /// Builder-style method to set Listener Configuration.
    pub fn with_listeners(mut self, listeners: ListenerConfiguration) -> Self {
        self.listeners = listeners;
        self
    }

    /// Builder-style method to set Static Assets.
    pub fn with_assets(mut self, assets: Vec<StaticAsset>) -> Self {
        self.assets = assets;
        self
    }
}

/// Builder for constructing [`RequestedWebCapabilities`].
#[derive(Debug, Clone, Default)]
pub struct RequestedWebCapabilitiesBuilder {
    capabilities: RequestedWebCapabilities,
}

impl RequestedWebCapabilitiesBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set user REST API request.
    pub fn user_rest(mut self, enabled: bool) -> Self {
        self.capabilities.user_rest = enabled;
        self
    }

    /// Set WebSocket transport request.
    pub fn websocket(mut self, enabled: bool) -> Self {
        self.capabilities.websocket = enabled;
        self
    }

    /// Set BOSH transport request.
    pub fn bosh(mut self, enabled: bool) -> Self {
        self.capabilities.bosh = enabled;
        self
    }

    /// Set Web Client SPA request.
    pub fn web_client(mut self, enabled: bool) -> Self {
        self.capabilities.web_client = enabled;
        self
    }

    /// Set Web Admin request.
    pub fn web_admin(mut self, enabled: bool) -> Self {
        self.capabilities.web_admin = enabled;
        self
    }

    /// Set HTTP Upload mode request.
    pub fn upload_mode(mut self, mode: UploadMode) -> Self {
        self.capabilities.upload_mode = mode;
        self
    }

    /// Set whether the XEP-0363 protocol adapter is requested.
    pub fn upload_protocol(mut self, enabled: bool) -> Self {
        self.capabilities.upload_protocol = enabled;
        self
    }

    /// Set Upload runtime facts.
    pub fn upload_facts(mut self, facts: UploadRuntimeFacts) -> Self {
        self.capabilities.upload_facts = facts;
        self
    }

    /// Set Download ceiling.
    pub fn upload_ceiling(mut self, ceiling: DownloadCeiling) -> Self {
        self.capabilities.upload_ceiling = ceiling;
        self
    }

    /// Set Observability request.
    pub fn observability(mut self, enabled: bool) -> Self {
        self.capabilities.observability = enabled;
        self
    }

    /// Set single authority Registration mode.
    pub fn registration(mut self, mode: RegistrationMode) -> Self {
        self.capabilities.registration = mode;
        self
    }

    /// Set Listener configuration.
    pub fn listeners(mut self, listeners: ListenerConfiguration) -> Self {
        self.capabilities.listeners = listeners;
        self
    }

    /// Set Static assets list.
    pub fn assets(mut self, assets: Vec<StaticAsset>) -> Self {
        self.capabilities.assets = assets;
        self
    }

    /// Build the final [`RequestedWebCapabilities`].
    pub fn build(self) -> RequestedWebCapabilities {
        self.capabilities
    }
}

/// Resolved capabilities resulting from deterministic dependency resolution and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWebCapabilities {
    /// Whether user REST is effectively enabled.
    pub user_rest: bool,
    /// Whether WebSocket is effectively enabled.
    pub websocket: bool,
    /// Whether BOSH is effectively enabled.
    pub bosh: bool,
    /// Whether Web Client SPA is effectively enabled.
    pub web_client: bool,
    /// Whether Web Admin is effectively enabled.
    pub web_admin: bool,
    /// Resolved upload mode.
    pub upload_mode: UploadMode,
    /// Detailed upload subsystem resolution.
    pub upload: UploadSubsystems,
    /// `true` only for a startup plan that still requires the application
    /// layer to prove the durable upload tables and object authority empty
    /// before constructing a Disabled runtime.
    pub upload_disable_requires_runtime_proof: bool,
    /// Whether Observability is effectively enabled.
    pub observability: bool,
    /// Resolved registration policy and immutable dependency lock.
    pub registration: ResolvedRegistrationPolicy,
    /// Active resolved listeners.
    pub listeners: ResolvedListeners,
    /// Partitioned and verified static assets.
    pub assets: ResolvedAssets,
    /// Auditable list of automatic adjustments made during resolution.
    pub adjustments: Vec<EffectiveAdjustment>,
}

impl ResolvedWebCapabilities {
    /// Returns whether a given deployment surface is effectively enabled.
    pub fn is_surface_enabled(&self, surface: SurfaceId) -> bool {
        match surface {
            SurfaceId::UserRest => self.user_rest,
            SurfaceId::WebSocket => self.websocket,
            SurfaceId::Bosh => self.bosh,
            SurfaceId::WebClientAssets => self.web_client,
            SurfaceId::WebAdmin => self.web_admin,
            SurfaceId::HttpUpload => {
                self.upload.put || self.upload.get || self.upload.slot_admission
            }
            SurfaceId::Observability => self.observability,
        }
    }

    /// Returns whether a given capability is effectively enabled.
    pub fn is_capability_enabled(&self, capability: CapabilityId) -> bool {
        match capability {
            CapabilityId::UserRest => self.user_rest,
            CapabilityId::WebSocket => self.websocket,
            CapabilityId::Bosh => self.bosh,
            CapabilityId::WebClient => self.web_client,
            CapabilityId::WebAdmin => self.web_admin,
            CapabilityId::HttpUpload => self.upload_mode.permits_reads(),
            CapabilityId::Observability => self.observability,
            CapabilityId::Registration => !self.registration.mode.is_closed(),
        }
    }

    /// Returns the resolved upload subsystems.
    pub const fn upload_subsystems(&self) -> UploadSubsystems {
        self.upload
    }

    /// Returns the effective registration mode.
    pub const fn registration_mode(&self) -> RegistrationMode {
        self.registration.mode
    }

    /// Returns whether registration is dependency-locked.
    pub const fn is_registration_locked(&self) -> bool {
        self.registration.lock.is_locked()
    }

    /// Validate a runtime transition of registration mode.
    pub fn validate_registration_transition(
        &self,
        target_mode: RegistrationMode,
    ) -> Result<ResolvedRegistrationPolicy, RegistrationTransitionError> {
        self.registration.validate_transition(target_mode)
    }

    /// Returns true if any automated adjustments were made during resolution.
    pub fn has_adjustments(&self) -> bool {
        !self.adjustments.is_empty()
    }

    /// Returns slice of all automated adjustments.
    pub fn adjustments(&self) -> &[EffectiveAdjustment] {
        &self.adjustments
    }
}
