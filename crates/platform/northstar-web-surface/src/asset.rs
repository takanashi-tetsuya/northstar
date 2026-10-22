//! Static asset ownership, scopes, and route validation.

use std::fmt;

use crate::surface::SurfaceId;

/// Scope specifying which deployment surface has ownership of a static asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AssetScope {
    /// Exclusively owned by the public end-user Web Client surface.
    ClientOnly,
    /// Exclusively owned by the Web Admin management surface (contains admin logic/UI).
    AdminOnly,
    /// Explicitly shared between public client and admin surfaces.
    Shared,
}

impl AssetScope {
    /// Returns the stable string identifier for this asset scope.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientOnly => "client-only",
            Self::AdminOnly => "admin-only",
            Self::Shared => "shared",
        }
    }

    /// Returns true if this asset scope is allowed to be served on the given surface.
    pub const fn is_allowed_on(self, surface: SurfaceId) -> bool {
        matches!(
            (self, surface),
            (Self::ClientOnly, SurfaceId::WebClientAssets)
                | (Self::AdminOnly, SurfaceId::WebAdmin)
                | (
                    Self::Shared,
                    SurfaceId::WebClientAssets | SurfaceId::WebAdmin
                )
        )
    }
}

impl fmt::Display for AssetScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A static asset descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StaticAsset {
    /// Web URI route path (e.g. `"/client.js"`).
    pub uri_path: String,
    /// Visibility and ownership scope.
    pub scope: AssetScope,
    /// MIME content type header.
    pub content_type: &'static str,
}

impl StaticAsset {
    /// Create a new static asset descriptor.
    pub fn new(uri_path: impl Into<String>, scope: AssetScope, content_type: &'static str) -> Self {
        Self {
            uri_path: uri_path.into(),
            scope,
            content_type,
        }
    }
}

/// Returns the standard built-in static assets for Northstar.
pub fn default_static_assets() -> Vec<StaticAsset> {
    vec![
        // Public client-only assets
        StaticAsset::new(
            "/client.html",
            AssetScope::ClientOnly,
            "text/html; charset=utf-8",
        ),
        StaticAsset::new(
            "/client.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/client.css",
            AssetScope::ClientOnly,
            "text/css; charset=utf-8",
        ),
        StaticAsset::new(
            "/app.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/xmpp.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/omemo.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/omemo-recovery.mjs",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/omemo-recovery-worker.mjs",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/omemo-recovery-worker-client.mjs",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/omemo-state-validation.mjs",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/outbox-delivery.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/avatar-editor.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/pow.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/pow-worker.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/storage.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        // Admin-only assets
        StaticAsset::new(
            "/admin.css",
            AssetScope::AdminOnly,
            "text/css; charset=utf-8",
        ),
        StaticAsset::new(
            "/index.html",
            AssetScope::AdminOnly,
            "text/html; charset=utf-8",
        ),
        StaticAsset::new(
            "/admin/admin.js",
            AssetScope::AdminOnly,
            "application/javascript; charset=utf-8",
        ),
        // Explicitly shared assets
        StaticAsset::new("/styles.css", AssetScope::Shared, "text/css; charset=utf-8"),
        // Locale executables belong exclusively to the public client trust
        // domain.  The administration origin intentionally ships with its
        // own built-in English strings and never executes client locale code.
        StaticAsset::new(
            "/i18n.css",
            AssetScope::ClientOnly,
            "text/css; charset=utf-8",
        ),
        StaticAsset::new(
            "/i18n.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
        StaticAsset::new(
            "/locales.generated.js",
            AssetScope::ClientOnly,
            "application/javascript; charset=utf-8",
        ),
    ]
}

/// Resolved static assets segregated by ownership scope.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedAssets {
    /// Client-exclusive static assets.
    pub client_assets: Vec<StaticAsset>,
    /// Admin-exclusive static assets.
    pub admin_assets: Vec<StaticAsset>,
    /// Explicitly shared static assets.
    pub shared_assets: Vec<StaticAsset>,
}

impl ResolvedAssets {
    /// Returns all static asset route paths served on the public client surface.
    pub fn client_visible_paths(&self) -> Vec<&str> {
        self.client_assets
            .iter()
            .chain(self.shared_assets.iter())
            .map(|a| a.uri_path.as_str())
            .collect()
    }

    /// Returns all static asset route paths served on the admin surface.
    pub fn admin_visible_paths(&self) -> Vec<&str> {
        self.admin_assets
            .iter()
            .chain(self.shared_assets.iter())
            .map(|a| a.uri_path.as_str())
            .collect()
    }
}
