//! Stable surface identifiers for Northstar HTTP and WebSocket deployment surfaces.

use std::fmt;

/// Stable deployment surface identifier.
///
/// Surfaces define distinct network entry points, routing domains,
/// and security boundaries in Northstar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SurfaceId {
    /// Public end-user REST API surface (auth, session, password reset, account recovery).
    UserRest,
    /// Real-time WebSocket transport surface (RFC 7395 / XMPP over WebSocket).
    WebSocket,
    /// BOSH transport surface (XEP-0124 / XEP-0206 HTTP Binding).
    Bosh,
    /// Public Web client static asset surface.
    WebClientAssets,
    /// Web admin management surface (admin SPA assets and admin control REST API).
    WebAdmin,
    /// HTTP File Upload surface (XEP-0363 slot request and upload/download routes).
    HttpUpload,
    /// Observability surface (health checks, readiness probes, Prometheus metrics).
    Observability,
}

impl SurfaceId {
    /// All known deployment surface IDs in stable order.
    pub const ALL: [SurfaceId; 7] = [
        SurfaceId::UserRest,
        SurfaceId::WebSocket,
        SurfaceId::Bosh,
        SurfaceId::WebClientAssets,
        SurfaceId::WebAdmin,
        SurfaceId::HttpUpload,
        SurfaceId::Observability,
    ];

    /// Returns the stable string identifier for this surface.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserRest => "user-rest",
            Self::WebSocket => "websocket",
            Self::Bosh => "bosh",
            Self::WebClientAssets => "web-client-assets",
            Self::WebAdmin => "web-admin",
            Self::HttpUpload => "http-upload",
            Self::Observability => "observability",
        }
    }
}

impl fmt::Display for SurfaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
