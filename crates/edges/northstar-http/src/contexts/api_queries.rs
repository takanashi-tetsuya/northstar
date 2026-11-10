//! Read-only runtime capabilities used by REST collection handlers.
use northstar_operations_application::api_queries::{
    ApiQueryRepository, ApiQueryService, LiveAdminStats, SessionView,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

/// This node's live sessions and MUC occupants, read without session or room authority.
pub trait LocalPresenceDirectory: Send + Sync {
    fn online_session_count(&self) -> usize;
    fn room_occupant_total(&self) -> usize;
    /// Routable local sessions as REST views, each stamped with `node`.
    fn routable_sessions(&self, node: &str) -> Vec<SessionView>;
    fn room_occupant_count(&self, room_jid: &str) -> usize;
}

pub struct ApiQueryRuntime {
    pub domain: String,
    pub node_id: String,
    pub require_encrypted_archive: bool,
    pub federation_configured: bool,
    pub configured_registration_mode: northstar_config::RegistrationMode,
    pub registration_dependency_locked: bool,
    pub registration_closed: Arc<AtomicBool>,
    pub island_mode: Arc<AtomicBool>,
    pub presence: Arc<dyn LocalPresenceDirectory>,
    pub metrics: Arc<northstar_telemetry::metrics::Metrics>,
    pub started_at: Instant,
}

#[derive(Clone)]
pub struct ApiQueryContext<R> {
    queries: ApiQueryService<R>,
    cursor: Arc<crate::cursor::CursorKeyring>,
    runtime: Arc<ApiQueryRuntime>,
}

pub struct ApiQueryCounters {
    pub federation_inbound_connections: u64,
    pub federation_outbound_deliveries: u64,
    pub federation_failures: u64,
    pub anti_abuse_challenges: u64,
    pub rate_limited_operations: u64,
    pub reports_created: u64,
    pub appeals_created: u64,
}

impl<R: ApiQueryRepository> ApiQueryContext<R> {
    pub fn new(
        queries: ApiQueryService<R>,
        cursor: Arc<crate::cursor::CursorKeyring>,
        runtime: ApiQueryRuntime,
    ) -> Self {
        Self {
            queries,
            cursor,
            runtime: Arc::new(runtime),
        }
    }
    pub fn api_query_service(&self) -> &ApiQueryService<R> {
        &self.queries
    }
    pub fn api_cursor(&self) -> &crate::cursor::CursorKeyring {
        &self.cursor
    }
    pub fn domain(&self) -> &str {
        &self.runtime.domain
    }
    pub fn node_id(&self) -> &str {
        &self.runtime.node_id
    }
    pub fn uptime(&self) -> Duration {
        self.runtime.started_at.elapsed()
    }
    pub fn archive_policy(&self) -> &'static str {
        if self.runtime.require_encrypted_archive {
            "encrypted_only"
        } else {
            "all"
        }
    }
    pub fn federation_configured(&self) -> bool {
        self.runtime.federation_configured
    }
    fn registration_is_closed(&self) -> bool {
        self.runtime.registration_dependency_locked
            || self.runtime.registration_closed.load(Ordering::Acquire)
    }
    pub fn registration_requires_invitation(&self) -> bool {
        !self.registration_is_closed()
            && self.runtime.configured_registration_mode
                == northstar_config::RegistrationMode::InvitationOnly
    }
    pub fn live_statistics(&self) -> LiveAdminStats {
        LiveAdminStats {
            island_mode: self.runtime.island_mode.load(Ordering::Acquire),
            registration_open: !self.registration_is_closed(),
            online_sessions: self.runtime.presence.online_session_count(),
            room_occupants: self.runtime.presence.room_occupant_total(),
        }
    }
    pub fn local_sessions(&self) -> Vec<SessionView> {
        self.runtime
            .presence
            .routable_sessions(&self.runtime.node_id)
    }
    pub fn room_occupant_count(&self, localpart: &str) -> usize {
        let room_jid = format!("{}@conference.{}", localpart, self.runtime.domain);
        self.runtime.presence.room_occupant_count(&room_jid)
    }
    pub fn authentication_timer(&self) -> northstar_telemetry::metrics::DurationTimer<'_> {
        self.runtime
            .metrics
            .authentication_duration_seconds
            .start_timer()
    }
    pub fn database_timer(&self) -> northstar_telemetry::metrics::DurationTimer<'_> {
        self.runtime
            .metrics
            .database_operation_duration_seconds
            .start_timer()
    }
    pub fn counters(&self) -> ApiQueryCounters {
        let metrics = &self.runtime.metrics;
        ApiQueryCounters {
            federation_inbound_connections: metrics
                .federation_inbound_connections_total
                .load(Ordering::Relaxed),
            federation_outbound_deliveries: metrics
                .federation_outbound_deliveries_total
                .load(Ordering::Relaxed),
            federation_failures: metrics.federation_failures_total.load(Ordering::Relaxed),
            anti_abuse_challenges: metrics.anti_abuse_challenges_total.load(Ordering::Relaxed),
            rate_limited_operations: metrics.rate_limited_total.load(Ordering::Relaxed),
            reports_created: metrics.reports_total.load(Ordering::Relaxed),
            appeals_created: metrics.appeals_total.load(Ordering::Relaxed),
        }
    }
}
