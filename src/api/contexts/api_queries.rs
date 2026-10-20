//! Read-only runtime capabilities used by REST collection handlers.
use crate::services::api_queries::{
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
pub(crate) trait LocalPresenceDirectory: Send + Sync {
    fn online_session_count(&self) -> usize;
    fn room_occupant_total(&self) -> usize;
    /// Routable local sessions as REST views, each stamped with `node`.
    fn routable_sessions(&self, node: &str) -> Vec<SessionView>;
    fn room_occupant_count(&self, room_jid: &str) -> usize;
}

pub(crate) struct ApiQueryRuntime {
    pub(crate) domain: String,
    pub(crate) node_id: String,
    pub(crate) require_encrypted_archive: bool,
    pub(crate) federation_configured: bool,
    pub(crate) configured_registration_mode: crate::platform::config::RegistrationMode,
    pub(crate) registration_dependency_locked: bool,
    pub(crate) registration_closed: Arc<AtomicBool>,
    pub(crate) island_mode: Arc<AtomicBool>,
    pub(crate) presence: Arc<dyn LocalPresenceDirectory>,
    pub(crate) metrics: Arc<crate::platform::metrics::Metrics>,
    pub(crate) started_at: Instant,
}

#[derive(Clone)]
pub(crate) struct ApiQueryContext<R> {
    queries: ApiQueryService<R>,
    cursor: Arc<crate::api::cursor::CursorKeyring>,
    runtime: Arc<ApiQueryRuntime>,
}

pub(crate) struct ApiQueryCounters {
    pub(crate) federation_inbound_connections: u64,
    pub(crate) federation_outbound_deliveries: u64,
    pub(crate) federation_failures: u64,
    pub(crate) anti_abuse_challenges: u64,
    pub(crate) rate_limited_operations: u64,
    pub(crate) reports_created: u64,
    pub(crate) appeals_created: u64,
}

impl<R: ApiQueryRepository> ApiQueryContext<R> {
    pub(crate) fn new(
        queries: ApiQueryService<R>,
        cursor: Arc<crate::api::cursor::CursorKeyring>,
        runtime: ApiQueryRuntime,
    ) -> Self {
        Self {
            queries,
            cursor,
            runtime: Arc::new(runtime),
        }
    }
    pub(crate) fn api_query_service(&self) -> &ApiQueryService<R> {
        &self.queries
    }
    pub(crate) fn api_cursor(&self) -> &crate::api::cursor::CursorKeyring {
        &self.cursor
    }
    pub(crate) fn domain(&self) -> &str {
        &self.runtime.domain
    }
    pub(crate) fn node_id(&self) -> &str {
        &self.runtime.node_id
    }
    pub(crate) fn uptime(&self) -> Duration {
        self.runtime.started_at.elapsed()
    }
    pub(crate) fn archive_policy(&self) -> &'static str {
        if self.runtime.require_encrypted_archive {
            "encrypted_only"
        } else {
            "all"
        }
    }
    pub(crate) fn federation_configured(&self) -> bool {
        self.runtime.federation_configured
    }
    fn registration_is_closed(&self) -> bool {
        self.runtime.registration_dependency_locked
            || self.runtime.registration_closed.load(Ordering::Acquire)
    }
    pub(crate) fn registration_requires_invitation(&self) -> bool {
        !self.registration_is_closed()
            && self.runtime.configured_registration_mode
                == crate::platform::config::RegistrationMode::InvitationOnly
    }
    pub(crate) fn live_statistics(&self) -> LiveAdminStats {
        LiveAdminStats {
            island_mode: self.runtime.island_mode.load(Ordering::Acquire),
            registration_open: !self.registration_is_closed(),
            online_sessions: self.runtime.presence.online_session_count(),
            room_occupants: self.runtime.presence.room_occupant_total(),
        }
    }
    pub(crate) fn local_sessions(&self) -> Vec<SessionView> {
        self.runtime
            .presence
            .routable_sessions(&self.runtime.node_id)
    }
    pub(crate) fn room_occupant_count(&self, localpart: &str) -> usize {
        let room_jid = format!("{}@conference.{}", localpart, self.runtime.domain);
        self.runtime.presence.room_occupant_count(&room_jid)
    }
    pub(crate) fn authentication_timer(&self) -> crate::platform::metrics::DurationTimer<'_> {
        self.runtime
            .metrics
            .authentication_duration_seconds
            .start_timer()
    }
    pub(crate) fn database_timer(&self) -> crate::platform::metrics::DurationTimer<'_> {
        self.runtime
            .metrics
            .database_operation_duration_seconds
            .start_timer()
    }
    pub(crate) fn counters(&self) -> ApiQueryCounters {
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
