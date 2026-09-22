//! Read-only runtime capabilities used by REST collection handlers.
use super::{MucOccupant, OnlineSession};
use crate::services::api_queries::{
    ApiQueryRepository, ApiQueryService, LiveAdminStats, SessionView,
};
use dashmap::DashMap;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub(super) struct ApiQueryRuntime {
    pub(super) domain: String,
    pub(super) node_id: String,
    pub(super) require_encrypted_archive: bool,
    pub(super) federation_configured: bool,
    pub(super) configured_registration_mode: crate::config::RegistrationMode,
    pub(super) registration_dependency_locked: bool,
    pub(super) registration_closed: Arc<AtomicBool>,
    pub(super) island_mode: Arc<AtomicBool>,
    pub(super) sessions: Arc<DashMap<String, OnlineSession>>,
    pub(super) occupants: Arc<DashMap<String, MucOccupant>>,
    pub(super) metrics: Arc<crate::metrics::Metrics>,
    pub(super) started_at: Instant,
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
    pub(super) fn new(
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
                == crate::config::RegistrationMode::InvitationOnly
    }
    pub(crate) fn live_statistics(&self) -> LiveAdminStats {
        LiveAdminStats {
            island_mode: self.runtime.island_mode.load(Ordering::Acquire),
            registration_open: !self.registration_is_closed(),
            online_sessions: self.runtime.sessions.len(),
            room_occupants: self.runtime.occupants.len(),
        }
    }
    pub(crate) fn local_sessions(&self) -> Vec<SessionView> {
        let now = Instant::now();
        self.runtime
            .sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value();
                if !session.routable.load(Ordering::Acquire) {
                    return None;
                }
                Some(SessionView {
                    connection_id: session.connection_id,
                    node: self.runtime.node_id.clone(),
                    jid: entry.key().clone(),
                    ip: session.ip.map(|ip| ip.to_string()),
                    resource: session.resource.clone(),
                    carbons_enabled: session.carbons.load(Ordering::Acquire),
                    connected_duration_seconds: now
                        .saturating_duration_since(session.connected_at)
                        .as_secs(),
                })
            })
            .collect()
    }
    pub(crate) fn room_occupant_count(&self, localpart: &str) -> usize {
        let room_jid = format!("{}@conference.{}", localpart, self.runtime.domain);
        self.runtime
            .occupants
            .iter()
            .filter(|occupant| occupant.room_jid == room_jid)
            .count()
    }
    pub(crate) fn authentication_timer(&self) -> crate::metrics::DurationTimer<'_> {
        self.runtime
            .metrics
            .authentication_duration_seconds
            .start_timer()
    }
    pub(crate) fn database_timer(&self) -> crate::metrics::DurationTimer<'_> {
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
