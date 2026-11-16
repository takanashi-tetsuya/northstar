//! Read-only runtime capabilities used by REST collection handlers.
use dashmap::DashMap;
use northstar_operations_application::api_queries::{
    ApiQueryRepository, ApiQueryService, LiveAdminStats, SessionView,
};
use northstar_stream::local_routes::{muc::MucOccupant, session::OnlineSession};
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

/// The REST query context's read-only view of this node's live session and MUC occupant maps.
pub struct StreamPresenceDirectory {
    sessions: Arc<DashMap<String, OnlineSession>>,
    occupants: Arc<DashMap<String, MucOccupant>>,
}

impl StreamPresenceDirectory {
    pub fn new(
        sessions: Arc<DashMap<String, OnlineSession>>,
        occupants: Arc<DashMap<String, MucOccupant>>,
    ) -> Self {
        Self {
            sessions,
            occupants,
        }
    }
}

impl LocalPresenceDirectory for StreamPresenceDirectory {
    fn online_session_count(&self) -> usize {
        self.sessions.len()
    }

    fn room_occupant_total(&self) -> usize {
        self.occupants.len()
    }

    fn routable_sessions(&self, node: &str) -> Vec<SessionView> {
        let now = Instant::now();
        self.sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value();
                if !session.routable.load(Ordering::Acquire) {
                    return None;
                }
                Some(SessionView {
                    connection_id: session.connection_id,
                    node: node.to_owned(),
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

    fn room_occupant_count(&self, room_jid: &str) -> usize {
        self.occupants
            .iter()
            .filter(|occupant| occupant.room_jid == room_jid)
            .count()
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_session_application::RouteIncarnationSignal;
    use northstar_stream::{local_routes::muc::MucOccupantEndpoint, outbound::OutboundSender};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    fn session(connection_id: Uuid, routable: bool) -> OnlineSession {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        OnlineSession {
            user_id: Uuid::new_v4(),
            auth_generation: 0,
            user_agent_epoch: None,
            connection_id,
            route_incarnation: RouteIncarnationSignal::new(connection_id),
            lifecycle: Arc::default(),
            metrics_counted: Arc::default(),
            routable: Arc::new(AtomicBool::new(routable)),
            sender: OutboundSender::new(sender),
            available: Arc::default(),
            availability_generation: Arc::default(),
            post_actions: northstar_session_application::post_actions::PostActionHandle::default(),
            recovery_replay_inflight_epoch: Arc::default(),
            recovery_replay_completed_epoch: Arc::default(),
            bind2_mam_catchup: false,
            mix_presence_gate: Arc::default(),
            mix_presence_fallback_suppressed: Arc::default(),
            caps_observation_generation: Arc::default(),
            carbons: Arc::default(),
            priority: Arc::default(),
            show: Arc::default(),
            blocklist_requested: Arc::default(),
            roster_requested: Arc::default(),
            roster_sync: Arc::default(),
            mix_roster_annotations: Arc::default(),
            privacy_active: Arc::default(),
            privacy_requested: Arc::default(),
            directed_presence: Arc::default(),
            last_presence: Arc::default(),
            ip: None,
            resource: "fixture".into(),
            user_agent_id: None,
            sm_session_id: Arc::default(),
            muc_memberships: Arc::default(),
            connected_at: Instant::now(),
            last_activity: Arc::new(std::sync::RwLock::new(Instant::now())),
            disconnect: CancellationToken::new(),
        }
    }

    fn occupant(room_jid: &str, nick: &str) -> MucOccupant {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        MucOccupant {
            full_jid: format!("{nick}@example.test/fixture"),
            room_jid: room_jid.into(),
            nick: nick.into(),
            endpoint: MucOccupantEndpoint::Local(OutboundSender::new(sender)),
            affiliation: "member".into(),
            role: "participant".into(),
            room_non_anonymous: false,
            occupant_id: nick.into(),
            cluster_epoch: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            sm_session_id: None,
            payload: String::new(),
        }
    }

    #[test]
    fn routable_sessions_skip_unroutable_entries_and_occupants_are_counted_per_room() {
        let sessions = Arc::new(DashMap::new());
        let occupants = Arc::new(DashMap::new());
        let directory = StreamPresenceDirectory::new(Arc::clone(&sessions), Arc::clone(&occupants));
        let connection_id = Uuid::new_v4();
        let mut live = session(connection_id, true);
        live.ip = Some("192.0.2.1".parse().unwrap());
        live.carbons.store(true, Ordering::Release);
        live.connected_at = Instant::now() - Duration::from_secs(30);
        sessions.insert("alice@example.test/fixture".into(), live);
        sessions.insert(
            "bob@example.test/fixture".into(),
            session(Uuid::new_v4(), false),
        );
        occupants.insert(
            "one/alice".into(),
            occupant("one@conference.example.test", "alice"),
        );
        occupants.insert(
            "one/bob".into(),
            occupant("one@conference.example.test", "bob"),
        );
        occupants.insert(
            "two/alice".into(),
            occupant("two@conference.example.test", "alice"),
        );

        assert_eq!(directory.online_session_count(), 2);
        let views = directory.routable_sessions("node-a");
        assert_eq!(views.len(), 1);
        let view = &views[0];
        assert_eq!(view.connection_id, connection_id);
        assert_eq!(view.node, "node-a");
        assert_eq!(view.jid, "alice@example.test/fixture");
        assert_eq!(view.ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(view.resource, "fixture");
        assert!(view.carbons_enabled);
        assert!(view.connected_duration_seconds >= 30);
        assert_eq!(directory.room_occupant_total(), 3);
        assert_eq!(
            directory.room_occupant_count("one@conference.example.test"),
            2
        );
        assert_eq!(
            directory.room_occupant_count("two@conference.example.test"),
            1
        );
        assert_eq!(
            directory.room_occupant_count("missing@conference.example.test"),
            0
        );
    }
}
