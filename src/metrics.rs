use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub tcp_connections_total: AtomicU64,
    pub websocket_connections_total: AtomicU64,
    pub active_sessions: AtomicU64,
    pub stanzas_in_total: AtomicU64,
    pub stanzas_out_total: AtomicU64,
    pub registrations_total: AtomicU64,
    pub authentication_failures_total: AtomicU64,
    pub authentication_backend_failures_total: AtomicU64,
    pub messages_routed_total: AtomicU64,
    pub federation_inbound_connections_total: AtomicU64,
    pub federation_outbound_deliveries_total: AtomicU64,
    pub federation_failures_total: AtomicU64,
    pub anti_abuse_challenges_total: AtomicU64,
    pub rate_limited_total: AtomicU64,
    pub reports_total: AtomicU64,
    pub appeals_total: AtomicU64,
}

impl Metrics {
    pub fn render(&self) -> String {
        let read = |v: &AtomicU64| v.load(Ordering::Relaxed);
        format!(
            concat!(
                "# TYPE xmpp_tcp_connections_total counter\n",
                "xmpp_tcp_connections_total {}\n",
                "# TYPE xmpp_websocket_connections_total counter\n",
                "xmpp_websocket_connections_total {}\n",
                "# TYPE xmpp_active_sessions gauge\n",
                "xmpp_active_sessions {}\n",
                "# TYPE xmpp_stanzas_in_total counter\n",
                "xmpp_stanzas_in_total {}\n",
                "# TYPE xmpp_stanzas_out_total counter\n",
                "xmpp_stanzas_out_total {}\n",
                "# TYPE xmpp_registrations_total counter\n",
                "xmpp_registrations_total {}\n",
                "# TYPE xmpp_authentication_failures_total counter\n",
                "xmpp_authentication_failures_total {}\n",
                "# TYPE xmpp_authentication_backend_failures_total counter\n",
                "xmpp_authentication_backend_failures_total {}\n",
                "# TYPE xmpp_messages_routed_total counter\n",
                "xmpp_messages_routed_total {}\n",
                "# TYPE xmpp_federation_inbound_connections_total counter\n",
                "xmpp_federation_inbound_connections_total {}\n",
                "# TYPE xmpp_federation_outbound_deliveries_total counter\n",
                "xmpp_federation_outbound_deliveries_total {}\n",
                "# TYPE xmpp_federation_failures_total counter\n",
                "xmpp_federation_failures_total {}\n",
                "# TYPE xmpp_anti_abuse_challenges_total counter\n",
                "xmpp_anti_abuse_challenges_total {}\n",
                "# TYPE xmpp_rate_limited_total counter\n",
                "xmpp_rate_limited_total {}\n",
                "# TYPE xmpp_reports_total counter\n",
                "xmpp_reports_total {}\n",
                "# TYPE xmpp_appeals_total counter\n",
                "xmpp_appeals_total {}\n"
            ),
            read(&self.tcp_connections_total),
            read(&self.websocket_connections_total),
            read(&self.active_sessions),
            read(&self.stanzas_in_total),
            read(&self.stanzas_out_total),
            read(&self.registrations_total),
            read(&self.authentication_failures_total),
            read(&self.authentication_backend_failures_total),
            read(&self.messages_routed_total),
            read(&self.federation_inbound_connections_total),
            read(&self.federation_outbound_deliveries_total),
            read(&self.federation_failures_total),
            read(&self.anti_abuse_challenges_total),
            read(&self.rate_limited_total),
            read(&self.reports_total),
            read(&self.appeals_total),
        )
    }
}
