//! The node's capabilities as BOSH sees them.

use crate::node::ServerNode;
use axum::http::HeaderMap;
use northstar_bosh::host::{BoshHost, BoshPolicy};
use northstar_bosh::BoshManager;
use northstar_room_application::mix_service::MixService;
use northstar_session_application::replay::ReplayService;
use northstar_session_application::sm_capacity::SmMemoryGovernor;
use northstar_session_postgres::replay_repository::PostgresReplayRepository;
use northstar_workflows::room_effects::PostgresMixRepository;
use std::{net::IpAddr, sync::Arc};

impl BoshHost for ServerNode {
    type ReplayStore = PostgresReplayRepository;
    type MixStore = PostgresMixRepository;

    fn bosh_manager(&self) -> &BoshManager {
        ServerNode::bosh_manager(self)
    }

    fn bosh_policy(&self) -> BoshPolicy {
        northstar_bosh::host::BoshPolicy {
            max_wait_seconds: self.config.bosh_max_wait_seconds,
            inactivity_seconds: self.config.bosh_inactivity_seconds,
            polling_seconds: self.config.bosh_polling_seconds,
            max_pause_seconds: self.config.bosh_max_pause_seconds,
            body_read_timeout_seconds: self.config.bosh_body_read_timeout_seconds,
            max_request_bytes: self.config.bosh_max_request_bytes,
            max_response_bytes: self.config.bosh_max_response_bytes,
            max_stanzas_per_request: self.config.bosh_max_stanzas_per_request,
            max_output_stanzas: self.config.bosh_max_output_stanzas,
            max_output_bytes: self.config.bosh_max_output_bytes,
        }
    }

    fn trusted_proxy_ips(&self) -> &[IpAddr] {
        &self.config.trusted_proxy_ips
    }

    fn client_ip(&self, peer_ip: IpAddr, headers: &HeaderMap) -> IpAddr {
        northstar_http::client_ip(peer_ip, headers, &self.http_transport_policy())
    }

    fn replay_service(&self) -> &ReplayService<PostgresReplayRepository> {
        self.session.replay_service()
    }

    fn mix_service(&self) -> &MixService<PostgresMixRepository> {
        self.room.mix_service()
    }

    fn sm_memory_governor(&self) -> &Arc<SmMemoryGovernor> {
        ServerNode::sm_memory_governor(self)
    }

    fn record_bosh_session_opened(&self) {
        self.metrics.record_bosh_session_opened();
    }
}

impl ServerNode {
    /// Process-local XEP-0124/XEP-0206 session authority. Transport handlers
    /// may submit bounded manager operations but cannot replace the manager.
    pub(crate) fn bosh_manager(&self) -> &northstar_bosh::BoshManager {
        self.bosh
            .as_ref()
            .expect("BOSH routes exist only when the capability runtime is enabled")
    }
}
