//! The node's capabilities as BOSH sees them.

use super::AppState;
use axum::http::HeaderMap;
use northstar_bosh::host::{BoshHost, BoshPolicy};
use northstar_bosh::BoshManager;
use northstar_room_application::mix_service::MixService;
use northstar_session_application::replay::ReplayService;
use northstar_session_application::sm_capacity::SmMemoryGovernor;
use northstar_session_postgres::replay_repository::PostgresReplayRepository;
use northstar_workflows::room_effects::PostgresMixRepository;
use std::{net::IpAddr, sync::Arc};

impl BoshHost for AppState {
    type ReplayStore = PostgresReplayRepository;
    type MixStore = PostgresMixRepository;

    fn bosh_manager(&self) -> &BoshManager {
        AppState::bosh_manager(self)
    }

    fn bosh_policy(&self) -> BoshPolicy {
        AppState::bosh_policy(self)
    }

    fn trusted_proxy_ips(&self) -> &[IpAddr] {
        AppState::trusted_proxy_ips(self)
    }

    fn client_ip(&self, peer_ip: IpAddr, headers: &HeaderMap) -> IpAddr {
        northstar_http::client_ip(peer_ip, headers, &self.http_transport_policy())
    }

    fn replay_service(&self) -> &ReplayService<PostgresReplayRepository> {
        AppState::replay_service(self)
    }

    fn mix_service(&self) -> &MixService<PostgresMixRepository> {
        AppState::mix_service(self)
    }

    fn sm_memory_governor(&self) -> &Arc<SmMemoryGovernor> {
        AppState::sm_memory_governor(self)
    }

    fn record_bosh_session_opened(&self) {
        AppState::record_bosh_session_opened(self);
    }
}
