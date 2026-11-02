//! What BOSH needs from the node beyond every transport's [`TransportHost`]: the session manager
//! and its limits, the proxies it trusts, the services a BOSH actor drives directly (offline
//! replay, MIX transfer and the SM memory governor) and the session metric. Its session must also
//! be a [`RecordPort`].

use super::ownership::RecordPort;
use super::BoshManager;
use axum::http::HeaderMap;
use northstar_room_application::mix_service::{MixRepository, MixService};
use northstar_session_application::replay::{ReplayRepository, ReplayService};
use northstar_session_application::sm_capacity::SmMemoryGovernor;
use northstar_stream::host::TransportHost;
use std::{net::IpAddr, sync::Arc};

/// The configured BOSH limits, read once per session or request.
#[derive(Clone, Copy)]
pub(crate) struct BoshPolicy {
    pub(crate) max_wait_seconds: u64,
    pub(crate) inactivity_seconds: u64,
    pub(crate) polling_seconds: u64,
    pub(crate) max_pause_seconds: u64,
    pub(crate) body_read_timeout_seconds: u64,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
    pub(crate) max_stanzas_per_request: usize,
    pub(crate) max_output_stanzas: usize,
    pub(crate) max_output_bytes: usize,
}

pub(crate) trait BoshHost: TransportHost<Session: RecordPort> {
    /// The repository behind a BOSH session's offline replay.
    type ReplayStore: ReplayRepository + Clone + 'static;

    /// The repository behind the transfer of pending MIX deliveries.
    type MixStore: MixRepository + Clone + 'static;

    fn bosh_manager(&self) -> &BoshManager;

    fn bosh_policy(&self) -> BoshPolicy;

    /// Proxies whose forwarded headers may vouch for a request's TLS.
    fn trusted_proxy_ips(&self) -> &[IpAddr];

    /// The client address behind trusted proxies, for admission and logs.
    fn client_ip(&self, peer_ip: IpAddr, headers: &HeaderMap) -> IpAddr;

    fn replay_service(&self) -> &ReplayService<Self::ReplayStore>;

    fn mix_service(&self) -> &MixService<Self::MixStore>;

    fn sm_memory_governor(&self) -> &Arc<SmMemoryGovernor>;

    fn record_bosh_session_opened(&self);
}
