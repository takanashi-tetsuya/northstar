use anyhow::Result;
use northstar_roster_application::probe_decision::{PresenceRoute, ProbeQuery, ProbeStatus};
use northstar_roster_core::{PresenceAccount, RosterActor};
use std::future::Future;

#[derive(Clone, Copy)]
pub enum PresenceEffect {
    /// Broadcast presence, tagged with the sender's process-local CSI epoch.
    Broadcast {
        source_epoch: Option<u64>,
    },
    CurrentReplay,
    ProbeResponse,
}

/// Exact-route operations supplied by the composition root.
pub trait ExactPresenceHost: Send + Sync {
    fn capture_presence_routes(
        &self,
        target: &str,
        account: &PresenceAccount,
        available_only: bool,
    ) -> impl Future<Output = Result<Vec<PresenceRoute>>> + Send;

    fn send_presence_route(
        &self,
        source: &RosterActor,
        recipient: &PresenceRoute,
        stanza: &str,
        effect: PresenceEffect,
        available_only: bool,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn answer_presence_probe(
        &self,
        owner: &PresenceAccount,
        target: &str,
        requester: &RosterActor,
        active_list: Option<String>,
        id: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn replay_presence_to_routes(
        &self,
        owner: &PresenceAccount,
        target: &str,
        recipient: &str,
        routes: &[PresenceRoute],
    ) -> impl Future<Output = Result<()>> + Send;

    fn request_captured_presence(
        &self,
        query: ProbeQuery<'_>,
        owners: &[PresenceRoute],
    ) -> impl Future<Output = Result<Option<ProbeStatus>>> + Send;
}

pub trait ExactPresenceSession: Sync {
    fn exact_presence_host(&self) -> &impl ExactPresenceHost;
}
