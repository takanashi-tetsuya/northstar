use anyhow::Result;
use northstar_roster_application::probe_decision::{PresenceRoute, ProbeStatus};
use northstar_roster_core::PresenceAccount;
use std::future::Future;

#[derive(Clone, Copy)]
pub enum FederatedPresenceEffect {
    Forward {
        pending_created_at_micros: Option<i64>,
    },
    Probe,
    Replay,
}

#[derive(Clone, Copy)]
pub struct FederatedPresenceHandoff<'a> {
    pub target: &'a str,
    /// The canonical stanza peer before subscription presence is stamped bare.
    pub sender: &'a str,
    /// The domain authenticated by the inbound S2S or component connection.
    pub remote_peer: &'a str,
    pub stanza: &'a str,
    pub effect: FederatedPresenceEffect,
}

/// Transport to the exact resource owners for authenticated inbound federation.
pub trait FederatedPresenceOwnerHost: Send + Sync {
    fn capture_federated_presence(
        &self,
        target: &str,
        account: &PresenceAccount,
    ) -> impl Future<Output = Result<Vec<PresenceRoute>>> + Send;

    fn handoff_federated_presence(
        &self,
        account: &PresenceAccount,
        request: FederatedPresenceHandoff<'_>,
        routes: &[PresenceRoute],
    ) -> impl Future<Output = Result<Option<ProbeStatus>>> + Send;
}
