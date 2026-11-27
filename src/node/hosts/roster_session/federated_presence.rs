use super::ServerNode;
use anyhow::Result;
use northstar_cluster::{
    presence_routing::{FederatedPresenceOwner, FederatedPresenceRequest},
    ExactControlKind,
};
use northstar_roster_application::probe_decision::{PresenceRoute, ProbeStatus};
use northstar_roster_core::PresenceAccount;
use northstar_roster_xmpp::{
    exact_presence::ExactPresenceHost, FederatedPresenceEffect, FederatedPresenceHandoff,
    FederatedPresenceOwnerHost,
};

impl FederatedPresenceOwnerHost for ServerNode {
    async fn capture_federated_presence(
        &self,
        target: &str,
        account: &PresenceAccount,
    ) -> Result<Vec<PresenceRoute>> {
        self.capture_presence_routes(target, account, false).await
    }

    async fn handoff_federated_presence(
        &self,
        account: &PresenceAccount,
        request: FederatedPresenceHandoff<'_>,
        routes: &[PresenceRoute],
    ) -> Result<Option<ProbeStatus>> {
        let (kind, pending_created_at_micros) = match request.effect {
            FederatedPresenceEffect::Forward {
                pending_created_at_micros,
            } => (
                ExactControlKind::FederatedInboundPresence,
                pending_created_at_micros,
            ),
            FederatedPresenceEffect::Probe => (ExactControlKind::ProbeResponse, None),
            FederatedPresenceEffect::Replay => (ExactControlKind::CurrentPresenceReplay, None),
        };
        let owner = FederatedPresenceOwner::new(
            self.session.live().sessions().clone(),
            self.roster.presence_service(),
            self.session.replay_service(),
            &self.federation.federation_outbox,
            &self.config.domain,
        );
        self.cluster
            .handoff_federated_presence(
                &owner,
                account,
                FederatedPresenceRequest {
                    target: request.target,
                    sender: request.sender,
                    stanza: request.stanza,
                    remote_peer: request.remote_peer,
                    kind,
                    pending_created_at_micros,
                },
                routes,
            )
            .await
    }
}
