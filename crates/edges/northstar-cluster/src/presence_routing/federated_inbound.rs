pub use crate::listener::FederatedPresenceOwner;
use crate::{ClusterControlOutcome, ClusterManager, ExactControl, ExactControlKind};
use anyhow::Result;
use northstar_roster_application::presence::PresenceRepository;
use northstar_roster_application::probe_decision::{PresenceRoute, ProbeQuery, ProbeStatus};
use northstar_roster_core::PresenceAccount;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct FederatedPresenceRequest<'a> {
    pub target: &'a str,
    pub sender: &'a str,
    /// Ordinary or subscription input, the incoming probe, or a replay request
    /// addressed from the remote contact to the local owner.
    pub stanza: &'a str,
    pub remote_peer: &'a str,
    pub kind: ExactControlKind,
    pub pending_created_at_micros: Option<i64>,
}

impl FederatedPresenceRequest<'_> {
    pub(crate) fn control(
        self,
        account: &PresenceAccount,
        expected_connections: BTreeMap<String, Uuid>,
    ) -> ExactControl {
        ExactControl {
            kind: self.kind,
            account_id: account.id,
            auth_generation: account.auth_generation,
            expected_connections,
            roster_version: None,
            blocklist_revision: None,
            remote_peer: Some(self.remote_peer.to_owned()),
            source: None,
            sequence: None,
        }
    }

    pub(crate) fn payload(self, control: &ExactControl) -> serde_json::Value {
        serde_json::json!({
            "target": self.target,
            "stanza": self.stanza,
            "sender": self.sender,
            "pending_created_at_micros": self.pending_created_at_micros,
            "exact_control": control,
        })
    }
}

impl ClusterManager {
    pub async fn handoff_federated_presence(
        &self,
        owner: &FederatedPresenceOwner<
            '_,
            impl PresenceRepository,
            impl northstar_session_application::replay::pending_presence::PendingPresenceRepository,
            impl northstar_federation_core::FederationRoute,
        >,
        account: &PresenceAccount,
        request: FederatedPresenceRequest<'_>,
        routes: &[PresenceRoute],
    ) -> Result<Option<ProbeStatus>> {
        let probe = request.kind == ExactControlKind::ProbeResponse;
        let mut nodes = BTreeMap::<_, BTreeMap<_, _>>::new();
        for route in routes {
            let exact = &route.exact;
            if exact.account_id == account.id && exact.auth_generation == account.auth_generation {
                let node = exact
                    .node_id
                    .as_deref()
                    .filter(|node| *node != self.node_id);
                nodes
                    .entry(node)
                    .or_default()
                    .insert(exact.full_jid.clone(), exact.connection_id);
            }
        }
        if nodes.is_empty() && probe {
            let decision = owner
                .presence
                .decide_probe(ProbeQuery {
                    owner: account,
                    target: request.target,
                    requester: request.sender,
                    candidates: &[],
                    recipients: &[],
                    explicit: true,
                })
                .await?;
            return Ok(Some(decision.status()));
        }

        let mut status: Option<ProbeStatus> = None;
        let mut failure = None;
        for (node, routes) in nodes {
            let control = request.control(account, routes);
            let result = match node {
                Some(node) => self.send_federated_presence(node, request, &control).await,
                None => owner
                    .deliver(request, &control)
                    .await
                    .map(|delivery| delivery.status),
            };
            match result {
                Ok(Some(next)) => status = Some(status.map_or(next, |prior| prior.combine(next))),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        ?node,
                        target = request.target,
                        "federated presence owner handoff failed"
                    );
                    failure = Some(error);
                }
            }
        }
        // A silent owner can reflect a block committed during the fan-out.
        if status == Some(ProbeStatus::Silent) {
            return Ok(status);
        }
        failure.map_or(Ok(status), Err)
    }

    async fn send_federated_presence(
        &self,
        node: &str,
        request: FederatedPresenceRequest<'_>,
        control: &ExactControl,
    ) -> Result<Option<ProbeStatus>> {
        let ack = self
            .correlated_control_sender()
            .send_control_to_node_ack(node, request.target, request.payload(control))
            .await?;
        anyhow::ensure!(
            ack.control_processed == Some(true),
            "federated presence control rejected"
        );
        let status = match ack.control_outcome {
            Some(ClusterControlOutcome::PresenceSilent) => ProbeStatus::Silent,
            Some(ClusterControlOutcome::PresenceUnsubscribed) => ProbeStatus::Unsubscribed,
            Some(ClusterControlOutcome::PresenceUnavailable) => ProbeStatus::Unavailable,
            Some(ClusterControlOutcome::PresenceAvailable) => ProbeStatus::Available,
            _ if request.kind != ExactControlKind::ProbeResponse => return Ok(None),
            _ => anyhow::bail!("federated probe reply could not be admitted"),
        };
        Ok(Some(status))
    }
}
