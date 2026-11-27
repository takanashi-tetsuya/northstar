use super::PresenceProbeTelemetry;
use crate::ClusterManager;
use anyhow::Result;
use northstar_roster_application::probe_decision::{PresenceRoute, ProbeQuery, ProbeStatus};
use northstar_roster_core::ExactPresenceRoute;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapturedPresenceProbe {
    pub(crate) owner_id: Uuid,
    pub(crate) owner_auth_generation: i64,
    pub(crate) owners: BTreeMap<String, Uuid>,
    pub(crate) requester: String,
    pub(crate) recipients: Vec<ExactPresenceRoute>,
    pub(crate) explicit: bool,
}

impl ClusterManager {
    pub async fn delegate_authorized_full_presence_probe_remote(
        &self,
        query: ProbeQuery<'_>,
        owners: &[PresenceRoute],
    ) -> Result<Option<ProbeStatus>> {
        self.request_captured_remote_presence(query, owners, None)
            .await
    }

    pub async fn replay_current_presence_from_remote_owners(
        &self,
        query: ProbeQuery<'_>,
        owners: &[PresenceRoute],
        telemetry: &PresenceProbeTelemetry<'_>,
    ) -> Result<Option<ProbeStatus>> {
        self.request_captured_remote_presence(query, owners, Some(telemetry))
            .await
    }

    async fn request_captured_remote_presence(
        &self,
        query: ProbeQuery<'_>,
        owners: &[PresenceRoute],
        telemetry: Option<&PresenceProbeTelemetry<'_>>,
    ) -> Result<Option<ProbeStatus>> {
        let mut nodes = BTreeMap::<_, BTreeMap<_, _>>::new();
        for owner in owners {
            let route = &owner.exact;
            if let Some(node) = route
                .node_id
                .as_deref()
                .filter(|node| *node != self.node_id)
            {
                nodes
                    .entry(node)
                    .or_default()
                    .insert(route.full_jid.clone(), route.connection_id);
            }
        }
        let mut status: Option<ProbeStatus> = None;
        let mut failure = None;
        for (node, owners) in nodes {
            let probe = CapturedPresenceProbe {
                owner_id: query.owner.id,
                owner_auth_generation: query.owner.auth_generation,
                owners,
                requester: query.requester.to_owned(),
                recipients: query
                    .recipients
                    .iter()
                    .map(|route| {
                        let mut exact = route.exact.clone();
                        if exact.node_id.is_none() {
                            exact.node_id = Some(self.node_id.clone());
                        }
                        exact
                    })
                    .collect(),
                explicit: query.explicit,
            };
            match self
                .request_presence_probe_from_node(node, query.target, &probe)
                .await
            {
                Ok(result) => {
                    status = Some(status.map_or(result, |previous| previous.combine(result)));
                }
                Err(error) => {
                    if let Some(telemetry) = telemetry {
                        telemetry.failed();
                        tracing::warn!(?error, owner = %query.target, recipient = %query.requester, %node, "cross-node current-presence replay failed");
                    } else {
                        failure = Some(error);
                    }
                }
            }
        }
        failure.map_or(Ok(status), Err)
    }
}
