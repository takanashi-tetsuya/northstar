use super::RemoteRouteFailure;
use crate::ClusterManager;
use anyhow::Result;
use northstar_roster_core::RosterActor;

impl ClusterManager {
    pub async fn route_remote_blocklist_push(
        &self,
        actor: &RosterActor,
        revision: i64,
        mut push: impl FnMut() -> Result<String> + Send,
    ) -> Result<Vec<RemoteRouteFailure>> {
        let mut failures = Vec::new();
        for route in self
            .capture_remote_message_routes(
                actor.bare_jid(),
                actor.account_id,
                actor.auth_generation,
            )
            .await?
        {
            let Some(node_id) = route.node_id.clone() else {
                continue;
            };
            let stanza = push()?;
            if let Err(error) = require_policy_push_ack(
                self.send_to_node_blocklist(&route, revision, &stanza).await,
                &route.full_jid,
            ) {
                failures.push(RemoteRouteFailure { node_id, error });
            }
        }
        Ok(failures)
    }

    pub async fn route_remote_privacy_push(
        &self,
        actor: &RosterActor,
        push: &str,
    ) -> Result<Vec<RemoteRouteFailure>> {
        let mut failures = Vec::new();
        for route in self
            .capture_remote_message_routes(
                actor.bare_jid(),
                actor.account_id,
                actor.auth_generation,
            )
            .await?
        {
            let Some(node_id) = route.node_id.clone() else {
                continue;
            };
            if let Err(error) = require_policy_push_ack(
                self.send_to_node_privacy(&route, push).await,
                &route.full_jid,
            ) {
                failures.push(RemoteRouteFailure { node_id, error });
            }
        }
        Ok(failures)
    }
}

pub(crate) fn require_policy_push_ack(result: Result<bool>, target: &str) -> Result<()> {
    anyhow::ensure!(
        result?,
        "no acknowledgement for exact policy push to {target}"
    );
    Ok(())
}
