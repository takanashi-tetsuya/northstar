//! Account-scoped cluster delivery used by roster, privacy, and blocking.

use super::AppState;
use anyhow::Result;

pub(crate) struct RemoteRouteFailure {
    pub(crate) node_id: String,
    pub(crate) error: anyhow::Error,
}

pub(crate) enum RemoteRosterPushFailure {
    NotAccepted { node_id: String },
    Delivery(RemoteRouteFailure),
}

impl AppState {
    /// Discovery combines the disposable cluster cache with this node's
    /// current occupants, then returns a stable nickname order for paging.
    pub(crate) async fn discovery_room_occupants(
        &self,
        room_jid: &str,
    ) -> Result<Vec<super::SerializableMucOccupant>> {
        let mut occupants = self
            .cluster
            .get_muc_occupants(room_jid)
            .await?
            .into_values()
            .filter_map(|json| serde_json::from_str::<super::SerializableMucOccupant>(&json).ok())
            .map(|occupant| (occupant.nick.clone(), occupant))
            .collect::<std::collections::HashMap<_, _>>();
        for (_, occupant) in self.muc_occupants_for(room_jid) {
            let occupant = super::SerializableMucOccupant::from(&occupant);
            occupants.insert(occupant.nick.clone(), occupant);
        }
        let mut occupants = occupants.into_values().collect::<Vec<_>>();
        occupants.sort_by(|left, right| left.nick.cmp(&right.nick));
        Ok(occupants)
    }

    /// Push-service notifications use deterministic node order and stop when
    /// one primary resource accepts the IQ.
    pub(crate) async fn route_push_service_notification_remote(
        &self,
        service_jid: &str,
        notification: &str,
    ) -> bool {
        let mut nodes = self
            .cluster
            .lookup_nodes(service_jid)
            .await
            .unwrap_or_default();
        nodes.sort();
        for node_id in nodes {
            if node_id != self.cluster.node_id
                && self
                    .cluster
                    .send_to_node_primary(&node_id, service_jid, notification)
                    .await
                    .is_ok_and(|receipt| receipt.delivered)
            {
                return true;
            }
        }
        false
    }

    /// Resolve only other nodes. A full-JID lookup retains the exact target
    /// semantics of the underlying session-route authority.
    pub(crate) async fn remote_resource_nodes(&self, target: &str) -> Result<Vec<String>> {
        let nodes = self.cluster.lookup_nodes(target).await?;
        Ok(nodes
            .into_iter()
            .filter(|node_id| node_id != &self.cluster.node_id)
            .collect())
    }

    pub(crate) async fn account_has_remote_resources(&self, account: &str) -> Result<bool> {
        Ok(!self.remote_resource_nodes(account).await?.is_empty())
    }

    pub(crate) async fn route_remote_blocklist_push(
        &self,
        owner: &str,
        mut push: impl FnMut() -> String + Send,
    ) -> Result<Vec<RemoteRouteFailure>> {
        let mut failures = Vec::new();
        for node_id in self.remote_resource_nodes(owner).await? {
            let stanza = push();
            if let Err(error) = self
                .cluster
                .send_to_node_blocklist(&node_id, owner, &stanza)
                .await
            {
                failures.push(RemoteRouteFailure { node_id, error });
            }
        }
        Ok(failures)
    }

    pub(crate) async fn route_remote_blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        patterns: &[String],
        available: bool,
    ) -> Result<Vec<RemoteRouteFailure>> {
        let mut failures = Vec::new();
        for node_id in self.remote_resource_nodes(owner).await? {
            if let Err(error) = self
                .cluster
                .send_blocking_presence_change(&node_id, owner, targets, patterns, available)
                .await
            {
                failures.push(RemoteRouteFailure { node_id, error });
            }
        }
        Ok(failures)
    }

    pub(crate) async fn route_remote_privacy_push(
        &self,
        account: &str,
        push: &str,
    ) -> Result<Vec<RemoteRouteFailure>> {
        let mut failures = Vec::new();
        for node_id in self.remote_resource_nodes(account).await? {
            if let Err(error) = self
                .cluster
                .send_to_node_privacy(&node_id, account, push)
                .await
            {
                failures.push(RemoteRouteFailure { node_id, error });
            }
        }
        Ok(failures)
    }

    /// A roster removal's subscription presence is best effort, as it was
    /// before this routing adapter. The authority fences remain unchanged.
    pub(crate) async fn route_remote_roster_removal_presence(
        &self,
        target_bare: &str,
        stanza: &str,
        authority: crate::cluster::ClusterPresenceAuthority,
    ) {
        if let Ok(nodes) = self.remote_resource_nodes(target_bare).await {
            for node_id in nodes {
                let _ = self
                    .cluster
                    .send_to_node_presence_subscription(
                        &node_id,
                        target_bare,
                        stanza,
                        false,
                        authority,
                    )
                    .await;
            }
        }
    }

    pub(crate) async fn route_remote_available_presence_to_node(
        &self,
        node_id: &str,
        target: &str,
        stanza: &str,
    ) -> Result<bool> {
        self.cluster
            .send_to_node_available_presence(node_id, target, stanza)
            .await
    }
}
