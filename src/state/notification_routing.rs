use super::AppState;

pub(crate) struct RemoteNotificationDelivery {
    pub(crate) remote_nodes: usize,
    pub(crate) delivered: bool,
}

impl AppState {
    /// PEP and PubSub notifications target the first remote node that accepts
    /// the recipient, while the caller retains local privacy and retry policy.
    pub(crate) async fn route_local_notification_remote(
        &self,
        recipient: &str,
        stanza: &str,
    ) -> anyhow::Result<RemoteNotificationDelivery> {
        let mut outcome = RemoteNotificationDelivery {
            remote_nodes: 0,
            delivered: false,
        };
        for node_id in self.cluster.lookup_nodes(recipient).await? {
            if node_id != self.cluster.node_id {
                outcome.remote_nodes += 1;
                if self
                    .cluster
                    .send_to_node(&node_id, recipient, stanza, false, None)
                    .await?
                {
                    outcome.delivered = true;
                    break;
                }
            }
        }
        Ok(outcome)
    }
}
