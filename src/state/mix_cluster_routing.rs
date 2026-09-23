//! Cluster routing used by MIX ingress and durable outbox delivery.

use super::AppState;
use anyhow::Result;

pub(crate) struct MixClusterRouting<'a> {
    state: &'a AppState,
}

fn remote_nodes_in_order(nodes: Vec<String>, local_node: &str) -> Vec<String> {
    nodes
        .into_iter()
        .filter(|node| node != local_node)
        .collect()
}

impl AppState {
    pub(crate) fn mix_cluster_routing(&self) -> MixClusterRouting<'_> {
        MixClusterRouting { state: self }
    }
}

impl MixClusterRouting<'_> {
    /// Live ingress resolves Redis route authority without entering the
    /// durable outbox database-admission lane.
    pub(crate) async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let nodes = self.state.cluster.lookup_nodes(jid).await?;
        Ok(remote_nodes_in_order(nodes, &self.state.cluster.node_id))
    }

    /// A claimed outbox row uses MIX's existing route lookup path; it never
    /// holds the database-admission permit while awaiting Redis.
    pub(crate) async fn outbox_lookup_cluster_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let nodes = self
            .state
            .mix_service()
            .outbox_lookup_cluster_nodes(&self.state.cluster, jid)
            .await?;
        Ok(remote_nodes_in_order(nodes, &self.state.cluster.node_id))
    }

    /// Preserve the peer's typed receipt, including v13 hand-off ownership.
    /// The caller decides whether the source lease must stop or retry.
    pub(crate) async fn send_to_node_mix(
        &self,
        node: &str,
        recipient: &str,
        stanza: &str,
        source: Option<crate::outbound::MixDelivery>,
    ) -> Result<crate::cluster::NodeDeliveryReceipt> {
        self.state
            .cluster
            .send_to_node_mix(node, recipient, stanza, source)
            .await
    }

    /// PAM results use an account-bound IQ hand-off, not MIX fan-out.
    pub(crate) async fn send_to_node_exact_account(
        &self,
        node: &str,
        target_full_jid: &str,
        result_xml: &str,
        expected_user_id: uuid::Uuid,
    ) -> Result<bool> {
        self.state
            .cluster
            .send_to_node_exact_account(node, target_full_jid, result_xml, expected_user_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::remote_nodes_in_order;

    #[test]
    fn remote_mix_nodes_keep_authority_order_and_duplicate_routes() {
        assert_eq!(
            remote_nodes_in_order(
                vec!["second", "local", "first", "second"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                "local",
            ),
            vec!["second", "first", "second"]
        );
    }
}
