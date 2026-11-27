//! Typed policy and durable hand-off effects for authenticated node delivery.

use crate::node::adapters::cluster_adapters::PostgresClusterAdapters;
use crate::node::ServerNode;
use northstar_cluster::ClusterListenerMessagePolicy;
use std::sync::Arc;

impl ServerNode {
    pub(crate) fn cluster_listener_message_policy(
        &self,
    ) -> ClusterListenerMessagePolicy<PostgresClusterAdapters> {
        ClusterListenerMessagePolicy {
            local_domain: self.config.domain.clone(),
            presence: self.roster.presence_service.clone(),
            message: self.message.message_service.clone(),
            notification: northstar_workflows::pubsub_repository::PostgresPubSubRepository::new(
                self.pool.clone(),
                &self.config.domain,
            ),
            mix: self.room.mix_service.clone(),
            verifier: northstar_session_application::node_message_contract_verifier::NodeMessageContractVerifier::new(
                northstar_session_postgres::node_message_projection_repository::PostgresNodeMessageProjectionRepository::new(
                    self.pool.clone(),
                ),
            ),
            metrics: Arc::clone(&self.metrics),
        }
    }
}
