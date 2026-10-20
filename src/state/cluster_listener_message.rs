//! Typed policy and durable hand-off effects for authenticated node delivery.

use super::AppState;
use crate::cluster::ClusterListenerMessagePolicy;
use std::sync::Arc;

impl AppState {
    pub(crate) fn cluster_listener_message_policy(&self) -> ClusterListenerMessagePolicy {
        ClusterListenerMessagePolicy {
            local_domain: self.config.domain.clone(),
            presence: self.presence_service.clone(),
            message: self.message_service.clone(),
            mix: self.mix_service.clone(),
            verifier: self.node_message_contract_verifier(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}
