//! Builds the cluster listener's blocking-presence fanout (`cluster::listener_blocking`).

use super::AppState;
use crate::cluster::listener_blocking::ClusterListenerBlocking;
use std::sync::Arc;

impl AppState {
    pub(crate) fn cluster_listener_blocking(&self) -> ClusterListenerBlocking {
        ClusterListenerBlocking {
            sessions: Arc::clone(&self.sessions),
            remote_routes: self.cluster.listener_presence_routes(),
            local_domain: self.config.domain.clone(),
            external_routes: self.config.external_route_domain_policy(),
            federation: self.federation_outbox.clone(),
        }
    }
}
