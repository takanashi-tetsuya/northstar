//! Builds the cluster listener's blocking-presence fanout (`cluster::listener_blocking`).

use crate::node::ServerNode;
use northstar_cluster::listener_blocking::ClusterListenerBlocking;
use std::sync::Arc;

impl ServerNode {
    pub(crate) fn cluster_listener_blocking(
        &self,
    ) -> ClusterListenerBlocking<crate::node::adapters::cluster_adapters::PostgresClusterAdapters>
    {
        let roster_pool = self.pool.clone();
        let external_routes = self.config.external_route_domain_policy();
        ClusterListenerBlocking::new(
            Arc::clone(self.session.live().sessions()),
            self.cluster.clone(),
            self.config.domain.clone(),
            Arc::new(move |domain| external_routes.external_route_domain_allowed(domain)),
            self.federation.federation_outbox.clone(),
            northstar_roster_postgres::privacy::PostgresPrivacyRepository::new(self.pool.clone()),
            Arc::new(move |owner, contact| {
                let pool = roster_pool.clone();
                Box::pin(async move {
                    Ok(
                        northstar_roster_postgres::roster::roster_item(&pool, owner, &contact)
                            .await?
                            .is_some_and(|(_, _, subscription, _)| {
                                matches!(subscription.as_str(), "from" | "both")
                            }),
                    )
                })
            }),
        )
    }
}
