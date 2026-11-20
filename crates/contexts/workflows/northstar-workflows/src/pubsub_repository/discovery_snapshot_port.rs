use super::{map_database_busy, PostgresPubSubRepository};
use anyhow::Result;
use northstar_pubsub_application::{
    PubSubDiscoverySnapshotRepository, PubSubNodeInfo, PubSubNodeInfoQuery, PubSubNodeItems,
    PubSubNodeItemsQuery, PubSubSelfList, PubSubSelfListQuery,
};
use northstar_pubsub_core::{PubSubAffiliation, PubSubSubscription};

impl PubSubDiscoverySnapshotRepository for PostgresPubSubRepository {
    async fn node_info(&self, query: &PubSubNodeInfoQuery<'_>) -> Result<PubSubNodeInfo> {
        northstar_pubsub_postgres::node_info(&self.pool, query)
            .await
            .map_err(map_database_busy)
    }

    async fn node_items(&self, query: &PubSubNodeItemsQuery<'_>) -> Result<PubSubNodeItems> {
        northstar_pubsub_postgres::node_items(&self.pool, query)
            .await
            .map_err(map_database_busy)
    }

    async fn self_subscriptions(
        &self,
        query: &PubSubSelfListQuery<'_>,
    ) -> Result<PubSubSelfList<PubSubSubscription>> {
        northstar_pubsub_postgres::self_subscriptions(&self.pool, query)
            .await
            .map_err(map_database_busy)
    }

    async fn self_affiliations(
        &self,
        query: &PubSubSelfListQuery<'_>,
    ) -> Result<PubSubSelfList<PubSubAffiliation>> {
        northstar_pubsub_postgres::self_affiliations(&self.pool, query)
            .await
            .map_err(map_database_busy)
    }
}
