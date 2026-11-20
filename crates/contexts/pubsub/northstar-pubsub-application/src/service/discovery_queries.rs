use super::PubSubService;
use crate::{
    PubSubDiscoverySnapshotRepository, PubSubNodeInfo, PubSubNodeInfoQuery, PubSubNodeItems,
    PubSubNodeItemsQuery, PubSubSelfList, PubSubSelfListQuery,
};
use anyhow::Result;
use northstar_pubsub_core::{PubSubAffiliation, PubSubSubscription};

impl<R: PubSubDiscoverySnapshotRepository> PubSubService<R> {
    pub async fn node_info(&self, query: &PubSubNodeInfoQuery<'_>) -> Result<PubSubNodeInfo> {
        self.repository.node_info(query).await
    }

    pub async fn node_items(&self, query: &PubSubNodeItemsQuery<'_>) -> Result<PubSubNodeItems> {
        self.repository.node_items(query).await
    }

    pub async fn self_subscriptions(
        &self,
        query: &PubSubSelfListQuery<'_>,
    ) -> Result<PubSubSelfList<PubSubSubscription>> {
        self.repository.self_subscriptions(query).await
    }

    pub async fn self_affiliations(
        &self,
        query: &PubSubSelfListQuery<'_>,
    ) -> Result<PubSubSelfList<PubSubAffiliation>> {
        self.repository.self_affiliations(query).await
    }
}
