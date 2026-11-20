use crate::{
    PepAccountItemsRead, PepAccountQuery, PepItemQuery, PepItemRead, PepNodeInfoRead,
    PepNodeItemsRead, PepNodeQuery, PepOwnerQuery, PepOwnerSubscriptionsRead,
    PepSnapshotRepository,
};
use anyhow::Result;

use super::PubSubService;

impl<R: PepSnapshotRepository> PubSubService<R> {
    pub async fn pep_items_read(&self, query: &PepItemQuery<'_>) -> Result<PepItemRead> {
        self.repository.pep_items_read(query).await
    }

    pub async fn pep_node_info(&self, query: &PepNodeQuery<'_>) -> Result<PepNodeInfoRead> {
        self.repository.pep_node_info(query).await
    }

    pub async fn pep_node_items(&self, query: &PepNodeQuery<'_>) -> Result<PepNodeItemsRead> {
        self.repository.pep_node_items(query).await
    }

    pub async fn pep_account_items(
        &self,
        query: &PepAccountQuery<'_>,
    ) -> Result<PepAccountItemsRead> {
        self.repository.pep_account_items(query).await
    }

    pub async fn pep_owner_subscriptions(
        &self,
        query: &PepOwnerQuery<'_>,
    ) -> Result<PepOwnerSubscriptionsRead> {
        self.repository.pep_owner_subscriptions(query).await
    }
}
