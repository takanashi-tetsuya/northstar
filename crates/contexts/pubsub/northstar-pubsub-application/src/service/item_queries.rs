use super::PubSubService;
use crate::{
    PubSubItemQuery, PubSubItemRead, PubSubItemSnapshotRepository, PubSubOptionsQuery,
    PubSubOptionsRead,
};
use anyhow::Result;

impl<R: PubSubItemSnapshotRepository> PubSubService<R> {
    pub async fn read_items(&self, query: &PubSubItemQuery<'_>) -> Result<PubSubItemRead> {
        self.repository.item_read(query).await
    }

    pub async fn subscription_options_read(
        &self,
        query: &PubSubOptionsQuery<'_>,
    ) -> Result<PubSubOptionsRead> {
        self.repository.subscription_options_read(query).await
    }
}
