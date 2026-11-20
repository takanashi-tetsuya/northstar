use super::{map_database_busy, PostgresPubSubRepository, Result};
use northstar_pubsub_application::{
    PubSubItemQuery, PubSubItemRead, PubSubItemSnapshotRepository, PubSubOptionsQuery,
    PubSubOptionsRead,
};

impl PubSubItemSnapshotRepository for PostgresPubSubRepository {
    async fn item_read(&self, query: &PubSubItemQuery<'_>) -> Result<PubSubItemRead> {
        northstar_pubsub_postgres::item_read(&self.pool, query)
            .await
            .map_err(map_database_busy)
    }

    async fn subscription_options_read(
        &self,
        query: &PubSubOptionsQuery<'_>,
    ) -> Result<PubSubOptionsRead> {
        northstar_pubsub_postgres::subscription_options_read(&self.pool, query)
            .await
            .map_err(map_database_busy)
    }
}
