use super::{map_database_busy, PostgresPubSubRepository};
use anyhow::Result;
use northstar_pubsub_application::PubSubOwnerPreflightRepository;
use northstar_pubsub_core::{PubSubBareJid, PubSubNodeName, PubSubOwnerPreflight};

impl PubSubOwnerPreflightRepository for PostgresPubSubRepository {
    async fn owner_preflight(
        &self,
        node: &PubSubNodeName,
        requester: &PubSubBareJid,
        include_graph: bool,
    ) -> Result<Option<PubSubOwnerPreflight>> {
        northstar_pubsub_postgres::owner_preflight(&self.pool, node, requester, include_graph)
            .await
            .map_err(map_database_busy)
    }
}
