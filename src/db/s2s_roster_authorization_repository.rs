//! PostgreSQL subscription read for inbound federation roster visibility.

use crate::db;
use crate::services::s2s_roster_authorization::{
    FederatedRosterRepository, FederatedRosterSubscription,
};
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresFederatedRosterRepository {
    pool: PgPool,
}

impl PostgresFederatedRosterRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl FederatedRosterRepository for PostgresFederatedRosterRepository {
    async fn subscription_for(
        &self,
        recipient_id: Uuid,
        requester_bare: &str,
    ) -> Result<Option<FederatedRosterSubscription>> {
        let item = db::roster_item(&self.pool, recipient_id, requester_bare).await?;
        Ok(item.map(|item| match item.2.as_str() {
            "from" => FederatedRosterSubscription::From,
            "both" => FederatedRosterSubscription::Both,
            _ => FederatedRosterSubscription::Other,
        }))
    }
}
