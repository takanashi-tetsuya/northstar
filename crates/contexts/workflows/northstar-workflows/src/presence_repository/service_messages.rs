use super::PostgresPresenceRepository;
use anyhow::Result;
use northstar_operations_postgres::admin_commands::{
    admit_admin_service_message_claim, claim_admin_service_messages_for_route,
    complete_admin_service_message_claim_for_route,
};
use northstar_roster_application::presence::{
    ServiceMessageClaim, ServiceMessageRepository, ServiceMessageRoute,
};

impl ServiceMessageRepository for PostgresPresenceRepository {
    async fn claim_service_messages(
        &self,
        route: &ServiceMessageRoute,
    ) -> Result<Vec<ServiceMessageClaim>> {
        Ok(claim_admin_service_messages_for_route(&self.pool, route)
            .await?
            .into_iter()
            .map(|lease| ServiceMessageClaim::from_lease(route.clone(), lease))
            .collect())
    }

    async fn admit_service_message_claim(&self, claim: &ServiceMessageClaim) -> Result<bool> {
        admit_admin_service_message_claim(&self.pool, claim.route(), claim.lease()).await
    }

    async fn complete_service_message_claim(&self, claim: &ServiceMessageClaim) -> Result<bool> {
        complete_admin_service_message_claim_for_route(&self.pool, claim.route(), claim.lease())
            .await
    }
}
