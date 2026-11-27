use super::PostgresPresenceRepository;
use northstar_roster_application::{
    CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader,
};
use northstar_roster_postgres::privacy::PostgresPrivacyRepository;

impl CommunicationPolicyReader for PostgresPresenceRepository {
    async fn read_communication_policies(
        &self,
        queries: &[CommunicationPolicyQuery],
    ) -> anyhow::Result<Vec<CommunicationDecision>> {
        PostgresPrivacyRepository::new(self.pool.clone())
            .read_communication_policies(queries)
            .await
    }
}
