use super::UnusedRepository;
use anyhow::Result;
use northstar_roster_application::presence::{
    ServiceMessageClaim, ServiceMessageRepository, ServiceMessageRoute,
};

impl ServiceMessageRepository for UnusedRepository {
    async fn claim_service_messages(
        &self,
        _route: &ServiceMessageRoute,
    ) -> Result<Vec<ServiceMessageClaim>> {
        panic!("unexpected port call: claim_service_messages")
    }

    async fn admit_service_message_claim(&self, _claim: &ServiceMessageClaim) -> Result<bool> {
        panic!("unexpected port call: admit_service_message_claim")
    }

    async fn complete_service_message_claim(&self, _claim: &ServiceMessageClaim) -> Result<bool> {
        panic!("unexpected port call: complete_service_message_claim")
    }
}
