use super::UnusedPorts;
use anyhow::Result;
use northstar_roster_application::presence::{
    ServiceMessageClaim, ServiceMessageRepository, ServiceMessageRoute,
};

impl ServiceMessageRepository for UnusedPorts {
    async fn claim_service_messages(
        &self,
        _route: &ServiceMessageRoute,
    ) -> Result<Vec<ServiceMessageClaim>> {
        panic!("unused ServiceMessageRepository::claim_service_messages port");
    }

    async fn admit_service_message_claim(&self, _claim: &ServiceMessageClaim) -> Result<bool> {
        panic!("unused ServiceMessageRepository::admit_service_message_claim port");
    }

    async fn complete_service_message_claim(&self, _claim: &ServiceMessageClaim) -> Result<bool> {
        panic!("unused ServiceMessageRepository::complete_service_message_claim port");
    }
}
