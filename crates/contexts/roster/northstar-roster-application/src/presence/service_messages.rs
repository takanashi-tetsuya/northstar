use super::ServiceMessageClaim;
use anyhow::Result;
use std::future::Future;

/// The exact authenticated resource that claims and receives a service message.
pub type ServiceMessageRoute = northstar_roster_core::RosterActor;

pub trait ServiceMessageRepository: Send + Sync {
    fn claim_service_messages(
        &self,
        route: &ServiceMessageRoute,
    ) -> impl Future<Output = Result<Vec<ServiceMessageClaim>>> + Send;

    fn admit_service_message_claim(
        &self,
        claim: &ServiceMessageClaim,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn complete_service_message_claim(
        &self,
        claim: &ServiceMessageClaim,
    ) -> impl Future<Output = Result<bool>> + Send;
}
