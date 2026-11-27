use super::UnusedRepository;
use anyhow::Result;
use northstar_roster_application::subscription_retry::{
    SubscriptionRetryAdmission, SubscriptionRetryIdentity, SubscriptionRetryRepository,
    SubscriptionRetryRequest,
};

impl SubscriptionRetryRepository for UnusedRepository {
    async fn pending_retry_identity(
        &self,
        _: SubscriptionRetryRequest<'_>,
    ) -> Result<Option<SubscriptionRetryIdentity>> {
        panic!("unexpected subscription retry snapshot")
    }

    async fn retry_outbound_subscription(
        &self,
        _: SubscriptionRetryRequest<'_>,
        _: SubscriptionRetryIdentity,
        _: &str,
    ) -> Result<SubscriptionRetryAdmission> {
        panic!("unexpected subscription retry admission")
    }
}
