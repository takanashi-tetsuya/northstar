use super::{PostgresPresenceRepository, Result};
use crate::roster::WorkflowRosterEffects;
use northstar_roster_application::subscription_retry::{
    SubscriptionRetryAdmission, SubscriptionRetryIdentity, SubscriptionRetryRepository,
    SubscriptionRetryRequest,
};

impl SubscriptionRetryRepository for PostgresPresenceRepository {
    async fn pending_retry_identity(
        &self,
        request: SubscriptionRetryRequest<'_>,
    ) -> Result<Option<SubscriptionRetryIdentity>> {
        northstar_roster_postgres::roster::pending_retry_identity(&self.pool, request).await
    }

    async fn retry_outbound_subscription(
        &self,
        request: SubscriptionRetryRequest<'_>,
        expected: SubscriptionRetryIdentity,
        minimal_stanza: &str,
    ) -> Result<SubscriptionRetryAdmission> {
        northstar_roster_postgres::roster::retry_outbound_subscription(
            &WorkflowRosterEffects,
            &self.pool,
            request,
            expected,
            minimal_stanza,
        )
        .await
    }
}
