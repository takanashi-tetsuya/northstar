//! Outbox compatibility commands for repository tests.

#[cfg(any(test, feature = "test-support"))]
use super::{
    resolve_pending_subscription_with_renderer, set_affiliations_with_renderer,
    set_subscription_limited_with_options_and_renderer, set_subscriptions_with_renderer,
    unsubscribe_checked_with_renderer, FixedMutationOutboxRenderer, PgPool,
    PubSubSubscriptionOptions, Result, SetAffiliationsOutcome, SetSubscriptionsOutcome,
    SubscribeOutcome, SubscriptionAuthorizationOutcome, UnsubscribeOutcome, Uuid,
};

// Compatibility shims for legacy repository-level tests. Production callers
// cannot provide pre-authorized recipients; they must use the renderer APIs.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub async fn set_subscription_limited_with_options_and_outbox(
    pool: &PgPool,
    local_domain: &str,
    node_id: Uuid,
    requester: &str,
    jid: &str,
    state: &str,
    expected_node_type: &str,
    expected_access_model: &str,
    max_subscriptions: i64,
    options: Option<&PubSubSubscriptionOptions>,
    requested_subid: &str,
    outbox: &[super::super::PubSubOutboxInsert],
) -> Result<SubscribeOutcome> {
    set_subscription_limited_with_options_and_renderer(
        pool,
        local_domain,
        node_id,
        requester,
        jid,
        state,
        expected_node_type,
        expected_access_model,
        max_subscriptions,
        options,
        requested_subid,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn unsubscribe_checked_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    subscriber_jid: &str,
    expected_subid: &str,
    outbox: &[super::super::PubSubOutboxInsert],
) -> Result<UnsubscribeOutcome> {
    unsubscribe_checked_with_renderer(
        pool,
        node_id,
        requester,
        subscriber_jid,
        expected_subid,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn resolve_pending_subscription_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    subscriber_jid: &str,
    expected_subid: &str,
    allow: bool,
    outbox: &[super::super::PubSubOutboxInsert],
) -> Result<SubscriptionAuthorizationOutcome> {
    resolve_pending_subscription_with_renderer(
        pool,
        node_id,
        requester,
        subscriber_jid,
        expected_subid,
        allow,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn set_subscriptions_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    changes: &[(String, String, Option<String>)],
    expected_transitions: Option<&[(String, String, String)]>,
    outbox: &[super::super::PubSubOutboxInsert],
) -> Result<SetSubscriptionsOutcome> {
    set_subscriptions_with_renderer(
        pool,
        node_id,
        requester,
        changes,
        expected_transitions,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}

#[cfg(any(test, feature = "test-support"))]
pub async fn set_affiliations_with_outbox(
    pool: &PgPool,
    node_id: Uuid,
    requester: &str,
    changes: &[(String, String)],
    expected_revoked: Option<&[(String, String)]>,
    expected_approved: Option<&[(String, String)]>,
    outbox: &[super::super::PubSubOutboxInsert],
) -> Result<SetAffiliationsOutcome> {
    set_affiliations_with_renderer(
        pool,
        node_id,
        requester,
        changes,
        expected_revoked,
        expected_approved,
        &FixedMutationOutboxRenderer(outbox),
    )
    .await
}
