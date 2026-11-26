//! Implement local and remote presence-subscription transitions, pending-state queries, and transactional outbox admission.

use super::*;

mod inbound;
mod local;
mod outbound;

pub use self::inbound::transition_inbound_remote_presence_subscription;
pub use self::local::{
    suppressed_local_presence_transition, transition_local_presence_subscription_authorized,
    transition_local_presence_subscription_authorized_with_hook,
    transition_local_presence_subscription_in_transaction,
};
pub use self::outbound::{
    transition_remote_presence_subscription_authorized,
    transition_remote_presence_subscription_authorized_inner,
    transition_remote_presence_subscription_in_transaction,
    transition_remote_presence_subscription_with_outbox_authorized,
};

pub fn add_subscription_direction(current: &str, direction: &str) -> &'static str {
    match (current, direction) {
        ("none", "to") => "to",
        ("none", "from") => "from",
        ("to", "from") | ("from", "to") | ("both", _) => "both",
        ("to", "to") => "to",
        ("from", "from") => "from",
        _ => "none",
    }
}

pub fn remove_subscription_direction(current: &str, direction: &str) -> &'static str {
    match (current, direction) {
        ("both", "to") => "from",
        ("both", "from") => "to",
        ("to", "to") | ("from", "from") => "none",
        ("to", "from") => "to",
        ("from", "to") => "from",
        _ => "none",
    }
}

pub async fn pending_presence_subscription_count(pool: &PgPool, recipient_id: Uuid) -> Result<i64> {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM pending_presence_subscriptions WHERE recipient_id = $1) + (SELECT COUNT(*) FROM federated_presence_pending WHERE recipient_id = $1)",
    )
    .bind(recipient_id)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}
