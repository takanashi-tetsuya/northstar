use anyhow::Result;
use northstar_pubsub_application::{PubSubOwnerRead, PubSubOwnerReadKind};
use northstar_pubsub_core::{pubsub_subscribe_policy, PubSubSubscribePolicy};
use northstar_time::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::BTreeSet;
use std::time::Duration;
use uuid::Uuid;

mod affiliation;
mod auto_create;
mod collection;
mod digest;
mod disco;
mod discovery_snapshot;
mod item;
mod item_snapshot;
mod locked;
mod node;
mod outbox_commands;
mod renderer;
mod replay_snapshot;
mod subscription;
mod types;

use self::locked::{
    canonical_bare_jids, edge_exceeds_max_depth, enqueue_locked_mutation_outbox,
    get_node_by_id_in_transaction, latest_item_in_transaction, lock_notification_authority,
    locked_event_time, locked_publish_authorization, notification_audience_in_transaction,
    owner_jids_in_transaction, publish_preconditions_match, requester_is_owner,
    requester_owns_locked_collection_child, row_to_node, row_to_subscription,
};
#[cfg(any(test, feature = "test-support"))]
use self::renderer::FixedMutationOutboxRenderer;
use self::types::row_to_affiliation;

pub use self::affiliation::*;
pub use self::auto_create::*;
pub use self::collection::*;
pub use self::digest::*;
pub use self::disco::*;
pub use self::discovery_snapshot::*;
pub use self::item::*;
pub use self::item_snapshot::*;
pub use self::node::*;
#[cfg(any(test, feature = "test-support"))]
pub use self::outbox_commands::{
    resolve_pending_subscription_with_outbox, set_affiliations_with_outbox,
    set_subscription_limited_with_options_and_outbox, set_subscriptions_with_outbox,
    unsubscribe_checked_with_outbox,
};
#[cfg(any(test, feature = "test-support"))]
pub use self::renderer::NoopMutationOutboxRenderer;
pub use self::renderer::PubSubMutationOutboxRenderer;
pub use self::replay_snapshot::read_presence_replay_candidates;
pub use self::subscription::*;
pub use self::types::{
    CollectionUpdateOutcome, CollectionVisibleItem, CreateNodeOutcome, OwnerMutationOutcome,
    PubSubAffiliation, PubSubConfigOutcome, PubSubItem, PubSubNotificationDelivery,
    PubSubSubscription, PubSubSubscriptionOptions, PublishItemsOutcome, RetractItemsOutcome,
    SetAffiliationsOutcome, SetSubscriptionsOutcome, SubscribeOutcome,
    SubscriptionAuthorizationOutcome, SubscriptionOptionsOutcome, UnsubscribeOutcome,
};
pub use northstar_pubsub_core::{
    PubSubNode, PubSubNodeConfig, PubSubNodeMetadata, PubSubRootDiscoNode, PubSubRootDiscoPage,
};

const PUBSUB_POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);
const COLLECTION_ITEMS_XML_BYTES_MAX: i64 = 4 * 1_048_576;

/// A PubSub/PEP mutation could not enter its bounded database execution
/// window.  Protocol callers deliberately map this retryable condition to
/// XMPP `resource-constraint` instead of keeping a connection actor blocked
/// behind PostgreSQL row/advisory locks.
#[derive(Debug, thiserror::Error)]
#[error("PubSub mutation capacity is temporarily exhausted")]
pub struct PubSubMutationBusy;

/// Start a network-facing PubSub/PEP mutation with bounded pool and database
/// lock waits.  The process-local admission gate in `PubSubService` runs
/// before this helper; these limits are the cross-process/foreign-transaction
/// safety net and therefore remain transaction-local.
pub async fn begin_bounded_pubsub_mutation(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    begin_bounded_pubsub_mutation_with_timeout(pool, PUBSUB_POOL_ACQUIRE_TIMEOUT).await
}

/// [`begin_bounded_pubsub_mutation`] with another admission timeout.
pub async fn begin_bounded_pubsub_mutation_with_timeout(
    pool: &PgPool,
    admission_timeout: Duration,
) -> Result<Transaction<'static, Postgres>> {
    // Pool acquisition can be cancelled before BEGIN is sent. Once a
    // connection is owned, let BEGIN finish in a separate task so a caller
    // timeout cannot interrupt the wire exchange.
    let deadline = tokio::time::Instant::now() + admission_timeout;
    let connection = tokio::time::timeout_at(deadline, pool.acquire())
        .await
        .map_err(|_| PubSubMutationBusy)??;
    let mut transaction =
        finish_bounded_pubsub_begin(deadline, Transaction::begin(connection, None)).await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

/// Waits until `deadline` for `begin`, which runs in its own task so that a timeout cannot
/// interrupt the BEGIN exchange.
pub async fn finish_bounded_pubsub_begin(
    deadline: tokio::time::Instant,
    begin: impl std::future::Future<
            Output = std::result::Result<Transaction<'static, Postgres>, sqlx::Error>,
        > + Send
        + 'static,
) -> Result<Transaction<'static, Postgres>> {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (transaction_tx, transaction_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        match begin.await {
            Ok(transaction) => {
                // Keep ownership until the caller confirms that its deadline
                // has not elapsed. A late BEGIN is always explicitly rolled
                // back, including the race at the deadline.
                if ready_tx.send(Ok(())).is_err() || accepted_rx.await.is_err() {
                    let _ = transaction.rollback().await;
                } else if let Err(transaction) = transaction_tx.send(transaction) {
                    let _ = transaction.rollback().await;
                }
            }
            Err(error) => {
                let _ = ready_tx.send(Err(error));
            }
        }
    });
    tokio::time::timeout_at(deadline, ready_rx)
        .await
        .map_err(|_| PubSubMutationBusy)?
        .map_err(|_| PubSubMutationBusy)??;
    // A completed oneshot can win a poll even after the timer deadline when
    // this task was not scheduled promptly. Do not admit that late BEGIN.
    if tokio::time::Instant::now() >= deadline {
        return Err(PubSubMutationBusy.into());
    }
    accepted_tx.send(()).map_err(|_| PubSubMutationBusy)?;
    Ok(transaction_rx.await.map_err(|_| PubSubMutationBusy)?)
}
