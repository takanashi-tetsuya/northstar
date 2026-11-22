//! Atomic creation and first publication for service nodes.

use super::item::{lock_creator_storage_quota, publish_items_in_transaction, PublishPolicyScope};
use super::node::{
    create_node_in_transaction, lock_node_owner_quota, CreateNodeInTransactionOutcome,
};
use super::*;
pub use northstar_pubsub_core::AutoCreatePublishOutcome;

#[allow(clippy::too_many_arguments)]
pub async fn create_node_and_publish_items_with_renderer(
    pool: &PgPool,
    node: &str,
    publisher_jid: &str,
    config: &PubSubNodeConfig,
    max_nodes_per_owner: i64,
    items: &[(String, String)],
    max_storage_bytes_per_owner: i64,
    renderer: &dyn PubSubMutationOutboxRenderer,
) -> Result<AutoCreatePublishOutcome> {
    let mut transaction = begin_bounded_pubsub_mutation(pool).await?;
    let publisher_jid = northstar_xmpp_types::jid::canonical_bare_key(publisher_jid)?;
    let association_whitelist = canonical_bare_jids(&config.children_association_whitelist)?;
    lock_node_owner_quota(&mut transaction, &publisher_jid).await?;
    lock_creator_storage_quota(&mut transaction, &publisher_jid).await?;
    let outcome = match create_node_in_transaction(
        &mut transaction,
        node,
        &publisher_jid,
        config,
        &association_whitelist,
        max_nodes_per_owner,
        renderer,
        true,
    )
    .await?
    {
        CreateNodeInTransactionOutcome::Created(created) => match publish_items_in_transaction(
            &mut transaction,
            &created,
            &publisher_jid,
            items,
            None,
            max_storage_bytes_per_owner,
            renderer,
            PublishPolicyScope::AutoCreate(config),
        )
        .await?
        {
            PublishItemsOutcome::Published => AutoCreatePublishOutcome::Published,
            outcome => AutoCreatePublishOutcome::Publish(outcome.into()),
        },
        CreateNodeInTransactionOutcome::NodeExists => AutoCreatePublishOutcome::NodeExists,
        CreateNodeInTransactionOutcome::Failed(outcome) => {
            AutoCreatePublishOutcome::Create(outcome.into())
        }
    };
    if outcome == AutoCreatePublishOutcome::Published {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    Ok(outcome)
}
