//! Generic PubSub owner commands.

use super::PubSubService;
use crate::{
    validate_pubsub_collection_edge_command, validate_pubsub_configure_node_command,
    validate_pubsub_create_node_command, validate_pubsub_delete_node_command,
    validate_pubsub_purge_node_command, validate_pubsub_set_affiliations_command,
    validate_pubsub_set_subscriptions_command, PubSubAdmissionKey,
    PubSubAffiliationMutationRepository, PubSubCollectionEdgeCommand,
    PubSubCollectionEdgeOperation, PubSubCollectionEdgeResult, PubSubConfigureNodeCommand,
    PubSubConfigureNodeResult, PubSubCreateNodeCommand, PubSubCreateNodeResult,
    PubSubDeleteNodeCommand, PubSubDeleteNodeResult, PubSubItemMutationRepository,
    PubSubNodeMutationRepository, PubSubNodeQueryRepository, PubSubPurgeNodeCommand,
    PubSubPurgeNodeResult, PubSubSetAffiliationsCommand, PubSubSetAffiliationsResult,
    PubSubSetSubscriptionsCommand, PubSubSetSubscriptionsResult,
    PubSubSubscriptionMutationRepository,
};
use anyhow::Result;
use northstar_pubsub_core::{OwnerMutationOutcome, PubSubNodeId};

impl<
        R: PubSubNodeMutationRepository
            + PubSubItemMutationRepository
            + PubSubSubscriptionMutationRepository
            + PubSubAffiliationMutationRepository,
    > PubSubService<R>
{
    pub async fn execute_pubsub_create_node(
        &self,
        command: PubSubCreateNodeCommand<'_>,
    ) -> Result<PubSubCreateNodeResult> {
        validate_pubsub_create_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .create_node(
                write.node,
                write.creator_jid,
                write.config,
                write.max_nodes_per_owner,
            )
            .await?;
        Ok(PubSubCreateNodeResult { outcome })
    }
    pub async fn execute_pubsub_delete_node(
        &self,
        command: PubSubDeleteNodeCommand<'_>,
    ) -> Result<PubSubDeleteNodeResult> {
        validate_pubsub_delete_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .delete_node_as_owner_with_redirect_and_outbox(
                write.node_id.get(),
                write.requester,
                write.redirect,
            )
            .await?;
        Ok(PubSubDeleteNodeResult { outcome })
    }
    pub async fn execute_pubsub_purge_node(
        &self,
        command: PubSubPurgeNodeCommand<'_>,
    ) -> Result<PubSubPurgeNodeResult> {
        validate_pubsub_purge_node_command(&command)?;
        let write = command.write;
        let node = write.observed_node;
        if node.node_type != "leaf" || !node.persist_items {
            return Ok(PubSubPurgeNodeResult {
                outcome: OwnerMutationOutcome::Invalid,
            });
        }
        let outcome = self
            .purge_node_as_owner_with_outbox(write.node_id.get(), write.requester)
            .await?;
        Ok(PubSubPurgeNodeResult { outcome })
    }
    pub async fn execute_pubsub_configure_node(
        &self,
        command: PubSubConfigureNodeCommand<'_>,
    ) -> Result<PubSubConfigureNodeResult> {
        validate_pubsub_configure_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .update_node_config_and_graph_with_outbox(
                write.node,
                write.requester,
                write.expected,
                write.config,
            )
            .await?;
        Ok(PubSubConfigureNodeResult { outcome })
    }
    pub async fn execute_pubsub_set_subscriptions(
        &self,
        command: PubSubSetSubscriptionsCommand<'_>,
    ) -> Result<PubSubSetSubscriptionsResult> {
        validate_pubsub_set_subscriptions_command(&command)?;
        let write = command.write;
        let outcome = self
            .set_subscriptions(write.node_id.get(), write.requester, write.changes)
            .await?;
        Ok(PubSubSetSubscriptionsResult { outcome })
    }
    pub async fn execute_pubsub_set_affiliations(
        &self,
        command: PubSubSetAffiliationsCommand<'_>,
    ) -> Result<PubSubSetAffiliationsResult> {
        validate_pubsub_set_affiliations_command(&command)?;
        let write = command.write;
        let outcome = self
            .set_affiliations(write.node_id.get(), write.requester, write.changes)
            .await?;
        Ok(PubSubSetAffiliationsResult { outcome })
    }
}

impl<R: PubSubNodeQueryRepository + PubSubNodeMutationRepository> PubSubService<R> {
    pub async fn execute_pubsub_collection_edge(
        &self,
        command: PubSubCollectionEdgeCommand<'_>,
    ) -> Result<PubSubCollectionEdgeResult> {
        validate_pubsub_collection_edge_command(&command)?;
        let collection = command.collection;
        let Some(child) = self.get_node(command.child).await? else {
            return Ok(PubSubCollectionEdgeResult::MissingChild);
        };
        let _permit = self
            .mutation_admission
            .acquire_keys(
                &[
                    PubSubAdmissionKey::Text(command.requester),
                    PubSubAdmissionKey::NodeId(PubSubNodeId::new(collection.id)),
                    PubSubAdmissionKey::NodeId(PubSubNodeId::new(child.id)),
                ],
                true,
            )
            .await?;
        // Node snapshots here identify graph endpoints only. The PostgreSQL
        // adapter locks the graph, reloads policy and ownership, and commits
        // its audience snapshot with the edge change and outbox entries.
        let outcome = match command.operation {
            PubSubCollectionEdgeOperation::Associate => {
                self.repository
                    .associate_collection_child(collection, &child, command.requester)
                    .await?
            }
            PubSubCollectionEdgeOperation::Dissociate => {
                self.repository
                    .dissociate_collection_child(collection, &child, command.requester)
                    .await?
            }
        };
        Ok(PubSubCollectionEdgeResult::Mutation(outcome))
    }
}
