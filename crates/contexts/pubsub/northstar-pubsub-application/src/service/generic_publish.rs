//! Generic PubSub publish and retract commands and profile publication.

use super::PubSubService;
use crate::profile::{
    ProfileOutboxFactory, ProfilePepWrite, ProfilePublishResult, ProfileRepository, ProfileService,
};
use crate::{
    existing_node_publish_admission_outcome, publish_validation_outcome,
    validate_pubsub_publish_command, validate_pubsub_retract_command, AutoCreatePublishOutcome,
    PubSubAffiliationMutationRepository, PubSubAffiliationQueryRepository,
    PubSubItemMutationRepository, PubSubItemQueryRepository, PubSubNodeMutationRepository,
    PubSubNodeQueryRepository, PubSubPublishCommand, PubSubPublishResult, PubSubRetractCommand,
    PubSubRetractResult, PubSubSubscriptionMutationRepository, PubSubSubscriptionQueryRepository,
};
use anyhow::Result;
use northstar_pubsub_core::{
    CreateNodeOutcome, PepProfileWrite, PubSubNodeConfig, PubSubPublishOutcome,
    PubSubRetractOutcome, PublishItemsOutcome, RetractItemsOutcome,
};

impl<R> PubSubService<R> {
    pub async fn publish_profile_items(
        &self,
        profile_service: &ProfileService<impl ProfileRepository>,
        write: PepProfileWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
        require_content_change: bool,
    ) -> Result<ProfilePublishResult> {
        profile_service
            .publish_profile_items(
                ProfilePepWrite {
                    user_id: write.user_id,
                    auth_generation: write.auth_generation,
                    connection_id: write.connection_id,
                    node: write.node,
                    requested: write.requested,
                    enforce_preconditions: write.enforce_preconditions,
                    items: write.items,
                    max_nodes: write.max_nodes,
                    max_storage_bytes: write.max_storage_bytes,
                },
                explicit_factory,
                require_content_change,
            )
            .await
    }
    pub async fn publish_avatar_metadata(
        &self,
        profile_service: &ProfileService<impl ProfileRepository>,
        write: PepProfileWrite<'_>,
        explicit_factory: &dyn ProfileOutboxFactory,
    ) -> Result<ProfilePublishResult> {
        profile_service
            .publish_avatar_metadata(
                ProfilePepWrite {
                    user_id: write.user_id,
                    auth_generation: write.auth_generation,
                    connection_id: write.connection_id,
                    node: write.node,
                    requested: write.requested,
                    enforce_preconditions: write.enforce_preconditions,
                    items: write.items,
                    max_nodes: write.max_nodes,
                    max_storage_bytes: write.max_storage_bytes,
                },
                explicit_factory,
            )
            .await
    }
}

fn publish_result(outcome: PublishItemsOutcome, items: &[(String, String)]) -> PubSubPublishResult {
    let outcome = match outcome {
        PublishItemsOutcome::Published => PubSubPublishOutcome::Published {
            item_ids: items.iter().map(|(id, _)| id.clone()).collect(),
        },
        PublishItemsOutcome::Conflict => PubSubPublishOutcome::Conflict,
        PublishItemsOutcome::QuotaExceeded => PubSubPublishOutcome::QuotaExceeded,
        PublishItemsOutcome::Forbidden => PubSubPublishOutcome::Forbidden,
        PublishItemsOutcome::PreconditionFailed => PubSubPublishOutcome::PreconditionNotMet,
    };
    PubSubPublishResult { outcome }
}

impl<
        R: PubSubNodeQueryRepository
            + PubSubNodeMutationRepository
            + PubSubItemQueryRepository
            + PubSubItemMutationRepository
            + PubSubSubscriptionQueryRepository
            + PubSubSubscriptionMutationRepository
            + PubSubAffiliationQueryRepository
            + PubSubAffiliationMutationRepository,
    > PubSubService<R>
{
    pub async fn execute_pubsub_publish(
        &self,
        command: PubSubPublishCommand<'_>,
    ) -> Result<PubSubPublishResult> {
        validate_pubsub_publish_command(&command)?;
        let write = command.write;
        if write.node == "serverinfo" {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::Forbidden,
            });
        }
        let mut node = self.get_node(write.node).await?;
        if node.is_none() {
            let requested_config = write
                .publish_options
                .cloned()
                .unwrap_or_else(PubSubNodeConfig::default);
            // A node created by publish must be validated before its creation
            // side effect. Once the node is reloaded (including a create
            // conflict), authorization always precedes policy validation so a
            // racing unauthorized sender cannot probe another owner's node.
            if let Some(outcome) = publish_validation_outcome(&requested_config, write.items) {
                return Ok(PubSubPublishResult { outcome });
            }
            let outcome = {
                let _permit = self
                    .admit_mutation(&[write.publisher_jid, write.node], true)
                    .await?;
                self.repository
                    .create_node_and_publish_items(
                        write.node,
                        write.publisher_jid,
                        &requested_config,
                        write.max_nodes_per_owner,
                        write.items,
                        write.max_storage_bytes_per_owner,
                    )
                    .await?
            };
            match outcome {
                AutoCreatePublishOutcome::Published => {
                    return Ok(publish_result(PublishItemsOutcome::Published, write.items));
                }
                AutoCreatePublishOutcome::NodeExists
                | AutoCreatePublishOutcome::Create(CreateNodeOutcome::Conflict) => {}
                AutoCreatePublishOutcome::Create(CreateNodeOutcome::QuotaExceeded) => {
                    return Ok(PubSubPublishResult {
                        outcome: PubSubPublishOutcome::QuotaExceeded,
                    });
                }
                AutoCreatePublishOutcome::Create(
                    CreateNodeOutcome::InvalidOptions
                    | CreateNodeOutcome::Forbidden
                    | CreateNodeOutcome::CollectionLimitExceeded
                    | CreateNodeOutcome::Cycle
                    | CreateNodeOutcome::Created,
                ) => {
                    return Ok(PubSubPublishResult {
                        outcome: PubSubPublishOutcome::Conflict,
                    });
                }
                AutoCreatePublishOutcome::Publish(outcome) => {
                    return Ok(publish_result(outcome, write.items));
                }
            }
            node = self.get_node(write.node).await?;
        }
        let Some(node) = node else {
            return Ok(PubSubPublishResult {
                outcome: PubSubPublishOutcome::MissingNode,
            });
        };
        // This covers a concurrent creator as well as a node that existed at
        // the initial lookup. Both its publish options and payload policy are
        // private until the requester has passed authorization.
        let node_config = node.config();
        let authorized = self.can_publish(&node, write.publisher_jid).await?;
        if let Some(outcome) = existing_node_publish_admission_outcome(
            authorized,
            &node_config,
            write.publish_options,
            write.items,
        ) {
            return Ok(PubSubPublishResult { outcome });
        }
        let outcome = self
            .publish_items(
                &node,
                write.publisher_jid,
                write.items,
                write.max_storage_bytes_per_owner,
            )
            .await?;
        Ok(publish_result(outcome, write.items))
    }
    pub async fn execute_pubsub_retract(
        &self,
        command: PubSubRetractCommand<'_>,
    ) -> Result<PubSubRetractResult> {
        validate_pubsub_retract_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubRetractResult {
                outcome: PubSubRetractOutcome::NotFound,
            });
        };
        if node.node_type != "leaf" {
            return Ok(PubSubRetractResult {
                outcome: PubSubRetractOutcome::NotLeafNode,
            });
        }
        if !node.persist_items {
            return Ok(PubSubRetractResult {
                outcome: PubSubRetractOutcome::NotPersistent,
            });
        }
        if !self.can_publish(&node, write.requester).await? {
            return Ok(PubSubRetractResult {
                outcome: PubSubRetractOutcome::Forbidden,
            });
        }
        let outcome = self
            .retract_items(
                node.id,
                write.item_ids,
                write.requester,
                write.force_notification,
            )
            .await?;
        let pubsub_outcome = match outcome {
            RetractItemsOutcome::Retracted => PubSubRetractOutcome::Retracted,
            RetractItemsOutcome::NotFound => PubSubRetractOutcome::ItemNotFound,
            RetractItemsOutcome::Forbidden => PubSubRetractOutcome::Forbidden,
        };
        Ok(PubSubRetractResult {
            outcome: pubsub_outcome,
        })
    }
}
