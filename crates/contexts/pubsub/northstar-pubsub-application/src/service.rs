//! PubSub command validation, mutation admission and publication policy.
use crate::profile::{
    ProfileOutboxFactory, ProfilePepWrite, ProfilePublishResult, ProfileRepository, ProfileService,
};
use crate::{
    authorization_precheck, existing_node_publish_admission_outcome, publish_validation_outcome,
    subscription_options_precheck, validate_pep_commit_legacy_bookmarks_command,
    validate_pep_configure_node_command, validate_pep_create_node_command,
    validate_pep_delete_node_command, validate_pep_publish_command,
    validate_pep_purge_node_command, validate_pep_retract_command,
    validate_pep_set_affiliations_command, validate_pep_subscribe_command,
    validate_pep_unsubscribe_batch_command, validate_pep_unsubscribe_command,
    validate_pubsub_authorize_subscription_command, validate_pubsub_collection_edge_command,
    validate_pubsub_configure_node_command, validate_pubsub_create_node_command,
    validate_pubsub_delete_node_command, validate_pubsub_publish_command,
    validate_pubsub_purge_node_command, validate_pubsub_retract_command,
    validate_pubsub_set_affiliations_command, validate_pubsub_set_subscriptions_command,
    validate_pubsub_subscribe_command, validate_pubsub_unsubscribe_command,
    validate_pubsub_update_subscription_options_command, PepCommitLegacyBookmarksCommand,
    PepCommitLegacyBookmarksResult, PepConfigureNodeCommand, PepConfigureNodeResult,
    PepCreateNodeCommand, PepCreateNodeResult, PepDeleteNodeCommand, PepDeleteNodeResult,
    PepPublishItemsCommand, PepPublishItemsResult, PepPurgeNodeCommand, PepPurgeNodeResult,
    PepRetractCommand, PepRetractResult, PepSetAffiliationsCommand, PepSetAffiliationsResult,
    PepSubscribeCommand, PepSubscribeResult, PepUnsubscribeBatchCommand, PepUnsubscribeBatchResult,
    PepUnsubscribeCommand, PepUnsubscribeResult, PubSubAuthorizeSubscriptionCommand,
    PubSubAuthorizeSubscriptionResult, PubSubCollectionDiscoChild, PubSubCollectionEdgeCommand,
    PubSubCollectionEdgeOperation, PubSubCollectionEdgeResult, PubSubConfigureNodeCommand,
    PubSubConfigureNodeResult, PubSubCreateNodeCommand, PubSubCreateNodeResult,
    PubSubDeleteNodeCommand, PubSubDeleteNodeResult, PubSubMutationAdmission, PubSubMutationPermit,
    PubSubOwnerRead, PubSubOwnerReadKind, PubSubPublishCommand, PubSubPublishResult,
    PubSubPurgeNodeCommand, PubSubPurgeNodeResult, PubSubRetractCommand, PubSubRetractResult,
    PubSubRootDiscoQuery, PubSubRootDiscoResult, PubSubSetAffiliationsCommand,
    PubSubSetAffiliationsResult, PubSubSetSubscriptionsCommand, PubSubSetSubscriptionsResult,
    PubSubSubscribeCommand, PubSubSubscribeResult, PubSubSubscriptionOptionsPrecheck,
    PubSubUnsubscribeCommand, PubSubUnsubscribeResult, PubSubUpdateSubscriptionOptionsCommand,
    PubSubUpdateSubscriptionOptionsResult,
};
use anyhow::Result;
use northstar_pubsub_core::{pubsub_subscribe_policy, PubSubSubscribePolicy};
use northstar_pubsub_core::{
    CollectionVisibleItem, CreateNodeOutcome, OwnerMutationOutcome, PepItem, PepNodeConfig,
    PepOwnerMutationOutcome, PepPresenceSubscription, PepProfileWrite, PepSubscription,
    PubSubAccount, PubSubAffiliation, PubSubConfigOutcome, PubSubItem, PubSubNode,
    PubSubNodeConfig, PubSubNodeMetadata, PubSubPublishOutcome, PubSubRetractOutcome,
    PubSubSubscribeOutcome, PubSubSubscription, PubSubSubscriptionOptions,
    PubSubUnsubscribeOutcome, PublishItemsOutcome, RetractItemsOutcome, SetAffiliationsOutcome,
    SetSubscriptionsOutcome, SubscribeOutcome, SubscriptionAuthorizationOutcome,
    SubscriptionOptionsOutcome, UnsubscribeOutcome,
};

use crate::{
    PepAffiliationRepository, PepItemMutationRepository, PepItemQueryRepository,
    PepNodeMutationRepository, PepNodeQueryRepository, PepSubscriptionMutationRepository,
    PepSubscriptionQueryRepository, PubSubAffiliationMutationRepository,
    PubSubAffiliationQueryRepository, PubSubItemMutationRepository, PubSubItemQueryRepository,
    PubSubNodeMutationRepository, PubSubNodeQueryRepository, PubSubOutboxRepository,
    PubSubRootDiscoveryQueryRepository, PubSubSubscriptionMutationRepository,
    PubSubSubscriptionQueryRepository,
};
use northstar_pubsub_core::{
    ClaimedPubSubOutboxDelivery, DuePubSubDigest, PepDirectOutboxFactory,
    PepOutboxAuthorizationOutcome, PepOutboxFactory, PepSubscribeOutboxFactory,
    PubSubNotificationDelivery, PubSubOutboxDeliveryKind, PubSubOutboxFailureDisposition,
    PubSubOutboxInsert, PubSubOutboxSnapshot, PubSubOutboxSource,
};
use northstar_xml_builder::XmlElement;
use std::sync::Arc;
use uuid::Uuid;

mod outbox;
mod repository_access;

#[derive(Clone)]
pub struct PubSubService<R> {
    repository: R,
    mutation_admission: Arc<PubSubMutationAdmission>,
    durable_outbox_database_admission:
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
}

impl<R> PubSubService<R> {
    pub fn new_with_durable_outbox_database_admission(
        repository: R,
        primary_pool_max_connections: u32,
        durable_outbox_database_admission: northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
    ) -> Self {
        Self {
            repository,
            mutation_admission: Arc::new(PubSubMutationAdmission::new(
                primary_pool_max_connections as usize,
            )),
            durable_outbox_database_admission,
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn repository_for_tests(&self) -> &R {
        &self.repository
    }
    pub fn mutation_admission(&self) -> Arc<PubSubMutationAdmission> {
        Arc::clone(&self.mutation_admission)
    }
    async fn admit_mutation(
        &self,
        keys: &[&str],
        collection_graph: bool,
    ) -> Result<PubSubMutationPermit> {
        self.mutation_admission
            .acquire(keys, collection_graph)
            .await
    }
    async fn durable_outbox_database_turn(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.durable_outbox_database_admission.acquire().await
    }
}

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
            match self
                .create_node(
                    write.node,
                    write.publisher_jid,
                    &requested_config,
                    write.max_nodes_per_owner,
                )
                .await?
            {
                CreateNodeOutcome::Created | CreateNodeOutcome::Conflict => {}
                CreateNodeOutcome::QuotaExceeded => {
                    return Ok(PubSubPublishResult {
                        outcome: PubSubPublishOutcome::QuotaExceeded,
                    });
                }
                CreateNodeOutcome::InvalidOptions
                | CreateNodeOutcome::Forbidden
                | CreateNodeOutcome::CollectionLimitExceeded
                | CreateNodeOutcome::Cycle => {
                    return Ok(PubSubPublishResult {
                        outcome: PubSubPublishOutcome::Conflict,
                    });
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
        let pubsub_outcome = match outcome {
            PublishItemsOutcome::Published => PubSubPublishOutcome::Published {
                item_ids: write.items.iter().map(|(id, _)| id.clone()).collect(),
            },
            PublishItemsOutcome::Conflict => PubSubPublishOutcome::Conflict,
            PublishItemsOutcome::QuotaExceeded => PubSubPublishOutcome::QuotaExceeded,
            PublishItemsOutcome::Forbidden => PubSubPublishOutcome::Forbidden,
            PublishItemsOutcome::PreconditionFailed => PubSubPublishOutcome::PreconditionNotMet,
        };
        Ok(PubSubPublishResult {
            outcome: pubsub_outcome,
        })
    }
    pub async fn execute_pubsub_subscribe(
        &self,
        command: PubSubSubscribeCommand<'_>,
    ) -> Result<PubSubSubscribeResult> {
        validate_pubsub_subscribe_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubSubscribeResult {
                outcome: PubSubSubscribeOutcome::NotFound,
            });
        };
        let affiliation = self.get_node_affiliation(node.id, write.requester).await?;
        let policy = pubsub_subscribe_policy(&node.access_model, affiliation.as_deref());
        if policy == PubSubSubscribePolicy::Forbidden {
            return Ok(PubSubSubscribeResult {
                outcome: PubSubSubscribeOutcome::Forbidden,
            });
        }
        let existing_subscription = self.get_subscription(node.id, write.subscriber_jid).await?;
        if let Some(ref existing) = existing_subscription {
            if existing.state == "pending" {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::PendingSubscription,
                });
            }
            if existing.is_active_at(chrono::Utc::now()) && write.options.is_none() {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::ExistingActive(existing.clone()),
                });
            }
        }
        let state_value = match policy {
            PubSubSubscribePolicy::Subscribed => "subscribed",
            PubSubSubscribePolicy::Pending => "pending",
            PubSubSubscribePolicy::ClosedNode => {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::ClosedNode,
                });
            }
            PubSubSubscribePolicy::Forbidden => {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::Forbidden,
                });
            }
        };
        let planned_subid = existing_subscription
            .as_ref()
            .map(|sub| sub.subid.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let default_options = PubSubSubscriptionOptions::for_node_type(&node.node_type);
        let effective_options = write.options.unwrap_or(&default_options);
        let outcome = self
            .set_subscription_limited_with_options(
                node.id,
                write.requester,
                write.subscriber_jid,
                state_value,
                &node.node_type,
                &node.access_model,
                write.max_subscriptions,
                Some(effective_options),
                &planned_subid,
            )
            .await?;
        let pubsub_outcome = match outcome {
            SubscribeOutcome::Subscribed(sub) => PubSubSubscribeOutcome::Subscribed(sub),
            SubscribeOutcome::LimitExceeded => PubSubSubscribeOutcome::LimitExceeded,
            SubscribeOutcome::NotFound => PubSubSubscribeOutcome::NotFound,
            SubscribeOutcome::Forbidden => PubSubSubscribeOutcome::Forbidden,
            SubscribeOutcome::ClosedNode => PubSubSubscribeOutcome::ClosedNode,
            SubscribeOutcome::PreconditionFailed => PubSubSubscribeOutcome::PreconditionFailed,
            SubscribeOutcome::InvalidOptions => PubSubSubscribeOutcome::InvalidOptions,
        };
        Ok(PubSubSubscribeResult {
            outcome: pubsub_outcome,
        })
    }
    pub async fn execute_pubsub_unsubscribe(
        &self,
        command: PubSubUnsubscribeCommand<'_>,
    ) -> Result<PubSubUnsubscribeResult> {
        validate_pubsub_unsubscribe_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubUnsubscribeResult {
                outcome: PubSubUnsubscribeOutcome::NotFound,
            });
        };
        let Some(subscription) = self.get_subscription(node.id, write.subscriber_jid).await? else {
            return Ok(PubSubUnsubscribeResult {
                outcome: PubSubUnsubscribeOutcome::NotSubscribed,
            });
        };
        if subscription.is_expired_at(chrono::Utc::now()) {
            return Ok(PubSubUnsubscribeResult {
                outcome: PubSubUnsubscribeOutcome::NotSubscribed,
            });
        }
        if write.subid.is_some_and(|value| value != subscription.subid) {
            return Ok(PubSubUnsubscribeResult {
                outcome: PubSubUnsubscribeOutcome::InvalidSubid,
            });
        }
        let outcome = self
            .unsubscribe_checked(
                node.id,
                write.requester,
                write.subscriber_jid,
                &subscription.subid,
            )
            .await?;
        let pubsub_outcome = match outcome {
            UnsubscribeOutcome::Unsubscribed => PubSubUnsubscribeOutcome::Unsubscribed {
                subid: Some(subscription.subid),
            },
            UnsubscribeOutcome::NotFound => PubSubUnsubscribeOutcome::NotSubscribed,
            UnsubscribeOutcome::InvalidSubid => PubSubUnsubscribeOutcome::InvalidSubid,
            UnsubscribeOutcome::Forbidden => PubSubUnsubscribeOutcome::Forbidden,
        };
        Ok(PubSubUnsubscribeResult {
            outcome: pubsub_outcome,
        })
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
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubDeleteNodeResult {
                outcome: OwnerMutationOutcome::NotFound,
            });
        };
        let outcome = self
            .delete_node_as_owner_with_redirect_and_outbox(node.id, write.requester, write.redirect)
            .await?;
        Ok(PubSubDeleteNodeResult { outcome })
    }
    pub async fn execute_pubsub_purge_node(
        &self,
        command: PubSubPurgeNodeCommand<'_>,
    ) -> Result<PubSubPurgeNodeResult> {
        validate_pubsub_purge_node_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubPurgeNodeResult {
                outcome: OwnerMutationOutcome::NotFound,
            });
        };
        if node.node_type != "leaf" || !node.persist_items {
            return Ok(PubSubPurgeNodeResult {
                outcome: OwnerMutationOutcome::Invalid,
            });
        }
        let outcome = self
            .purge_node_as_owner_with_outbox(node.id, write.requester)
            .await?;
        Ok(PubSubPurgeNodeResult { outcome })
    }
    pub async fn execute_pubsub_configure_node(
        &self,
        command: PubSubConfigureNodeCommand<'_>,
    ) -> Result<PubSubConfigureNodeResult> {
        validate_pubsub_configure_node_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubConfigureNodeResult {
                outcome: PubSubConfigOutcome::NotFound,
            });
        };
        let outcome = self
            .update_node_config_and_graph_with_outbox(
                &node,
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
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubSetSubscriptionsResult {
                outcome: SetSubscriptionsOutcome::NotFound,
            });
        };
        let outcome = self
            .set_subscriptions(node.id, write.requester, write.changes)
            .await?;
        Ok(PubSubSetSubscriptionsResult { outcome })
    }
    pub async fn execute_pubsub_set_affiliations(
        &self,
        command: PubSubSetAffiliationsCommand<'_>,
    ) -> Result<PubSubSetAffiliationsResult> {
        validate_pubsub_set_affiliations_command(&command)?;
        let write = command.write;
        let Some(node) = self.get_node(write.node).await? else {
            return Ok(PubSubSetAffiliationsResult {
                outcome: SetAffiliationsOutcome::NotFound,
            });
        };
        let outcome = self
            .set_affiliations(node.id, write.requester, write.changes)
            .await?;
        Ok(PubSubSetAffiliationsResult { outcome })
    }
}

impl<
        R: PepNodeMutationRepository
            + PepItemMutationRepository
            + PepSubscriptionMutationRepository
            + PepAffiliationRepository,
    > PubSubService<R>
{
    pub async fn execute_pep_retract(
        &self,
        command: PepRetractCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepRetractResult> {
        validate_pep_retract_command(&command)?;
        let write = command.write;
        let item_ids: Vec<&str> = write.item_ids.iter().map(String::as_str).collect();
        let outcome = self
            .retract_pep_items(
                write.owner,
                write.connection_id,
                write.node,
                &item_ids,
                write.notify,
                factory,
            )
            .await?;
        Ok(PepRetractResult { outcome })
    }
    pub async fn execute_pep_delete_node(
        &self,
        command: PepDeleteNodeCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepDeleteNodeResult> {
        validate_pep_delete_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .delete_pep_node(write.owner, write.connection_id, write.node, factory)
            .await?;
        Ok(PepDeleteNodeResult { outcome })
    }
    pub async fn execute_pep_purge_node(
        &self,
        command: PepPurgeNodeCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepPurgeNodeResult> {
        validate_pep_purge_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .purge_pep_node(write.owner, write.connection_id, write.node, factory)
            .await?;
        Ok(PepPurgeNodeResult { outcome })
    }
    pub async fn execute_pep_configure_node(
        &self,
        command: PepConfigureNodeCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepConfigureNodeResult> {
        validate_pep_configure_node_command(&command)?;
        let write = command.write;
        let outcome = self
            .update_pep_node_config(
                write.owner,
                write.connection_id,
                write.node,
                write.expected,
                write.config,
                factory,
            )
            .await?;
        Ok(PepConfigureNodeResult { outcome })
    }
    pub async fn execute_pep_set_affiliations(
        &self,
        command: PepSetAffiliationsCommand<'_>,
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepSetAffiliationsResult> {
        validate_pep_set_affiliations_command(&command)?;
        let write = command.write;
        let outcome = self
            .update_pep_affiliations(
                write.owner,
                write.connection_id,
                write.node,
                write.expected,
                write.changes,
                factory,
            )
            .await?;
        Ok(PepSetAffiliationsResult { outcome })
    }
}

impl<
        R: PepNodeMutationRepository
            + PepItemMutationRepository
            + PepSubscriptionMutationRepository
            + PepAffiliationRepository,
    > PubSubService<R>
{
    pub async fn execute_pep_create_node(
        &self,
        command: PepCreateNodeCommand<'_>,
    ) -> Result<PepCreateNodeResult> {
        validate_pep_create_node_command(&command)?;
        let owner_key = command.owner_id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, command.node], false)
            .await?;
        self.repository
            .create_pep_node(
                command.owner_id,
                command.node,
                &command.config,
                command.max_nodes,
            )
            .await
            .map(Into::into)
    }
    pub async fn subscribe_pep_node(
        &self,
        command: PepSubscribeCommand<'_>,
        factory: &dyn PepSubscribeOutboxFactory,
    ) -> Result<PepSubscribeResult> {
        validate_pep_subscribe_command(&command)?;
        let write = &command.write;
        let owner_key = write.owner.id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, write.subscriber_jid, write.node], false)
            .await?;
        self.repository.subscribe_pep_node(command, factory).await
    }
    pub async fn unsubscribe_pep_node(
        &self,
        command: PepUnsubscribeCommand<'_>,
    ) -> Result<PepUnsubscribeResult> {
        validate_pep_unsubscribe_command(&command)?;
        let write = &command.write;
        let owner_key = write.owner.id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, write.subscriber_jid, write.node], false)
            .await?;
        self.repository.unsubscribe_pep_node(command).await
    }
    pub async fn update_pep_node_config(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        config: &PepNodeConfig,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        self.repository
            .update_pep_node_config(owner, sender_connection_id, node, expected, config, factory)
            .await
    }
    pub async fn update_pep_affiliations(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        changes: &[(String, String)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        self.repository
            .update_pep_affiliations(
                owner,
                sender_connection_id,
                node,
                expected,
                changes,
                factory,
            )
            .await
    }
    pub async fn purge_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        self.repository
            .purge_pep_node(owner, sender_connection_id, node, factory)
            .await
    }
    pub async fn delete_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        self.repository
            .delete_pep_node(owner, sender_connection_id, node, factory)
            .await
    }
    pub async fn retract_pep_items(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        item_ids: &[&str],
        notify: bool,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        self.repository
            .retract_pep_items(owner, sender_connection_id, node, item_ids, notify, factory)
            .await
    }
    pub async fn execute_pep_unsubscribe_batch(
        &self,
        command: PepUnsubscribeBatchCommand<'_>,
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepUnsubscribeBatchResult> {
        validate_pep_unsubscribe_batch_command(&command)?;
        let owner_key = command.owner.id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, command.node], false)
            .await?;
        self.repository
            .unsubscribe_pep_nodes_batch(
                command.owner,
                command.connection_id,
                command.node,
                command.changes,
                factory,
            )
            .await
            .map(Into::into)
    }
    pub async fn commit_legacy_bookmarks(
        &self,
        command: PepCommitLegacyBookmarksCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepCommitLegacyBookmarksResult> {
        const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
        validate_pep_commit_legacy_bookmarks_command(&command)?;
        let owner_key = command.owner.id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, BOOKMARKS2], false)
            .await?;
        self.repository
            .commit_legacy_bookmarks(command, factory)
            .await
    }
    pub async fn publish_pep_items(
        &self,
        command: PepPublishItemsCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepPublishItemsResult> {
        validate_pep_publish_command(&command)?;
        let write = &command.write;
        let owner_key = write.user_id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, write.node], false)
            .await?;
        self.repository.publish_pep_items(command, factory).await
    }
}

impl<
        R: PubSubNodeQueryRepository
            + PubSubSubscriptionQueryRepository
            + PubSubSubscriptionMutationRepository,
    > PubSubService<R>
{
    pub async fn execute_pubsub_authorize_subscription(
        &self,
        command: PubSubAuthorizeSubscriptionCommand<'_>,
    ) -> Result<PubSubAuthorizeSubscriptionResult> {
        validate_pubsub_authorize_subscription_command(&command)?;
        let Some(node) = self.get_node(command.node).await? else {
            return Ok(PubSubAuthorizeSubscriptionResult {
                outcome: SubscriptionAuthorizationOutcome::NotFound,
            });
        };
        let Some(subscription) = self
            .get_subscription(node.id, command.subscriber_jid)
            .await?
        else {
            return Ok(PubSubAuthorizeSubscriptionResult {
                outcome: SubscriptionAuthorizationOutcome::NotFound,
            });
        };
        // This read is only a cheap precheck. The locked PostgreSQL mutation
        // rechecks ownership, pending state and SubID before committing.
        let requester_is_owner = self.is_owner(node.id, command.requester).await?;
        if let Some(outcome) = authorization_precheck(
            &subscription.state,
            &subscription.subid,
            command.echoed_subid,
            requester_is_owner,
        ) {
            return Ok(PubSubAuthorizeSubscriptionResult { outcome });
        }
        let node_key = node.id.to_string();
        let _permit = self
            .admit_mutation(
                &[command.requester, command.subscriber_jid, &node_key],
                false,
            )
            .await?;
        let outcome = self
            .repository
            .resolve_pending_subscription(
                node.id,
                command.requester,
                command.subscriber_jid,
                &subscription.subid,
                command.allow,
            )
            .await?;
        Ok(PubSubAuthorizeSubscriptionResult { outcome })
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
        let collection_key = collection.id.to_string();
        let child_key = child.id.to_string();
        let _permit = self
            .admit_mutation(&[command.requester, &collection_key, &child_key], true)
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

pub enum PubSubSubscriptionOptionsRead {
    MissingNode,
    NotSubscribed,
    InvalidSubid,
    Ready {
        node: Box<PubSubNode>,
        subscription: PubSubSubscription,
    },
}

impl<R: PubSubNodeQueryRepository + PubSubSubscriptionQueryRepository> PubSubService<R> {
    pub async fn subscription_options_read(
        &self,
        node_name: &str,
        subscriber_jid: &str,
        echoed_subid: Option<&str>,
    ) -> Result<PubSubSubscriptionOptionsRead> {
        let Some(node) = self.get_node(node_name).await? else {
            return Ok(PubSubSubscriptionOptionsRead::MissingNode);
        };
        let Some(subscription) = self.get_subscription(node.id, subscriber_jid).await? else {
            return Ok(PubSubSubscriptionOptionsRead::NotSubscribed);
        };
        match subscription_options_precheck(
            subscription.is_expired_at(chrono::Utc::now()),
            &subscription.subid,
            echoed_subid,
        ) {
            PubSubSubscriptionOptionsPrecheck::Ready => Ok(PubSubSubscriptionOptionsRead::Ready {
                node: Box::new(node),
                subscription,
            }),
            PubSubSubscriptionOptionsPrecheck::NotSubscribed => {
                Ok(PubSubSubscriptionOptionsRead::NotSubscribed)
            }
            PubSubSubscriptionOptionsPrecheck::InvalidSubid => {
                Ok(PubSubSubscriptionOptionsRead::InvalidSubid)
            }
        }
    }
}

impl<R: PubSubSubscriptionMutationRepository> PubSubService<R> {
    pub async fn execute_pubsub_update_subscription_options(
        &self,
        command: PubSubUpdateSubscriptionOptionsCommand<'_>,
    ) -> Result<PubSubUpdateSubscriptionOptionsResult> {
        validate_pubsub_update_subscription_options_command(&command)?;
        let requester = northstar_pubsub_core::CanonicalJid::parse_bare(command.requester)?;
        let subscriber = northstar_pubsub_core::CanonicalJid::parse(command.subscriber_jid)?;
        if subscriber.to_bare() != requester {
            return Ok(PubSubUpdateSubscriptionOptionsResult {
                outcome: SubscriptionOptionsOutcome::Forbidden,
            });
        }
        if !northstar_xep_0060::subscription_show_values_allowed(
            requester.domainpart(),
            self.repository.local_domain(),
            &command.options.show_values,
        ) {
            return Ok(PubSubUpdateSubscriptionOptionsResult {
                outcome: SubscriptionOptionsOutcome::InvalidOptions,
            });
        }
        let node_key = command.node_id.to_string();
        let _permit = self
            .admit_mutation(
                &[command.requester, command.subscriber_jid, &node_key],
                false,
            )
            .await?;
        let outcome = self
            .repository
            .update_subscription_options_checked(
                command.node_id,
                command.requester,
                command.subscriber_jid,
                Some(command.expected_subid),
                command.options,
            )
            .await?;
        Ok(PubSubUpdateSubscriptionOptionsResult { outcome })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeafDiscoItems {
    NotFound,
    NotLeaf,
    Forbidden,
    Items(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionDiscoItems {
    NotFound,
    NotCollection,
    Forbidden,
    Items(Vec<PubSubCollectionDiscoChild>),
}

#[derive(Clone)]
pub struct PubSubEventRenderer {
    service_jid: String,
}
impl PubSubEventRenderer {
    pub fn new(domain: &str) -> Self {
        Self {
            service_jid: format!("pubsub.{domain}"),
        }
    }
}
const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
const NS_DATA: &str = "jabber:x:data";
const NODE_CONFIG_FORM: &str = "http://jabber.org/protocol/pubsub#node_config";

fn pubsub_config_field(
    variable: &str,
    field_type: Option<&str>,
    values: impl IntoIterator<Item = impl ToString>,
) -> XmlElement {
    let mut field = XmlElement::new("field")
        .attr("var", variable)
        .optional_attr("type", field_type);
    for value in values {
        field.push_child(XmlElement::new("value").text(value.to_string()));
    }
    field
}

fn pubsub_bool_text(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// Render a complete node-configuration form from a locked database snapshot.
/// The same helper is used for owner IQ responses and durable notifications so
/// notification XML cannot be assembled from a pre-lock request object.
pub fn pubsub_node_config_form(config: &PubSubNodeConfig, form_type: &str) -> String {
    let mut form = XmlElement::namespaced("x", NS_DATA).attr("type", form_type);
    form.push_child(pubsub_config_field(
        "FORM_TYPE",
        Some("hidden"),
        [NODE_CONFIG_FORM],
    ));
    for (variable, field_type, value) in [
        (
            "pubsub#title",
            "text-single",
            config.title.clone().unwrap_or_default(),
        ),
        (
            "pubsub#description",
            "text-single",
            config.description.clone().unwrap_or_default(),
        ),
        (
            "pubsub#access_model",
            "list-single",
            config.access_model.clone(),
        ),
        (
            "pubsub#publish_model",
            "list-single",
            config.publish_model.clone(),
        ),
        (
            "pubsub#max_items",
            "text-single",
            config.max_items.to_string(),
        ),
        (
            "pubsub#deliver_notifications",
            "boolean",
            pubsub_bool_text(config.deliver_notifications).to_owned(),
        ),
        (
            "pubsub#deliver_payloads",
            "boolean",
            pubsub_bool_text(config.deliver_payloads).to_owned(),
        ),
        (
            "pubsub#notify_config",
            "boolean",
            pubsub_bool_text(config.notify_config).to_owned(),
        ),
        (
            "pubsub#notify_delete",
            "boolean",
            pubsub_bool_text(config.notify_delete).to_owned(),
        ),
        (
            "pubsub#notify_retract",
            "boolean",
            pubsub_bool_text(config.notify_retract).to_owned(),
        ),
        (
            "pubsub#notify_sub",
            "boolean",
            pubsub_bool_text(config.notify_sub).to_owned(),
        ),
        (
            "pubsub#persist_items",
            "boolean",
            pubsub_bool_text(config.persist_items).to_owned(),
        ),
        (
            "pubsub#send_last_published_item",
            "list-single",
            config.send_last_published_item.clone(),
        ),
        (
            "pubsub#language",
            "text-single",
            config.language.clone().unwrap_or_default(),
        ),
        (
            "pubsub#type",
            "text-single",
            config.payload_type.clone().unwrap_or_default(),
        ),
        (
            "pubsub#max_payload_size",
            "text-single",
            config.max_payload_size.to_string(),
        ),
        ("pubsub#node_type", "list-single", config.node_type.clone()),
    ] {
        form.push_child(pubsub_config_field(variable, Some(field_type), [value]));
    }
    form.push_child(pubsub_config_field(
        "pubsub#collection",
        Some("text-multi"),
        config.collections.iter(),
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children",
        Some("text-multi"),
        config.children.iter(),
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children_max",
        Some("text-single"),
        [config.children_max.to_string()],
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children_association_policy",
        Some("list-single"),
        [if config.children_association_policy == "owner" {
            "owners"
        } else {
            &config.children_association_policy
        }],
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children_association_whitelist",
        Some("jid-multi"),
        config.children_association_whitelist.iter(),
    ));
    form.finish()
}
const SUBSCRIBE_AUTH_FORM: &str = "http://jabber.org/protocol/pubsub#subscribe_authorization";

pub fn subscription_event_children(
    subscription: &PubSubSubscription,
    event: &str,
    collection: Option<&str>,
    delay: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<String> {
    let body = if subscription.include_body {
        northstar_xep_0060::extract_atom_event_body(event)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
    } else {
        None
    };
    let stamp = delay.map(|stamp| stamp.to_rfc3339());
    northstar_xep_0060::build_subscription_event_children(
        event,
        &subscription.subid,
        collection,
        body.as_deref(),
        stamp.as_deref(),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[cfg(test)]
mod tests;
