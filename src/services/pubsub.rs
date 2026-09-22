//! PubSub command validation, mutation admission and publication policy.
use crate::services::profile::{
    ProfileOutboxFactory, ProfilePepWrite, ProfilePublishResult, ProfileRepository, ProfileService,
};
use anyhow::Result;
pub(crate) use northstar_pubsub_application::{
    is_pubsub_mutation_busy as is_pubsub_mutation_busy_core,
    pubsub_mutation_admission_active as pubsub_mutation_admission_active_core,
    pubsub_mutation_admission_rejections_total as pubsub_mutation_admission_rejections_total_core,
    pubsub_mutation_admission_waiters as pubsub_mutation_admission_waiters_core,
    validate_pep_configure_node_command, validate_pep_delete_node_command,
    validate_pep_publish_command, validate_pep_purge_node_command, validate_pep_retract_command,
    validate_pep_set_affiliations_command, validate_pep_subscribe_command,
    validate_pep_unsubscribe_command, validate_pubsub_configure_node_command,
    validate_pubsub_create_node_command, validate_pubsub_delete_node_command,
    validate_pubsub_publish_command, validate_pubsub_purge_node_command,
    validate_pubsub_retract_command, validate_pubsub_set_affiliations_command,
    validate_pubsub_set_subscriptions_command, validate_pubsub_subscribe_command,
    validate_pubsub_unsubscribe_command, PepConfigureNodeCommand, PepConfigureNodeResult,
    PepDeleteNodeCommand, PepDeleteNodeResult, PepPublishItemsCommand, PepPublishItemsOutcome,
    PepPublishItemsResult, PepPurgeNodeCommand, PepPurgeNodeResult, PepRetractCommand,
    PepRetractResult, PepSetAffiliationsCommand, PepSetAffiliationsResult, PepSubscribeCommand,
    PepSubscribeResult, PepUnsubscribeCommand, PepUnsubscribeResult, PubSubConfigureNodeCommand,
    PubSubConfigureNodeResult, PubSubCreateNodeCommand, PubSubCreateNodeResult,
    PubSubDeleteNodeCommand, PubSubDeleteNodeResult,
    PubSubMutationPermit as ApplicationPubSubMutationPermit, PubSubPublishCommand,
    PubSubPublishResult, PubSubPurgeNodeCommand, PubSubPurgeNodeResult, PubSubRetractCommand,
    PubSubRetractResult, PubSubSetAffiliationsCommand, PubSubSetAffiliationsResult,
    PubSubSetSubscriptionsCommand, PubSubSetSubscriptionsResult, PubSubSubscribeCommand,
    PubSubSubscribeResult, PubSubUnsubscribeCommand, PubSubUnsubscribeResult,
};
pub(crate) use northstar_pubsub_core::{
    CollectionUpdateOutcome, CollectionVisibleItem, CreateNodeOutcome, OwnerMutationOutcome,
    PepAudienceSnapshot, PepBookmarkMutationOutcome, PepConfigureNodeWrite, PepCreateOutcome,
    PepDeleteNodeWrite, PepDirectStateSnapshot, PepDirectStateTransition, PepItem, PepNodeConfig,
    PepOwnerMutationOutcome, PepPresenceSubscription, PepProfileWrite, PepPublishOutcome,
    PepPublishWrite, PepPurgeNodeWrite, PepQuotas, PepRetractWrite, PepSetAffiliationsWrite,
    PepSubscribeOutcome, PepSubscribeSnapshot, PepSubscribeWrite, PepSubscription,
    PepSubscriptionActor, PepUnsubscribeOutcome, PepUnsubscribeWrite, PubSubAccount,
    PubSubAffiliation, PubSubConfigOutcome, PubSubConfigureNodeWrite, PubSubCreateNodeWrite,
    PubSubDeleteNodeWrite, PubSubDiscoNode, PubSubItem, PubSubNode, PubSubNodeConfig,
    PubSubPublishOutcome, PubSubPublishWrite, PubSubPurgeNodeWrite, PubSubRetractOutcome,
    PubSubRetractWrite, PubSubSetAffiliationsWrite, PubSubSetSubscriptionsWrite,
    PubSubSubscribeOutcome, PubSubSubscribeWrite, PubSubSubscription, PubSubSubscriptionOptions,
    PubSubUnsubscribeOutcome, PubSubUnsubscribeWrite, PublishItemsOutcome, RetractItemsOutcome,
    SetAffiliationsOutcome, SetSubscriptionsOutcome, SubscribeOutcome,
    SubscriptionAuthorizationOutcome, SubscriptionOptionsOutcome, UnsubscribeOutcome,
};

pub(crate) use northstar_pubsub_application::{
    PepAffiliationRepository, PepItemRepository, PepNodeRepository, PepSubscriptionRepository,
    PubSubAffiliationRepository, PubSubItemRepository, PubSubNodeRepository,
    PubSubOutboxRepository, PubSubRepository, PubSubSubscriptionRepository,
};
pub(crate) use northstar_pubsub_core::{
    canonical_profile_item_id, default_pep_node_config, ClaimedPubSubOutboxDelivery,
    DuePubSubDigest, PepDirectOutboxFactory, PepOutboxAuthorizationMode,
    PepOutboxAuthorizationOutcome, PepOutboxDropReason, PepOutboxEventKind, PepOutboxFactory,
    PepSubscribeOutboxFactory, PubSubNotificationDelivery, PubSubOutboxDeliveryKind,
    PubSubOutboxFailureDisposition, PubSubOutboxInsert, PubSubOutboxSnapshot, PubSubOutboxSource,
    PEP_MAX_ITEMS,
};
use northstar_xml_builder::XmlElement;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) type PubSubMutationAdmission = northstar_pubsub_application::PubSubMutationAdmission;
pub(crate) type PubSubMutationPermit = ApplicationPubSubMutationPermit;

pub(crate) fn pubsub_mutation_admission_rejections_total() -> u64 {
    pubsub_mutation_admission_rejections_total_core()
}

pub(crate) fn pubsub_mutation_admission_waiters() -> u64 {
    pubsub_mutation_admission_waiters_core()
}

pub(crate) fn pubsub_mutation_admission_active() -> u64 {
    pubsub_mutation_admission_active_core()
}

pub(crate) fn is_pubsub_mutation_busy(error: &anyhow::Error) -> bool {
    is_pubsub_mutation_busy_core(error)
}

#[derive(Clone)]
pub(crate) struct PubSubService<R> {
    repository: R,
    mutation_admission: Arc<PubSubMutationAdmission>,
    durable_outbox_database_admission:
        crate::services::durable_outbox::DurableOutboxDatabaseAdmission,
}

impl<R: PubSubRepository> PubSubService<R> {
    pub(crate) fn new_with_durable_outbox_database_admission(
        repository: R,
        primary_pool_max_connections: u32,
        durable_outbox_database_admission: crate::services::durable_outbox::DurableOutboxDatabaseAdmission,
    ) -> Self {
        Self {
            repository,
            mutation_admission: Arc::new(PubSubMutationAdmission::new(
                primary_pool_max_connections as usize,
            )),
            durable_outbox_database_admission,
        }
    }
    #[cfg(test)]
    pub(crate) fn repository_for_tests(&self) -> &R {
        &self.repository
    }
    pub(crate) fn mutation_admission(&self) -> Arc<PubSubMutationAdmission> {
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
    pub(crate) async fn publish_profile_items(
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
    pub(crate) async fn publish_avatar_metadata(
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
    pub(crate) async fn execute_pubsub_publish(
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
    pub(crate) async fn execute_pubsub_subscribe(
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
        if affiliation.as_deref() == Some("outcast") {
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
            if existing.is_active() && write.options.is_none() {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::ExistingActive(existing.clone()),
                });
            }
        }
        let state_value = match node.access_model.as_str() {
            "open" => "subscribed",
            "whitelist"
                if matches!(
                    affiliation.as_deref(),
                    Some("owner" | "publisher" | "member")
                ) =>
            {
                "subscribed"
            }
            "authorize"
                if matches!(
                    affiliation.as_deref(),
                    Some("owner" | "publisher" | "member")
                ) =>
            {
                "subscribed"
            }
            "authorize" => "pending",
            "whitelist" => {
                return Ok(PubSubSubscribeResult {
                    outcome: PubSubSubscribeOutcome::ClosedNode,
                });
            }
            _ => {
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
        };
        Ok(PubSubSubscribeResult {
            outcome: pubsub_outcome,
        })
    }
    pub(crate) async fn execute_pubsub_unsubscribe(
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
        if subscription.is_expired() {
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
    pub(crate) async fn execute_pubsub_retract(
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
    pub(crate) async fn execute_pubsub_create_node(
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
    pub(crate) async fn execute_pubsub_delete_node(
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
    pub(crate) async fn execute_pubsub_purge_node(
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
    pub(crate) async fn execute_pubsub_configure_node(
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
    pub(crate) async fn execute_pubsub_set_subscriptions(
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
    pub(crate) async fn execute_pubsub_set_affiliations(
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
    pub(crate) async fn execute_pep_retract(
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
    pub(crate) async fn execute_pep_delete_node(
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
    pub(crate) async fn execute_pep_purge_node(
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
    pub(crate) async fn execute_pep_configure_node(
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
    pub(crate) async fn execute_pep_set_affiliations(
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
    pub(crate) async fn pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Option<PepNodeConfig>> {
        self.repository.pep_node(owner_id, node).await
    }
    pub(crate) async fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        self.repository
            .pep_items(owner_id, node, item_id, limit)
            .await
    }
    pub(crate) async fn pep_items_by_ids(
        &self,
        owner_id: Uuid,
        node: &str,
        item_ids: &[&str],
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        self.repository
            .pep_items_by_ids(owner_id, node, item_ids, limit)
            .await
    }
    pub(crate) async fn pep_items_with_timestamp(
        &self,
        owner_id: Uuid,
        node: &str,
        limit: i64,
    ) -> Result<Vec<PepItem>> {
        self.repository
            .pep_items_with_timestamp(owner_id, node, limit)
            .await
    }
    pub(crate) async fn pep_nodes(&self, owner_id: Uuid) -> Result<Vec<String>> {
        self.repository.pep_nodes(owner_id).await
    }
    pub(crate) async fn pep_subscribers(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Vec<PepSubscription>> {
        self.repository.pep_subscribers(owner_id, node).await
    }
    pub(crate) async fn pep_subscriptions_for_available_resource(
        &self,
        subscriber_jid: &str,
    ) -> Result<Vec<PepPresenceSubscription>> {
        self.repository
            .pep_subscriptions_for_available_resource(subscriber_jid)
            .await
    }
    pub(crate) async fn pep_owner_usernames_for_presence_subscriber(
        &self,
        subscriber_bare: &str,
    ) -> Result<Vec<String>> {
        self.repository
            .pep_owner_usernames_for_presence_subscriber(subscriber_bare)
            .await
    }
    pub(crate) async fn find_enabled_user(&self, username: &str) -> Result<Option<PubSubAccount>> {
        self.repository.find_enabled_user(username).await
    }
    pub(crate) async fn roster(
        &self,
        owner_id: Uuid,
    ) -> Result<Vec<(String, Option<String>, String, Option<String>)>> {
        self.repository.roster(owner_id).await
    }
    pub(crate) async fn roster_item(
        &self,
        owner_id: Uuid,
        jid: &str,
    ) -> Result<Option<(String, Option<String>, String, Option<String>)>> {
        self.repository.roster_item(owner_id, jid).await
    }
    pub(crate) async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        self.repository.is_blocked(owner_id, candidate).await
    }
    pub(crate) async fn roster_group_allowed(
        &self,
        owner_id: Uuid,
        jid: &str,
        groups: &[String],
    ) -> Result<bool> {
        self.repository
            .roster_group_allowed(owner_id, jid, groups)
            .await
    }
    pub(crate) async fn create_pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
        config: &PepNodeConfig,
        max_nodes: i64,
    ) -> Result<PepCreateOutcome> {
        let owner_key = owner_id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        self.repository
            .create_pep_node(owner_id, node, config, max_nodes)
            .await
    }
    pub(crate) async fn subscribe_pep_node(
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
    pub(crate) async fn unsubscribe_pep_node(
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
    pub(crate) async fn update_pep_node_config(
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
    pub(crate) async fn update_pep_affiliations(
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
    pub(crate) async fn purge_pep_node(
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
    pub(crate) async fn delete_pep_node(
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
    pub(crate) async fn retract_pep_items(
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
    pub(crate) async fn unsubscribe_pep_nodes_batch(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        changes: &[(String, Option<String>)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let owner_key = owner.id.to_string();
        let _permit = self.admit_mutation(&[&owner_key, node], false).await?;
        self.repository
            .unsubscribe_pep_nodes_batch(owner, sender_connection_id, node, changes, factory)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn commit_legacy_bookmarks(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        private_xml: &str,
        items: &mut [(String, String)],
        expected_previous_items: &[(String, String)],
        max_private_bytes: i64,
        quotas: PepQuotas,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepBookmarkMutationOutcome> {
        const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
        let owner_key = owner.id.to_string();
        let _permit = self
            .admit_mutation(&[&owner_key, BOOKMARKS2], false)
            .await?;
        self.repository
            .commit_legacy_bookmarks(
                owner,
                sender_connection_id,
                private_xml,
                items,
                expected_previous_items,
                max_private_bytes,
                quotas,
                factory,
            )
            .await
    }
    pub(crate) async fn publish_pep_items(
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
    pub(crate) async fn get_node(&self, node: &str) -> Result<Option<PubSubNode>> {
        self.repository.get_node(node).await
    }
    pub(crate) async fn get_node_affiliation(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<String>> {
        self.repository.get_node_affiliation(node_id, jid).await
    }
    pub(crate) async fn affiliations_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubAffiliation>> {
        self.repository.affiliations_for_jid(jid, node).await
    }
    pub(crate) async fn node_affiliations(&self, node_id: Uuid) -> Result<Vec<PubSubAffiliation>> {
        self.repository.node_affiliations(node_id).await
    }
    pub(crate) async fn is_subscribed(&self, node_id: Uuid, jid: &str) -> Result<bool> {
        self.repository.is_subscribed(node_id, jid).await
    }
    pub(crate) async fn subscriptions_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubSubscription>> {
        self.repository.subscriptions_for_jid(jid, node).await
    }
    pub(crate) async fn subscriptions_addressing_jid_page(
        &self,
        jid: &str,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> Result<Vec<PubSubSubscription>> {
        self.repository
            .subscriptions_addressing_jid_page(jid, after, limit)
            .await
    }
    pub(crate) async fn node_subscriptions(
        &self,
        node_id: Uuid,
    ) -> Result<Vec<PubSubSubscription>> {
        self.repository.node_subscriptions(node_id).await
    }
    pub(crate) async fn get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<PubSubSubscription>> {
        self.repository.get_subscription(node_id, jid).await
    }
    pub(crate) async fn outbox_get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<PubSubSubscription>> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.outbox_get_subscription(node_id, jid).await
    }
    pub(crate) async fn get_owner_jids(&self, node_id: Uuid) -> Result<Vec<String>> {
        self.repository.get_owner_jids(node_id).await
    }
    pub(crate) async fn get_publisher_jids(&self, node_id: Uuid) -> Result<Vec<String>> {
        self.repository.get_publisher_jids(node_id).await
    }
    pub(crate) async fn active_subscriber_count(&self, node_id: Uuid) -> Result<i64> {
        self.repository.active_subscriber_count(node_id).await
    }
    pub(crate) async fn get_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        limit: i64,
    ) -> Result<Vec<PubSubItem>> {
        self.repository.get_items(node_id, item_ids, limit).await
    }
    pub(crate) async fn item_ids_for_disco(&self, node_id: Uuid) -> Result<Vec<String>> {
        self.repository.item_ids_for_disco(node_id).await
    }
    pub(crate) async fn node_redirect(&self, node: &str) -> Result<Option<String>> {
        self.repository.node_redirect(node).await
    }
    pub(crate) async fn collection_parents(&self, child_id: Uuid) -> Result<Vec<PubSubNode>> {
        self.repository.collection_parents(child_id).await
    }
    pub(crate) async fn collection_children(&self, collection_id: Uuid) -> Result<Vec<PubSubNode>> {
        self.repository.collection_children(collection_id).await
    }
    pub(crate) async fn collection_visible_items(
        &self,
        collection_id: Uuid,
        requester: &str,
        global_item_limit: i64,
        xml_byte_limit: i64,
    ) -> Result<Vec<CollectionVisibleItem>> {
        self.repository
            .collection_visible_items(collection_id, requester, global_item_limit, xml_byte_limit)
            .await
    }
    pub(crate) async fn visible_root_disco_count(&self, requester: &str) -> Result<i64> {
        self.repository.visible_root_disco_count(requester).await
    }
    pub(crate) async fn visible_root_disco_cursor_exists(
        &self,
        requester: &str,
        cursor: &str,
    ) -> Result<bool> {
        self.repository
            .visible_root_disco_cursor_exists(requester, cursor)
            .await
    }
    pub(crate) async fn visible_root_disco_index(
        &self,
        requester: &str,
        node: &str,
    ) -> Result<i64> {
        self.repository
            .visible_root_disco_index(requester, node)
            .await
    }
    pub(crate) async fn visible_root_disco_page(
        &self,
        requester: &str,
        cursor: Option<&str>,
        backwards: bool,
        limit: i64,
    ) -> Result<Vec<PubSubDiscoNode>> {
        self.repository
            .visible_root_disco_page(requester, cursor, backwards, limit)
            .await
    }
    pub(crate) async fn can_publish(&self, node: &PubSubNode, requester: &str) -> Result<bool> {
        self.repository.can_publish(node, requester).await
    }
    pub(crate) async fn is_owner(&self, node_id: Uuid, requester: &str) -> Result<bool> {
        self.repository.is_owner(node_id, requester).await
    }
    pub(crate) async fn update_subscription_options_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: Option<&str>,
        options: &PubSubSubscriptionOptions,
    ) -> Result<SubscriptionOptionsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, subscriber_jid, &node_key], false)
            .await?;
        self.repository
            .update_subscription_options_checked(
                node_id,
                requester,
                subscriber_jid,
                expected_subid,
                options,
            )
            .await
    }
    pub(crate) async fn create_node(
        &self,
        node: &str,
        creator_jid: &str,
        config: &PubSubNodeConfig,
        max_nodes_per_owner: i64,
    ) -> Result<CreateNodeOutcome> {
        let _permit = self.admit_mutation(&[creator_jid, node], true).await?;
        self.repository
            .create_node(node, creator_jid, config, max_nodes_per_owner)
            .await
    }
    pub(crate) async fn publish_items(
        &self,
        node: &PubSubNode,
        publisher_jid: &str,
        items: &[(String, String)],
        max_storage_bytes_per_owner: i64,
    ) -> Result<PublishItemsOutcome> {
        let node_key = node.id.to_string();
        let _permit = self
            .admit_mutation(&[publisher_jid, &node_key], true)
            .await?;
        self.repository
            .publish_items(node, publisher_jid, items, max_storage_bytes_per_owner)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn set_subscription_limited_with_options(
        &self,
        node_id: Uuid,
        requester: &str,
        jid: &str,
        state: &str,
        expected_node_type: &str,
        expected_access_model: &str,
        max_subscriptions: i64,
        options: Option<&PubSubSubscriptionOptions>,
        requested_subid: &str,
    ) -> Result<SubscribeOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, jid, &node_key], false)
            .await?;
        self.repository
            .set_subscription_limited_with_options(
                node_id,
                requester,
                jid,
                state,
                expected_node_type,
                expected_access_model,
                max_subscriptions,
                options,
                requested_subid,
            )
            .await
    }
    pub(crate) async fn unsubscribe_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
    ) -> Result<UnsubscribeOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, subscriber_jid, &node_key], false)
            .await?;
        self.repository
            .unsubscribe_checked(node_id, requester, subscriber_jid, expected_subid)
            .await
    }
    pub(crate) async fn retract_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        publisher_jid: &str,
        force_notification: bool,
    ) -> Result<RetractItemsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[publisher_jid, &node_key], true)
            .await?;
        self.repository
            .retract_items(node_id, item_ids, publisher_jid, force_notification)
            .await
    }
    pub(crate) async fn associate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> Result<CollectionUpdateOutcome> {
        let collection_key = collection.id.to_string();
        let child_key = child.id.to_string();
        let _permit = self
            .admit_mutation(&[requester, &collection_key, &child_key], true)
            .await?;
        self.repository
            .associate_collection_child(collection, child, requester)
            .await
    }
    pub(crate) async fn dissociate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> Result<CollectionUpdateOutcome> {
        let collection_key = collection.id.to_string();
        let child_key = child.id.to_string();
        let _permit = self
            .admit_mutation(&[requester, &collection_key, &child_key], true)
            .await?;
        self.repository
            .dissociate_collection_child(collection, child, requester)
            .await
    }
    pub(crate) async fn update_node_config_and_graph_with_outbox(
        &self,
        node: &PubSubNode,
        requester: &str,
        expected: &PubSubNodeConfig,
        config: &PubSubNodeConfig,
    ) -> Result<PubSubConfigOutcome> {
        let node_key = node.id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], true).await?;
        self.repository
            .update_node_config_and_graph_with_outbox(node, requester, expected, config)
            .await
    }
    pub(crate) async fn set_subscriptions(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String, Option<String>)],
    ) -> Result<SetSubscriptionsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], false).await?;
        self.repository
            .set_subscriptions(node_id, requester, changes)
            .await
    }
    pub(crate) async fn set_affiliations(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String)],
    ) -> Result<SetAffiliationsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], false).await?;
        self.repository
            .set_affiliations(node_id, requester, changes)
            .await
    }
    pub(crate) async fn purge_node_as_owner_with_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
    ) -> Result<OwnerMutationOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], true).await?;
        self.repository
            .purge_node_as_owner_with_outbox(node_id, requester)
            .await
    }
    pub(crate) async fn delete_node_as_owner_with_redirect_and_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
        redirect: Option<&str>,
    ) -> Result<OwnerMutationOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], true).await?;
        self.repository
            .delete_node_as_owner_with_redirect_and_outbox(node_id, requester, redirect)
            .await
    }
    pub(crate) async fn resolve_pending_subscription(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
        allow: bool,
    ) -> Result<SubscriptionAuthorizationOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, subscriber_jid, &node_key], false)
            .await?;
        self.repository
            .resolve_pending_subscription(node_id, requester, subscriber_jid, expected_subid, allow)
            .await
    }
    pub(crate) async fn local_account_blocks_pubsub(
        &self,
        username: &str,
        service: &str,
    ) -> Result<bool> {
        self.repository
            .local_account_blocks_pubsub(username, service)
            .await
    }
    pub(crate) async fn presence_delivery_denied(
        &self,
        recipient_id: Uuid,
        active_privacy_list: Option<&str>,
        connection_id: Uuid,
        service: &str,
    ) -> Result<bool> {
        self.repository
            .presence_delivery_denied(recipient_id, active_privacy_list, connection_id, service)
            .await
    }
    pub(crate) async fn authorize_pep_outbox_delivery(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
    ) -> Result<PepOutboxAuthorizationOutcome> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.authorize_pep_outbox_delivery(item).await
    }
    pub(crate) async fn claim_pubsub_outbox(
        &self,
        limit: i64,
    ) -> Result<Vec<ClaimedPubSubOutboxDelivery>> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.claim_pubsub_outbox(limit).await
    }
    pub(crate) async fn acknowledge_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .acknowledge_pubsub_outbox(delivery_id, lease_token)
            .await
    }
    pub(crate) async fn renew_pubsub_outbox_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .renew_pubsub_outbox_lease(delivery_id, lease_token)
            .await
    }
    pub(crate) async fn retry_pubsub_outbox(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.retry_pubsub_outbox(item, error).await
    }
    pub(crate) async fn dead_letter_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        reason: &str,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .dead_letter_pubsub_outbox(delivery_id, lease_token, reason, error)
            .await
    }
    pub(crate) async fn expire_pubsub_outbox(&self, limit: i64) -> Result<u64> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.expire_pubsub_outbox(limit).await
    }
    pub(crate) async fn cleanup_pubsub_dead_letters(&self, limit: i64) -> Result<u64> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.cleanup_pubsub_dead_letters(limit).await
    }
    pub(crate) async fn cleanup_idle_pubsub_event_streams(&self, limit: i64) -> Result<u64> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .cleanup_idle_pubsub_event_streams(limit)
            .await
    }
    pub(crate) async fn pubsub_outbox_snapshot(&self) -> Result<PubSubOutboxSnapshot> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.pubsub_outbox_snapshot().await
    }
    pub(crate) async fn enqueue_pubsub_digest_snapshot(
        &self,
        source_delivery_id: Uuid,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
        show_values: &[String],
    ) -> Result<()> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository
            .enqueue_pubsub_digest_snapshot(
                source_delivery_id,
                node_id,
                subscriber_jid,
                event_xml,
                frequency_ms,
                show_values,
            )
            .await
    }
    pub(crate) async fn enqueue_pubsub_digest(
        &self,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
    ) -> Result<bool> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[subscriber_jid, &node_key], false)
            .await?;
        self.repository
            .enqueue_pubsub_digest(node_id, subscriber_jid, event_xml, frequency_ms)
            .await
    }
    pub(crate) async fn claim_due_pubsub_digests(
        &self,
        limit: i64,
    ) -> Result<Vec<DuePubSubDigest>> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.claim_due_pubsub_digests(limit).await
    }
    pub(crate) async fn release_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.release_pubsub_digests(ids).await
    }
    pub(crate) async fn acknowledge_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        let _database_turn = self.durable_outbox_database_turn().await;

        self.repository.acknowledge_pubsub_digests(ids).await
    }
}
fn serialized_item_payload_matches_type(item_xml: &str, payload_type: &str) -> bool {
    roxmltree::Document::parse(item_xml)
        .ok()
        .is_some_and(|document| {
            document
                .root_element()
                .children()
                .find(roxmltree::Node::is_element)
                .and_then(|payload| payload.tag_name().namespace())
                == Some(payload_type)
        })
}
fn item_xml_has_payload(item_xml: &str) -> bool {
    roxmltree::Document::parse(item_xml)
        .ok()
        .is_some_and(|document| {
            document
                .root_element()
                .children()
                .any(|node| node.is_element())
        })
}
fn publish_validation_outcome(
    config: &PubSubNodeConfig,
    items: &[(String, String)],
) -> Option<PubSubPublishOutcome> {
    if config.node_type != "leaf" {
        return Some(PubSubPublishOutcome::NotLeafNode);
    }
    if items.len() > config.max_items as usize {
        return Some(PubSubPublishOutcome::MaxItemsExceeded);
    }
    if config.persist_items && items.is_empty() {
        return Some(PubSubPublishOutcome::ItemRequired);
    }
    if !config.persist_items && !config.deliver_payloads && !items.is_empty() {
        return Some(PubSubPublishOutcome::ItemForbidden);
    }
    if !config.persist_items && config.deliver_payloads && items.is_empty() {
        return Some(PubSubPublishOutcome::ItemRequired);
    }
    if config.deliver_payloads
        && items
            .iter()
            .any(|(_, item_xml)| !item_xml_has_payload(item_xml))
    {
        return Some(PubSubPublishOutcome::PayloadRequired);
    }
    if items
        .iter()
        .any(|(_, item_xml)| item_xml.len() > config.max_payload_size as usize)
    {
        return Some(PubSubPublishOutcome::PayloadTooBig);
    }
    if config.payload_type.as_deref().is_some_and(|expected| {
        items
            .iter()
            .any(|(_, item_xml)| !serialized_item_payload_matches_type(item_xml, expected))
    }) {
        return Some(PubSubPublishOutcome::InvalidPayload);
    }
    None
}
fn existing_node_publish_admission_outcome(
    authorized: bool,
    config: &PubSubNodeConfig,
    publish_options: Option<&PubSubNodeConfig>,
    items: &[(String, String)],
) -> Option<PubSubPublishOutcome> {
    if !authorized {
        return Some(PubSubPublishOutcome::Forbidden);
    }
    if publish_options.is_some_and(|options| options != config) {
        return Some(PubSubPublishOutcome::PreconditionNotMet);
    }
    publish_validation_outcome(config, items)
}
#[derive(Clone)]
pub(crate) struct PubSubEventRenderer {
    service_jid: String,
}
impl PubSubEventRenderer {
    pub(crate) fn new(domain: &str) -> Self {
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
pub(crate) fn pubsub_node_config_form(config: &PubSubNodeConfig, form_type: &str) -> String {
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

impl PubSubEventRenderer {
    pub(crate) fn render_transactional_node_event(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        direct_recipients: &[String],
        event: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let ordering_key = format!("pubsub:{}", node.id);
        let mut outbox = Vec::with_capacity(audience.len() + direct_recipients.len());
        for delivery in audience {
            let children = subscription_event_children(
                &delivery.subscription,
                event,
                delivery.collection.as_deref(),
                None,
            )?;
            let (kind, digest) = if delivery.subscription.digest {
                (
                    PubSubOutboxDeliveryKind::PubSubDigest,
                    Some((
                        delivery.subscription_node_id,
                        delivery.subscription.digest_frequency,
                    )),
                )
            } else {
                (PubSubOutboxDeliveryKind::PubSubChildren, None)
            };
            outbox.push(PubSubOutboxInsert::new(
                event_id,
                ordering_key.clone(),
                PubSubOutboxSource::PubSub,
                kind,
                delivery.subscription.jid.clone(),
                children,
                Some(delivery.subscription.show_values.clone()),
                digest,
                &node.node,
                None,
                created_at,
            )?);
        }
        for recipient in direct_recipients {
            let mut wrapper = XmlElement::namespaced("event", NS_PUBSUB_EVENT);
            wrapper.push_validated_fragment(event)?;
            let message = XmlElement::namespaced("message", "jabber:client")
                .attr("type", "headline")
                .attr("id", event_id)
                .attr("from", &self.service_jid)
                .attr("to", recipient)
                .child(wrapper)
                .finish();
            outbox.push(PubSubOutboxInsert::new(
                event_id,
                ordering_key.clone(),
                PubSubOutboxSource::PubSub,
                PubSubOutboxDeliveryKind::PubSubDirect,
                recipient.clone(),
                message,
                None,
                None,
                &node.node,
                None,
                created_at,
            )?);
        }
        Ok(outbox)
    }
}

impl PubSubEventRenderer {
    pub(crate) fn render_create(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let event = XmlElement::new("create").attr("node", &node.node).finish();
        self.render_transactional_node_event(node, audience, &[], &event, event_id, created_at)
    }

    pub(crate) fn render_items(
        &self,
        node: &PubSubNode,
        items: &[(String, String)],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let mut event = XmlElement::new("items").attr("node", &node.node);
        for (item_id, payload) in items {
            if node.deliver_payloads {
                event.push_validated_fragment(payload)?;
            } else {
                event.push_child(XmlElement::new("item").attr("id", item_id));
            }
        }
        self.render_transactional_node_event(
            node,
            audience,
            &[],
            &event.finish(),
            event_id,
            created_at,
        )
    }

    pub(crate) fn render_purge(
        &self,
        node: &PubSubNode,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let event = XmlElement::new("purge").attr("node", &node.node).finish();
        self.render_transactional_node_event(node, audience, &[], &event, event_id, created_at)
    }

    pub(crate) fn render_retract(
        &self,
        node: &PubSubNode,
        item_ids: &[String],
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let mut items = XmlElement::new("items").attr("node", &node.node);
        for item_id in item_ids {
            items.push_child(XmlElement::new("retract").attr("id", item_id));
        }
        self.render_transactional_node_event(
            node,
            audience,
            &[],
            &items.finish(),
            event_id,
            created_at,
        )
    }

    pub(crate) fn render_delete(
        &self,
        node: &PubSubNode,
        redirect: Option<&str>,
        audience: &[PubSubNotificationDelivery],
        nonactive_recipients: &[String],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        if !node.notify_delete {
            return Ok(Vec::new());
        }
        let mut delete = XmlElement::new("delete").attr("node", &node.node);
        if let Some(uri) = redirect {
            delete.push_child(XmlElement::new("redirect").attr("uri", uri));
        }
        self.render_transactional_node_event(
            node,
            audience,
            nonactive_recipients,
            &delete.finish(),
            event_id,
            created_at,
        )
    }

    pub(crate) fn render_configuration(
        &self,
        node: &PubSubNode,
        config: &PubSubNodeConfig,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let form = pubsub_node_config_form(config, "result");
        let mut event = XmlElement::new("configuration").attr("node", &node.node);
        event.push_validated_fragment(&form)?;
        self.render_transactional_node_event(
            node,
            audience,
            &[],
            &event.finish(),
            event_id,
            created_at,
        )
    }

    pub(crate) fn render_collection_edge(
        &self,
        source: &PubSubNode,
        action: &str,
        target_node: &str,
        audience: &[PubSubNotificationDelivery],
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        anyhow::ensure!(matches!(action, "associate" | "dissociate"));
        let action = XmlElement::dynamic(action)
            .map_err(|error| anyhow::anyhow!("invalid collection action QName: {error}"))?
            .attr("node", target_node);
        let event = XmlElement::new("collection")
            .attr("node", &source.node)
            .child(action)
            .finish();
        self.render_transactional_node_event(source, audience, &[], &event, event_id, created_at)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn render_subscription_transition(
        &self,
        node: &PubSubNode,
        subscription: &PubSubSubscription,
        notify_recipients: &[String],
        authorization_recipients: &[String],
        last_item: Option<&PubSubItem>,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let transition = XmlElement::new("subscription")
            .attr("node", &node.node)
            .attr("jid", &subscription.jid)
            .attr("subscription", &subscription.state)
            .attr("subid", &subscription.subid)
            .finish();
        let mut outbox = self.render_transactional_node_event(
            node,
            &[],
            notify_recipients,
            &transition,
            event_id,
            created_at,
        )?;

        if !authorization_recipients.is_empty() {
            let authorization_event_id = Uuid::new_v4();
            let form = XmlElement::namespaced("x", NS_DATA)
                .attr("type", "form")
                .child(data_form_field(
                    "FORM_TYPE",
                    Some("hidden"),
                    SUBSCRIBE_AUTH_FORM,
                ))
                .child(data_form_field("pubsub#node", None, &node.node))
                .child(data_form_field(
                    "pubsub#subscriber_jid",
                    None,
                    &subscription.jid,
                ))
                .child(data_form_field("pubsub#subid", None, &subscription.subid))
                .child(data_form_field("pubsub#allow", Some("boolean"), "false"))
                .finish();
            for recipient in authorization_recipients {
                let mut message = XmlElement::namespaced("message", "jabber:client")
                    .attr("id", Uuid::new_v4())
                    .attr("from", &self.service_jid)
                    .attr("to", recipient);
                message.push_validated_fragment(&form)?;
                outbox.push(PubSubOutboxInsert::new(
                    authorization_event_id,
                    format!("pubsub:{}", node.id),
                    PubSubOutboxSource::PubSub,
                    PubSubOutboxDeliveryKind::PubSubDirect,
                    recipient.clone(),
                    message.finish(),
                    None,
                    None,
                    &node.node,
                    None,
                    created_at,
                )?);
            }
        }

        if let Some(item) = last_item {
            let last_item_event_id = Uuid::new_v4();
            let mut event = XmlElement::new("items").attr("node", &node.node);
            if node.deliver_payloads {
                event.push_validated_fragment(&item.xml_payload)?;
            } else {
                event.push_child(XmlElement::new("item").attr("id", &item.item_id));
            }
            let children = subscription_event_children(
                subscription,
                &event.finish(),
                None,
                Some(item.created_at),
            )?;
            let (kind, digest) = if subscription.digest {
                (
                    PubSubOutboxDeliveryKind::PubSubDigest,
                    Some((node.id, subscription.digest_frequency)),
                )
            } else {
                (PubSubOutboxDeliveryKind::PubSubChildren, None)
            };
            outbox.push(PubSubOutboxInsert::new(
                last_item_event_id,
                format!("pubsub:{}", node.id),
                PubSubOutboxSource::PubSub,
                kind,
                subscription.jid.clone(),
                children,
                Some(subscription.show_values.clone()),
                digest,
                &node.node,
                None,
                created_at,
            )?);
        }
        Ok(outbox)
    }

    pub(crate) fn render_affiliation_transition(
        &self,
        node: &PubSubNode,
        jid: &str,
        affiliation: &str,
        event_id: Uuid,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<PubSubOutboxInsert>> {
        let event = XmlElement::new("affiliation")
            .attr("node", &node.node)
            .attr("jid", jid)
            .attr("affiliation", affiliation)
            .finish();
        self.render_transactional_node_event(
            node,
            &[],
            &[jid.to_owned()],
            &event,
            event_id,
            created_at,
        )
    }
}

fn data_form_field(var: &str, field_type: Option<&str>, value: &str) -> XmlElement {
    let mut field = XmlElement::new("field").attr("var", var);
    if let Some(field_type) = field_type {
        field = field.attr("type", field_type);
    }
    field.child(XmlElement::new("value").text(value.to_owned()))
}

fn subscription_event_children(
    subscription: &PubSubSubscription,
    event: &str,
    collection: Option<&str>,
    delay: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<String> {
    let mut headers = XmlElement::namespaced("headers", "http://jabber.org/protocol/shim").child(
        XmlElement::new("header")
            .attr("name", "SubID")
            .text(subscription.subid.clone()),
    );
    if let Some(collection) = collection {
        headers.push_child(
            XmlElement::new("header")
                .attr("name", "Collection")
                .text(collection.to_owned()),
        );
    }
    let mut children = XmlElement::new("northstar-children");
    let mut wrapper = XmlElement::namespaced("event", NS_PUBSUB_EVENT);
    wrapper.push_validated_fragment(event)?;
    children.push_child(wrapper);
    if subscription.include_body {
        if let Some(body) = pubsub_event_body(event)? {
            children.push_child(XmlElement::new("body").text(body));
        }
    }
    children.push_child(headers);
    if let Some(stamp) = delay {
        children.push_child(
            XmlElement::namespaced("delay", "urn:xmpp:delay").attr("stamp", stamp.to_rfc3339()),
        );
    }
    Ok(children.finish_children())
}

fn pubsub_event_body(event: &str) -> Result<Option<String>> {
    northstar_xep_0060::extract_atom_event_body(event)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::db::pubsub_repository::{
        db_outbox, pep_outbox_authorization_lock_plan, PepOutboxAuthorizationLockPlan,
    };
    use chrono::{TimeZone, Utc};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    #[tokio::test]
    async fn injected_durable_outbox_admission_stays_separate_from_foreground_mutations() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy("postgres://unused:unused@localhost/unused")
            .expect("a lazy test pool does not connect");
        let durable =
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(2);
        let service = PubSubService::new_with_durable_outbox_database_admission(
            db::pubsub_repository::PostgresPubSubRepository::new(pool, "example.test"),
            2,
            durable.clone(),
        );

        assert!(service
            .durable_outbox_database_admission
            .shares_with(&durable));
        assert_eq!(
            service.mutation_admission.available_transaction_permits(),
            1,
            "the foreground mutation budget remains independently available"
        );
    }

    #[test]
    fn atom_event_body_limit_never_splits_a_utf8_character() {
        let summary = format!("{}ƞ", "a".repeat(1_023));
        let event = format!(
            "<entry xmlns='http://www.w3.org/2005/Atom'><summary>{summary}</summary></entry>"
        );
        let body = pubsub_event_body(&event).unwrap().unwrap();
        assert_eq!(body.len(), 1_023);
        assert_eq!(body, "a".repeat(1_023));
    }

    #[test]
    fn live_pep_authorization_locks_audience_before_block_policy() {
        assert_eq!(
            pep_outbox_authorization_lock_plan(PepOutboxAuthorizationMode::LiveNodeAccess),
            PepOutboxAuthorizationLockPlan::AudienceThenBlockPolicy
        );
        assert_eq!(
            pep_outbox_authorization_lock_plan(PepOutboxAuthorizationMode::CausalAudience),
            PepOutboxAuthorizationLockPlan::BlockPolicyOnly
        );
    }

    #[test]
    fn publish_validation_reports_the_specific_payload_failure() {
        let items = vec![(
            "one".to_owned(),
            "<item id='one'><payload xmlns='urn:test:wrong'>value</payload></item>".to_owned(),
        )];
        let mut config = PubSubNodeConfig {
            payload_type: Some("urn:test:expected".to_owned()),
            ..PubSubNodeConfig::default()
        };

        assert_eq!(
            publish_validation_outcome(&config, &items),
            Some(PubSubPublishOutcome::InvalidPayload),
        );

        config.payload_type = None;
        config.max_payload_size = 1;
        assert_eq!(
            publish_validation_outcome(&config, &items),
            Some(PubSubPublishOutcome::PayloadTooBig),
        );

        config.max_payload_size = 1_048_576;
        let missing_payload = vec![("two".to_owned(), "<item id='two'/>".to_owned())];
        assert_eq!(
            publish_validation_outcome(&config, &missing_payload),
            Some(PubSubPublishOutcome::PayloadRequired),
        );
    }

    #[test]
    fn existing_node_publish_hides_payload_policy_before_authorization() {
        let items = vec![(
            "wrong-namespace".to_owned(),
            "<item id='wrong-namespace'><payload xmlns='urn:test:wrong'/></item>".to_owned(),
        )];
        let node_config = PubSubNodeConfig {
            payload_type: Some("urn:test:expected".to_owned()),
            ..PubSubNodeConfig::default()
        };
        let stale_options = PubSubNodeConfig {
            max_items: node_config.max_items + 1,
            ..node_config.clone()
        };

        // The same request has both policy-sensitive failures, but a caller
        // without publish authorization must learn neither one.
        assert_eq!(
            existing_node_publish_admission_outcome(
                false,
                &node_config,
                Some(&stale_options),
                &items,
            ),
            Some(PubSubPublishOutcome::Forbidden),
        );
        assert_eq!(
            existing_node_publish_admission_outcome(
                true,
                &node_config,
                Some(&stale_options),
                &items,
            ),
            Some(PubSubPublishOutcome::PreconditionNotMet),
        );
        assert_eq!(
            existing_node_publish_admission_outcome(true, &node_config, None, &items,),
            Some(PubSubPublishOutcome::InvalidPayload),
        );
    }

    fn renderer_node(id: Uuid, name: &str, node_type: &str) -> db::PubSubNode {
        db::PubSubNode {
            id,
            node: name.to_owned(),
            creator_jid: "owner@example.test".to_owned(),
            access_model: "open".to_owned(),
            publish_model: "publishers".to_owned(),
            max_items: 100,
            title: None,
            description: None,
            deliver_payloads: true,
            notify_delete: true,
            notify_retract: true,
            persist_items: true,
            send_last_published_item: "on_sub_and_presence".to_owned(),
            node_type: node_type.to_owned(),
            deliver_notifications: true,
            notify_config: true,
            notify_sub: true,
            language: None,
            payload_type: None,
            max_payload_size: 1_048_576,
            children_max: 1_000,
            children_association_policy: "owner".to_owned(),
            children_association_whitelist: Vec::new(),
            created_at: Utc.with_ymd_and_hms(2030, 4, 5, 6, 7, 8).unwrap(),
        }
    }

    fn renderer_subscription(node: &str, jid: &str) -> db::PubSubSubscription {
        db::PubSubSubscription {
            node: node.to_owned(),
            jid: jid.to_owned(),
            state: "subscribed".to_owned(),
            subid: "sub<&\"1".to_owned(),
            deliver: true,
            digest: false,
            digest_frequency: 86_400_000,
            expire: None,
            include_body: false,
            show_values: vec!["online".to_owned()],
            subscription_type: "items".to_owned(),
            subscription_depth: Some(1),
        }
    }

    #[tokio::test]
    async fn mutation_admission_waits_before_database_capacity_and_fails_bounded() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect_lazy("postgres://unused:unused@localhost/unused")
            .unwrap();
        let admission = PubSubMutationAdmission::new(pool.options().get_max_connections() as usize);
        // One of four configured database connections remains outside the
        // PubSub mutation budget for unrelated authentication/routing work.
        assert_eq!(admission.available_transaction_permits(), 3);

        let first = admission
            .acquire_with_timeout(&["alice@example.test"], false, Duration::from_millis(50))
            .await
            .unwrap();
        let rejected_before = pubsub_mutation_admission_rejections_total();
        let error = admission
            .acquire_with_timeout(&["alice@example.test"], false, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(error
            .downcast_ref::<northstar_pubsub_application::PubSubMutationBusy>()
            .is_some());
        assert!(pubsub_mutation_admission_rejections_total() > rejected_before);
        drop(first);

        admission
            .acquire_with_timeout(&["alice@example.test"], false, Duration::from_millis(50))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn collection_graph_admission_serializes_distinct_owners_without_pool_waiters() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect_lazy("postgres://unused:unused@localhost/unused")
            .unwrap();
        let admission = PubSubMutationAdmission::new(pool.options().get_max_connections() as usize);
        let first = admission
            .acquire_with_timeout(&["alice@example.test"], true, Duration::from_millis(50))
            .await
            .unwrap();
        let error = admission
            .acquire_with_timeout(&["bob@example.test"], true, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(error
            .downcast_ref::<northstar_pubsub_application::PubSubMutationBusy>()
            .is_some());
        drop(first);
        admission
            .acquire_with_timeout(&["bob@example.test"], true, Duration::from_millis(50))
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn same_owner_advisory_contention_does_not_exhaust_the_shared_pool() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let owner_id = Uuid::new_v4();
        let username = format!("poolguard{}", &owner_id.simple().to_string()[..10]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(owner_id)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
            .bind(owner_id.to_string())
            .execute(&mut *blocker)
            .await
            .unwrap();
        let service = Arc::new(PubSubService::new(pool.clone(), "example.test"));
        let mut requests = Vec::new();
        for index in 0..16 {
            let service = Arc::clone(&service);
            requests.push(tokio::spawn(async move {
                let node = format!("urn:test:pool-admission:{owner_id}:{index}");
                let config = default_pep_node_config(&node);
                service.create_pep_node(owner_id, &node, &config, 100).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        let unrelated = tokio::time::timeout(
            Duration::from_millis(500),
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&pool),
        )
        .await
        .expect("same-owner PubSub waiters consumed the whole shared pool")
        .unwrap();
        assert_eq!(unrelated, 1);

        blocker.rollback().await.unwrap();
        for request in requests {
            match request.await.unwrap() {
                Ok(PepCreateOutcome::Created | PepCreateOutcome::Conflict) => {}
                Err(error) if is_pubsub_mutation_busy(&error) => {}
                result => panic!("unexpected bounded PubSub admission result: {result:?}"),
            }
        }
    }

    #[tokio::test]
    async fn generic_transaction_renderer_preserves_collection_and_last_item_snapshots() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@localhost/unused")
            .unwrap();
        let service = PubSubService::new(pool, "example.test");
        let child = renderer_node(Uuid::from_u128(10), "child<&", "leaf");
        let parent = renderer_node(Uuid::from_u128(11), "parent<&", "collection");
        let subscription = renderer_subscription(&parent.node, "alice@example.test/phone");
        let audience = [db::PubSubNotificationDelivery {
            subscription_node_id: parent.id,
            subscription: subscription.clone(),
            collection: Some(parent.node.clone()),
        }];
        let created_at = Utc.with_ymd_and_hms(2031, 1, 2, 3, 4, 5).unwrap();
        let create = db::PubSubMutationOutboxRenderer::render_create(
            &service,
            &child,
            &audience,
            Uuid::from_u128(12),
            created_at,
        )
        .unwrap();
        assert_eq!(create.len(), 1);
        let create_payload = format!("<root>{}</root>", create[0].payload_xml);
        let create_document = roxmltree::Document::parse(&create_payload).unwrap();
        let create_event = create_document
            .descendants()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "create"
                    && node.tag_name().namespace() == Some(NS_PUBSUB_EVENT)
            })
            .expect("create event");
        assert_eq!(create_event.attribute("node"), Some("child<&"));
        let headers = create_document
            .descendants()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "header"
                    && node.tag_name().namespace() == Some("http://jabber.org/protocol/shim")
            })
            .map(|node| (node.attribute("name"), node.text()))
            .collect::<Vec<_>>();
        assert!(headers.contains(&(Some("Collection"), Some("parent<&"))));
        assert!(headers.contains(&(Some("SubID"), Some("sub<&\"1"))));

        let mut pending = renderer_subscription(&child.node, "bob@example.test/tablet");
        pending.state = "pending".to_owned();
        let item = db::PubSubItem {
            item_id: "item<&".to_owned(),
            publisher_jid: "owner@example.test".to_owned(),
            xml_payload: "<item id='item&amp;&lt;'><value xmlns='urn:test'>safe</value></item>"
                .to_owned(),
            created_at,
        };
        let rendered = db::PubSubMutationOutboxRenderer::render_subscription_transition(
            &service,
            &child,
            &pending,
            &["owner@example.test".to_owned()],
            &["owner@example.test".to_owned()],
            Some(&item),
            Uuid::from_u128(13),
            created_at,
        )
        .unwrap();
        assert_eq!(rendered.len(), 3);
        let authorization = rendered
            .iter()
            .find(|row| {
                let payload = format!("<root>{}</root>", row.payload_xml);
                roxmltree::Document::parse(&payload).is_ok_and(|document| {
                    document.descendants().any(|node| {
                        node.is_element()
                            && node.tag_name().name() == "value"
                            && node.text() == Some(SUBSCRIBE_AUTH_FORM)
                    })
                })
            })
            .expect("subscription authorization form");
        let authorization_payload = format!("<root>{}</root>", authorization.payload_xml);
        let authorization_document = roxmltree::Document::parse(&authorization_payload).unwrap();
        assert!(authorization_document.descendants().any(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.attribute("var") == Some("pubsub#subscriber_jid")
                && node
                    .children()
                    .any(|child| child.is_element() && child.text() == Some(pending.jid.as_str()))
        }));

        let last_item = rendered
            .iter()
            .find(|row| {
                if row.recipient_jid != pending.jid {
                    return false;
                }
                let payload = format!("<root>{}</root>", row.payload_xml);
                roxmltree::Document::parse(&payload).is_ok_and(|document| {
                    let has_delay = document.descendants().any(|node| {
                        node.is_element()
                            && node.tag_name().name() == "delay"
                            && node.tag_name().namespace() == Some("urn:xmpp:delay")
                    });
                    let has_item_snapshot = document.descendants().any(|node| {
                        node.is_element()
                            && node.tag_name().name() == "items"
                            && node.attribute("node") == Some("child<&")
                            && node.descendants().any(|item| {
                                item.is_element()
                                    && item.tag_name().name() == "item"
                                    && item.attribute("id") == Some("item&<")
                            })
                    });
                    has_delay && has_item_snapshot
                })
            })
            .expect("last-item snapshot");
        let last_item_payload = format!("<root>{}</root>", last_item.payload_xml);
        let last_item_document = roxmltree::Document::parse(&last_item_payload).unwrap();
        assert!(last_item_document.descendants().any(|node| {
            node.is_element()
                && node.tag_name().name() == "value"
                && node.tag_name().namespace() == Some("urn:test")
                && node.text() == Some("safe")
        }));
    }

    fn snapshot_deliveries(audience: &PepAudienceSnapshot) -> Result<Vec<(String, String)>> {
        Ok(audience
            .roster_jids
            .iter()
            .chain(audience.explicit_jids.iter())
            .map(|jid| {
                (
                    jid.clone(),
                    format!("<message xmlns='jabber:client' to='{jid}'/>"),
                )
            })
            .collect())
    }

    #[test]
    fn node_config_mapping_round_trips_every_policy_field() {
        let service = PubSubNodeConfig {
            access_model: "whitelist".to_owned(),
            publish_model: "subscribers".to_owned(),
            max_items: 37,
            title: Some("A title".to_owned()),
            description: Some("A description".to_owned()),
            deliver_payloads: false,
            notify_delete: false,
            notify_retract: false,
            persist_items: false,
            send_last_published_item: "never".to_owned(),
            node_type: "collection".to_owned(),
            deliver_notifications: false,
            notify_config: false,
            notify_sub: false,
            language: Some("en".to_owned()),
            payload_type: Some("urn:example:payload".to_owned()),
            max_payload_size: 65_535,
            children_max: 23,
            children_association_policy: "whitelist".to_owned(),
            children_association_whitelist: vec!["owner@example.test".to_owned()],
            collections: vec!["parent".to_owned()],
            children: vec!["child".to_owned()],
        };

        let repository = db::PubSubNodeConfig::from(&service);
        let round_trip = PubSubNodeConfig::from(repository);

        assert_eq!(round_trip, service);
    }

    #[test]
    fn subscription_mapping_round_trips_authoritative_delivery_options() {
        let expiry = Utc.with_ymd_and_hms(2030, 4, 5, 6, 7, 8).unwrap();
        let service = PubSubSubscription {
            node: "urn:example:node".to_owned(),
            jid: "alice@example.test/phone".to_owned(),
            state: "subscribed".to_owned(),
            subid: "sub-1".to_owned(),
            deliver: false,
            digest: true,
            digest_frequency: 12_345,
            expire: Some(expiry),
            include_body: true,
            show_values: vec!["chat".to_owned(), "online".to_owned()],
            subscription_type: "nodes".to_owned(),
            subscription_depth: Some(7),
        };

        let repository = db::PubSubSubscription::from(&service);
        let round_trip = PubSubSubscription::from(repository);

        assert_eq!(round_trip.node, service.node);
        assert_eq!(round_trip.jid, service.jid);
        assert_eq!(round_trip.state, service.state);
        assert_eq!(round_trip.subid, service.subid);
        assert_eq!(
            subscription_options(&round_trip),
            subscription_options(&service)
        );
    }

    #[test]
    fn outbox_request_mapping_preserves_recipient_order_and_kind() {
        let event_id = Uuid::from_u128(1);
        let now = Utc.with_ymd_and_hms(2030, 4, 5, 6, 7, 8).unwrap();
        let first = db::PubSubOutboxInsert::new(
            event_id,
            "node:one",
            db::PubSubOutboxSource::PubSub,
            db::PubSubOutboxDeliveryKind::PubSubDirect,
            "alice@example.test/phone",
            "<message xmlns='jabber:client'/>",
            None,
            None,
            "urn:example:node",
            None,
            now,
        )
        .unwrap();
        let sender_id = Uuid::from_u128(2);
        let second = PubSubOutboxInsert::new_pep_stanza(
            event_id,
            sender_id,
            "alice@example.test",
            None,
            "bob@remote.test/laptop",
            None,
            PepOutboxEventKind::Publish,
            PepOutboxAuthorizationMode::CausalAudience,
            "<message xmlns='jabber:client'/>",
            "urn:example:pep",
            "example.test",
            now,
        )
        .unwrap();

        let repository = db_outbox(&[first, second]);

        assert_eq!(repository.len(), 2);
        assert_eq!(repository[0].recipient_jid, "alice@example.test/phone");
        assert_eq!(
            repository[0].delivery_kind,
            db::PubSubOutboxDeliveryKind::PubSubDirect
        );
        assert_eq!(repository[1].recipient_jid, "bob@remote.test/laptop");
        assert_eq!(
            repository[1].delivery_kind,
            db::PubSubOutboxDeliveryKind::PepStanza
        );
        assert_eq!(repository[0].event_id, repository[1].event_id);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn paused_pep_delivery_rechecks_block_privacy_disable_and_sensitive_acl() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(6)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let sender_id = Uuid::new_v4();
        let recipient_id = Uuid::new_v4();
        let sender_username = format!("pep-auth-s-{}", &suffix[..10]);
        let recipient_username = format!("pep-auth-r-{}", &suffix[..10]);
        for (id, username) in [
            (sender_id, sender_username.as_str()),
            (recipient_id, recipient_username.as_str()),
        ] {
            sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
                .bind(id)
                .bind(username)
                .execute(&pool)
                .await
                .unwrap();
        }
        let sender_bare = format!("{sender_username}@example.test");
        let recipient_bare = format!("{recipient_username}@example.test");
        let recipient_full = format!("{recipient_bare}/phone");
        let node = format!("urn:xmpp:omemo:2:devices:{suffix}");
        let mut config = db::default_pep_node_config(&node);
        config.access_model = "open".to_owned();
        config.deliver_notifications = true;
        assert_eq!(
            db::create_pep_node(&pool, sender_id, &node, &config, 20)
                .await
                .unwrap(),
            db::PepCreateOutcome::Created
        );
        let insert = db::PubSubOutboxInsert::new_pep_stanza(
            Uuid::new_v4(),
            sender_id,
            &sender_bare,
            None,
            &recipient_full,
            Some(recipient_id),
            db::PepOutboxEventKind::Publish,
            db::PepOutboxAuthorizationMode::CausalAudience,
            "<message id='paused-pep'/>",
            &node,
            "example.test",
            Utc::now(),
        )
        .unwrap();
        let delivery_id = insert.delivery_id;
        let ordering_key = insert.ordering_key.clone();
        let mut transaction = pool.begin().await.unwrap();
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &[insert])
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        let service = PubSubService::new(pool.clone(), "example.test");
        let item = service
            .claim_pubsub_outbox(100)
            .await
            .unwrap()
            .into_iter()
            .find(|item| item.delivery_id == delivery_id)
            .unwrap();
        assert_eq!(
            service.authorize_pep_outbox_delivery(&item).await.unwrap(),
            PepOutboxAuthorizationOutcome::Deliver
        );

        db::block_jids(&pool, sender_id, std::slice::from_ref(&recipient_bare))
            .await
            .unwrap();
        assert_eq!(
            service.authorize_pep_outbox_delivery(&item).await.unwrap(),
            PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::Blocked)
        );
        db::unblock_jids(
            &pool,
            sender_id,
            Some(std::slice::from_ref(&recipient_bare)),
        )
        .await
        .unwrap();

        let privacy = db::PrivacyList {
            name: "deny-pep".to_owned(),
            items: vec![db::PrivacyItem {
                order: 1,
                action: db::PrivacyAction::Deny,
                match_type: None,
                match_value: None,
                message: true,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        };
        db::replace_privacy_list(&pool, sender_id, &privacy)
            .await
            .unwrap();
        assert!(
            db::set_default_privacy_list(&pool, sender_id, Some(&privacy.name))
                .await
                .unwrap()
        );
        assert_eq!(
            service.authorize_pep_outbox_delivery(&item).await.unwrap(),
            PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::PrivacyDenied)
        );
        assert!(db::set_default_privacy_list(&pool, sender_id, None)
            .await
            .unwrap());

        sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
            .bind(recipient_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            service.authorize_pep_outbox_delivery(&item).await.unwrap(),
            PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::RecipientUnavailable)
        );
        sqlx::query("UPDATE users SET is_disabled=FALSE WHERE id=$1")
            .bind(recipient_id)
            .execute(&pool)
            .await
            .unwrap();

        config.access_model = "whitelist".to_owned();
        config.access_whitelist.clear();
        assert!(db::update_pep_node_config(&pool, sender_id, &node, &config)
            .await
            .unwrap());
        assert_eq!(
            service.authorize_pep_outbox_delivery(&item).await.unwrap(),
            PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::NodeAccessRevoked)
        );

        service
            .acknowledge_pubsub_outbox(item.delivery_id, item.lease_token)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id=ANY($1)")
            .bind([sender_id, recipient_id])
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pubsub_event_streams WHERE ordering_key=$1")
            .bind(ordering_key)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn pep_publish_audience_is_linearizable_with_every_revocation_input() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(12)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let owner_id = Uuid::new_v4();
        let username = format!("owner{}", &owner_id.simple().to_string()[..10]);
        let auth_generation = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
             RETURNING auth_generation",
        )
        .bind(owner_id)
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();
        let node = format!("urn:test:pep:audience:{}", Uuid::new_v4().simple());
        let mut config = db::default_pep_node_config(&node);
        config.access_model = "open".to_owned();
        assert_eq!(
            db::create_pep_node(&pool, owner_id, &node, &config, 10)
                .await
                .unwrap(),
            db::PepCreateOutcome::Created
        );
        let unsubscribed = format!("unsubscribe{}@remote.test/phone", Uuid::new_v4().simple());
        let blocked = format!("blocked{}@remote.test/tablet", Uuid::new_v4().simple());
        let roster = format!("roster{}@remote.test", Uuid::new_v4().simple());
        let unsubscribed_record =
            db::subscribe_pep_node(&pool, owner_id, &node, &unsubscribed, 100)
                .await
                .unwrap()
                .unwrap();
        db::subscribe_pep_node(&pool, owner_id, &node, &blocked, 100)
            .await
            .unwrap()
            .unwrap();
        db::update_subscription(&pool, owner_id, &roster, "from", None)
            .await
            .unwrap();

        let service = Arc::new(PubSubService::new(pool.clone(), "example.test"));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let factory_gate = Arc::clone(&gate);
        let (snapshot_tx, mut snapshot_rx) = tokio::sync::mpsc::unbounded_channel();
        let publish_service = Arc::clone(&service);
        let publish_username = username.clone();
        let publish_node = node.clone();
        let publish_config = PepNodeConfig::from(config.clone());
        let publish = tokio::spawn(async move {
            let payload = "<item id='one'><value xmlns='urn:test'>one</value></item>";
            let items = [("one", payload)];
            publish_service
                .publish_pep_items(
                    PepPublishItemsCommand::new(
                        PepPublishWrite {
                            user_id: owner_id,
                            username: &publish_username,
                            auth_generation,
                            connection_id: Uuid::new_v4(),
                            node: &publish_node,
                            requested: &publish_config,
                            enforce_preconditions: false,
                            items: &items,
                            quotas: PepQuotas {
                                max_nodes: 10,
                                max_storage_bytes: 1_000_000,
                            },
                        },
                        false,
                    ),
                    &move |audience: &PepAudienceSnapshot| {
                        snapshot_tx
                            .send((audience.roster_jids.clone(), audience.explicit_jids.clone()))
                            .map_err(|_| anyhow::anyhow!("PEP snapshot observer closed"))?;
                        let (released, wake) = &*factory_gate;
                        let mut released = released.lock().expect("PEP gate poisoned");
                        while !*released {
                            released = wake.wait(released).expect("PEP gate poisoned");
                        }
                        snapshot_deliveries(audience)
                    },
                )
                .await
        });
        let (first_roster, mut first_explicit) =
            tokio::time::timeout(Duration::from_secs(3), snapshot_rx.recv())
                .await
                .expect("publication never reached its audience snapshot")
                .expect("PEP snapshot observer closed");
        first_explicit.sort_unstable();
        let mut expected_explicit = vec![blocked.clone(), unsubscribed.clone()];
        expected_explicit.sort_unstable();
        assert_eq!(first_roster, vec![roster.clone()]);
        assert_eq!(first_explicit, expected_explicit);

        let unsubscribe_pool = pool.clone();
        let unsubscribe_node = node.clone();
        let unsubscribe_jid = unsubscribed.clone();
        let mut unsubscribe = tokio::spawn(async move {
            db::unsubscribe_pep_node(
                &unsubscribe_pool,
                owner_id,
                &unsubscribe_node,
                &unsubscribe_jid,
                Some(&unsubscribed_record.subid),
            )
            .await
        });
        let block_pool = pool.clone();
        let blocked_jid = blocked.clone();
        let mut block =
            tokio::spawn(
                async move { db::block_jids(&block_pool, owner_id, &[blocked_jid]).await },
            );
        let roster_pool = pool.clone();
        let roster_jid = roster.clone();
        let mut roster_removal =
            tokio::spawn(
                async move { db::delete_roster(&roster_pool, owner_id, &roster_jid).await },
            );
        let config_pool = pool.clone();
        let config_node = node.clone();
        let mut restricted_config = config.clone();
        restricted_config.access_model = "whitelist".to_owned();
        restricted_config.access_whitelist.clear();
        let mut access_change = tokio::spawn(async move {
            db::update_pep_node_config(&config_pool, owner_id, &config_node, &restricted_config)
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut unsubscribe)
                .await
                .is_err(),
            "unsubscribe bypassed the PEP publication audience lock"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut block)
                .await
                .is_err(),
            "block bypassed the PEP publication audience lock"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut roster_removal)
                .await
                .is_err(),
            "roster removal bypassed the PEP publication audience lock"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut access_change)
                .await
                .is_err(),
            "access-model change bypassed the PEP publication audience lock"
        );
        {
            let (released, wake) = &*gate;
            *released.lock().expect("PEP gate poisoned") = true;
            wake.notify_all();
        }
        let publish_result = publish.await.unwrap().unwrap();
        assert_eq!(publish_result.outcome, PepPublishItemsOutcome::Published);
        assert!(publish_result.content_changed);
        unsubscribe.await.unwrap().unwrap().unwrap();
        assert!(matches!(
            block.await.unwrap().unwrap(),
            db::BlockJidsUpdate::Changed(_)
        ));
        roster_removal.await.unwrap().unwrap().unwrap();
        assert!(access_change.await.unwrap().unwrap());

        let second_payload = "<item id='one'><value xmlns='urn:test'>two</value></item>";
        let second_items = [("one", second_payload)];
        let (second_tx, mut second_rx) = tokio::sync::mpsc::unbounded_channel();
        let second_config = PepNodeConfig::from(config);
        let result = service
            .publish_pep_items(
                PepPublishItemsCommand::new(
                    PepPublishWrite {
                        user_id: owner_id,
                        username: &username,
                        auth_generation,
                        connection_id: Uuid::new_v4(),
                        node: &node,
                        requested: &second_config,
                        enforce_preconditions: false,
                        items: &second_items,
                        quotas: PepQuotas {
                            max_nodes: 10,
                            max_storage_bytes: 1_000_000,
                        },
                    },
                    false,
                ),
                &|audience: &PepAudienceSnapshot| {
                    second_tx
                        .send((audience.roster_jids.clone(), audience.explicit_jids.clone()))
                        .map_err(|_| anyhow::anyhow!("second PEP observer closed"))?;
                    snapshot_deliveries(audience)
                },
            )
            .await
            .unwrap();
        assert_eq!(result.outcome, PepPublishItemsOutcome::Published);
        assert!(result.content_changed);
        assert_eq!(second_rx.recv().await.unwrap(), (Vec::new(), Vec::new()));
        let mut expected_recipients = vec![blocked, roster, unsubscribed];
        expected_recipients.sort_unstable();
        assert_eq!(
            sqlx::query_scalar::<_, Vec<String>>(
                "SELECT COALESCE(ARRAY_AGG(recipient_jid ORDER BY recipient_jid),ARRAY[]::TEXT[])
                   FROM pubsub_event_outbox WHERE source_node=$1",
            )
            .bind(&node)
            .fetch_one(&pool)
            .await
            .unwrap(),
            expected_recipients,
            "revocation-first publication must not append a stale audience"
        );
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn pep_subscription_admission_is_linearizable_and_principal_scoped() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let owner_id = Uuid::new_v4();
        let owner_username = format!("owner{}", &owner_id.simple().to_string()[..10]);
        let owner_generation = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
             RETURNING auth_generation",
        )
        .bind(owner_id)
        .bind(&owner_username)
        .fetch_one(&pool)
        .await
        .unwrap();
        let owner = PubSubAccount {
            id: owner_id,
            username: owner_username.clone(),
            auth_generation: owner_generation,
        };
        let service = Arc::new(PubSubService::new(pool.clone(), "example.test"));
        let subscriber = format!("remote{}@remote.test/phone", Uuid::new_v4().simple());
        let subscriber_bare = crate::jid::canonical_bare_key(&subscriber).unwrap();

        // Subscription-first: every revocation input must wait until the
        // subscription and its outbox projection commit from one snapshot.
        let node = format!("urn:test:pep:subscribe-race:{}", Uuid::new_v4().simple());
        let mut config = db::default_pep_node_config(&node);
        config.access_model = "roster".to_owned();
        config.roster_groups_allowed = vec!["friends".to_owned()];
        assert_eq!(
            db::create_pep_node(&pool, owner_id, &node, &config, 20)
                .await
                .unwrap(),
            db::PepCreateOutcome::Created
        );
        db::upsert_roster(
            &pool,
            owner_id,
            &subscriber_bare,
            None,
            &["friends".to_owned()],
        )
        .await
        .unwrap();
        db::update_subscription(&pool, owner_id, &subscriber_bare, "from", None)
            .await
            .unwrap();

        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let subscribe_service = Arc::clone(&service);
        let subscribe_owner = owner.clone();
        let subscribe_node = node.clone();
        let subscribe_jid = subscriber.clone();
        let subscribe_gate = Arc::clone(&gate);
        let subscribe = tokio::spawn(async move {
            let subid = Uuid::new_v4().to_string();
            subscribe_service
                .subscribe_pep_node(
                    northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                        owner: &subscribe_owner,
                        actor: PepSubscriptionActor {
                            jid: &subscribe_jid,
                            local_account: None,
                        },
                        node: &subscribe_node,
                        subscriber_jid: &subscribe_jid,
                        max_subscriptions: 100,
                        requested_subid: &subid,
                    }),
                    &move |_: &PepSubscribeSnapshot| {
                        entered_tx
                            .send(())
                            .map_err(|_| anyhow::anyhow!("subscription observer closed"))?;
                        let (released, wake) = &*subscribe_gate;
                        let mut released = released.lock().expect("subscription gate poisoned");
                        while !*released {
                            released = wake.wait(released).expect("subscription gate poisoned");
                        }
                        Ok(Vec::new())
                    },
                )
                .await
        });
        entered_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("subscription never reached its locked snapshot");

        let block_pool = pool.clone();
        let block_jid = subscriber_bare.clone();
        let mut block =
            tokio::spawn(async move { db::block_jids(&block_pool, owner_id, &[block_jid]).await });
        let roster_pool = pool.clone();
        let roster_jid = subscriber_bare.clone();
        let mut roster_revoke = tokio::spawn(async move {
            db::upsert_roster_authorized(
                &roster_pool,
                owner_id,
                owner_generation,
                &roster_jid,
                None,
                &[],
            )
            .await
        });
        let config_pool = pool.clone();
        let config_node = node.clone();
        let mut restricted = config.clone();
        restricted.access_model = "whitelist".to_owned();
        restricted.access_whitelist.clear();
        let mut access_revoke = tokio::spawn(async move {
            db::update_pep_node_config(&config_pool, owner_id, &config_node, &restricted).await
        });
        let delete_pool = pool.clone();
        let delete_node = node.clone();
        let mut node_delete =
            tokio::spawn(
                async move { db::delete_pep_node(&delete_pool, owner_id, &delete_node).await },
            );
        for (name, blocked) in [
            (
                "block",
                tokio::time::timeout(Duration::from_millis(200), &mut block)
                    .await
                    .is_err(),
            ),
            (
                "roster",
                tokio::time::timeout(Duration::from_millis(200), &mut roster_revoke)
                    .await
                    .is_err(),
            ),
            (
                "access-model",
                tokio::time::timeout(Duration::from_millis(200), &mut access_revoke)
                    .await
                    .is_err(),
            ),
            (
                "node-delete",
                tokio::time::timeout(Duration::from_millis(200), &mut node_delete)
                    .await
                    .is_err(),
            ),
        ] {
            assert!(blocked, "{name} revocation bypassed subscription locks");
        }
        {
            let (released, wake) = &*gate;
            *released.lock().expect("subscription gate poisoned") = true;
            wake.notify_all();
        }
        assert!(matches!(
            subscribe.await.unwrap().unwrap().outcome,
            PepSubscribeOutcome::Subscribed(_)
        ));
        assert!(matches!(
            block.await.unwrap().unwrap(),
            db::BlockJidsUpdate::Changed(_)
        ));
        roster_revoke.await.unwrap().unwrap().unwrap();
        let _ = access_revoke.await.unwrap().unwrap();
        let _ = node_delete.await.unwrap().unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pep_subscriptions WHERE owner_id=$1 AND node=$2",
            )
            .bind(owner_id)
            .bind(&node)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );

        // Revocation-first snapshots deterministically deny admission.
        let blocked_node = format!("urn:test:pep:blocked:{}", Uuid::new_v4().simple());
        let mut open = db::default_pep_node_config(&blocked_node);
        open.access_model = "open".to_owned();
        assert_eq!(
            db::create_pep_node(&pool, owner_id, &blocked_node, &open, 20)
                .await
                .unwrap(),
            db::PepCreateOutcome::Created
        );
        let denied_subid = Uuid::new_v4().to_string();
        assert!(matches!(
            service
                .subscribe_pep_node(
                    northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                        owner: &owner,
                        actor: PepSubscriptionActor {
                            jid: &subscriber,
                            local_account: None,
                        },
                        node: &blocked_node,
                        subscriber_jid: &subscriber,
                        max_subscriptions: 100,
                        requested_subid: &denied_subid,
                    }),
                    &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
                )
                .await
                .unwrap()
                .outcome,
            PepSubscribeOutcome::NotAuthorized(_)
        ));
        db::unblock_jids(
            &pool,
            owner_id,
            Some(std::slice::from_ref(&subscriber_bare)),
        )
        .await
        .unwrap();

        let mut whitelist_only = open.clone();
        whitelist_only.access_model = "whitelist".to_owned();
        whitelist_only.access_whitelist.clear();
        assert!(
            db::update_pep_node_config(&pool, owner_id, &blocked_node, &whitelist_only,)
                .await
                .unwrap()
        );
        let access_denied_subid = Uuid::new_v4().to_string();
        assert!(matches!(
            service
                .subscribe_pep_node(
                    northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                        owner: &owner,
                        actor: PepSubscriptionActor {
                            jid: &subscriber,
                            local_account: None,
                        },
                        node: &blocked_node,
                        subscriber_jid: &subscriber,
                        max_subscriptions: 100,
                        requested_subid: &access_denied_subid,
                    }),
                    &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
                )
                .await
                .unwrap()
                .outcome,
            PepSubscribeOutcome::NotAuthorized(_)
        ));

        let roster_node = format!("urn:test:pep:roster-deny:{}", Uuid::new_v4().simple());
        let mut roster_config = db::default_pep_node_config(&roster_node);
        roster_config.access_model = "roster".to_owned();
        roster_config.roster_groups_allowed = vec!["friends".to_owned()];
        assert_eq!(
            db::create_pep_node(&pool, owner_id, &roster_node, &roster_config, 20)
                .await
                .unwrap(),
            db::PepCreateOutcome::Created
        );
        let roster_denied_subid = Uuid::new_v4().to_string();
        assert!(matches!(
            service
                .subscribe_pep_node(
                    northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                        owner: &owner,
                        actor: PepSubscriptionActor {
                            jid: &subscriber,
                            local_account: None,
                        },
                        node: &roster_node,
                        subscriber_jid: &subscriber,
                        max_subscriptions: 100,
                        requested_subid: &roster_denied_subid,
                    }),
                    &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
                )
                .await
                .unwrap()
                .outcome,
            PepSubscribeOutcome::NotAuthorized(_)
        ));

        db::update_subscription(&pool, owner_id, &subscriber_bare, "none", None)
            .await
            .unwrap();
        let presence_node = format!("urn:test:pep:presence-deny:{}", Uuid::new_v4().simple());
        let mut presence_config = db::default_pep_node_config(&presence_node);
        presence_config.access_model = "presence".to_owned();
        assert_eq!(
            db::create_pep_node(&pool, owner_id, &presence_node, &presence_config, 20)
                .await
                .unwrap(),
            db::PepCreateOutcome::Created
        );
        let presence_denied_subid = Uuid::new_v4().to_string();
        assert!(matches!(
            service
                .subscribe_pep_node(
                    northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                        owner: &owner,
                        actor: PepSubscriptionActor {
                            jid: &subscriber,
                            local_account: None,
                        },
                        node: &presence_node,
                        subscriber_jid: &subscriber,
                        max_subscriptions: 100,
                        requested_subid: &presence_denied_subid,
                    }),
                    &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
                )
                .await
                .unwrap()
                .outcome,
            PepSubscribeOutcome::NotAuthorized(_)
        ));

        let deleted_node = format!("urn:test:pep:deleted:{}", Uuid::new_v4().simple());
        assert_eq!(
            db::create_pep_node(
                &pool,
                owner_id,
                &deleted_node,
                &db::default_pep_node_config(&deleted_node),
                20,
            )
            .await
            .unwrap(),
            db::PepCreateOutcome::Created
        );
        assert!(db::delete_pep_node(&pool, owner_id, &deleted_node)
            .await
            .unwrap());
        let deleted_subid = Uuid::new_v4().to_string();
        assert_eq!(
            service
                .subscribe_pep_node(
                    northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                        owner: &owner,
                        actor: PepSubscriptionActor {
                            jid: &subscriber,
                            local_account: None,
                        },
                        node: &deleted_node,
                        subscriber_jid: &subscriber,
                        max_subscriptions: 100,
                        requested_subid: &deleted_subid,
                    }),
                    &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
                )
                .await
                .unwrap()
                .outcome,
            PepSubscribeOutcome::NotFound
        );

        // Concurrent duplicate requests converge on one row, one subid and
        // one send-last rendering. A sibling resource cannot remove it.
        let duplicate_node = format!("urn:test:pep:duplicate:{}", Uuid::new_v4().simple());
        let mut duplicate_config = db::default_pep_node_config(&duplicate_node);
        duplicate_config.access_model = "open".to_owned();
        assert_eq!(
            db::create_pep_node(&pool, owner_id, &duplicate_node, &duplicate_config, 20,)
                .await
                .unwrap(),
            db::PepCreateOutcome::Created
        );
        let render_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_service = Arc::clone(&service);
        let first_owner = owner.clone();
        let first_node = duplicate_node.clone();
        let first_jid = subscriber.clone();
        let first_count = Arc::clone(&render_count);
        let first = tokio::spawn(async move {
            let subid = Uuid::new_v4().to_string();
            first_service
                .subscribe_pep_node(
                    northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                        owner: &first_owner,
                        actor: PepSubscriptionActor {
                            jid: &first_jid,
                            local_account: None,
                        },
                        node: &first_node,
                        subscriber_jid: &first_jid,
                        max_subscriptions: 100,
                        requested_subid: &subid,
                    }),
                    &move |_: &PepSubscribeSnapshot| {
                        first_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(Vec::new())
                    },
                )
                .await
        });
        let second_service = Arc::clone(&service);
        let second_owner = owner.clone();
        let second_node = duplicate_node.clone();
        let second_jid = subscriber.clone();
        let second_count = Arc::clone(&render_count);
        let second = tokio::spawn(async move {
            let subid = Uuid::new_v4().to_string();
            second_service
                .subscribe_pep_node(
                    northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                        owner: &second_owner,
                        actor: PepSubscriptionActor {
                            jid: &second_jid,
                            local_account: None,
                        },
                        node: &second_node,
                        subscriber_jid: &second_jid,
                        max_subscriptions: 100,
                        requested_subid: &subid,
                    }),
                    &move |_: &PepSubscribeSnapshot| {
                        second_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(Vec::new())
                    },
                )
                .await
        });
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();
        let (PepSubscribeOutcome::Subscribed(first), PepSubscribeOutcome::Subscribed(second)) =
            (first.outcome, second.outcome)
        else {
            panic!("duplicate subscriptions were not accepted idempotently");
        };
        assert_eq!(first.subid, second.subid);
        assert_eq!(render_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM pep_subscriptions
                  WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3",
            )
            .bind(owner_id)
            .bind(&duplicate_node)
            .bind(&subscriber)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        let sibling = subscriber.replace("/phone", "/tablet");
        assert_eq!(
            service
                .unsubscribe_pep_node(northstar_pubsub_application::PepUnsubscribeCommand::from(
                    PepUnsubscribeWrite {
                        owner: &owner,
                        actor: PepSubscriptionActor {
                            jid: &sibling,
                            local_account: None,
                        },
                        node: &duplicate_node,
                        subscriber_jid: &subscriber,
                        subid: Some(&first.subid),
                    },
                ))
                .await
                .unwrap()
                .outcome,
            PepUnsubscribeOutcome::Forbidden
        );
        assert_eq!(
            service
                .unsubscribe_pep_node(northstar_pubsub_application::PepUnsubscribeCommand::from(
                    PepUnsubscribeWrite {
                        owner: &owner,
                        actor: PepSubscriptionActor {
                            jid: &subscriber,
                            local_account: None,
                        },
                        node: &duplicate_node,
                        subscriber_jid: &subscriber,
                        subid: Some(&first.subid),
                    },
                ))
                .await
                .unwrap()
                .outcome,
            PepUnsubscribeOutcome::Unsubscribed(Some(first.subid.clone()))
        );
        assert_eq!(
            service
                .unsubscribe_pep_node(northstar_pubsub_application::PepUnsubscribeCommand::from(
                    PepUnsubscribeWrite {
                        owner: &owner,
                        actor: PepSubscriptionActor {
                            jid: &subscriber,
                            local_account: None,
                        },
                        node: &duplicate_node,
                        subscriber_jid: &subscriber,
                        subid: Some(&first.subid),
                    },
                ))
                .await
                .unwrap()
                .outcome,
            PepUnsubscribeOutcome::Unsubscribed(None)
        );

        // A hosted subscriber's own block policy is the reciprocal half of
        // the admission decision and is locked with the target owner's policy.
        let local_id = Uuid::new_v4();
        let local_username = format!("local{}", &local_id.simple().to_string()[..10]);
        let local_generation = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
             RETURNING auth_generation",
        )
        .bind(local_id)
        .bind(&local_username)
        .fetch_one(&pool)
        .await
        .unwrap();
        let local = PubSubAccount {
            id: local_id,
            username: local_username.clone(),
            auth_generation: local_generation,
        };
        let local_jid = format!("{local_username}@example.test/phone");
        let owner_bare = format!("{owner_username}@example.test");
        assert!(matches!(
            db::block_jids(&pool, local_id, &[owner_bare])
                .await
                .unwrap(),
            db::BlockJidsUpdate::Changed(_)
        ));
        let reciprocal_subid = Uuid::new_v4().to_string();
        assert!(matches!(
            service
                .subscribe_pep_node(
                    northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                        owner: &owner,
                        actor: PepSubscriptionActor {
                            jid: &local_jid,
                            local_account: Some(&local),
                        },
                        node: &duplicate_node,
                        subscriber_jid: &local_jid,
                        max_subscriptions: 100,
                        requested_subid: &reciprocal_subid,
                    }),
                    &|_: &PepSubscribeSnapshot| Ok(Vec::new()),
                )
                .await
                .unwrap()
                .outcome,
            PepSubscribeOutcome::NotAuthorized(_)
        ));

        sqlx::query("DELETE FROM users WHERE id=ANY($1)")
            .bind(vec![owner_id, local_id])
            .execute(&pool)
            .await
            .unwrap();
    }

    fn subscription_options(subscription: &PubSubSubscription) -> PubSubSubscriptionOptions {
        PubSubSubscriptionOptions {
            deliver: subscription.deliver,
            digest: subscription.digest,
            digest_frequency: subscription.digest_frequency,
            expire: subscription.expire,
            include_body: subscription.include_body,
            show_values: subscription.show_values.clone(),
            subscription_type: subscription.subscription_type.clone(),
            subscription_depth: subscription.subscription_depth,
        }
    }
}
