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

pub(crate) fn subscription_event_children(
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
#[path = "pubsub_tests.rs"]
mod tests;
