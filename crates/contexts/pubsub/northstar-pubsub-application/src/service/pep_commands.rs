//! Personal Eventing Protocol commands.

use super::PubSubService;
use crate::{
    validate_pep_commit_legacy_bookmarks_command, validate_pep_configure_node_command,
    validate_pep_create_node_command, validate_pep_delete_node_command,
    validate_pep_publish_command, validate_pep_purge_node_command, validate_pep_retract_command,
    validate_pep_set_affiliations_command, validate_pep_subscribe_command,
    validate_pep_unsubscribe_batch_command, validate_pep_unsubscribe_command,
    PepAffiliationRepository, PepCommitLegacyBookmarksCommand, PepCommitLegacyBookmarksResult,
    PepConfigureNodeCommand, PepConfigureNodeResult, PepCreateNodeCommand, PepCreateNodeResult,
    PepDeleteNodeCommand, PepDeleteNodeResult, PepItemMutationRepository,
    PepNodeMutationRepository, PepPublishItemsCommand, PepPublishItemsResult, PepPurgeNodeCommand,
    PepPurgeNodeResult, PepRetractCommand, PepRetractResult, PepSetAffiliationsCommand,
    PepSetAffiliationsResult, PepSubscribeCommand, PepSubscribeResult,
    PepSubscriptionMutationRepository, PepUnsubscribeBatchCommand, PepUnsubscribeBatchResult,
    PepUnsubscribeCommand, PepUnsubscribeResult, PubSubAdmissionKey, PubSubMutationPermit,
};
use anyhow::Result;
use northstar_pubsub_core::{
    PepDirectOutboxFactory, PepNodeConfig, PepOutboxFactory, PepOwnerMutationOutcome,
    PepSubscribeOutboxFactory, PubSubAccount,
};
use uuid::Uuid;

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
        let _permit = self
            .admit_pep_node_mutation(command.owner.id, command.node)
            .await?;
        self.repository
            .create_pep_node(
                command.owner,
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
        let _permit = self
            .mutation_admission
            .acquire_keys(
                &[
                    PubSubAdmissionKey::Owner(write.owner.id),
                    PubSubAdmissionKey::Text(write.subscriber_jid),
                    PubSubAdmissionKey::Text(write.node),
                ],
                false,
            )
            .await?;
        self.repository.subscribe_pep_node(command, factory).await
    }
    pub async fn unsubscribe_pep_node(
        &self,
        command: PepUnsubscribeCommand<'_>,
    ) -> Result<PepUnsubscribeResult> {
        validate_pep_unsubscribe_command(&command)?;
        let write = &command.write;
        let _permit = self
            .mutation_admission
            .acquire_keys(
                &[
                    PubSubAdmissionKey::Owner(write.owner.id),
                    PubSubAdmissionKey::Text(write.subscriber_jid),
                    PubSubAdmissionKey::Text(write.node),
                ],
                false,
            )
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
        let _permit = self.admit_pep_node_mutation(owner.id, node).await?;
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
        let _permit = self.admit_pep_node_mutation(owner.id, node).await?;
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
        let _permit = self.admit_pep_node_mutation(owner.id, node).await?;
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
        let _permit = self.admit_pep_node_mutation(owner.id, node).await?;
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
        let _permit = self.admit_pep_node_mutation(owner.id, node).await?;
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
        let _permit = self
            .admit_pep_node_mutation(command.owner.id, command.node)
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
        let _permit = self
            .admit_pep_node_mutation(command.owner.id, BOOKMARKS2)
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
        let _permit = self
            .admit_pep_node_mutation(write.user_id, write.node)
            .await?;
        self.repository.publish_pep_items(command, factory).await
    }
}

impl<R> PubSubService<R> {
    async fn admit_pep_node_mutation(
        &self,
        owner: Uuid,
        node: &str,
    ) -> Result<PubSubMutationPermit> {
        self.mutation_admission
            .acquire_keys(
                &[
                    PubSubAdmissionKey::Owner(owner),
                    PubSubAdmissionKey::Text(node),
                ],
                false,
            )
            .await
    }
}
