//! Generic PubSub subscription commands.

use super::PubSubService;
use crate::{
    authorization_precheck, validate_pubsub_authorize_subscription_command,
    validate_pubsub_subscribe_command, validate_pubsub_unsubscribe_command,
    validate_pubsub_update_subscription_options_command, PubSubAdmissionKey,
    PubSubAuthorizeSubscriptionCommand, PubSubAuthorizeSubscriptionResult,
    PubSubNodeQueryRepository, PubSubSubscribeCommand, PubSubSubscribeResult,
    PubSubSubscriptionMutationRepository, PubSubSubscriptionQueryRepository,
    PubSubUnsubscribeCommand, PubSubUnsubscribeResult, PubSubUpdateSubscriptionOptionsCommand,
    PubSubUpdateSubscriptionOptionsResult,
};
use anyhow::Result;
use northstar_pubsub_core::{
    PubSubAddress, PubSubBareJid, PubSubNodeId, PubSubNodeName, PubSubSubscribeOutcome,
    PubSubUnsubscribeOutcome, SubscriptionAuthorizationOutcome, SubscriptionOptionsOutcome,
};

impl<R: PubSubNodeQueryRepository + PubSubSubscriptionMutationRepository> PubSubService<R> {
    pub async fn execute_pubsub_subscribe(
        &self,
        command: PubSubSubscribeCommand<'_>,
    ) -> Result<PubSubSubscribeResult> {
        validate_pubsub_subscribe_command(&command)?;
        let write = command.write;
        let node_id = if let Some(node_id) = command.resolved_node_id {
            node_id
        } else {
            let name = PubSubNodeName::parse(write.node)?;
            let Some(node) = self.get_node(name.as_str()).await? else {
                return Ok(PubSubSubscribeOutcome::NotFound.into());
            };
            PubSubNodeId::new(node.id)
        };
        let requester = PubSubAddress::parse(write.requester)?.bare();
        let subscriber = PubSubAddress::parse(write.subscriber_jid)?;
        let planned_subid = self.time_sources().new_uuid().to_string();
        let _permit = self
            .admit_subscription_mutation(node_id, write.requester, write.subscriber_jid)
            .await?;
        let outcome = self
            .repository
            .subscribe_checked(
                node_id,
                &requester,
                &subscriber,
                write.max_subscriptions,
                write.options,
                &planned_subid,
                self.time_sources(),
            )
            .await?;
        Ok(outcome.into())
    }

    pub async fn execute_pubsub_unsubscribe(
        &self,
        command: PubSubUnsubscribeCommand<'_>,
    ) -> Result<PubSubUnsubscribeResult> {
        validate_pubsub_unsubscribe_command(&command)?;
        let write = command.write;
        let name = PubSubNodeName::parse(write.node)?;
        let Some(node) = self.get_node(name.as_str()).await? else {
            return Ok(PubSubUnsubscribeOutcome::NotFound.into());
        };
        let node_id = PubSubNodeId::new(node.id);
        let requester = PubSubAddress::parse(write.requester)?.bare();
        let subscriber = PubSubAddress::parse(write.subscriber_jid)?;
        let _permit = self
            .admit_subscription_mutation(node_id, write.requester, write.subscriber_jid)
            .await?;
        let outcome = self
            .repository
            .unsubscribe_checked(
                node_id,
                &requester,
                &subscriber,
                write.requested_subid,
                self.time_sources(),
            )
            .await?;
        Ok(outcome.into())
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
        let _permit = self
            .mutation_admission
            .acquire_keys(
                &[
                    PubSubAdmissionKey::Text(command.requester),
                    PubSubAdmissionKey::Text(command.subscriber_jid),
                    PubSubAdmissionKey::NodeId(PubSubNodeId::new(node.id)),
                ],
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
                self.time_sources(),
            )
            .await?;
        Ok(PubSubAuthorizeSubscriptionResult { outcome })
    }
}

impl<R: PubSubSubscriptionMutationRepository> PubSubService<R> {
    pub async fn execute_pubsub_update_subscription_options(
        &self,
        command: PubSubUpdateSubscriptionOptionsCommand<'_>,
    ) -> Result<PubSubUpdateSubscriptionOptionsResult> {
        validate_pubsub_update_subscription_options_command(&command)?;
        let requester = PubSubBareJid::parse(command.requester)?;
        let subscriber = PubSubAddress::parse(command.subscriber_jid)?;
        if subscriber.bare() != requester {
            return Ok(PubSubUpdateSubscriptionOptionsResult {
                outcome: SubscriptionOptionsOutcome::Forbidden,
            });
        }
        if command.patch.show_values.as_ref().is_some_and(|values| {
            !northstar_xep_0060::subscription_show_values_allowed(
                requester.canonical().domainpart(),
                self.repository.local_domain(),
                values,
            )
        }) {
            return Ok(PubSubUpdateSubscriptionOptionsResult {
                outcome: SubscriptionOptionsOutcome::InvalidOptions,
            });
        }
        let _permit = self
            .admit_subscription_mutation(command.node_id, command.requester, command.subscriber_jid)
            .await?;
        let outcome = self
            .repository
            .update_subscription_options_checked(
                command.node_id,
                &requester,
                &subscriber,
                command.expected_subid,
                command.patch,
            )
            .await?;
        Ok(PubSubUpdateSubscriptionOptionsResult { outcome })
    }
}

#[cfg(test)]
mod tests;
