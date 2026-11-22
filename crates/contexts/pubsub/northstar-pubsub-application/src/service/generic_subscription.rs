//! Generic PubSub subscription commands.

use super::PubSubService;
use crate::{
    authorization_precheck, validate_pubsub_authorize_subscription_command,
    validate_pubsub_subscribe_command, validate_pubsub_unsubscribe_command,
    validate_pubsub_update_subscription_options_command, PubSubAffiliationMutationRepository,
    PubSubAffiliationQueryRepository, PubSubAuthorizeSubscriptionCommand,
    PubSubAuthorizeSubscriptionResult, PubSubItemMutationRepository, PubSubItemQueryRepository,
    PubSubNodeMutationRepository, PubSubNodeQueryRepository, PubSubSubscribeCommand,
    PubSubSubscribeResult, PubSubSubscriptionMutationRepository, PubSubSubscriptionQueryRepository,
    PubSubUnsubscribeCommand, PubSubUnsubscribeResult, PubSubUpdateSubscriptionOptionsCommand,
    PubSubUpdateSubscriptionOptionsResult,
};
use anyhow::Result;
use northstar_pubsub_core::{
    pubsub_subscribe_policy, PubSubSubscribeOutcome, PubSubSubscribePolicy,
    PubSubSubscriptionOptions, PubSubUnsubscribeOutcome, SubscribeOutcome,
    SubscriptionAuthorizationOutcome, SubscriptionOptionsOutcome, UnsubscribeOutcome,
};

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
            if existing.is_active_at(northstar_time::Utc::now()) && write.options.is_none() {
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
        if subscription.is_expired_at(northstar_time::Utc::now()) {
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
