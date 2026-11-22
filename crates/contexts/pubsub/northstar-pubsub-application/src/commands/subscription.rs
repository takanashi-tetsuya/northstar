//! Generic PubSub subscription commands and prechecks.

use anyhow::Result;
use northstar_pubsub_core::{
    PubSubNodeId, PubSubSubscribeOutcome, PubSubSubscribeWrite, PubSubUnsubscribeOutcome,
    PubSubUnsubscribeWrite, SubscriptionAuthorizationOutcome, SubscriptionOptionsOutcome,
    SubscriptionOptionsPatch,
};

pub struct PubSubSubscribeCommand<'a> {
    pub write: PubSubSubscribeWrite<'a>,
    pub(crate) resolved_node_id: Option<PubSubNodeId>,
}

impl PubSubSubscribeCommand<'_> {
    /// Reuse the identity resolved for node-dependent form validation.
    pub fn with_node_id(mut self, node_id: PubSubNodeId) -> Self {
        self.resolved_node_id = Some(node_id);
        self
    }
}

impl<'a> From<PubSubSubscribeWrite<'a>> for PubSubSubscribeCommand<'a> {
    fn from(write: PubSubSubscribeWrite<'a>) -> Self {
        Self {
            write,
            resolved_node_id: None,
        }
    }
}

#[derive(Debug)]
pub struct PubSubSubscribeResult {
    pub outcome: PubSubSubscribeOutcome,
}

impl From<PubSubSubscribeOutcome> for PubSubSubscribeResult {
    fn from(outcome: PubSubSubscribeOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PubSubUnsubscribeCommand<'a> {
    pub write: PubSubUnsubscribeWrite<'a>,
}

impl<'a> From<PubSubUnsubscribeWrite<'a>> for PubSubUnsubscribeCommand<'a> {
    fn from(write: PubSubUnsubscribeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PubSubUnsubscribeResult {
    pub outcome: PubSubUnsubscribeOutcome,
}

impl From<PubSubUnsubscribeOutcome> for PubSubUnsubscribeResult {
    fn from(outcome: PubSubUnsubscribeOutcome) -> Self {
        Self { outcome }
    }
}

#[derive(Clone, Copy)]
pub struct PubSubAuthorizeSubscriptionCommand<'a> {
    pub requester: &'a str,
    pub node: &'a str,
    pub subscriber_jid: &'a str,
    pub echoed_subid: Option<&'a str>,
    pub allow: bool,
}

#[derive(Debug)]
pub struct PubSubAuthorizeSubscriptionResult {
    pub outcome: SubscriptionAuthorizationOutcome,
}

pub struct PubSubUpdateSubscriptionOptionsCommand<'a> {
    pub node_id: PubSubNodeId,
    pub requester: &'a str,
    pub subscriber_jid: &'a str,
    pub expected_subid: &'a str,
    pub patch: &'a SubscriptionOptionsPatch,
}

#[derive(Debug)]
pub struct PubSubUpdateSubscriptionOptionsResult {
    pub outcome: SubscriptionOptionsOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubSubscriptionOptionsPrecheck {
    Ready,
    NotSubscribed,
    InvalidSubid,
}

pub fn subscription_options_precheck(
    expired: bool,
    current_subid: &str,
    echoed_subid: Option<&str>,
) -> PubSubSubscriptionOptionsPrecheck {
    if expired {
        PubSubSubscriptionOptionsPrecheck::NotSubscribed
    } else if echoed_subid.is_some_and(|subid| subid != current_subid) {
        PubSubSubscriptionOptionsPrecheck::InvalidSubid
    } else {
        PubSubSubscriptionOptionsPrecheck::Ready
    }
}

/// A read snapshot only filters invalid authorization forms. The repository
/// must repeat these checks under its node and subscription locks before write.
pub fn authorization_precheck(
    state: &str,
    stored_subid: &str,
    echoed_subid: Option<&str>,
    requester_is_owner: bool,
) -> Option<SubscriptionAuthorizationOutcome> {
    if echoed_subid.is_some_and(|echoed| echoed != stored_subid) {
        return Some(SubscriptionAuthorizationOutcome::Stale);
    }
    if !requester_is_owner {
        return Some(SubscriptionAuthorizationOutcome::Forbidden);
    }
    if state != "pending" {
        return Some(SubscriptionAuthorizationOutcome::Stale);
    }
    None
}

pub fn validate_pubsub_subscribe_command(command: &PubSubSubscribeCommand<'_>) -> Result<()> {
    if command.write.requester.trim().is_empty() {
        return Err(anyhow::anyhow!("requester must not be empty"));
    }
    if command.write.subscriber_jid.trim().is_empty() {
        return Err(anyhow::anyhow!("subscriber_jid must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
    if command.write.max_subscriptions < 1 {
        return Err(anyhow::anyhow!("max_subscriptions must be positive"));
    }
    Ok(())
}

pub fn validate_pubsub_unsubscribe_command(command: &PubSubUnsubscribeCommand<'_>) -> Result<()> {
    if command.write.requester.trim().is_empty() {
        return Err(anyhow::anyhow!("requester must not be empty"));
    }
    if command.write.subscriber_jid.trim().is_empty() {
        return Err(anyhow::anyhow!("subscriber_jid must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
    Ok(())
}

pub fn validate_pubsub_authorize_subscription_command(
    command: &PubSubAuthorizeSubscriptionCommand<'_>,
) -> Result<()> {
    if command.requester.trim().is_empty()
        || command.node.trim().is_empty()
        || command.subscriber_jid.trim().is_empty()
    {
        return Err(anyhow::anyhow!("invalid PubSub subscription authorization"));
    }
    Ok(())
}

pub fn validate_pubsub_update_subscription_options_command(
    command: &PubSubUpdateSubscriptionOptionsCommand<'_>,
) -> Result<()> {
    if command.node_id.get().is_nil()
        || command.requester.trim().is_empty()
        || command.subscriber_jid.trim().is_empty()
        || command.expected_subid.is_empty()
    {
        return Err(anyhow::anyhow!(
            "invalid PubSub subscription options command"
        ));
    }
    Ok(())
}
