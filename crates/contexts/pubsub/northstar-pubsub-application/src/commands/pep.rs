//! Personal Eventing Protocol commands, results, and validation.

use anyhow::{Error, Result};
use northstar_pubsub_core::{
    PepBookmarkMutationOutcome, PepConfigureNodeWrite, PepCreateOutcome, PepDeleteNodeWrite,
    PepNodeConfig, PepOwnerMutationOutcome, PepPublishOutcome, PepPublishWrite, PepPurgeNodeWrite,
    PepQuotas, PepRetractWrite, PepSetAffiliationsWrite, PepSubscribeOutcome, PepSubscribeWrite,
    PepUnsubscribeOutcome, PepUnsubscribeWrite, PubSubAccount,
};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

pub struct PepPublishItemsCommand<'a> {
    pub write: PepPublishWrite<'a>,
    pub require_content_change: bool,
}

impl<'a> PepPublishItemsCommand<'a> {
    pub const fn new(write: PepPublishWrite<'a>, require_content_change: bool) -> Self {
        Self {
            write,
            require_content_change,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepPublishItemsOutcome {
    Published,
    Unauthorized,
    PreconditionFailed,
    MaxItemsExceeded,
    QuotaExceeded,
}

impl From<PepPublishOutcome> for PepPublishItemsOutcome {
    fn from(outcome: PepPublishOutcome) -> Self {
        match outcome {
            PepPublishOutcome::Published => Self::Published,
            PepPublishOutcome::Unauthorized => Self::Unauthorized,
            PepPublishOutcome::PreconditionFailed => Self::PreconditionFailed,
            PepPublishOutcome::MaxItemsExceeded => Self::MaxItemsExceeded,
            PepPublishOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}

impl From<PepPublishItemsOutcome> for PepPublishOutcome {
    fn from(outcome: PepPublishItemsOutcome) -> Self {
        match outcome {
            PepPublishItemsOutcome::Published => Self::Published,
            PepPublishItemsOutcome::Unauthorized => Self::Unauthorized,
            PepPublishItemsOutcome::PreconditionFailed => Self::PreconditionFailed,
            PepPublishItemsOutcome::MaxItemsExceeded => Self::MaxItemsExceeded,
            PepPublishItemsOutcome::QuotaExceeded => Self::QuotaExceeded,
        }
    }
}

#[derive(Debug)]
pub struct PepPublishItemsResult {
    pub outcome: PepPublishItemsOutcome,
    pub content_changed: bool,
}

pub struct PepSubscribeCommand<'a> {
    pub write: PepSubscribeWrite<'a>,
}

pub struct PepCreateNodeCommand<'a> {
    pub owner: &'a PubSubAccount,
    pub node: &'a str,
    pub max_nodes: i64,
    pub config: PepNodeConfig,
}

impl<'a> PepCreateNodeCommand<'a> {
    pub fn new(owner: &'a PubSubAccount, node: &'a str, max_nodes: i64) -> Self {
        Self {
            owner,
            node,
            max_nodes,
            config: northstar_pubsub_core::default_pep_node_config(node),
        }
    }
}

#[derive(Debug)]
pub struct PepCreateNodeResult {
    pub outcome: PepCreateOutcome,
}

impl From<PepCreateOutcome> for PepCreateNodeResult {
    fn from(outcome: PepCreateOutcome) -> Self {
        Self { outcome }
    }
}

impl<'a> From<PepSubscribeWrite<'a>> for PepSubscribeCommand<'a> {
    fn from(write: PepSubscribeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PepSubscribeResult {
    pub outcome: PepSubscribeOutcome,
}

impl From<PepSubscribeOutcome> for PepSubscribeResult {
    fn from(outcome: PepSubscribeOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PepUnsubscribeCommand<'a> {
    pub write: PepUnsubscribeWrite<'a>,
}

impl<'a> From<PepUnsubscribeWrite<'a>> for PepUnsubscribeCommand<'a> {
    fn from(write: PepUnsubscribeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PepUnsubscribeResult {
    pub outcome: PepUnsubscribeOutcome,
}

impl From<PepUnsubscribeOutcome> for PepUnsubscribeResult {
    fn from(outcome: PepUnsubscribeOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PepRetractCommand<'a> {
    pub write: PepRetractWrite<'a>,
}

impl<'a> From<PepRetractWrite<'a>> for PepRetractCommand<'a> {
    fn from(write: PepRetractWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PepRetractResult {
    pub outcome: PepOwnerMutationOutcome,
}

impl From<PepOwnerMutationOutcome> for PepRetractResult {
    fn from(outcome: PepOwnerMutationOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PepDeleteNodeCommand<'a> {
    pub write: PepDeleteNodeWrite<'a>,
}

impl<'a> From<PepDeleteNodeWrite<'a>> for PepDeleteNodeCommand<'a> {
    fn from(write: PepDeleteNodeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PepDeleteNodeResult {
    pub outcome: PepOwnerMutationOutcome,
}

impl From<PepOwnerMutationOutcome> for PepDeleteNodeResult {
    fn from(outcome: PepOwnerMutationOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PepPurgeNodeCommand<'a> {
    pub write: PepPurgeNodeWrite<'a>,
}

impl<'a> From<PepPurgeNodeWrite<'a>> for PepPurgeNodeCommand<'a> {
    fn from(write: PepPurgeNodeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PepPurgeNodeResult {
    pub outcome: PepOwnerMutationOutcome,
}

impl From<PepOwnerMutationOutcome> for PepPurgeNodeResult {
    fn from(outcome: PepOwnerMutationOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PepConfigureNodeCommand<'a> {
    pub write: PepConfigureNodeWrite<'a>,
}

impl<'a> From<PepConfigureNodeWrite<'a>> for PepConfigureNodeCommand<'a> {
    fn from(write: PepConfigureNodeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PepConfigureNodeResult {
    pub outcome: PepOwnerMutationOutcome,
}

impl From<PepOwnerMutationOutcome> for PepConfigureNodeResult {
    fn from(outcome: PepOwnerMutationOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PepSetAffiliationsCommand<'a> {
    pub write: PepSetAffiliationsWrite<'a>,
}

impl<'a> From<PepSetAffiliationsWrite<'a>> for PepSetAffiliationsCommand<'a> {
    fn from(write: PepSetAffiliationsWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PepSetAffiliationsResult {
    pub outcome: PepOwnerMutationOutcome,
}

impl From<PepOwnerMutationOutcome> for PepSetAffiliationsResult {
    fn from(outcome: PepOwnerMutationOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PepUnsubscribeBatchCommand<'a> {
    pub owner: &'a northstar_pubsub_core::PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub changes: &'a [(String, Option<String>)],
}

#[derive(Debug)]
pub struct PepUnsubscribeBatchResult {
    pub outcome: PepOwnerMutationOutcome,
}

impl From<PepOwnerMutationOutcome> for PepUnsubscribeBatchResult {
    fn from(outcome: PepOwnerMutationOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PepCommitLegacyBookmarksCommand<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub private_xml: &'a str,
    pub items: &'a mut [(String, String)],
    pub expected_previous_items: &'a [(String, String)],
    pub max_private_bytes: i64,
    pub quotas: PepQuotas,
}

#[derive(Debug)]
pub struct PepCommitLegacyBookmarksResult {
    pub outcome: PepBookmarkMutationOutcome,
}

impl From<PepBookmarkMutationOutcome> for PepCommitLegacyBookmarksResult {
    fn from(outcome: PepBookmarkMutationOutcome) -> Self {
        Self { outcome }
    }
}

/// The notification delta is calculated from the transaction's locked item
/// snapshot, not from the protocol handler's optimistic read.
#[derive(Debug, Eq, PartialEq)]
pub struct PepBookmarkEventPlan<'a> {
    pub changed_items: Vec<(&'a str, &'a str)>,
    pub retracted_item_ids: Vec<&'a str>,
}

impl PepBookmarkEventPlan<'_> {
    pub fn is_empty(&self) -> bool {
        self.changed_items.is_empty() && self.retracted_item_ids.is_empty()
    }
}

pub fn plan_pep_bookmark_event<'a>(
    current: &[(&'a str, &'a str)],
    previous: &[(&'a str, &'a str)],
) -> PepBookmarkEventPlan<'a> {
    let previous_by_id = previous.iter().copied().collect::<HashMap<_, _>>();
    let current_ids = current.iter().map(|(id, _)| *id).collect::<HashSet<_>>();
    let changed_items = current
        .iter()
        .copied()
        .filter(|(id, payload)| previous_by_id.get(id).copied() != Some(*payload))
        .collect();
    let mut retracted_item_ids = previous
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| !current_ids.contains(id))
        .collect::<Vec<_>>();
    retracted_item_ids.sort_unstable();
    PepBookmarkEventPlan {
        changed_items,
        retracted_item_ids,
    }
}

pub fn validate_pep_commit_legacy_bookmarks_command(
    command: &PepCommitLegacyBookmarksCommand<'_>,
) -> Result<()> {
    if command.owner.id.is_nil() || command.owner.username.is_empty() {
        return Err(anyhow::anyhow!("invalid PEP bookmarks owner"));
    }
    Ok(())
}

#[derive(Debug)]
pub enum PepSubscriptionCommandValidationError {
    EmptyOwner,
    EmptyActor,
    EmptyNode,
    EmptySubscriberJid,
    InvalidSubscriberLimit,
    EmptySubid,
}

impl std::fmt::Display for PepSubscriptionCommandValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyOwner => f.write_str("subscription command requires an owner account"),
            Self::EmptyActor => f.write_str("subscription command requires an actor jid"),
            Self::EmptyNode => f.write_str("subscription command requires a non-empty node"),
            Self::EmptySubscriberJid => {
                f.write_str("subscription command requires a non-empty subscriber jid")
            }
            Self::InvalidSubscriberLimit => {
                f.write_str("subscription command requires a positive max_subscriptions quota")
            }
            Self::EmptySubid => f.write_str("subscription command requires a non-empty subid"),
        }
    }
}

impl std::error::Error for PepSubscriptionCommandValidationError {}

pub fn validate_pep_create_node_command(command: &PepCreateNodeCommand<'_>) -> Result<()> {
    if command.owner.id.is_nil() || command.node.trim().is_empty() || command.max_nodes < 1 {
        return Err(anyhow::anyhow!("invalid PEP create command"));
    }
    Ok(())
}

pub fn validate_pep_subscribe_command(command: &PepSubscribeCommand<'_>) -> Result<()> {
    if command.write.owner.id == Uuid::nil() {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::EmptyOwner)
                .context("invalid PEP subscribe owner"),
        );
    }
    if command.write.owner.username.is_empty() {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::EmptyOwner)
                .context("invalid PEP subscribe owner"),
        );
    }
    if command.write.actor.jid.trim().is_empty() {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::EmptyActor)
                .context("invalid PEP subscribe actor"),
        );
    }
    if command.write.node.trim().is_empty() {
        return Err(Error::new(PepSubscriptionCommandValidationError::EmptyNode)
            .context("invalid PEP subscribe node"));
    }
    if command.write.subscriber_jid.trim().is_empty() {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::EmptySubscriberJid)
                .context("invalid PEP subscription target"),
        );
    }
    if command.write.max_subscriptions < 1 {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::InvalidSubscriberLimit)
                .context("invalid PEP max subscriptions"),
        );
    }
    if command.write.requested_subid.trim().is_empty() {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::EmptySubid)
                .context("invalid PEP subscription subid"),
        );
    }
    Ok(())
}

pub fn validate_pep_unsubscribe_command(command: &PepUnsubscribeCommand<'_>) -> Result<()> {
    if command.write.owner.id == Uuid::nil() {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::EmptyOwner)
                .context("invalid PEP unsubscribe owner"),
        );
    }
    if command.write.owner.username.is_empty() {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::EmptyOwner)
                .context("invalid PEP unsubscribe owner"),
        );
    }
    if command.write.actor.jid.trim().is_empty() {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::EmptyActor)
                .context("invalid PEP unsubscribe actor"),
        );
    }
    if command.write.node.trim().is_empty() {
        return Err(Error::new(PepSubscriptionCommandValidationError::EmptyNode)
            .context("invalid PEP unsubscribe node"));
    }
    if command.write.subscriber_jid.trim().is_empty() {
        return Err(
            Error::new(PepSubscriptionCommandValidationError::EmptySubscriberJid)
                .context("invalid PEP unsubscribe target"),
        );
    }
    Ok(())
}

#[derive(Debug)]
pub enum PepPublishCommandValidationError {
    EmptyActor,
    EmptyNode,
    EmptyItems,
    InvalidQuota,
    EmptyItemId(usize),
}

impl std::fmt::Display for PepPublishCommandValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyActor => f.write_str("publish command requires an authenticated owner"),
            Self::EmptyNode => f.write_str("publish command requires a non-empty node"),
            Self::EmptyItems => f.write_str("publish command requires at least one item"),
            Self::InvalidQuota => f.write_str("publish quota values must be strictly positive"),
            Self::EmptyItemId(index) => {
                write!(f, "publish item at index {} has an empty id", index)
            }
        }
    }
}

impl std::error::Error for PepPublishCommandValidationError {}

pub fn validate_pep_publish_command(command: &PepPublishItemsCommand<'_>) -> Result<()> {
    if command.write.user_id == Uuid::nil() {
        return Err(Error::new(PepPublishCommandValidationError::EmptyActor)
            .context("invalid PEP publish actor"));
    }
    if command.write.node.trim().is_empty() {
        return Err(Error::new(PepPublishCommandValidationError::EmptyNode)
            .context("invalid PEP publish node"));
    }
    if command.write.items.is_empty() {
        return Err(Error::new(PepPublishCommandValidationError::EmptyItems)
            .context("invalid PEP publish payload"));
    }
    if command.write.quotas.max_nodes < 1 || command.write.quotas.max_storage_bytes < 1 {
        return Err(Error::new(PepPublishCommandValidationError::InvalidQuota)
            .context("invalid PEP publish quotas"));
    }
    command
        .write
        .items
        .iter()
        .enumerate()
        .try_for_each(|(index, (item_id, _))| {
            if item_id.trim().is_empty() {
                Err(
                    Error::new(PepPublishCommandValidationError::EmptyItemId(index))
                        .context("invalid publish item identifier"),
                )
            } else {
                Ok(())
            }
        })?;
    Ok(())
}

pub fn validate_pep_retract_command(command: &PepRetractCommand<'_>) -> Result<()> {
    if command.write.owner.id == Uuid::nil() || command.write.owner.username.is_empty() {
        return Err(anyhow::anyhow!("invalid PEP retract owner"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("invalid PEP retract node"));
    }
    if command.write.item_ids.is_empty() {
        return Err(anyhow::anyhow!("invalid PEP retract items"));
    }
    Ok(())
}

pub fn validate_pep_delete_node_command(command: &PepDeleteNodeCommand<'_>) -> Result<()> {
    if command.write.owner.id == Uuid::nil() || command.write.owner.username.is_empty() {
        return Err(anyhow::anyhow!("invalid PEP delete owner"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("invalid PEP delete node"));
    }
    Ok(())
}

pub fn validate_pep_purge_node_command(command: &PepPurgeNodeCommand<'_>) -> Result<()> {
    if command.write.owner.id == Uuid::nil() || command.write.owner.username.is_empty() {
        return Err(anyhow::anyhow!("invalid PEP purge owner"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("invalid PEP purge node"));
    }
    Ok(())
}

pub fn validate_pep_configure_node_command(command: &PepConfigureNodeCommand<'_>) -> Result<()> {
    if command.write.owner.id == Uuid::nil() || command.write.owner.username.is_empty() {
        return Err(anyhow::anyhow!("invalid PEP configure owner"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("invalid PEP configure node"));
    }
    Ok(())
}

pub fn validate_pep_set_affiliations_command(
    command: &PepSetAffiliationsCommand<'_>,
) -> Result<()> {
    if command.write.owner.id == Uuid::nil() || command.write.owner.username.is_empty() {
        return Err(anyhow::anyhow!("invalid PEP affiliations owner"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("invalid PEP affiliations node"));
    }
    Ok(())
}

pub fn validate_pep_unsubscribe_batch_command(
    command: &PepUnsubscribeBatchCommand<'_>,
) -> Result<()> {
    if command.owner.id.is_nil()
        || command.owner.username.is_empty()
        || command.node.trim().is_empty()
        || command.changes.is_empty()
        || command.changes.len() > 1_000
    {
        return Err(anyhow::anyhow!("invalid PEP unsubscribe batch command"));
    }
    Ok(())
}
