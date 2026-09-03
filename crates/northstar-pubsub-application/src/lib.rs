#![forbid(unsafe_code)]

//! Application-level PubSub mutation admission and concurrency gate.
//!
//! This crate owns only non-database backpressure behavior:
//! owner-serialized mutation stripes, optional graph gate, and bounded
//! wait semantics plus admission counters.

use anyhow::{Error, Result};
use northstar_pubsub_core::{
    CreateNodeOutcome, OwnerMutationOutcome, PepConfigureNodeWrite, PepDeleteNodeWrite,
    PepOwnerMutationOutcome, PepPublishOutcome, PepPublishWrite, PepPurgeNodeWrite,
    PepRetractWrite, PepSetAffiliationsWrite, PepSubscribeOutcome, PepSubscribeWrite,
    PepUnsubscribeOutcome, PepUnsubscribeWrite, PubSubConfigOutcome, PubSubConfigureNodeWrite,
    PubSubCreateNodeWrite, PubSubDeleteNodeWrite, PubSubPublishOutcome, PubSubPublishWrite,
    PubSubPurgeNodeWrite, PubSubRetractOutcome, PubSubRetractWrite, PubSubSetAffiliationsWrite,
    PubSubSetSubscriptionsWrite, PubSubSubscribeOutcome, PubSubSubscribeWrite,
    PubSubUnsubscribeOutcome, PubSubUnsubscribeWrite, SetAffiliationsOutcome,
    SetSubscriptionsOutcome,
};
pub mod repository;
pub use repository::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};
use uuid::Uuid;

const PUBSUB_MUTATION_ADMISSION_TIMEOUT: Duration = Duration::from_secs(2);
const PUBSUB_MUTATION_OWNER_STRIPES: usize = 64;
const PUBSUB_MUTATION_MAX_TRANSACTIONS: usize = 8;

static PUBSUB_MUTATION_ADMISSION_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static PUBSUB_MUTATION_ADMISSION_WAITERS: AtomicU64 = AtomicU64::new(0);
static PUBSUB_MUTATION_ADMISSION_ACTIVE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct PubSubMutationBusy;

impl std::fmt::Display for PubSubMutationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pubsub mutation admission rejected due to bounded concurrency")
    }
}

impl std::error::Error for PubSubMutationBusy {}

pub fn pubsub_mutation_admission_rejections_total() -> u64 {
    PUBSUB_MUTATION_ADMISSION_REJECTIONS_TOTAL.load(Ordering::Relaxed)
}

pub fn pubsub_mutation_admission_waiters() -> u64 {
    PUBSUB_MUTATION_ADMISSION_WAITERS.load(Ordering::Relaxed)
}

pub fn pubsub_mutation_admission_active() -> u64 {
    PUBSUB_MUTATION_ADMISSION_ACTIVE.load(Ordering::Relaxed)
}

/// True only for retryable PubSub capacity/lock pressure errors.
pub fn is_pubsub_mutation_busy(error: &Error) -> bool {
    error.downcast_ref::<PubSubMutationBusy>().is_some()
}

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

pub struct PubSubPublishCommand<'a> {
    pub write: PubSubPublishWrite<'a>,
}

impl<'a> From<PubSubPublishWrite<'a>> for PubSubPublishCommand<'a> {
    fn from(write: PubSubPublishWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PubSubPublishResult {
    pub outcome: PubSubPublishOutcome,
}

impl From<PubSubPublishOutcome> for PubSubPublishResult {
    fn from(outcome: PubSubPublishOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PubSubSubscribeCommand<'a> {
    pub write: PubSubSubscribeWrite<'a>,
}

impl<'a> From<PubSubSubscribeWrite<'a>> for PubSubSubscribeCommand<'a> {
    fn from(write: PubSubSubscribeWrite<'a>) -> Self {
        Self { write }
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

pub struct PubSubRetractCommand<'a> {
    pub write: PubSubRetractWrite<'a>,
}

impl<'a> From<PubSubRetractWrite<'a>> for PubSubRetractCommand<'a> {
    fn from(write: PubSubRetractWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PubSubRetractResult {
    pub outcome: PubSubRetractOutcome,
}

impl From<PubSubRetractOutcome> for PubSubRetractResult {
    fn from(outcome: PubSubRetractOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PubSubCreateNodeCommand<'a> {
    pub write: PubSubCreateNodeWrite<'a>,
}

impl<'a> From<PubSubCreateNodeWrite<'a>> for PubSubCreateNodeCommand<'a> {
    fn from(write: PubSubCreateNodeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PubSubCreateNodeResult {
    pub outcome: CreateNodeOutcome,
}

impl From<CreateNodeOutcome> for PubSubCreateNodeResult {
    fn from(outcome: CreateNodeOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PubSubDeleteNodeCommand<'a> {
    pub write: PubSubDeleteNodeWrite<'a>,
}

impl<'a> From<PubSubDeleteNodeWrite<'a>> for PubSubDeleteNodeCommand<'a> {
    fn from(write: PubSubDeleteNodeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PubSubDeleteNodeResult {
    pub outcome: OwnerMutationOutcome,
}

impl From<OwnerMutationOutcome> for PubSubDeleteNodeResult {
    fn from(outcome: OwnerMutationOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PubSubPurgeNodeCommand<'a> {
    pub write: PubSubPurgeNodeWrite<'a>,
}

impl<'a> From<PubSubPurgeNodeWrite<'a>> for PubSubPurgeNodeCommand<'a> {
    fn from(write: PubSubPurgeNodeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PubSubPurgeNodeResult {
    pub outcome: OwnerMutationOutcome,
}

impl From<OwnerMutationOutcome> for PubSubPurgeNodeResult {
    fn from(outcome: OwnerMutationOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PubSubConfigureNodeCommand<'a> {
    pub write: PubSubConfigureNodeWrite<'a>,
}

impl<'a> From<PubSubConfigureNodeWrite<'a>> for PubSubConfigureNodeCommand<'a> {
    fn from(write: PubSubConfigureNodeWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PubSubConfigureNodeResult {
    pub outcome: PubSubConfigOutcome,
}

impl From<PubSubConfigOutcome> for PubSubConfigureNodeResult {
    fn from(outcome: PubSubConfigOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PubSubSetSubscriptionsCommand<'a> {
    pub write: PubSubSetSubscriptionsWrite<'a>,
}

impl<'a> From<PubSubSetSubscriptionsWrite<'a>> for PubSubSetSubscriptionsCommand<'a> {
    fn from(write: PubSubSetSubscriptionsWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PubSubSetSubscriptionsResult {
    pub outcome: SetSubscriptionsOutcome,
}

impl From<SetSubscriptionsOutcome> for PubSubSetSubscriptionsResult {
    fn from(outcome: SetSubscriptionsOutcome) -> Self {
        Self { outcome }
    }
}

pub struct PubSubSetAffiliationsCommand<'a> {
    pub write: PubSubSetAffiliationsWrite<'a>,
}

impl<'a> From<PubSubSetAffiliationsWrite<'a>> for PubSubSetAffiliationsCommand<'a> {
    fn from(write: PubSubSetAffiliationsWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Debug)]
pub struct PubSubSetAffiliationsResult {
    pub outcome: SetAffiliationsOutcome,
}

impl From<SetAffiliationsOutcome> for PubSubSetAffiliationsResult {
    fn from(outcome: SetAffiliationsOutcome) -> Self {
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

pub fn validate_pubsub_publish_command(command: &PubSubPublishCommand<'_>) -> Result<()> {
    if command.write.publisher_jid.trim().is_empty() {
        return Err(anyhow::anyhow!("publisher_jid must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
    if command.write.max_storage_bytes_per_owner < 1 || command.write.max_nodes_per_owner < 1 {
        return Err(anyhow::anyhow!("quotas must be positive"));
    }
    Ok(())
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

pub fn validate_pubsub_retract_command(command: &PubSubRetractCommand<'_>) -> Result<()> {
    if command.write.requester.trim().is_empty() {
        return Err(anyhow::anyhow!("requester must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
    if command.write.item_ids.is_empty() {
        return Err(anyhow::anyhow!("item_ids must not be empty"));
    }
    Ok(())
}

pub fn validate_pubsub_create_node_command(command: &PubSubCreateNodeCommand<'_>) -> Result<()> {
    if command.write.creator_jid.trim().is_empty() {
        return Err(anyhow::anyhow!("creator_jid must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
    if command.write.max_nodes_per_owner < 1 {
        return Err(anyhow::anyhow!("max_nodes_per_owner must be positive"));
    }
    Ok(())
}

pub fn validate_pubsub_delete_node_command(command: &PubSubDeleteNodeCommand<'_>) -> Result<()> {
    if command.write.requester.trim().is_empty() {
        return Err(anyhow::anyhow!("requester must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
    Ok(())
}

pub fn validate_pubsub_purge_node_command(command: &PubSubPurgeNodeCommand<'_>) -> Result<()> {
    if command.write.requester.trim().is_empty() {
        return Err(anyhow::anyhow!("requester must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
    Ok(())
}

pub fn validate_pubsub_configure_node_command(
    command: &PubSubConfigureNodeCommand<'_>,
) -> Result<()> {
    if command.write.requester.trim().is_empty() {
        return Err(anyhow::anyhow!("requester must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
    Ok(())
}

pub fn validate_pubsub_set_subscriptions_command(
    command: &PubSubSetSubscriptionsCommand<'_>,
) -> Result<()> {
    if command.write.requester.trim().is_empty() {
        return Err(anyhow::anyhow!("requester must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
    Ok(())
}

pub fn validate_pubsub_set_affiliations_command(
    command: &PubSubSetAffiliationsCommand<'_>,
) -> Result<()> {
    if command.write.requester.trim().is_empty() {
        return Err(anyhow::anyhow!("requester must not be empty"));
    }
    if command.write.node.trim().is_empty() {
        return Err(anyhow::anyhow!("node must not be empty"));
    }
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

struct PubSubAdmissionWaiter;

impl PubSubAdmissionWaiter {
    fn enter() -> Self {
        PUBSUB_MUTATION_ADMISSION_WAITERS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for PubSubAdmissionWaiter {
    fn drop(&mut self) {
        PUBSUB_MUTATION_ADMISSION_WAITERS.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct PubSubMutationPermit {
    _owner_permits: Vec<OwnedSemaphorePermit>,
    _graph_permit: Option<OwnedSemaphorePermit>,
    _transaction_permit: OwnedSemaphorePermit,
}

impl Drop for PubSubMutationPermit {
    fn drop(&mut self) {
        PUBSUB_MUTATION_ADMISSION_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct PubSubMutationAdmission {
    owner_stripes: Box<[Arc<Semaphore>]>,
    graph: Arc<Semaphore>,
    transactions: Arc<Semaphore>,
}

impl PubSubMutationAdmission {
    pub fn new(pool_max_connections: usize) -> Self {
        let transaction_limit = pool_max_connections
            .saturating_sub(1)
            .clamp(1, PUBSUB_MUTATION_MAX_TRANSACTIONS);
        Self {
            owner_stripes: (0..PUBSUB_MUTATION_OWNER_STRIPES)
                .map(|_| Arc::new(Semaphore::new(1)))
                .collect(),
            graph: Arc::new(Semaphore::new(1)),
            transactions: Arc::new(Semaphore::new(transaction_limit)),
        }
    }

    fn stripe(key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as usize % PUBSUB_MUTATION_OWNER_STRIPES
    }

    async fn acquire_owned_before(
        semaphore: Arc<Semaphore>,
        deadline: Instant,
    ) -> Result<OwnedSemaphorePermit> {
        timeout_at(deadline, semaphore.acquire_owned())
            .await
            .map_err(|_| PubSubMutationBusy)?
            .map_err(|_| PubSubMutationBusy.into())
    }

    pub async fn acquire(&self, keys: &[&str], graph: bool) -> Result<PubSubMutationPermit> {
        self.acquire_with_timeout(keys, graph, PUBSUB_MUTATION_ADMISSION_TIMEOUT)
            .await
    }

    pub async fn acquire_with_timeout(
        &self,
        keys: &[&str],
        graph: bool,
        wait: Duration,
    ) -> Result<PubSubMutationPermit> {
        let _waiter = PubSubAdmissionWaiter::enter();
        let deadline = Instant::now() + wait;
        let mut stripes = keys.iter().map(|key| Self::stripe(key)).collect::<Vec<_>>();
        stripes.sort_unstable();
        stripes.dedup();

        let result = async {
            let mut owner_permits = Vec::with_capacity(stripes.len());
            for stripe in stripes {
                owner_permits.push(
                    Self::acquire_owned_before(Arc::clone(&self.owner_stripes[stripe]), deadline)
                        .await?,
                );
            }
            let graph_permit = if graph {
                Some(Self::acquire_owned_before(Arc::clone(&self.graph), deadline).await?)
            } else {
                None
            };
            let transaction_permit =
                Self::acquire_owned_before(Arc::clone(&self.transactions), deadline).await?;
            Ok(PubSubMutationPermit {
                _owner_permits: owner_permits,
                _graph_permit: graph_permit,
                _transaction_permit: transaction_permit,
            })
        }
        .await;

        match result {
            Ok(permit) => {
                PUBSUB_MUTATION_ADMISSION_ACTIVE.fetch_add(1, Ordering::Relaxed);
                Ok(permit)
            }
            Err(error) => {
                PUBSUB_MUTATION_ADMISSION_REJECTIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    pub fn available_transaction_permits(&self) -> usize {
        self.transactions.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_pubsub_core::{PubSubAccount, PubSubPublishWrite, PubSubSubscribeWrite};

    #[test]
    fn pubsub_publish_validation() {
        let write = PubSubPublishWrite {
            publisher_jid: "user@example.com",
            node: "princely_musings",
            items: &[],
            publish_options: None,
            max_storage_bytes_per_owner: 1024,
            max_nodes_per_owner: 10,
        };
        let cmd = PubSubPublishCommand::from(write);
        assert!(validate_pubsub_publish_command(&cmd).is_ok());

        let invalid_write = PubSubPublishWrite {
            publisher_jid: "",
            node: "node",
            items: &[],
            publish_options: None,
            max_storage_bytes_per_owner: 1024,
            max_nodes_per_owner: 10,
        };
        assert!(
            validate_pubsub_publish_command(&PubSubPublishCommand::from(invalid_write)).is_err()
        );
    }

    #[test]
    fn pubsub_subscribe_validation() {
        let write = PubSubSubscribeWrite {
            requester: "user@example.com",
            subscriber_jid: "user@example.com/phone",
            node: "princely_musings",
            options: None,
            max_subscriptions: 100,
        };
        assert!(validate_pubsub_subscribe_command(&PubSubSubscribeCommand::from(write)).is_ok());

        let invalid = PubSubSubscribeWrite {
            requester: "user@example.com",
            subscriber_jid: "",
            node: "node",
            options: None,
            max_subscriptions: 100,
        };
        assert!(validate_pubsub_subscribe_command(&PubSubSubscribeCommand::from(invalid)).is_err());
    }

    #[test]
    fn pep_retract_and_delete_validation() {
        let owner = PubSubAccount {
            id: Uuid::new_v4(),
            username: "romeo".to_string(),
            auth_generation: 1,
        };
        let item_ids = vec!["item1".to_string()];
        let retract = PepRetractWrite {
            owner: &owner,
            connection_id: Uuid::new_v4(),
            node: "urn:xmpp:avatar:data",
            item_ids: &item_ids,
            notify: false,
        };
        assert!(validate_pep_retract_command(&PepRetractCommand::from(retract)).is_ok());

        let empty_items: Vec<String> = vec![];
        let invalid_retract = PepRetractWrite {
            owner: &owner,
            connection_id: Uuid::new_v4(),
            node: "urn:xmpp:avatar:data",
            item_ids: &empty_items,
            notify: false,
        };
        assert!(validate_pep_retract_command(&PepRetractCommand::from(invalid_retract)).is_err());

        let delete = PepDeleteNodeWrite {
            owner: &owner,
            connection_id: Uuid::new_v4(),
            node: "urn:xmpp:avatar:data",
        };
        assert!(validate_pep_delete_node_command(&PepDeleteNodeCommand::from(delete)).is_ok());
    }
}
