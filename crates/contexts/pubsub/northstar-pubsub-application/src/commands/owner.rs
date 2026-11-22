//! Generic PubSub owner commands and validation.

use anyhow::Result;
use northstar_pubsub_core::{
    CollectionUpdateOutcome, CreateNodeOutcome, OwnerMutationOutcome, PubSubConfigOutcome,
    PubSubConfigureNodeWrite, PubSubCreateNodeWrite, PubSubDeleteNodeWrite, PubSubPurgeNodeWrite,
    PubSubSetAffiliationsWrite, PubSubSetSubscriptionsWrite, SetAffiliationsOutcome,
    SetSubscriptionsOutcome,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubCollectionEdgeOperation {
    Associate,
    Dissociate,
}

#[derive(Clone, Copy)]
pub struct PubSubCollectionEdgeCommand<'a> {
    pub requester: &'a str,
    pub collection: &'a northstar_pubsub_core::PubSubNode,
    pub child: &'a str,
    pub operation: PubSubCollectionEdgeOperation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubCollectionEdgeResult {
    MissingChild,
    Mutation(CollectionUpdateOutcome),
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

pub fn validate_pubsub_collection_edge_command(
    command: &PubSubCollectionEdgeCommand<'_>,
) -> Result<()> {
    if command.requester.trim().is_empty()
        || command.collection.node.trim().is_empty()
        || command.child.trim().is_empty()
    {
        return Err(anyhow::anyhow!("invalid PubSub collection edge"));
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
    // The name and id are carried together by the preflight node.
    northstar_pubsub_core::PubSubNodeName::parse(&command.write.node.node)?;
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
