//! Generic PubSub publication and retraction commands.

use anyhow::Result;
use northstar_pubsub_core::{
    PubSubPublishOutcome, PubSubPublishWrite, PubSubRetractOutcome, PubSubRetractWrite,
};

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
