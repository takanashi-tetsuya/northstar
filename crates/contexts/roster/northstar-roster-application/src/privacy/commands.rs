//! Actor-fenced privacy and blocklist IQ operations.

use super::{PrivacyItem, PrivacyListMutationOutcome, PrivacySelectionOutcome, PrivacyService};
use crate::RosterActor;
use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

pub use northstar_xep_0016::PrivacyListName;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActorOutcome<T> {
    Current(T),
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyOverviewSnapshot {
    pub active: Option<PrivacyListName>,
    pub default: Option<PrivacyListName>,
    pub names: Vec<PrivacyListName>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyResource {
    pub connection_id: Uuid,
    pub effective_list: Option<PrivacyListName>,
}

/// Other connections with live leases as sampled under the account lock.
/// All count because the lease table cannot attest publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyProof {
    pub other_resources: Vec<TopologyResource>,
}

pub trait PolicyCommandRepository: Send + Sync {
    fn read_privacy_overview(
        &self,
        actor: &RosterActor,
    ) -> impl Future<Output = Result<ActorOutcome<PrivacyOverviewSnapshot>>> + Send;

    fn read_privacy_list(
        &self,
        actor: &RosterActor,
        name: &PrivacyListName,
    ) -> impl Future<Output = Result<ActorOutcome<Option<Vec<PrivacyItem>>>>> + Send;

    fn read_blocklist(
        &self,
        actor: &RosterActor,
    ) -> impl Future<Output = Result<ActorOutcome<Vec<String>>>> + Send;

    fn replace_privacy_list(
        &self,
        actor: &RosterActor,
        name: &PrivacyListName,
        items: &[PrivacyItem],
    ) -> impl Future<Output = Result<ActorOutcome<PrivacyListMutationOutcome>>> + Send;

    fn select_default_privacy_list(
        &self,
        actor: &RosterActor,
        name: Option<&PrivacyListName>,
    ) -> impl Future<Output = Result<ActorOutcome<(PrivacySelectionOutcome, TopologyProof)>>> + Send;

    fn remove_privacy_list(
        &self,
        actor: &RosterActor,
        name: &PrivacyListName,
    ) -> impl Future<Output = Result<ActorOutcome<(PrivacyListMutationOutcome, TopologyProof)>>> + Send;
}

impl<R: PolicyCommandRepository> PrivacyService<R> {
    pub fn command_repository(&self) -> &impl PolicyCommandRepository {
        &self.repository
    }
}
