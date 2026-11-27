//! Transactional blocklist mutation and presence planning.

use crate::blocking_mutation::{BlockingMutation, BlockingMutationOutcome, BlockingRouteCandidate};
use crate::RosterActor;
use anyhow::Result;
use std::future::Future;

pub trait BlockingMutationRepository: Send + Sync {
    fn apply_blocking(
        &self,
        actor: RosterActor,
        mutation: BlockingMutation,
        route_candidates: &[BlockingRouteCandidate],
    ) -> impl Future<Output = Result<BlockingMutationOutcome>> + Send;
}
