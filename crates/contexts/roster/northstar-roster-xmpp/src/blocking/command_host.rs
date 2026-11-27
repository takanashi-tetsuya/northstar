use anyhow::Result;
use northstar_roster_application::{
    blocking_mutation::{BlockingMutation, BlockingMutationOutcome},
    RosterActor,
};
use std::future::Future;

pub trait BlockingMutationHost: Sync {
    fn apply_blocking(
        &self,
        actor: RosterActor,
        mutation: BlockingMutation,
    ) -> impl Future<Output = Result<BlockingMutationOutcome>> + Send;
}
