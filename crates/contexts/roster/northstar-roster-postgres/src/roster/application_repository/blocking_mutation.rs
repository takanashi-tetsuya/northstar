use super::PostgresBlockingRepository;
use anyhow::Result;
use northstar_roster_application::blocking_mutation::{
    BlockingMutation, BlockingMutationOutcome, BlockingRouteCandidate,
};
use northstar_roster_application::blocking_mutation_repository::BlockingMutationRepository;
use northstar_roster_application::RosterActor;

impl BlockingMutationRepository for PostgresBlockingRepository {
    async fn apply_blocking(
        &self,
        actor: RosterActor,
        mutation: BlockingMutation,
        route_candidates: &[BlockingRouteCandidate],
    ) -> Result<BlockingMutationOutcome> {
        super::super::blocking::apply_blocking(&self.pool, &actor, &mutation, route_candidates)
            .await
    }
}
