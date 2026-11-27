use crate::node::ServerNode;
use anyhow::Result;
use northstar_roster_application::{
    blocking_mutation::{BlockingMutation, BlockingMutationOutcome},
    blocking_mutation_repository::BlockingMutationRepository,
    RosterActor,
};
use northstar_roster_postgres::roster::PostgresBlockingRepository;
use northstar_roster_xmpp::blocking::BlockingMutationHost;

impl BlockingMutationHost for ServerNode {
    async fn apply_blocking(
        &self,
        actor: RosterActor,
        mutation: BlockingMutation,
    ) -> Result<BlockingMutationOutcome> {
        let presence = self.cluster_listener_blocking();
        if !presence.admits_actor(&actor) {
            return Ok(BlockingMutationOutcome::Unavailable);
        }
        let candidates = presence
            .capture_candidates(&actor, mutation.patterns())
            .await;
        if !presence.admits_actor(&actor) {
            return Ok(BlockingMutationOutcome::Unavailable);
        }
        PostgresBlockingRepository::new(self.pool.clone())
            .apply_blocking(actor, mutation, &candidates)
            .await
    }
}
