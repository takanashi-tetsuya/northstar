use crate::{blocking::BlockingMutationHost, RosterSessionHost};
use anyhow::Result;
use northstar_roster_application::{
    blocking_mutation::{BlockingMutation, BlockingMutationOutcome},
    RosterActor,
};
use northstar_stream::protocol::{ProtocolSession, SessionHost};

impl<H: SessionHost + RosterSessionHost> BlockingMutationHost for ProtocolSession<H> {
    async fn apply_blocking(
        &self,
        actor: RosterActor,
        mutation: BlockingMutation,
    ) -> Result<BlockingMutationOutcome> {
        self.host().apply_blocking(actor, mutation).await
    }
}
