use super::UnusedRepository;
use anyhow::Result;
use northstar_roster_application::probe_decision::{
    BroadcastFacts, BroadcastQuery, PresenceDecisionReader, ProbeDecision, ProbeQuery,
};

impl PresenceDecisionReader for UnusedRepository {
    async fn read_broadcast_facts(
        &self,
        _query: BroadcastQuery<'_>,
    ) -> Result<Vec<BroadcastFacts>> {
        unreachable!("unused broadcast decision port")
    }

    async fn decide_probe(&self, _query: ProbeQuery<'_>) -> Result<ProbeDecision> {
        unreachable!("unused probe decision port")
    }
}
