use super::UnusedPorts;
use anyhow::Result;
use northstar_roster_application::probe_decision::{
    BroadcastFacts, BroadcastQuery, PresenceDecisionReader, ProbeDecision, ProbeQuery,
};
use northstar_roster_application::{
    CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader,
};

impl CommunicationPolicyReader for UnusedPorts {
    async fn read_communication_policies(
        &self,
        queries: &[CommunicationPolicyQuery],
    ) -> Result<Vec<CommunicationDecision>> {
        Ok(vec![CommunicationDecision::Allow; queries.len()])
    }
}

impl PresenceDecisionReader for UnusedPorts {
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
