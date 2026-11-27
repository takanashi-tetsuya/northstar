use super::PostgresPresenceRepository;
use anyhow::Result;
use northstar_roster_application::probe_decision::{
    BroadcastFacts, BroadcastQuery, PresenceDecisionReader, ProbeDecision, ProbeQuery,
};

impl PresenceDecisionReader for PostgresPresenceRepository {
    async fn read_broadcast_facts(&self, query: BroadcastQuery<'_>) -> Result<Vec<BroadcastFacts>> {
        northstar_roster_postgres::roster::read_broadcast_facts(&self.pool, query).await
    }

    async fn decide_probe(&self, query: ProbeQuery<'_>) -> Result<ProbeDecision> {
        northstar_roster_postgres::roster::decide_probe(&self.pool, query).await
    }
}
