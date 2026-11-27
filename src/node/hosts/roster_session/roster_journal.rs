use super::ServerNode;
use anyhow::Result;
use northstar_roster_core::{RosterGap, RosterReadSnapshot};
use northstar_roster_xmpp::RosterJournalReader;
use northstar_workflows::roster::WorkflowRosterEffects;
use uuid::Uuid;

impl RosterJournalReader for ServerNode {
    async fn read_roster_gap(
        &self,
        owner: (Uuid, i64),
        gap: RosterGap,
        annotations_requested: bool,
    ) -> Result<Option<RosterReadSnapshot>> {
        northstar_roster_postgres::roster::read_roster_gap(
            &WorkflowRosterEffects,
            &self.pool,
            owner,
            gap,
            annotations_requested,
        )
        .await
    }
}
