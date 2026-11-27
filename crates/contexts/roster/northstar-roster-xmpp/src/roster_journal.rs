use anyhow::Result;
use northstar_roster_core::{RosterGap, RosterReadSnapshot};
use std::future::Future;
use uuid::Uuid;

/// Read-only repair of a version-complete roster push gap.
pub trait RosterJournalReader: Send + Sync {
    fn read_roster_gap(
        &self,
        owner: (Uuid, i64),
        gap: RosterGap,
        annotations_requested: bool,
    ) -> impl Future<Output = Result<Option<RosterReadSnapshot>>> + Send;
}
