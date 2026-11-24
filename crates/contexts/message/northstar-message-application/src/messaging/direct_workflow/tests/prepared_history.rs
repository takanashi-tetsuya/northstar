use super::RecordingCommit;
use crate::messaging::{
    ArchiveAdmissionOutcome, ArchiveCandidate, MessageHistoryPreparation, PreparedMessageHistory,
};
use anyhow::Result;
use northstar_message_core::ActorGenerationFence;

impl MessageHistoryPreparation for RecordingCommit {
    async fn prepare_archive_history<'a>(
        &self,
        _: &[ArchiveCandidate<'a>],
    ) -> Result<PreparedMessageHistory<'a>> {
        panic!("service prepared separate history")
    }

    async fn write_prepared_archive_history(
        &self,
        _: PreparedMessageHistory<'_>,
        _: Option<ActorGenerationFence>,
    ) -> Result<ArchiveAdmissionOutcome> {
        panic!("service wrote separate history")
    }
}
