use super::{ArchiveAdmissionOutcome, ArchiveCandidate, MessageRepository, Repository, Result};
use northstar_message_application::messaging::{MessageHistoryPreparation, PreparedMessageHistory};
use northstar_message_core::ActorGenerationFence;

impl MessageHistoryPreparation for Repository {
    async fn prepare_archive_history<'a>(
        &self,
        candidates: &[ArchiveCandidate<'a>],
    ) -> Result<PreparedMessageHistory<'a>> {
        Ok(PreparedMessageHistory::from_selected(candidates.to_vec()))
    }

    async fn write_prepared_archive_history(
        &self,
        history: PreparedMessageHistory<'_>,
        _: Option<ActorGenerationFence>,
    ) -> Result<ArchiveAdmissionOutcome> {
        self.admit_history(history.selected()).await
    }
}
