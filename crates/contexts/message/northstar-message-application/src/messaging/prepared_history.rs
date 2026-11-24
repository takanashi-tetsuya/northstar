use super::{ArchiveAdmissionOutcome, ArchiveCandidate, MessageRepository, MessageService};
use anyhow::Result;
use northstar_message_core::ActorGenerationFence;
use std::future::Future;

/// Archive projections selected before a volatile send's route attempt.
pub struct PreparedMessageHistory<'a>(Vec<ArchiveCandidate<'a>>);

impl<'a> PreparedMessageHistory<'a> {
    pub fn from_selected(candidates: Vec<ArchiveCandidate<'a>>) -> Self {
        Self(candidates)
    }

    pub fn selected(&self) -> &[ArchiveCandidate<'a>] {
        &self.0
    }
}

pub trait MessageHistoryPreparation {
    fn prepare_archive_history<'a>(
        &self,
        candidates: &[ArchiveCandidate<'a>],
    ) -> impl Future<Output = Result<PreparedMessageHistory<'a>>> + Send;

    fn write_prepared_archive_history(
        &self,
        history: PreparedMessageHistory<'_>,
        actor: Option<ActorGenerationFence>,
    ) -> impl Future<Output = Result<ArchiveAdmissionOutcome>> + Send;
}

impl<R: MessageRepository> MessageService<R> {
    pub async fn prepare_archive_history<'a>(
        &self,
        candidates: &[ArchiveCandidate<'a>],
    ) -> Result<PreparedMessageHistory<'a>> {
        if candidates.is_empty() {
            return Ok(PreparedMessageHistory::from_selected(Vec::new()));
        }
        self.repository.prepare_archive_history(candidates).await
    }

    pub async fn write_prepared_archive_history(
        &self,
        history: PreparedMessageHistory<'_>,
        actor: Option<ActorGenerationFence>,
    ) -> Result<ArchiveAdmissionOutcome> {
        if history.selected().is_empty() {
            return Ok(ArchiveAdmissionOutcome::Projected(Vec::new()));
        }
        self.repository
            .write_prepared_archive_history(history, actor)
            .await
    }
}
