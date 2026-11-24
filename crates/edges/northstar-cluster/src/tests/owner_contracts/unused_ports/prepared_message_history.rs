use super::MessagePorts;
use anyhow::Result;
use northstar_message_application::messaging::{
    ArchiveAdmissionOutcome, ArchiveCandidate, MessageHistoryPreparation, PreparedMessageHistory,
};
use northstar_message_core::ActorGenerationFence;

impl MessageHistoryPreparation for MessagePorts {
    async fn prepare_archive_history<'a>(
        &self,
        _: &[ArchiveCandidate<'a>],
    ) -> Result<PreparedMessageHistory<'a>> {
        panic!("unused message history preparation port")
    }

    async fn write_prepared_archive_history(
        &self,
        _: PreparedMessageHistory<'_>,
        _: Option<ActorGenerationFence>,
    ) -> Result<ArchiveAdmissionOutcome> {
        panic!("unused prepared message history write port")
    }
}
