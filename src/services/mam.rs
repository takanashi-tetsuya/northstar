//! MAM validation and post-commit delivery through an archive repository.

use anyhow::Result;
use uuid::Uuid;

pub(crate) use northstar_archive_application::{
    validate_mam_preferences, validate_mam_query_command, ArchiveBoundary, ArchivePage, ArchiveRow,
    FederatedMamAdmissionOutcome, FederatedMamOutboxLimits, FederatedMamStreamPage,
    FederatedMamStreamRequest, FederatedMamStreamRow, MamArchiveQuery, MamMetadataCommand,
    MamMetadataResult, MamPreferences, MamPreferencesGetCommand, MamPreferencesSetCommand,
    MamQueryCommand, MamQueryResult, MamQueryScope, MamRepository, MamRoomAccess,
    MamRoomAccessOutcome, MamRoomReadOutcome, MamRsmPage,
};

#[derive(Clone)]
pub(crate) struct MamService<R> {
    repository: R,
    outbox_limits: FederatedMamOutboxLimits,
    outbox_wake: tokio::sync::mpsc::Sender<()>,
}

impl<R: MamRepository<Error = anyhow::Error>> MamService<R> {
    pub(crate) fn new(
        repository: R,
        outbox_limits: FederatedMamOutboxLimits,
        outbox_wake: tokio::sync::mpsc::Sender<()>,
    ) -> Self {
        Self {
            repository,
            outbox_limits,
            outbox_wake,
        }
    }

    pub(crate) async fn execute_mam_query(
        &self,
        command: MamQueryCommand,
    ) -> Result<MamQueryResult> {
        if let Err(error) = validate_mam_query_command(&command) {
            return Ok(MamQueryResult::ValidationFailed(error));
        }
        self.repository.query_archive(command).await
    }

    pub(crate) async fn execute_mam_metadata(
        &self,
        command: MamMetadataCommand,
    ) -> Result<MamMetadataResult> {
        self.repository.get_boundaries(command).await
    }

    pub(crate) async fn execute_mam_preferences_get(
        &self,
        command: MamPreferencesGetCommand,
    ) -> Result<MamPreferences> {
        self.repository.get_preferences(command).await
    }

    pub(crate) async fn execute_mam_preferences_set(
        &self,
        command: MamPreferencesSetCommand,
    ) -> Result<()> {
        if let Err(error) = validate_mam_preferences(&command.preferences) {
            anyhow::bail!("invalid mam preferences: {error:?}");
        }
        self.repository.set_preferences(command).await
    }
    pub(crate) async fn authorize_room(
        &self,
        localpart: &str,
        viewer_id: Uuid,
        currently_joined: bool,
    ) -> Result<MamRoomAccessOutcome> {
        self.repository
            .authorize_room(localpart, viewer_id, currently_joined)
            .await
    }

    pub(crate) async fn authorize_federated_room(
        &self,
        localpart: &str,
        viewer_bare_jid: &str,
        currently_joined: bool,
    ) -> Result<MamRoomAccessOutcome> {
        self.repository
            .authorize_federated_room(localpart, viewer_bare_jid, currently_joined)
            .await
    }

    pub(crate) async fn authorized_federated_room_boundaries(
        &self,
        localpart: &str,
        viewer_bare_jid: &str,
        currently_joined: bool,
    ) -> Result<MamRoomReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
        self.repository
            .authorized_federated_room_boundaries(localpart, viewer_bare_jid, currently_joined)
            .await
    }

    pub(crate) async fn admit_federated_room_stream<F>(
        &self,
        request: FederatedMamStreamRequest<'_>,
        render: F,
    ) -> Result<FederatedMamAdmissionOutcome>
    where
        F: FnOnce(&FederatedMamStreamPage) -> Result<Vec<String>> + Send,
    {
        let outcome = self
            .repository
            .admit_federated_room_stream(self.outbox_limits, request, render)
            .await?;
        if matches!(outcome, FederatedMamAdmissionOutcome::Queued) {
            // The committed outbox survives a closed or coalesced wake channel.
            let _ = self.outbox_wake.try_send(());
        }
        Ok(outcome)
    }
}
