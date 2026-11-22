//! MAM validation and post-commit delivery through an archive repository.

use anyhow::Result;

use crate::{
    validate_mam_preferences, validate_mam_query_command, FederatedMamAdmissionOutcome,
    FederatedMamMetadataCommand, FederatedMamOutboxLimits, FederatedMamStreamPage,
    FederatedMamStreamRequest, FederatedMamStreamWriter, MamAccountOutcome, MamLocalAuthority,
    MamMetadataCommand, MamMetadataResult, MamPreferences, MamPreferencesGetCommand,
    MamPreferencesSetCommand, MamPreferencesWriter, MamQueryCommand, MamQueryRepository,
    MamQueryResult, MamRoomAccessOutcome, MamRoomReadAuthority,
};

#[derive(Clone)]
pub struct MamService<R> {
    repository: R,
    outbox_limits: FederatedMamOutboxLimits,
    outbox_wake: tokio::sync::mpsc::Sender<()>,
}

impl<R> MamService<R> {
    pub fn new(
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
}

impl<R: MamQueryRepository<Error = anyhow::Error>> MamService<R> {
    pub async fn execute_mam_query(&self, command: MamQueryCommand) -> Result<MamQueryResult> {
        if let Err(error) = validate_mam_query_command(&command) {
            return Ok(MamQueryResult::ValidationFailed(error));
        }
        self.repository.query_archive(command).await
    }

    pub async fn execute_mam_metadata(
        &self,
        command: MamMetadataCommand,
    ) -> Result<MamMetadataResult> {
        self.repository.get_boundaries(command).await
    }

    pub async fn execute_federated_mam_metadata(
        &self,
        command: FederatedMamMetadataCommand,
    ) -> Result<MamMetadataResult> {
        self.repository.get_federated_boundaries(command).await
    }

    pub async fn execute_mam_preferences_get(
        &self,
        command: MamPreferencesGetCommand,
    ) -> Result<MamAccountOutcome<MamPreferences>> {
        self.repository.get_preferences(command).await
    }

    pub async fn authorize_personal(
        &self,
        authority: &MamLocalAuthority,
    ) -> Result<MamAccountOutcome<()>> {
        self.repository.authorize_personal(authority).await
    }

    pub async fn authorize_room(
        &self,
        localpart: &str,
        account: &MamLocalAuthority,
        authority: &MamRoomReadAuthority,
    ) -> Result<MamRoomAccessOutcome> {
        self.repository
            .authorize_room(localpart, account, authority)
            .await
    }

    pub async fn federated_room_visible(
        &self,
        localpart: &str,
        viewer_full_jid: &str,
    ) -> Result<bool> {
        self.repository
            .federated_room_visible(localpart, viewer_full_jid)
            .await
    }

    pub async fn authorize_federated_room(
        &self,
        localpart: &str,
        authority: &MamRoomReadAuthority,
    ) -> Result<MamRoomAccessOutcome> {
        self.repository
            .authorize_federated_room(localpart, authority)
            .await
    }
}

impl<R: MamPreferencesWriter<Error = anyhow::Error>> MamService<R> {
    pub async fn execute_mam_preferences_set(
        &self,
        command: MamPreferencesSetCommand,
    ) -> Result<MamAccountOutcome<()>> {
        if let Err(error) = validate_mam_preferences(&command.preferences) {
            anyhow::bail!("invalid mam preferences: {error:?}");
        }
        self.repository.set_preferences(command).await
    }
}

impl<R: FederatedMamStreamWriter<Error = anyhow::Error>> MamService<R> {
    pub async fn admit_federated_room_stream<F>(
        &self,
        request: FederatedMamStreamRequest<'_>,
        render: F,
    ) -> Result<FederatedMamAdmissionOutcome>
    where
        F: FnMut(&FederatedMamStreamPage) -> Result<Vec<String>> + Send,
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
