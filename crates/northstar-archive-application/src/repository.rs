//! Persistence operations for authorized archive reads and federated responses.

use crate::{
    ArchiveBoundary, FederatedMamAdmissionOutcome, FederatedMamStreamPage,
    FederatedMamStreamRequest, MamMetadataCommand, MamMetadataResult, MamPreferences,
    MamPreferencesGetCommand, MamPreferencesSetCommand, MamQueryCommand, MamQueryResult,
    MamRoomAccessOutcome, MamRoomReadOutcome,
};
use std::future::Future;

pub type MamArchiveBoundaries = (Option<ArchiveBoundary>, Option<ArchiveBoundary>);

#[derive(Clone, Copy)]
pub struct FederatedMamOutboxLimits {
    pub ttl_seconds: u64,
    pub max_rows: i64,
    pub max_bytes: i64,
    pub max_per_domain: i64,
}

/// Room archive reads retain authorization and page selection in one database
/// snapshot. Legacy rooms may also initialize a missing occupant-ID secret.
pub trait MamQueryRepository: Send + Sync {
    type Error;
    fn query_archive(
        &self,
        command: MamQueryCommand,
    ) -> impl Future<Output = Result<MamQueryResult, Self::Error>> + Send;
    fn get_boundaries(
        &self,
        command: MamMetadataCommand,
    ) -> impl Future<Output = Result<MamMetadataResult, Self::Error>> + Send;
    fn get_preferences(
        &self,
        command: MamPreferencesGetCommand,
    ) -> impl Future<Output = Result<MamPreferences, Self::Error>> + Send;
    fn authorize_room(
        &self,
        localpart: &str,
        viewer_id: uuid::Uuid,
        currently_joined: bool,
    ) -> impl Future<Output = Result<MamRoomAccessOutcome, Self::Error>> + Send;
    fn authorize_federated_room(
        &self,
        localpart: &str,
        viewer_bare_jid: &str,
        currently_joined: bool,
    ) -> impl Future<Output = Result<MamRoomAccessOutcome, Self::Error>> + Send;
    fn authorized_federated_room_boundaries(
        &self,
        localpart: &str,
        viewer_bare_jid: &str,
        currently_joined: bool,
    ) -> impl Future<Output = Result<MamRoomReadOutcome<MamArchiveBoundaries>, Self::Error>> + Send;
}

pub trait MamPreferencesWriter: Send + Sync {
    type Error;
    fn set_preferences(
        &self,
        command: MamPreferencesSetCommand,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub trait FederatedMamStreamWriter: Send + Sync {
    type Error;
    /// Keep room authorization and all response rows, including the terminal
    /// IQ, in one transaction. Rendering must be synchronous and side-effect free.
    fn admit_federated_room_stream<F>(
        &self,
        limits: FederatedMamOutboxLimits,
        request: FederatedMamStreamRequest<'_>,
        render: F,
    ) -> impl Future<Output = Result<FederatedMamAdmissionOutcome, Self::Error>> + Send
    where
        F: FnOnce(&FederatedMamStreamPage) -> Result<Vec<String>, Self::Error> + Send;
}
