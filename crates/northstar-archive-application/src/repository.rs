//! Repository port traits for MAM archive queries and metadata.

use northstar_archive_core::{ArchiveBoundary, ArchivePage, MamPreferences, MamRoomAccess};

use crate::{
    MamMetadataCommand, MamPreferencesGetCommand, MamPreferencesSetCommand, MamQueryCommand,
};

pub type MamRepoResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Repository port for persistent MAM message archives.
pub trait MamRepository: Send + Sync {
    /// Query archived messages matching the given command scope and filter.
    fn query_archive(
        &self,
        command: &MamQueryCommand,
    ) -> impl std::future::Future<Output = MamRepoResult<(Option<MamRoomAccess>, ArchivePage)>> + Send;

    /// Retrieve the start/end boundary timestamps for an archive scope.
    fn get_boundaries(
        &self,
        command: &MamMetadataCommand,
    ) -> impl std::future::Future<
        Output = MamRepoResult<(
            Option<MamRoomAccess>,
            Option<ArchiveBoundary>,
            Option<ArchiveBoundary>,
        )>,
    > + Send;

    /// Read MAM archiving preferences for a user.
    fn get_preferences(
        &self,
        command: &MamPreferencesGetCommand,
    ) -> impl std::future::Future<Output = MamRepoResult<MamPreferences>> + Send;

    /// Set MAM archiving preferences for a user.
    fn set_preferences(
        &self,
        command: &MamPreferencesSetCommand,
    ) -> impl std::future::Future<Output = MamRepoResult<()>> + Send;
}
