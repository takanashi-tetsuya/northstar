//! What the node provides to the session side of the archive context.

use northstar_archive_application::{MamPreferencesWriter, MamQueryRepository, MamService};

/// What the node provides to the XEP-0313 handlers of a client session. The composition root implements it.
pub trait ArchiveSessionHost: Send + Sync {
    /// The server's local domain.
    fn archive_local_domain(&self) -> &str;
    /// The node's MUC service domain, whose rooms keep their own archives.
    fn archive_muc_domain(&self) -> String;
    /// The archive service, over the repository the composition root binds.
    fn mam_service(
        &self,
    ) -> &MamService<
        impl MamQueryRepository<Error = anyhow::Error> + MamPreferencesWriter<Error = anyhow::Error>,
    >;
}
