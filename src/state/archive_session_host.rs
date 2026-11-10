//! The node's side of the archive context's session handlers.

use super::AppState;
use northstar_archive_application::{MamPreferencesWriter, MamQueryRepository, MamService};
use northstar_archive_xmpp::ArchiveSessionHost;

impl ArchiveSessionHost for AppState {
    fn archive_local_domain(&self) -> &str {
        self.local_domain()
    }

    fn archive_muc_domain(&self) -> String {
        northstar_muc_xmpp::muc::muc_service_domain(self.local_domain())
    }

    fn mam_service(
        &self,
    ) -> &MamService<
        impl MamQueryRepository<Error = anyhow::Error> + MamPreferencesWriter<Error = anyhow::Error>,
    > {
        AppState::mam_service(self)
    }
}
