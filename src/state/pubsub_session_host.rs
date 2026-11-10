//! The node's side of the PubSub context's session handlers.

use super::AppState;
use northstar_pubsub_application::private_storage::{
    PrivateStorageRepository, PrivateStorageService,
};
use northstar_pubsub_application::profile::{ProfileRepository, ProfileService};
use northstar_pubsub_core::PepQuotas;
use northstar_pubsub_xmpp::PubSubSessionHost;
use northstar_roster_xmpp::presence::inject_vcard_avatar_hash;

impl PubSubSessionHost for AppState {
    fn pep_account_quotas(&self) -> PepQuotas {
        AppState::pep_account_quotas(self)
    }

    fn profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        AppState::profile_service(self)
    }

    fn private_storage_service(&self) -> &PrivateStorageService<impl PrivateStorageRepository> {
        AppState::private_storage_service(self)
    }

    fn pep_record_published(&self, count: u64) {
        self.pep_telemetry().published(count);
    }

    fn pep_record_retracted(&self, count: u64) {
        self.pep_telemetry().retracted(count);
    }

    fn pep_record_retrieved(&self) {
        self.pep_telemetry().retrieved();
    }

    fn refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        for session in self.sessions_for(owner_bare) {
            let mut last_presence = session
                .last_presence
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let refreshed = last_presence.as_deref().and_then(|raw| {
                let document = roxmltree::Document::parse(raw).ok()?;
                Some(inject_vcard_avatar_hash(raw, document.root_element(), hash))
            });
            if let Some(refreshed) = refreshed {
                *last_presence = Some(refreshed);
            }
        }
    }
}
